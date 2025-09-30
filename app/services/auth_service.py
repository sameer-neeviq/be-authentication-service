"""
Authentication service for handling OAuth2 flows.
"""
import uuid
from typing import Optional
from urllib.parse import urlencode
from fastapi import Request, Response
import json
import base64
import time as _time
from typing import Dict
import httpx
from jose import jwk, jwt
from jose.utils import base64url_decode
from fastapi.responses import RedirectResponse
from app.db.db_tables_models import UserSession
from sqlalchemy import func
from datetime import datetime, timedelta

from app.utils import generate_state, make_pkce_pair
from ..config.settings import settings
from ..models.auth import StateRecord, AuthStatusResponse
from ..services.aws_client import AWSClient as _AWSClient
from .cognito_client import CognitoClient
from ..exceptions.auth_exceptions import InvalidStateException, MissingTokenException, CognitoAPIException
from app.db.db_tables_models import UserAppProfile, UserRole, AuthAuditLog
from ..middleware.logging_config import LoggerMixin
from ..utils.state_store import state_store
from ..utils.cookies import CookieManager




def _extract_username_from_id_token(id_jwt: str) -> Optional[str]:
    """
    Extract the Cognito username (or email) from an ID token.
    Uses unverified decode — only for pulling claims, NOT for auth.
    """
    try:
        claims = jwt.get_unverified_claims(id_jwt)
        return (
            claims.get("cognito:username")
            or claims.get("username")
            or claims.get("email")
        )
    except Exception:
        return None
    
class AuthService(LoggerMixin):
    """Service for handling authentication operations."""
    
    def __init__(self):
        self.cognito_client = CognitoClient()
        self.cookie_manager = CookieManager()
        # simple in-memory JWKS cache: { 'jwks': {...}, 'fetched_at': epoch }
        self._jwks_cache: Dict[str, object] = {}
        self.client_secret = settings.cognito_app_client_secret
    
    async def refresh_tokens(self, request: Request, response: Response, db) -> dict:
        """
        Refresh access/ID tokens using the refresh token cookie, via Cognito IDP.
        Mirrors the login flow.
        """
        self.logger.info("Refreshing tokens via Cognito IDP")

        # 1) Get refresh token
        refresh_token = request.cookies.get(self.cookie_manager.REFRESH_COOKIE)
        if not refresh_token:
            self.logger.warning("Missing refresh token in request")
            raise MissingTokenException("refresh token")

        # 2) Resolve username only IF a client secret exists
        username = None
        if self.client_secret:
            # Try username cookie first (if you set one at login)
            username = request.cookies.get(getattr(self.cookie_manager, "USERNAME_COOKIE", "username"))
            self.logger.debug(f"Tried username from cookie: {username}")
            if not username:
                # Fallback: decode from ID token claims
                id_jwt = request.cookies.get(self.cookie_manager.ID_COOKIE)
                if id_jwt:
                    username = _extract_username_from_id_token(id_jwt)
                    self.logger.debug(f"Tried username from ID token: {username}")

            # Optionally: try to extract from request headers or other context here

            if not username:
                self.logger.error("Username required to compute SECRET_HASH for IDP refresh but not found in cookie or ID token")
                raise CognitoAPIException("Cannot refresh: missing username context. Please re-login.")

        # 3) Call Cognito IDP
        try:
            aws = _AWSClient()  # uses your settings inside
            ar = aws.refresh_auth(refresh_token=refresh_token, username=username or "")
        except Exception as e:
            self.logger.exception("Cognito IDP refresh call failed")
            raise CognitoAPIException("Error communicating with Cognito IDP")

        # 4) Set new cookies
        access_token = ar.get("AccessToken")
        id_token = ar.get("IdToken")

        if refresh_token:
            expires_at = datetime.utcnow() + timedelta(seconds=settings.refresh_token_ttl_seconds)
            session_token = str(uuid.uuid4())
            session_id = uuid.uuid4()
            # Extract cognito_user_id from the ID token if possible
            id_jwt = request.cookies.get(self.cookie_manager.ID_COOKIE)
            cognito_user_id = None
            if id_jwt:
                claims = jwt.get_unverified_claims(id_jwt)
                cognito_user_id = claims.get("sub") or claims.get("cognito:username") or claims.get("username") or claims.get("email")
            # Extract user_agent from request headers if available
            user_agent = request.headers.get("user-agent", None)
            user_session = UserSession(
                id=session_id,
                cognito_user_id=cognito_user_id,
                session_token=session_token,
                refresh_token=refresh_token,
                user_agent=user_agent,
                created_at=func.now(),
                expires_at=expires_at,
                last_accessed=func.now(),
                is_active=True
            )
            db.add(user_session)

        self.logger.info("Successfully refreshed tokens")
        return {"success": True}
    
    async def logout(self, request: Request, response: Response, db) -> RedirectResponse:
        """Logout user, clear cookies, mark session inactive, and log event."""
        self.logger.info("Logging out user")

        # Identify user/session from cookies
        id_token = request.cookies.get(self.cookie_manager.ID_COOKIE)
        refresh_token = request.cookies.get(self.cookie_manager.REFRESH_COOKIE)
        session_token = request.cookies.get(self.cookie_manager.SESSION_COOKIE, None) if hasattr(self.cookie_manager, 'SESSION_COOKIE') else None
        cognito_user_id = None
        if id_token:
            try:
                claims = await self._verify_id_token(id_token)
                cognito_user_id = claims.get('sub') or claims.get('email') or claims.get('username') or '<unknown>'
                self.logger.info(f"Verified logout for user: {cognito_user_id}")
            except Exception as e:
                self.logger.warning(f"ID token verification failed: {e}; falling back to unverified decode for logging")
                try:
                    parts = id_token.split('.')
                    if len(parts) >= 2:
                        payload_b64 = parts[1]
                        rem = len(payload_b64) % 4
                        if rem:
                            payload_b64 += '=' * (4 - rem)
                        payload_bytes = base64.urlsafe_b64decode(payload_b64.encode('utf-8'))
                        claims = json.loads(payload_bytes.decode('utf-8'))
                        cognito_user_id = claims.get('sub') or claims.get('email') or claims.get('username') or '<unknown>'
                        self.logger.info(f"Logging out (unverified) user: {cognito_user_id}")
                    else:
                        self.logger.info("ID token present but JWT format is invalid")
                except Exception as e2:
                    self.logger.error(f"Failed to decode ID token payload after verification failure: {e2}")
        else:
            self.logger.info("No ID token cookie found; logging out anonymous session")

        # Mark user session as inactive in DB
        try:
            session_query = db.query(UserSession).filter(UserSession.is_active == True)
            if cognito_user_id:
                session_query = session_query.filter(UserSession.cognito_user_id == cognito_user_id)
            if refresh_token:
                session_query = session_query.filter(UserSession.refresh_token == refresh_token)
            if session_token:
                session_query = session_query.filter(UserSession.session_token == session_token)
            updated = session_query.update({UserSession.is_active: False, UserSession.last_accessed: func.now()})
            db.commit()
            self.logger.info(f"Marked {updated} user session(s) as inactive for logout.")
        except Exception as e:
            db.rollback()
            self.logger.error(f"Failed to mark user session inactive on logout: {e}")

        # Log logout event
        try:
            audit_log = AuthAuditLog(
                cognito_user_id=cognito_user_id,
                event_type="logout",
                event_status="success",
                event_category="user",
                user_agent=request.headers.get("user-agent")
            )
            db.add(audit_log)
            db.commit()
        except Exception as e:
            db.rollback()
            self.logger.error(f"Failed to log logout event: {e}")

        # Clear authentication cookies
        self.cookie_manager.clear_auth_cookies(response)

        # For non-Hosted UI: just return a JSON response after clearing cookies and updating DB
        self.logger.info("User logged out successfully (no Hosted UI redirect)")
        return {"message": "User logged out successfully"}

    async def _fetch_jwks(self) -> Dict[str, object]:
        """Fetch JWKS from Cognito and cache it for a short time (async)."""
        now = int(_time.time())
        cache = self._jwks_cache
        # cache for 15 minutes
        if cache.get('jwks') and (now - cache.get('fetched_at', 0) < 15 * 60):
            return cache['jwks']

        url = settings.jwks_url
        self.logger.debug(f"Fetching JWKS from {url}")
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, timeout=settings.cognito_timeout_seconds)
            resp.raise_for_status()
            jwks = resp.json()

        cache['jwks'] = jwks
        cache['fetched_at'] = now
        return jwks

    async def _verify_id_token(self, id_token: str) -> Dict[str, object]:
        """Verify ID token signature and claims using the JWKS from Cognito.

        Returns the verified claims dict or raises an exception on failure.
        """
        jwks = await self._fetch_jwks()
        # jose.jwt.decode will handle signature verification given the jwks
        # We need to pass the appropriate audience and issuer
        issuer = settings.issuer
        audience = settings.cognito_app_client_id

        # jose can accept the jwks as a dict via 'key' parameter, but requires
        # selecting the right key by kid. We'll use jose.jwt.get_unverified_header
        header = jwt.get_unverified_header(id_token)
        kid = header.get('kid')
        if not kid:
            raise RuntimeError('ID token missing kid in header')

        keys = jwks.get('keys', [])
        key_obj = None
        for k in keys:
            if k.get('kid') == kid:
                key_obj = k
                break
        if not key_obj:
            raise RuntimeError(f'No matching JWK found for kid={kid}')

        # Build public key and verify
        public_key = jwk.construct(key_obj)
        message, encoded_sig = id_token.rsplit('.', 1)
        decoded_sig = base64url_decode(encoded_sig.encode('utf-8'))
        if not public_key.verify(message.encode('utf-8'), decoded_sig):
            raise RuntimeError('ID token signature verification failed')

        # Now decode and validate claims (exp, iss, aud) using jose.jwt.decode
        claims = jwt.decode(id_token, key_obj, algorithms=[key_obj.get('alg', 'RS256')], audience=audience, issuer=issuer)
        return claims
        
    
    async def get_auth_status(self, request: Request) -> AuthStatusResponse:
        """Get current authentication status."""
        # Look for ID token in cookie first, then Authorization header
        id_token = request.cookies.get(self.cookie_manager.ID_COOKIE)
        if not id_token:
            # Try Authorization: Bearer <token>
            auth_header = request.headers.get('authorization') or request.headers.get('Authorization')
            if auth_header and auth_header.lower().startswith('bearer '):
                id_token = auth_header.split(' ', 1)[1].strip()

        if not id_token:
            self.logger.debug("Auth status check: no id_token present")
            return AuthStatusResponse(authenticated=False, user_info=None)

        # Verify the ID token and return claims as user_info
        try:
            claims = await self._verify_id_token(id_token)
            return AuthStatusResponse(authenticated=True, user_info=claims)
        except Exception as e:
            self.logger.warning(f"ID token verification failed in get_auth_status: {e}")
            return AuthStatusResponse(authenticated=False, user_info=None)

    async def signup_user(self, email: str, password: str, db, user_agent: str = None) -> dict:
        """Sign up a new user using Cognito SignUp API, create user profile, role, and log."""
        aws = _AWSClient()
        resp = aws.sign_up(username=email, password=password, user_attributes={"email": email})
        user_sub = resp.get("UserSub")
        # Create user profile
        
        user_profile = UserAppProfile(
            cognito_user_id=user_sub,
            email=email,
            oauth_provider="cognito",
            oauth_provider_id=user_sub,
            is_active=False
        )
        db.add(user_profile)
        db.flush()
        # Assign default role 'client'
        user_role = UserRole(
            cognito_user_id=user_sub,
            role_name="client",
            is_active=False
        )
        db.add(user_role)
        # Log event
        audit_log = AuthAuditLog(
            cognito_user_id=user_sub,
            event_type="signup",
            event_status="success",
            event_category="user",
            user_agent=user_agent
        )
        db.add(audit_log)
        db.commit()
        return resp

    async def confirm_signup(self, email: str, confirmation_code: str, db, user_agent: str = None) -> dict:
        """Confirm a signed up user with the provided confirmation code and log event."""
        aws = _AWSClient()
        resp = aws.confirm_sign_up(username=email, confirmation_code=confirmation_code)

        # Look up user profile by email
        user_profile = db.query(UserAppProfile).filter_by(email=email).first()
        cognito_user_id = user_profile.cognito_user_id if user_profile else None
        # Set user as active if found
        if user_profile:
            user_profile.is_active = True
        # Set user role as active if found
        user_role = db.query(UserRole).filter_by(cognito_user_id=cognito_user_id).first()
        if user_role:
            user_role.is_active = True
        # Flush changes to ensure updates are tracked
        db.flush()
        # Log event with correct cognito_user_id
        audit_log = AuthAuditLog(
            cognito_user_id=cognito_user_id,
            event_type="confirm_signup",
            event_status="success",
            event_category="user",
            user_agent=user_agent
        )
        db.add(audit_log)
        db.commit()
        return resp

    async def login_user(self, email: str, password: str, response: Response, db=None, user_agent: str = None) -> dict:
        """Authenticate a user using email/password, set auth cookies, update profile, and log login."""
        aws = _AWSClient()
        auth_result = aws.initiate_auth(username=email, password=password)

        access_token = auth_result.get('AccessToken')
        id_token = auth_result.get('IdToken')
        refresh_token = auth_result.get('RefreshToken')

        if access_token:
            self.cookie_manager.set_cookie(response, self.cookie_manager.ACCESS_COOKIE, access_token, settings.access_token_ttl_seconds)
        if id_token:
            self.cookie_manager.set_cookie(response, self.cookie_manager.ID_COOKIE, id_token, settings.access_token_ttl_seconds)
        if refresh_token:
            self.cookie_manager.set_cookie(response, self.cookie_manager.REFRESH_COOKIE, refresh_token, settings.refresh_token_ttl_seconds, path='/auth/')

        self.cookie_manager.set_cookie(
            response,
            self.cookie_manager.USERNAME_COOKIE,
            email,
            settings.refresh_token_ttl_seconds,
            path="/auth/"
        )

        # Generate and set dedicated session token
        session_token = str(uuid.uuid4())
        session_expires_at = datetime.utcnow() + timedelta(seconds=settings.refresh_token_ttl_seconds)
        self.cookie_manager.set_cookie(
            response,
            "session_token",
            session_token,
            settings.refresh_token_ttl_seconds,
            path="/"
        )

        # Update user profile, log login, and create session if db is provided
        if db is not None:
            user_profile = db.query(UserAppProfile).filter_by(email=email).first()
            cognito_user_id = user_profile.cognito_user_id if user_profile else None

            if user_profile:
                user_profile.last_login_at = func.now()
                user_profile.login_count = (user_profile.login_count or 0) + 1
            # Log login event
            audit_log = AuthAuditLog(
                cognito_user_id=cognito_user_id,
                event_type="login",
                event_status="success",
                event_category="user",
                user_agent=user_agent
            )
            db.add(audit_log)
            # Always create user session with session_token and store refresh_token if present
            try:
                user_session = UserSession(
                    cognito_user_id=cognito_user_id,
                    session_token=session_token,
                    refresh_token=refresh_token,
                    user_agent=user_agent,
                    created_at=func.now(),
                    expires_at=session_expires_at,
                    last_accessed=func.now(),
                    is_active=True
                )
                db.add(user_session)
                db.commit()
            except Exception as e:
                db.rollback()
                raise

        return auth_result
    
    async def resend_confirmation_code(self, email: str, db=None, user_agent: str = None) -> dict:
        """
        Resend Cognito signup confirmation code to the given email. Logs event if db provided.
        """
        try:
            aws_client = _AWSClient()
            result = aws_client.resend_confirmation_code(email)
            # Log event if db is provided
            if db is not None:
                user_profile = db.query(UserAppProfile).filter_by(email=email).first()
                cognito_user_id = user_profile.cognito_user_id if user_profile else None
                audit_log = AuthAuditLog(
                    cognito_user_id=cognito_user_id,
                    event_type="resend_confirmation_code",
                    event_status="success",
                    event_category="user",
                    user_agent=user_agent
                )
                db.add(audit_log)
                db.commit()
            return {"message": "Confirmation code resent", "result": result}
        except Exception as e:
            if db is not None:
                db.rollback()
            self.logger.error(f"Failed to resend confirmation code: {e}")
            raise

    async def forgot_password(self, email: str, db=None, user_agent: str = None) -> dict:
        """
        Initiate Cognito forgot password flow (send reset code to email). Logs event if db provided.
        """
        try:
            aws_client = _AWSClient()
            result = aws_client.forgot_password(email)
            # Log event if db is provided
            if db is not None:
                user_profile = db.query(UserAppProfile).filter_by(email=email).first()
                cognito_user_id = user_profile.cognito_user_id if user_profile else None
                audit_log = AuthAuditLog(
                    cognito_user_id=cognito_user_id,
                    event_type="forgot_password",
                    event_status="success",
                    event_category="user",
                    user_agent=user_agent
                )
                db.add(audit_log)
                db.commit()
            return {"message": "Password reset code sent", "result": result}
        except Exception as e:
            if db is not None:
                db.rollback()
            self.logger.error(f"Failed to initiate forgot password: {e}")
            raise

    async def reset_password(self, email: str, code: str, new_password: str, db=None, user_agent: str = None) -> dict:
        """
        Confirm Cognito password reset with code and new password. Logs event if db provided.
        """
        try:
            aws_client = _AWSClient()
            result = aws_client.reset_password(email, code, new_password)
            # Log event if db is provided
            if db is not None:
                user_profile = db.query(UserAppProfile).filter_by(email=email).first()
                cognito_user_id = user_profile.cognito_user_id if user_profile else None
                audit_log = AuthAuditLog(
                    cognito_user_id=cognito_user_id,
                    event_type="reset_password",
                    event_status="success",
                    event_category="user",
                    user_agent=user_agent
                )
                db.add(audit_log)
                db.commit()
            return {"message": "Password has been reset", "result": result}
        except Exception as e:
            if db is not None:
                db.rollback()
            self.logger.error(f"Failed to reset password: {e}")
            raise

    async def change_password(self, request: Request, old_password: str, new_password: str, db=None, user_agent: str = None) -> dict:
        """
        Change password for authenticated user (requires access token). Logs event if db provided.
        """
        # Extract access token from cookie or Authorization header
        access_token = request.cookies.get(self.cookie_manager.ACCESS_COOKIE)
        if not access_token:
            auth_header = request.headers.get("authorization")
            if auth_header and auth_header.lower().startswith("bearer "):
                access_token = auth_header[7:]
        if not access_token:
            self.logger.error("Missing access token for change password")
            raise Exception("Missing access token")
        self.logger.info("Changing password for authenticated user")
        try:
            aws_client = _AWSClient()
            result = aws_client.change_password(access_token, old_password, new_password)
            # Log event if db is provided
            if db is not None:
                # Try to extract user info from access token
                cognito_user_id = None
                try:
                    claims = jwt.get_unverified_claims(access_token)
                    cognito_user_id = claims.get('sub') or claims.get('email') or claims.get('username') or None
                except Exception:
                    pass
                audit_log = AuthAuditLog(
                    cognito_user_id=cognito_user_id,
                    event_type="change_password",
                    event_status="success",
                    event_category="user",
                    user_agent=user_agent
                )
                db.add(audit_log)
                db.commit()
            return {"message": "Password changed successfully", "result": result}
        except Exception as e:
            if db is not None:
                db.rollback()
            self.logger.error(f"Failed to change password: {e}")
            raise

    async def logout_all(self, request: Request, db) -> dict:
        """
        Log out user from all devices (global sign-out), mark all sessions inactive, and log event.
        """
        # Extract access token from cookie or Authorization header
        access_token = request.cookies.get(self.cookie_manager.ACCESS_COOKIE)
        if not access_token:
            auth_header = request.headers.get("authorization")
            if auth_header and auth_header.lower().startswith("bearer "):
                access_token = auth_header[7:]
        if not access_token:
            self.logger.error("Missing access token for global logout")
            raise Exception("Missing access token")
        self.logger.info("Global logout for authenticated user")

        # Identify user from access token (decode JWT)
        cognito_user_id = None
        try:
            claims = jwt.get_unverified_claims(access_token)
            cognito_user_id = claims.get('sub') or claims.get('email') or claims.get('username') or '<unknown>'
        except Exception as e:
            self.logger.warning(f"Failed to decode access token for logout-all: {e}")

        # Mark all user sessions as inactive in DB
        try:
            session_query = db.query(UserSession).filter(UserSession.is_active == True)
            if cognito_user_id:
                session_query = session_query.filter(UserSession.cognito_user_id == cognito_user_id)
            updated = session_query.update({UserSession.is_active: False, UserSession.last_accessed: func.now()})
            db.commit()
            self.logger.info(f"Marked {updated} user session(s) as inactive for logout-all.")
        except Exception as e:
            db.rollback()
            self.logger.error(f"Failed to mark user sessions inactive on logout-all: {e}")

        # Log logout-all event
        try:
            audit_log = AuthAuditLog(
                cognito_user_id=cognito_user_id,
                event_type="logout_all",
                event_status="success",
                event_category="user",
                user_agent=request.headers.get("user-agent")
            )
            db.add(audit_log)
            db.commit()
        except Exception as e:
            db.rollback()
            self.logger.error(f"Failed to log logout-all event: {e}")

        # Call Cognito global sign-out
        try:
            aws_client = _AWSClient()
            result = aws_client.logout_all(access_token)
            return {"message": "User logged out from all devices", "result": result}
        except Exception as e:
            self.logger.error(f"Failed to global logout: {e}")
            raise