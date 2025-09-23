"""
Authentication service for handling OAuth2 flows.
"""
import time
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

from app.utils import generate_state, make_pkce_pair
from ..config.settings import settings
from ..models.auth import StateRecord, AuthStatusResponse
from ..services.aws_client import AWSClient as _AWSClient
from .cognito_client import CognitoClient
from ..exceptions.auth_exceptions import InvalidStateException, MissingTokenException, CognitoAPIException
from ..middleware.logging_config import LoggerMixin
from ..utils.state_store import state_store
from ..utils.cookies import CookieManager
from jose import jwt


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
    
    async def refresh_tokens(self, request: Request, response: Response) -> dict:
        """
        Refresh access/ID tokens using the refresh token cookie, via Cognito IDP.
        Mirrors the login flow and avoids Hosted UI networking issues.
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
            # try username cookie first (if you set one at login)
            username = request.cookies.get(getattr(self.cookie_manager, "USERNAME_COOKIE", "username"))
            if not username:
                # fallback: decode from ID token claims
                id_jwt = request.cookies.get(self.cookie_manager.ID_COOKIE)
                if id_jwt:
                    username = _extract_username_from_id_token(id_jwt)

            if not username:
                self.logger.error("Username required to compute SECRET_HASH for IDP refresh but not found")
                raise CognitoAPIException("Cannot refresh: missing username context")

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

        if access_token:
            self.cookie_manager.set_cookie(
                response,
                self.cookie_manager.ACCESS_COOKIE,
                access_token,
                settings.access_token_ttl_seconds,
                path="/",
            )
        if id_token:
            self.cookie_manager.set_cookie(
                response,
                self.cookie_manager.ID_COOKIE,
                id_token,
                settings.access_token_ttl_seconds,
                path="/",
            )

        self.logger.info("Successfully refreshed tokens")
        return {"success": True}
    
    async def logout(self, request: Request, response: Response) -> RedirectResponse:
        """Logout user and clear cookies.

        Reads the ID token from cookies (if present), decodes the JWT payload
        without verifying the signature to identify which user is being
        logged out, logs and prints that information, clears cookies, and
        redirects to the Cognito logout URL.
        """
        self.logger.info("Logging out user")

        # Try to identify user from ID token in cookies and verify signature via JWKS
        id_token = request.cookies.get(self.cookie_manager.ID_COOKIE)
        if id_token:
            try:
                claims = await self._verify_id_token(id_token)
                user_id = claims.get('sub') or claims.get('email') or claims.get('username') or '<unknown>'
                self.logger.info(f"Verified logout for user: {user_id}")
                print(f"Verified logout for user: {user_id}")
            except Exception as e:
                # Verification failed; fall back to unverified decode for logging only
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
                        user_id = claims.get('sub') or claims.get('email') or claims.get('username') or '<unknown>'
                        self.logger.info(f"Logging out (unverified) user: {user_id}")
                        print(f"Logging out (unverified) user: {user_id}")
                    else:
                        self.logger.info("ID token present but JWT format is invalid")
                except Exception as e2:
                    self.logger.error(f"Failed to decode ID token payload after verification failure: {e2}")
        else:
            self.logger.info("No ID token cookie found; logging out anonymous session")

        # Clear authentication cookies
        self.cookie_manager.clear_auth_cookies(response)

        # Build Cognito logout URL
        logout_params = {
            "client_id": settings.cognito_app_client_id,
            "logout_uri": str(settings.post_logout_redirect)
        }
        logout_url = f"{settings.cognito_domain}/logout?{urlencode(logout_params)}"
        self.logger.debug(f"logout_url: {logout_url}")

        self.logger.info("User logged out successfully")
        return RedirectResponse(logout_url)

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

    async def signup_user(self, email: str, password: str) -> dict:
        """Sign up a new user using Cognito SignUp API."""
        # Use AWSClient wrapper to register user
        # import locally to avoid circular imports at module load

        aws = _AWSClient()
        resp = aws.sign_up(username=email, password=password, user_attributes={"email": email})
        return resp

    async def confirm_signup(self, email: str, confirmation_code: str) -> dict:
        """Confirm a signed up user with the provided confirmation code."""

        aws = _AWSClient()
        resp = aws.confirm_sign_up(username=email, confirmation_code=confirmation_code)
        return resp

    async def login_user(self, email: str, password: str, response: Response) -> dict:
        """Authenticate a user using email/password and set auth cookies on success."""

        aws = _AWSClient()
        auth_result = aws.initiate_auth(username=email, password=password)

        # auth_result may include AccessToken, IdToken, RefreshToken, ExpiresIn
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

        return auth_result
    
    async def resend_confirmation_code(self, email: str) -> dict:
        """
        Resend Cognito signup confirmation code to the given email.
        """
        try:
            aws_client = _AWSClient()
            result = aws_client.resend_confirmation_code(email)
            return {"message": "Confirmation code resent", "result": result}
        except Exception as e:
            self.logger.error(f"Failed to resend confirmation code: {e}")
            raise

    async def forgot_password(self, email: str) -> dict:
        """
        Initiate Cognito forgot password flow (send reset code to email).
        """
        try:
            aws_client = _AWSClient()
            result = aws_client.forgot_password(email)
            return {"message": "Password reset code sent", "result": result}
        except Exception as e:
            self.logger.error(f"Failed to initiate forgot password: {e}")
            raise

    async def reset_password(self, email: str, code: str, new_password: str) -> dict:
        """
        Confirm Cognito password reset with code and new password.
        """
        try:
            aws_client = _AWSClient()
            result = aws_client.reset_password(email, code, new_password)
            return {"message": "Password has been reset", "result": result}
        except Exception as e:
            self.logger.error(f"Failed to reset password: {e}")
            raise

    async def change_password(self, request: Request, old_password: str, new_password: str) -> dict:
        """
        Change password for authenticated user (requires access token).
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
            return {"message": "Password changed successfully", "result": result}
        except Exception as e:
            self.logger.error(f"Failed to change password: {e}")
            raise

    async def logout_all(self, request: Request) -> dict:
        """
        Log out user from all devices (global sign-out).
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
        try:
            aws_client = _AWSClient()
            result = aws_client.logout_all(access_token)
            return {"message": "User logged out from all devices", "result": result}
        except Exception as e:
            self.logger.error(f"Failed to global logout: {e}")
            raise