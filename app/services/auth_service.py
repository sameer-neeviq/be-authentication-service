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
# from ..utils import make_pkce_pair, generate_state
from .cognito_client import CognitoClient
from ..exceptions.auth_exceptions import InvalidStateException, MissingTokenException
from ..middleware.logging_config import LoggerMixin
from ..utils.state_store import state_store
from ..utils.cookies import CookieManager


class AuthService(LoggerMixin):
    """Service for handling authentication operations."""
    
    def __init__(self):
        self.cognito_client = CognitoClient()
        self.cookie_manager = CookieManager()
        # simple in-memory JWKS cache: { 'jwks': {...}, 'fetched_at': epoch }
        self._jwks_cache: Dict[str, object] = {}
    
    async def handle_callback(
        self,
        code: str,
        state: str,
        response: Response
    ) -> RedirectResponse:
        """Handle OAuth2 callback and exchange code for tokens."""
        self.logger.info("Handling OAuth2 callback")
        
        # Retrieve and validate state
        state_record = await state_store.retrieve(state)
        if not state_record:
            self.logger.warning(f"Invalid state in callback: {state[:8]}...")
            raise InvalidStateException()
        
        try:
            # Exchange code for tokens
            token_response = await self.cognito_client.exchange_code_for_tokens(
                code=code,
                code_verifier=state_record.verifier,
                redirect_uri=str(settings.redirect_uri)
            )
            
            # Set authentication cookies
            self.cookie_manager.set_auth_cookies(
                response=response,
                access_token=token_response.access_token,
                id_token=token_response.id_token,
                refresh_token=token_response.refresh_token
            )
            
            self.logger.info("Successfully completed OAuth2 callback")
            return RedirectResponse(state_record.redirect_to)
            
        except Exception as e:
            self.logger.error(f"Error during callback handling: {e}")
            raise
    
    async def refresh_tokens(self, request: Request, response: Response) -> dict:
        """Refresh access and ID tokens."""
        self.logger.info("Refreshing tokens")
        
        # Get refresh token from cookie
        refresh_token = request.cookies.get(self.cookie_manager.REFRESH_COOKIE)
        if not refresh_token:
            self.logger.warning("Missing refresh token in request")
            raise MissingTokenException("refresh token")
        
        try:
            # Refresh tokens with Cognito
            token_response = await self.cognito_client.refresh_tokens(refresh_token)
            
            # Update cookies with new tokens
            self.cookie_manager.set_cookie(
                response,
                self.cookie_manager.ACCESS_COOKIE,
                token_response.access_token,
                settings.access_token_ttl_seconds
            )
            
            if token_response.id_token:
                self.cookie_manager.set_cookie(
                    response,
                    self.cookie_manager.ID_COOKIE,
                    token_response.id_token,
                    settings.access_token_ttl_seconds
                )
            
            self.logger.info("Successfully refreshed tokens")
            return {"success": True}
            
        except Exception as e:
            self.logger.error(f"Error during token refresh: {e}")
            raise
    
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
            self.logger.debug(f"Auth status verified for sub={claims.get('sub')}")
            return AuthStatusResponse(authenticated=True, user_info=claims)
        except Exception as e:
            self.logger.warning(f"ID token verification failed in get_auth_status: {e}")
            return AuthStatusResponse(authenticated=False, user_info=None)

    async def signup_user(self, email: str, password: str) -> dict:
        """Sign up a new user using Cognito SignUp API."""
        self.logger.info(f"Signing up user: {email}")
        # Use AWSClient wrapper to register user
        # import locally to avoid circular imports at module load
        from ..services.aws_client import AWSClient as _AWSClient

        aws = _AWSClient()
        resp = aws.sign_up(username=email, password=password, user_attributes={"email": email})
        return resp

    async def confirm_signup(self, email: str, confirmation_code: str) -> dict:
        """Confirm a signed up user with the provided confirmation code."""
        self.logger.info(f"Confirming signup for: {email}")
        from ..services.aws_client import AWSClient as _AWSClient

        aws = _AWSClient()
        resp = aws.confirm_sign_up(username=email, confirmation_code=confirmation_code)
        return resp

    async def login_user(self, email: str, password: str, response: Response) -> dict:
        """Authenticate a user using email/password and set auth cookies on success."""
        self.logger.info(f"Logging in user: {email}")
        from ..services.aws_client import AWSClient as _AWSClient

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

        return auth_result
    