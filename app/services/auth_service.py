"""
Authentication service for handling OAuth2 flows.
"""
import time
from typing import Optional
from urllib.parse import urlencode
from fastapi import Request, Response
from fastapi.responses import RedirectResponse

from ..config.settings import settings
from ..models.auth import StateRecord, AuthStatusResponse
from ..utils import make_pkce_pair, generate_state
from ..utils.cookies import CookieManager
from ..utils.state_store import state_store
from ..services.cognito_client import CognitoClient
from ..exceptions.auth_exceptions import InvalidStateException, MissingTokenException
from ..middleware.logging_config import LoggerMixin


class AuthService(LoggerMixin):
    """Service for handling authentication operations."""
    
    def __init__(self):
        self.cognito_client = CognitoClient()
        self.cookie_manager = CookieManager()
    
    async def initiate_login(self, redirect_to: Optional[str] = None) -> RedirectResponse:
        """Initiate OAuth2 login flow."""
        self.logger.info("Initiating login flow")
        
        # Generate PKCE pair and state
        pkce_pair = make_pkce_pair()
        state = generate_state()
        
        # Store state with verifier and redirect info
        state_record = StateRecord(
            verifier=pkce_pair.verifier,
            redirect_to=redirect_to or str(settings.post_login_redirect),
            created_at=time.time()
        )
        await state_store.store(state, state_record)
        
        # Build authorization URL
        auth_params = {
            "client_id": settings.cognito_app_client_id,
            "response_type": "code",
            "scope": settings.cognito_scope,
            "redirect_uri": str(settings.redirect_uri),
            "state": state,
            "code_challenge_method": "S256",
            "code_challenge": pkce_pair.challenge,
        }
        
        auth_url = f"{settings.cognito_domain}/oauth2/authorize?{urlencode(auth_params)}"
        
        self.logger.info(f"Redirecting to Cognito for authentication")
        return RedirectResponse(auth_url)
    
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
    
    async def logout(self, response: Response) -> RedirectResponse:
        """Logout user and clear cookies."""
        self.logger.info("Logging out user")
        
        # Clear authentication cookies
        self.cookie_manager.clear_auth_cookies(response)
        
        # Build Cognito logout URL
        logout_params = {
            "client_id": settings.cognito_app_client_id,
            "logout_uri": str(settings.post_logout_redirect)
        }
        logout_url = f"{settings.cognito_domain}/logout?{urlencode(logout_params)}"
        
        self.logger.info("User logged out successfully")
        return RedirectResponse(logout_url)
    
    async def get_auth_status(self, request: Request) -> AuthStatusResponse:
        """Get current authentication status."""
        id_token = request.cookies.get(self.cookie_manager.ID_COOKIE)
        
        # TODO: Add proper JWT validation here
        authenticated = bool(id_token)
        
        self.logger.debug(f"Auth status check: authenticated={authenticated}")
        
        return AuthStatusResponse(
            authenticated=authenticated,
            user_info=None  # TODO: Extract user info from validated ID token
        )
