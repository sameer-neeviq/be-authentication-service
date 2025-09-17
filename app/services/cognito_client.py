"""
Cognito API client for token operations.
"""
import base64
from typing import Optional, Dict, Any
import httpx

from ..config.settings import settings
from ..models.auth import TokenResponse, CognitoTokenRequest
from ..exceptions.auth_exceptions import CognitoAPIException, TokenExchangeException, TokenRefreshException
from ..middleware.logging_config import LoggerMixin


class CognitoClient(LoggerMixin):
    """Client for interacting with AWS Cognito APIs."""
    
    def __init__(self):
        self.timeout = settings.cognito_timeout_seconds
        self.domain = str(settings.cognito_domain)
        self.client_id = settings.cognito_app_client_id
        self.client_secret = settings.cognito_app_client_secret
    
    def _get_auth_header(self) -> Dict[str, str]:
        """Get authorization header for client authentication."""
        headers = {}
        if self.client_secret:
            credentials = f"{self.client_id}:{self.client_secret}"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
        return headers
    
    async def exchange_code_for_tokens(
        self,
        code: str,
        code_verifier: str,
        redirect_uri: str
    ) -> TokenResponse:
        """Exchange authorization code for tokens."""
        self.logger.info("Exchanging authorization code for tokens")
        
        request_data = CognitoTokenRequest(
            grant_type="authorization_code",
            client_id=self.client_id,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier
        )
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.domain}/oauth2/token",
                    data=request_data.dict(exclude_none=True),
                    headers=self._get_auth_header()
                )
            
            if response.status_code != 200:
                error_details = {
                    "status_code": response.status_code,
                    "response_text": response.text
                }
                self.logger.error(f"Token exchange failed: {error_details}")
                raise TokenExchangeException(
                    "Failed to exchange authorization code for tokens",
                    details=error_details
                )
            
            token_data = response.json()
            self.logger.info("Successfully exchanged code for tokens")
            
            return TokenResponse(**token_data)
            
        except httpx.TimeoutException:
            self.logger.error("Timeout during token exchange")
            raise CognitoAPIException("Timeout communicating with Cognito")
        except httpx.RequestError as e:
            self.logger.error(f"Request error during token exchange: {e}")
            raise CognitoAPIException("Network error communicating with Cognito")
        except TokenExchangeException:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during token exchange: {e}")
            raise CognitoAPIException("Unexpected error during token exchange")
    
    async def refresh_tokens(self, refresh_token: str) -> TokenResponse:
        """Refresh access and ID tokens using refresh token."""
        self.logger.info("Refreshing tokens")
        
        request_data = CognitoTokenRequest(
            grant_type="refresh_token",
            client_id=self.client_id,
            refresh_token=refresh_token
        )
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.domain}/oauth2/token",
                    data=request_data.dict(exclude_none=True),
                    headers=self._get_auth_header()
                )
            
            if response.status_code != 200:
                error_details = {
                    "status_code": response.status_code,
                    "response_text": response.text
                }
                self.logger.error(f"Token refresh failed: {error_details}")
                raise TokenRefreshException(
                    "Failed to refresh tokens",
                    details=error_details
                )
            
            token_data = response.json()
            self.logger.info("Successfully refreshed tokens")
            
            return TokenResponse(**token_data)
            
        except httpx.TimeoutException:
            self.logger.error("Timeout during token refresh")
            raise CognitoAPIException("Timeout communicating with Cognito")
        except httpx.RequestError as e:
            self.logger.error(f"Request error during token refresh: {e}")
            raise CognitoAPIException("Network error communicating with Cognito")
        except TokenRefreshException:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during token refresh: {e}")
            raise CognitoAPIException("Unexpected error during token refresh")
