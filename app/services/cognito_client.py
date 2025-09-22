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
    