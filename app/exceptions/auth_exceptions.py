"""
Custom exceptions for authentication operations.
"""
from typing import Optional, Dict, Any


class AuthException(Exception):
    """Base exception for authentication errors."""
    
    def __init__(
        self, 
        message: str, 
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)


class InvalidStateException(AuthException):
    """Raised when OAuth state parameter is invalid or expired."""
    
    def __init__(self, message: str = "Invalid or expired state parameter"):
        super().__init__(message, status_code=400)


class TokenExchangeException(AuthException):
    """Raised when token exchange with Cognito fails."""
    
    def __init__(self, message: str = "Token exchange failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=401, details=details)


class TokenRefreshException(AuthException):
    """Raised when token refresh fails."""
    
    def __init__(self, message: str = "Token refresh failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=401, details=details)


class MissingTokenException(AuthException):
    """Raised when required token is missing."""
    
    def __init__(self, token_type: str = "token"):
        message = f"Missing {token_type}"
        super().__init__(message, status_code=401)


class CognitoAPIException(AuthException):
    """Raised when Cognito API calls fail."""
    
    def __init__(self, message: str = "Cognito API error", status_code: int = 502, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=status_code, details=details)


class StateStoreException(AuthException):
    """Raised when state store operations fail."""
    
    def __init__(self, message: str = "State store error"):
        super().__init__(message, status_code=500)
