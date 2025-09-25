"""
Configuration settings for the Auth BFF service.
Uses Pydantic for validation and type safety.
"""
import os
from typing import Optional, List
from pydantic_settings import BaseSettings
from pydantic import validator, HttpUrl


class Settings(BaseSettings):
    """Application settings with validation."""
    
    # Cognito Configuration
    cognito_domain: HttpUrl
    cognito_region: str = "ap-south-1"
    cognito_user_pool_id: str
    cognito_app_client_id: str
    cognito_app_client_secret: Optional[str] = None
    cognito_scope: str = "openid email profile"
    
    # Redirect URIs
    redirect_uri: HttpUrl
    post_login_redirect: HttpUrl
    post_logout_redirect: HttpUrl
    
    # Cookie Configuration
    cookie_domain: str = "localhost"
    secure_cookies: bool = False
    
    # CORS Configuration
    cors_origins: List[str] = [
        "http://localhost:5173", 
        "http://localhost:5174", 
        "http://127.0.0.1:5174",
    ]
    
    # Security
    state_ttl_seconds: int = 600  # 10 minutes
    access_token_ttl_seconds: int = 3300  # 55 minutes
    refresh_token_ttl_seconds: int = 604800  # 7 days
    
    # Application
    app_name: str = "Authentication Service"
    debug: bool = False
    log_level: str = "INFO"
    
    # External API timeouts
    cognito_timeout_seconds: int = 10
    
    @validator('cognito_domain', pre=True)
    def validate_cognito_domain(cls, v):
        """Ensure cognito domain is properly formatted."""
        if isinstance(v, str) and not v.startswith(('http://', 'https://')):
            return f"https://{v}"
        return v
    
    @validator('cors_origins', pre=True)
    def validate_cors_origins(cls, v):
        """Parse CORS origins from string or list."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(',')]
        return v
    
    @property
    def issuer(self) -> str:
        """Cognito issuer URL."""
        return f"https://cognito-idp.{self.cognito_region}.amazonaws.com/{self.cognito_user_pool_id}"
    
    @property
    def jwks_url(self) -> str:
        """Cognito JWKS URL."""
        return f"{self.issuer}/.well-known/jwks.json"
    
    class Config:
        env_file = ".env"
        env_prefix = ""
        case_sensitive = False
        # Map environment variables to field names
        fields = {
            'cognito_domain': {'env': 'COGNITO_DOMAIN'},
            'cognito_region': {'env': 'COGNITO_REGION'},
            'cognito_user_pool_id': {'env': 'COGNITO_USER_POOL_ID'},
            'cognito_app_client_id': {'env': 'COGNITO_APP_CLIENT_ID'},
            'cognito_app_client_secret': {'env': 'COGNITO_APP_CLIENT_SECRET'},
            'cognito_scope': {'env': 'COGNITO_SCOPE'},
            'redirect_uri': {'env': 'REDIRECT_URI'},
            'post_login_redirect': {'env': 'POST_LOGIN_REDIRECT'},
            'post_logout_redirect': {'env': 'POST_LOGOUT_REDIRECT'},
            'cookie_domain': {'env': 'COOKIE_DOMAIN'},
            'secure_cookies': {'env': 'SECURE_COOKIES'},
            'cors_origins': {'env': 'CORS_ORIGINS'},
            'debug': {'env': 'DEBUG'},
            'log_level': {'env': 'LOG_LEVEL'},
        }


# Global settings instance
settings = Settings()
