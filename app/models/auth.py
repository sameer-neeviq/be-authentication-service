"""
Pydantic models for authentication operations.
"""
from typing import Optional, Dict, Any
from pydantic import BaseModel, HttpUrl, validator


class LoginRequest(BaseModel):
    """Request model for login endpoint."""
    redirect_to: Optional[HttpUrl] = None


class TokenResponse(BaseModel):
    """Response model from Cognito token endpoint."""
    access_token: str
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "Bearer"
    expires_in: Optional[int] = None


class AuthCallbackRequest(BaseModel):
    """Request model for OAuth callback."""
    code: str
    state: str
    
    @validator('code')
    def validate_code(cls, v):
        if not v or not v.strip():
            raise ValueError('Authorization code cannot be empty')
        return v.strip()
    
    @validator('state')
    def validate_state(cls, v):
        if not v or not v.strip():
            raise ValueError('State parameter cannot be empty')
        return v.strip()


class RefreshTokenRequest(BaseModel):
    """Request model for token refresh."""
    # No body needed - refresh token comes from cookie
    pass


class AuthStatusResponse(BaseModel):
    """Response model for authentication status."""
    authenticated: bool
    user_info: Optional[Dict[str, Any]] = None


class LogoutResponse(BaseModel):
    """Response model for logout."""
    success: bool = True
    logout_url: Optional[HttpUrl] = None


class StateRecord(BaseModel):
    """Model for state store records."""
    verifier: str
    redirect_to: Optional[str] = None
    created_at: float
    
    @validator('verifier')
    def validate_verifier(cls, v):
        if not v or len(v) < 43:  # Base64url encoded 32 bytes minimum
            raise ValueError('Invalid PKCE verifier')
        return v


class PKCEPair(BaseModel):
    """Model for PKCE verifier/challenge pair."""
    verifier: str
    challenge: str
    
    @validator('verifier', 'challenge')
    def validate_pkce_values(cls, v):
        if not v or len(v) < 43:
            raise ValueError('Invalid PKCE value')
        return v


class CognitoTokenRequest(BaseModel):
    """Model for Cognito token exchange request."""
    grant_type: str
    client_id: str
    code: Optional[str] = None
    redirect_uri: Optional[str] = None
    code_verifier: Optional[str] = None
    refresh_token: Optional[str] = None
    
    @validator('grant_type')
    def validate_grant_type(cls, v):
        allowed_types = ['authorization_code', 'refresh_token']
        if v not in allowed_types:
            raise ValueError(f'Grant type must be one of: {allowed_types}')
        return v
