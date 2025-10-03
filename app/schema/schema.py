from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Any

class UserAppProfileCreate(BaseModel):
    cognito_user_id: str
    email: EmailStr
    oauth_provider: Optional[str] = None
    oauth_provider_id: Optional[str] = None
    provider_profile_data: Optional[Any] = None
    app_specific_data: Optional[Any] = None
    is_active: bool = True

class AuthAuditLogCreate(BaseModel):
    cognito_user_id: Optional[str] = None
    event_type: str
    event_status: str
    event_category: str
    user_agent: Optional[str] = None
    oauth_provider: Optional[str] = None
    session_id: Optional[str] = None
    event_data: Optional[Any] = None
    error_message: Optional[str] = None
    error_code: Optional[str] = None

    
class UserRoleCreate(BaseModel):
    cognito_user_id: str
    role_name: str
    permissions: Optional[Any] = None
    resource_scope: Optional[Any] = None
    is_active: bool = True

class UserSessionCreate(BaseModel):
    cognito_user_id: str
    session_token: str
    user_agent: Optional[str] = None
    expires_at: str
    is_active: bool = True

class ApiKeyCreate(BaseModel):
    key_name: str
    key_prefix: str
    api_key_hash: str
    permissions: Optional[Any] = None
    allowed_ips: Optional[Any] = None
    rate_limit_override: Optional[int] = None
    created_by: Optional[str] = None
    expires_at: Optional[str] = None
    is_active: bool = True

class RateLimitBucketCreate(BaseModel):
    identifier_type: str
    identifier_value: str
    application_id: str
    endpoint: Optional[str] = None
    request_count: int = 0
    window_start: str
    window_end: str
    is_blocked: bool = False
    blocked_until: Optional[str] = None
