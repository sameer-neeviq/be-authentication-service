from sqlalchemy import (
    Column, String, Integer, Boolean, Text, TIMESTAMP, ForeignKey, JSON, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB



from sqlalchemy import Column, String, Integer, Boolean, Text, TIMESTAMP, JSON, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
import uuid
from .base import Base

# --- UserAppProfile ---
class UserAppProfile(Base):
    __tablename__ = 'user_app_profiles'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cognito_user_id = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    oauth_provider = Column(String(20))
    oauth_provider_id = Column(String(100))
    provider_profile_data = Column(JSONB)
    last_login_at = Column(TIMESTAMP)
    login_count = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP, server_default="CURRENT_TIMESTAMP")
    updated_at = Column(TIMESTAMP, server_default="CURRENT_TIMESTAMP")
    __table_args__ = (
        Index('idx_user_app_cognito', 'cognito_user_id'),
        Index('idx_user_app_email', 'email'),
        Index('idx_user_app_last_login', 'last_login_at'),
        Index('idx_user_app_active', 'is_active'),
        {'sqlite_autoincrement': True},
    )

# --- UserSession ---
class UserSession(Base):
    __tablename__ = 'user_sessions'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cognito_user_id = Column(String(255), nullable=False)
    session_token = Column(String(255), nullable=False)  # unique constraint removed
    refresh_token = Column(Text)
    user_agent = Column(Text)
    created_at = Column(TIMESTAMP, server_default="CURRENT_TIMESTAMP")
    expires_at = Column(TIMESTAMP, nullable=False)
    last_accessed = Column(TIMESTAMP, server_default="CURRENT_TIMESTAMP")
    is_active = Column(Boolean, default=True)
    __table_args__ = (
        Index('idx_sessions_cognito_user', 'cognito_user_id'),
        Index('idx_sessions_token', 'session_token'),
        Index('idx_sessions_active', 'is_active'),
        Index('idx_sessions_expires', 'expires_at'),
    )

# --- UserRole ---
class UserRole(Base):
    __tablename__ = 'user_roles'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cognito_user_id = Column(String(255), nullable=False)
    role_name = Column(JSONB, nullable=False)  # Now stores a list of roles
    permissions = Column(JSONB)
    resource_scope = Column(JSONB)
    granted_at = Column(TIMESTAMP, server_default="CURRENT_TIMESTAMP")
    granted_by = Column(String(255))
    expires_at = Column(TIMESTAMP)
    is_active = Column(Boolean, default=True)
    __table_args__ = (
        Index('idx_user_roles_user', 'cognito_user_id'),
        Index('idx_user_roles_role', 'role_name'),
        Index('idx_user_roles_active', 'is_active'),
        Index('idx_user_roles_expires', 'expires_at'),
        {'sqlite_autoincrement': True},
    )

# --- ApiKey ---
class ApiKey(Base):
    __tablename__ = 'api_keys'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key_name = Column(String(100), nullable=False)
    key_prefix = Column(String(10), nullable=False)
    api_key_hash = Column(String(255), nullable=False)
    permissions = Column(JSONB)
    allowed_ips = Column(JSONB)
    rate_limit_override = Column(Integer)
    last_used_at = Column(TIMESTAMP)
    usage_count = Column(Integer, default=0)
    created_by = Column(String(255))
    created_at = Column(TIMESTAMP, server_default="CURRENT_TIMESTAMP")
    expires_at = Column(TIMESTAMP)
    is_active = Column(Boolean, default=True)
    __table_args__ = (
        Index('idx_api_keys_hash', 'api_key_hash'),
        Index('idx_api_keys_prefix', 'key_prefix'),
        Index('idx_api_keys_active', 'is_active'),
        Index('idx_api_keys_expires', 'expires_at'),
        {'sqlite_autoincrement': True},
    )

# --- AuthAuditLog ---
class AuthAuditLog(Base):
    __tablename__ = 'auth_audit_logs'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cognito_user_id = Column(String(255))
    event_type = Column(String(50), nullable=False)
    event_status = Column(String(20), nullable=False)
    event_category = Column(String(30), nullable=False)
    user_agent = Column(Text)
    oauth_provider = Column(String(20))
    session_id = Column(UUID(as_uuid=True))
    event_data = Column(JSONB)
    error_message = Column(Text)
    error_code = Column(String(50))
    retention_until = Column(TIMESTAMP)
    created_at = Column(TIMESTAMP, server_default="CURRENT_TIMESTAMP")
    __table_args__ = (
        Index('idx_audit_user', 'cognito_user_id'),
        Index('idx_audit_event', 'event_type'),
        Index('idx_audit_status', 'event_status'),
        Index('idx_audit_category', 'event_category'),
        Index('idx_audit_created', 'created_at'),
        Index('idx_audit_retention', 'retention_until'),
        {'sqlite_autoincrement': True},
    )

# --- RateLimitBucket ---
class RateLimitBucket(Base):
    __tablename__ = 'rate_limit_buckets'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    identifier_type = Column(String(20), nullable=False)
    identifier_value = Column(String(255), nullable=False)
    application_id = Column(String(50), nullable=False)
    endpoint = Column(String(100))
    request_count = Column(Integer, default=0)
    window_start = Column(TIMESTAMP, nullable=False)
    window_end = Column(TIMESTAMP, nullable=False)
    is_blocked = Column(Boolean, default=False)
    blocked_until = Column(TIMESTAMP)
    created_at = Column(TIMESTAMP, server_default="CURRENT_TIMESTAMP")
    updated_at = Column(TIMESTAMP, server_default="CURRENT_TIMESTAMP")
    __table_args__ = (
        Index('idx_rate_limit_identifier', 'identifier_type', 'identifier_value'),
        Index('idx_rate_limit_app', 'application_id'),
        Index('idx_rate_limit_window', 'window_end'),
        Index('idx_rate_limit_blocked', 'is_blocked', 'blocked_until'),
        {'sqlite_autoincrement': True},
    )

