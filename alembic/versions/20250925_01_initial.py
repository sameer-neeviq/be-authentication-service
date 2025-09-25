"""
Initial migration for user_app_profiles, user_sessions, user_roles, api_keys, auth_audit_logs, rate_limit_buckets
"""
from alembic import op
import sqlalchemy as sa
import sqlalchemy.dialects.postgresql as pg
import uuid

# revision identifiers, used by Alembic.
revision = '20250925_01'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        'user_app_profiles',
        sa.Column('id', pg.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('cognito_user_id', sa.String(255), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('oauth_provider', sa.String(20)),
        sa.Column('oauth_provider_id', sa.String(100)),
        sa.Column('provider_profile_data', pg.JSONB),
        sa.Column('app_specific_data', pg.JSONB),
        sa.Column('last_login_at', sa.TIMESTAMP()),
        sa.Column('login_count', sa.Integer(), default=0),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP')),
    )
    op.create_index('idx_user_app_cognito', 'user_app_profiles', ['cognito_user_id'])
    op.create_index('idx_user_app_email', 'user_app_profiles', ['email'])
    op.create_index('idx_user_app_last_login', 'user_app_profiles', ['last_login_at'])
    op.create_index('idx_user_app_active', 'user_app_profiles', ['is_active'])

    op.create_table(
        'user_sessions',
        sa.Column('id', pg.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('cognito_user_id', sa.String(255), nullable=False),
        sa.Column('session_token', sa.String(255), unique=True, nullable=False),
        sa.Column('user_agent', sa.Text()),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('expires_at', sa.TIMESTAMP(), nullable=False),
        sa.Column('last_accessed', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('is_active', sa.Boolean(), default=True),
    )
    op.create_index('idx_sessions_cognito_user', 'user_sessions', ['cognito_user_id'])
    op.create_index('idx_sessions_token', 'user_sessions', ['session_token'])
    op.create_index('idx_sessions_active', 'user_sessions', ['is_active'])
    op.create_index('idx_sessions_expires', 'user_sessions', ['expires_at'])

    op.create_table(
        'user_roles',
        sa.Column('id', pg.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('cognito_user_id', sa.String(255), nullable=False),
        sa.Column('role_name', sa.String(50), nullable=False),
        sa.Column('permissions', pg.JSONB),
        sa.Column('resource_scope', pg.JSONB),
        sa.Column('granted_at', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('granted_by', sa.String(255)),
        sa.Column('expires_at', sa.TIMESTAMP()),
        sa.Column('is_active', sa.Boolean(), default=True),
    )
    op.create_index('idx_user_roles_user', 'user_roles', ['cognito_user_id'])
    op.create_index('idx_user_roles_role', 'user_roles', ['role_name'])
    op.create_index('idx_user_roles_active', 'user_roles', ['is_active'])
    op.create_index('idx_user_roles_expires', 'user_roles', ['expires_at'])

    op.create_table(
        'api_keys',
        sa.Column('id', pg.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('key_name', sa.String(100), nullable=False),
        sa.Column('key_prefix', sa.String(10), nullable=False),
        sa.Column('api_key_hash', sa.String(255), nullable=False),
        sa.Column('permissions', pg.JSONB),
        sa.Column('allowed_ips', pg.JSONB),
        sa.Column('rate_limit_override', sa.Integer()),
        sa.Column('last_used_at', sa.TIMESTAMP()),
        sa.Column('usage_count', sa.Integer(), default=0),
        sa.Column('created_by', sa.String(255)),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('expires_at', sa.TIMESTAMP()),
        sa.Column('is_active', sa.Boolean(), default=True),
    )
    op.create_index('idx_api_keys_hash', 'api_keys', ['api_key_hash'])
    op.create_index('idx_api_keys_prefix', 'api_keys', ['key_prefix'])
    op.create_index('idx_api_keys_active', 'api_keys', ['is_active'])
    op.create_index('idx_api_keys_expires', 'api_keys', ['expires_at'])

    op.create_table(
        'auth_audit_logs',
        sa.Column('id', pg.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('cognito_user_id', sa.String(255)),
        sa.Column('event_type', sa.String(50), nullable=False),
        sa.Column('event_status', sa.String(20), nullable=False),
        sa.Column('event_category', sa.String(30), nullable=False),
        sa.Column('user_agent', sa.Text()),
        sa.Column('oauth_provider', sa.String(20)),
        sa.Column('session_id', pg.UUID(as_uuid=True)),
        sa.Column('event_data', pg.JSONB),
        sa.Column('error_message', sa.Text()),
        sa.Column('error_code', sa.String(50)),
        sa.Column('retention_until', sa.TIMESTAMP()),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP')),
    )
    op.create_index('idx_audit_user', 'auth_audit_logs', ['cognito_user_id'])
    op.create_index('idx_audit_event', 'auth_audit_logs', ['event_type'])
    op.create_index('idx_audit_status', 'auth_audit_logs', ['event_status'])
    op.create_index('idx_audit_category', 'auth_audit_logs', ['event_category'])
    op.create_index('idx_audit_created', 'auth_audit_logs', ['created_at'])
    op.create_index('idx_audit_retention', 'auth_audit_logs', ['retention_until'])

    op.create_table(
        'rate_limit_buckets',
        sa.Column('id', pg.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('identifier_type', sa.String(20), nullable=False),
        sa.Column('identifier_value', sa.String(255), nullable=False),
        sa.Column('application_id', sa.String(50), nullable=False),
        sa.Column('endpoint', sa.String(100)),
        sa.Column('request_count', sa.Integer(), default=0),
        sa.Column('window_start', sa.TIMESTAMP(), nullable=False),
        sa.Column('window_end', sa.TIMESTAMP(), nullable=False),
        sa.Column('is_blocked', sa.Boolean(), default=False),
        sa.Column('blocked_until', sa.TIMESTAMP()),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP')),
    )
    op.create_index('idx_rate_limit_identifier', 'rate_limit_buckets', ['identifier_type', 'identifier_value'])
    op.create_index('idx_rate_limit_app', 'rate_limit_buckets', ['application_id'])
    op.create_index('idx_rate_limit_window', 'rate_limit_buckets', ['window_end'])
    op.create_index('idx_rate_limit_blocked', 'rate_limit_buckets', ['is_blocked', 'blocked_until'])

def downgrade():
    op.drop_table('rate_limit_buckets')
    op.drop_table('auth_audit_logs')
    op.drop_table('api_keys')
    op.drop_table('user_roles')
    op.drop_table('user_sessions')
    op.drop_table('user_app_profiles')
