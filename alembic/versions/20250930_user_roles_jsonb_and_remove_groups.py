"""
Revision ID: 20250930_user_roles_jsonb_and_remove_groups
Revises: 20250930_add_groups_to_user_app_profiles
Create Date: 2025-09-30
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '20250930'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None

def upgrade():
    # Change user_roles.role_name to JSONB
    op.alter_column('user_roles', 'role_name',
        existing_type=sa.String(length=50),
        type_=postgresql.JSONB(),
        postgresql_using='role_name::jsonb',
        existing_nullable=False
    )
    # Remove groups column from user_app_profiles
    op.drop_column('user_app_profiles', 'groups')

def downgrade():
    # Revert user_roles.role_name to String(50)
    op.alter_column('user_roles', 'role_name',
        existing_type=postgresql.JSONB(),
        type_=sa.String(length=50),
        postgresql_using='role_name::text',
        existing_nullable=False
    )
    # Add groups column back to user_app_profiles
    op.add_column('user_app_profiles', sa.Column('groups', postgresql.JSONB(), nullable=True))
