"""
Revision ID: a1b2c3d4e5f6
Revises: 
Create Date: 2025-09-26
"""

revision = 'a1b2c3d4e5f6'
down_revision = '09d5f657717a'
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.alter_column('user_sessions', 'refresh_token',
        existing_type=sa.VARCHAR(length=255),
        type_=sa.Text(),
        existing_nullable=True
    )

def downgrade():
    op.alter_column('user_sessions', 'refresh_token',
        existing_type=sa.Text(),
        type_=sa.VARCHAR(length=255),
        existing_nullable=True
    )
