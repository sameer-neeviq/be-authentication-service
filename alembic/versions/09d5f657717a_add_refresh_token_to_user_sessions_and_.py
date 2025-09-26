from alembic import op
import sqlalchemy as sa

revision = '09d5f657717a'
down_revision = '20250925_01'  # previous revision id
branch_labels = None
depends_on = None

def upgrade():
    # Add refresh_token column
    op.add_column('user_sessions', sa.Column('refresh_token', sa.String(length=255), nullable=True))
    # Drop unique constraint on session_token if it exists
    with op.batch_alter_table('user_sessions') as batch_op:
        batch_op.drop_constraint('user_sessions_session_token_key', type_='unique')

def downgrade():
    # Remove refresh_token column
    op.drop_column('user_sessions', 'refresh_token')
    # Re-add unique constraint on session_token
    with op.batch_alter_table('user_sessions') as batch_op:
        batch_op.create_unique_constraint('user_sessions_session_token_key', ['session_token'])