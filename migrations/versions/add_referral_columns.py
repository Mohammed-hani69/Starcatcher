from alembic import op
import sqlalchemy as sa

"""add referral columns

Revision ID: add_referral_columns
Create Date: 2024-01-01 00:00:00.000000
"""

# revision identifiers
revision = 'add_referral_columns'
down_revision = None  # Update this with your last migration's revision ID
branch_labels = None
depends_on = None

def upgrade():
    # Add new columns to users table
    op.add_column('users', sa.Column('referral_code', sa.String(10), unique=True))
    op.add_column('users', sa.Column('referred_by', sa.String(10), nullable=True))
    op.add_column('users', sa.Column('total_referrals', sa.Integer(), default=0))
    op.add_column('users', sa.Column('referral_earnings', sa.Integer(), default=0))
    
    # Create referral_codes table
    op.create_table(
        'referral_codes',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('referrer_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('referred_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('code_used', sa.String(10), nullable=False),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
        sa.Column('status', sa.String(20), default='pending')
    )
    
    # Create referral_rewards table
    op.create_table(
        'referral_rewards',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('referral_id', sa.Integer(), sa.ForeignKey('referral_codes.id'), nullable=False),
        sa.Column('coins_amount', sa.Integer(), nullable=False),
        sa.Column('reward_type', sa.String(20)),
        sa.Column('claimed_at', sa.DateTime(), default=sa.func.now())
    )
    
    # Create indexes
    op.create_index('idx_referral_codes_referrer', 'referral_codes', ['referrer_id'])
    op.create_index('idx_referral_codes_referred', 'referral_codes', ['referred_id'])
    op.create_index('idx_referral_codes_status', 'referral_codes', ['status'])
    op.create_index('idx_users_referral_code', 'users', ['referral_code'])

def downgrade():
    # Drop indexes
    op.drop_index('idx_users_referral_code')
    op.drop_index('idx_referral_codes_status')
    op.drop_index('idx_referral_codes_referred')
    op.drop_index('idx_referral_codes_referrer')
    
    # Drop tables
    op.drop_table('referral_rewards')
    op.drop_table('referral_codes')
    
    # Drop columns from users table
    op.drop_column('users', 'referral_earnings')
    op.drop_column('users', 'total_referrals')
    op.drop_column('users', 'referred_by')
    op.drop_column('users', 'referral_code')
