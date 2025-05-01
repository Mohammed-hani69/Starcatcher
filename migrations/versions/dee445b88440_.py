"""empty message

Revision ID: dee445b88440
Revises: add_referral_columns, faefa9253df3, merge_heads
Create Date: 2025-04-29 03:08:23.786332

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'dee445b88440'
down_revision = ('add_referral_columns', 'faefa9253df3', 'merge_heads')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
