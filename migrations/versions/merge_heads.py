"""merge heads

Revision ID: merge_heads
Revises: [paste_revision_ids_here]  # Add the revision IDs from flask db heads
Create Date: 2024-01-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = 'merge_heads'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    pass

def downgrade():
    pass
