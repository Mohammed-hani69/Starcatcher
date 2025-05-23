"""add payment link

Revision ID: a55fcbd61e5f
Revises: e2e6939c4751
Create Date: 2025-04-29 18:36:35.042560

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a55fcbd61e5f'
down_revision = 'e2e6939c4751'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('subscriptions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('payment_link', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('payment_link_usd', sa.String(length=255), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('subscriptions', schema=None) as batch_op:
        batch_op.drop_column('payment_link_usd')
        batch_op.drop_column('payment_link')

    # ### end Alembic commands ###
