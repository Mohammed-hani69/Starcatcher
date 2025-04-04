"""add new_member_reward_collected field

Revision ID: 51ce8a5bb704
Revises: 8aae0a372a5f
Create Date: 2025-03-24 15:31:21.517025

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '51ce8a5bb704'
down_revision = '8aae0a372a5f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('new_member_reward_collected', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('new_member_reward_collected')

    # ### end Alembic commands ###
