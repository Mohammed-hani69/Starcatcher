"""add new_member_reward

Revision ID: 3f3ad31c40ef
Revises: e496ff61c228
Create Date: 2025-03-24 16:12:23.560337

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3f3ad31c40ef'
down_revision = 'e496ff61c228'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('transactions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('listing_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('payment_method', sa.String(length=50), nullable=True))
        batch_op.drop_constraint('transactions_ibfk_3', type_='foreignkey')
        batch_op.drop_constraint('transactions_ibfk_1', type_='foreignkey')
        batch_op.drop_constraint('transactions_ibfk_2', type_='foreignkey')
        batch_op.create_foreign_key(None, 'user_players', ['user_player_id'], ['id'])
        batch_op.create_foreign_key(None, 'users', ['buyer_id'], ['id'])
        batch_op.create_foreign_key(None, 'users', ['seller_id'], ['id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('transactions', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.create_foreign_key('transactions_ibfk_2', 'users', ['seller_id'], ['id'], ondelete='CASCADE')
        batch_op.create_foreign_key('transactions_ibfk_1', 'users', ['buyer_id'], ['id'], ondelete='CASCADE')
        batch_op.create_foreign_key('transactions_ibfk_3', 'user_players', ['user_player_id'], ['id'], ondelete='CASCADE')
        batch_op.drop_column('payment_method')
        batch_op.drop_column('listing_id')

    # ### end Alembic commands ###
