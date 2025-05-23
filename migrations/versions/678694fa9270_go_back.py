"""go back

Revision ID: 678694fa9270
Revises: 69d428fdbd3e
Create Date: 2025-05-01 03:23:41.890259

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '678694fa9270'
down_revision = '69d428fdbd3e'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user_subscription_purchases', schema=None) as batch_op:
        batch_op.drop_column('customer_phone')
        batch_op.drop_column('paid_amount')
        batch_op.drop_column('customer_name')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user_subscription_purchases', schema=None) as batch_op:
        batch_op.add_column(sa.Column('customer_name', mysql.VARCHAR(length=100), nullable=True))
        batch_op.add_column(sa.Column('paid_amount', mysql.FLOAT(), nullable=True))
        batch_op.add_column(sa.Column('customer_phone', mysql.VARCHAR(length=20), nullable=True))

    # ### end Alembic commands ###
