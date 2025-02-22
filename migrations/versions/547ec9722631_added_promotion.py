"""added promotion

Revision ID: 547ec9722631
Revises: 40a89ef39862
Create Date: 2024-11-12 16:18:02.681488

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '547ec9722631'
down_revision = '40a89ef39862'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('promotion',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('product_type', sa.String(), nullable=False),
    sa.Column('product_id', sa.Integer(), nullable=False),
    sa.Column('old_price', sa.Float(), nullable=False),
    sa.Column('discounted_price', sa.Float(), nullable=False),
    sa.Column('start_date', sa.DateTime(), nullable=False),
    sa.Column('end_date', sa.DateTime(), nullable=True),
    sa.Column('active', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.drop_table('returns')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('returns',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('invoice_id', sa.INTEGER(), nullable=False),
    sa.Column('user_id', sa.INTEGER(), nullable=False),
    sa.Column('product_id', sa.INTEGER(), nullable=False),
    sa.Column('product_type', sa.VARCHAR(), nullable=False),
    sa.Column('quantity', sa.INTEGER(), nullable=False),
    sa.Column('reason', sa.VARCHAR(), nullable=False),
    sa.Column('status', sa.VARCHAR(), nullable=False),
    sa.Column('action_taken', sa.VARCHAR(), nullable=True),
    sa.Column('date_requested', sa.DATETIME(), nullable=False),
    sa.Column('date_processed', sa.DATETIME(), nullable=True),
    sa.Column('processed_by', sa.INTEGER(), nullable=True),
    sa.Column('refund_amount', sa.FLOAT(), nullable=True),
    sa.Column('notes', sa.VARCHAR(), nullable=True),
    sa.ForeignKeyConstraint(['invoice_id'], ['invoices.invoice_id'], ),
    sa.ForeignKeyConstraint(['processed_by'], ['users.uid'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.uid'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.drop_table('promotion')
    # ### end Alembic commands ###
