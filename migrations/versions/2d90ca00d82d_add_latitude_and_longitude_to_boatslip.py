"""Add latitude and longitude to BoatSlip

Revision ID: 2d90ca00d82d
Revises: 
Create Date: 2024-12-31 12:15:04.209493

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2d90ca00d82d'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('boat_slip', schema=None) as batch_op:
        batch_op.add_column(sa.Column('latitude', sa.Float(), nullable=False, server_default='0.0'))
        batch_op.add_column(sa.Column('longitude', sa.Float(), nullable=False, server_default='0.0'))
    
    # Remove the default values after the migration
    with op.batch_alter_table('boat_slip', schema=None) as batch_op:
        batch_op.alter_column('latitude', server_default=None)
        batch_op.alter_column('longitude', server_default=None)

def downgrade():
    with op.batch_alter_table('boat_slip', schema=None) as batch_op:
        batch_op.drop_column('latitude')
        batch_op.drop_column('longitude')


    # ### end Alembic commands ###
