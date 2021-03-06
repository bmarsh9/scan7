"""empty message

Revision ID: 7653ab920f87
Revises: 1e0434c8c45b
Create Date: 2021-03-24 21:40:31.255957

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7653ab920f87'
down_revision = '1e0434c8c45b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('file_secret', sa.Column('path', sa.String(), nullable=True))
    op.drop_column('file_secret', 'file')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('file_secret', sa.Column('file', sa.VARCHAR(), autoincrement=False, nullable=True))
    op.drop_column('file_secret', 'path')
    # ### end Alembic commands ###
