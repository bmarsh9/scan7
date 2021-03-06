"""empty message

Revision ID: 6e3a3b8503b3
Revises: 5e12f37d3dbe
Create Date: 2021-04-26 04:03:55.916335

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6e3a3b8503b3'
down_revision = '5e12f37d3dbe'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('file_author', sa.Column('scan_id', sa.Integer(), nullable=True))
    op.add_column('file_copyright', sa.Column('scan_id', sa.Integer(), nullable=True))
    op.add_column('file_email', sa.Column('scan_id', sa.Integer(), nullable=True))
    op.add_column('file_holder', sa.Column('scan_id', sa.Integer(), nullable=True))
    op.add_column('file_license', sa.Column('scan_id', sa.Integer(), nullable=True))
    op.add_column('file_license_expression', sa.Column('scan_id', sa.Integer(), nullable=True))
    op.add_column('file_package', sa.Column('scan_id', sa.Integer(), nullable=True))
    op.add_column('file_scan_error', sa.Column('scan_id', sa.Integer(), nullable=True))
    op.add_column('file_secret', sa.Column('scan_id', sa.Integer(), nullable=True))
    op.add_column('file_url', sa.Column('scan_id', sa.Integer(), nullable=True))
    op.add_column('file_vuln', sa.Column('scan_id', sa.Integer(), nullable=True))
    op.add_column('package_dependency', sa.Column('scan_id', sa.Integer(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('package_dependency', 'scan_id')
    op.drop_column('file_vuln', 'scan_id')
    op.drop_column('file_url', 'scan_id')
    op.drop_column('file_secret', 'scan_id')
    op.drop_column('file_scan_error', 'scan_id')
    op.drop_column('file_package', 'scan_id')
    op.drop_column('file_license_expression', 'scan_id')
    op.drop_column('file_license', 'scan_id')
    op.drop_column('file_holder', 'scan_id')
    op.drop_column('file_email', 'scan_id')
    op.drop_column('file_copyright', 'scan_id')
    op.drop_column('file_author', 'scan_id')
    # ### end Alembic commands ###
