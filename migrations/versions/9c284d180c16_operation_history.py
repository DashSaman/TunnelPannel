"""Bounded tenant-local monitoring and operational transitions."""
from alembic import op
import sqlalchemy as sa

revision = '9c284d180c16'
down_revision = '7b6b540f5991'
branch_labels = depends_on = None


def upgrade():
    op.create_table('operation_policies', sa.Column('id', sa.String(16), primary_key=True),
                    sa.Column('enabled', sa.Boolean(), nullable=False),
                    sa.Column('interval_s', sa.Integer(), nullable=False))
    op.create_table('operation_records', sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
                    sa.Column('route_id', sa.String(32), nullable=False),
                    sa.Column('ts', sa.Float(), nullable=False),
                    sa.Column('kind', sa.String(16), nullable=False),
                    sa.Column('document', sa.JSON(), nullable=False))
    for name in ('route_id', 'ts', 'kind'):
        op.create_index('ix_operation_records_' + name, 'operation_records', [name])


def downgrade():
    op.drop_table('operation_records')
    op.drop_table('operation_policies')
