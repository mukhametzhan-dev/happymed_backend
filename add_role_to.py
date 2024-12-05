# migrations/versions/xxxx_set_patient_id_to_auto_increment.py
from alembic import op
import sqlalchemy as sa

revision = 'xxxx'
down_revision = 'yyyy'
branch_labels = None
depends_on = None

def upgrade():
    op.alter_column('patient', 'patient_id', existing_type=sa.Integer(), autoincrement=True)

def downgrade():
    op.alter_column('patient', 'patient_id', existing_type=sa.Integer(), autoincrement=False)
upgrade()