"""add tenants.extra_mailbox_seats

Mailbox seats purchased on top of the plan's included allowance.

Revision ID: d4e5f6071823
Revises: c3d4e5f60712
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "d4e5f6071823"
down_revision: str | None = "c3d4e5f60712"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column(
            "extra_mailbox_seats",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )


def downgrade() -> None:
    op.drop_column("tenants", "extra_mailbox_seats")
