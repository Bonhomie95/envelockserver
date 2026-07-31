"""add tenants.stripe_customer_id

Captured from the first completed Stripe Checkout so we can open the hosted
billing portal (update card / cancel).

Revision ID: c3d4e5f60712
Revises: b2c3d4e5f601
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "c3d4e5f60712"
down_revision: str | None = "b2c3d4e5f601"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tenants", sa.Column("stripe_customer_id", sa.String(length=64), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("tenants", "stripe_customer_id")
