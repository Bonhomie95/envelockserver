"""add IMAP sync cursor columns to mailbox_credentials

The broker needs to remember how far it has read each mailbox so a poll fetches
only new messages. UIDs are monotonic only within a UIDVALIDITY epoch, so both are
stored; imap_last_polled_at records the last successful poll for scheduling.

Revision ID: f70819234a56
Revises: e5f607182934
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "f70819234a56"
down_revision: str | None = "e5f607182934"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "mailbox_credentials",
        sa.Column("imap_last_uid", sa.BigInteger(), nullable=True),
    )
    op.add_column(
        "mailbox_credentials",
        sa.Column("imap_uidvalidity", sa.BigInteger(), nullable=True),
    )
    op.add_column(
        "mailbox_credentials",
        sa.Column("imap_last_polled_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("mailbox_credentials", "imap_last_polled_at")
    op.drop_column("mailbox_credentials", "imap_uidvalidity")
    op.drop_column("mailbox_credentials", "imap_last_uid")
