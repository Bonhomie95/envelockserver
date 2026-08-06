"""add mailboxes.needs_reconnect / connection_error

A stored credential can become unusable while the mailbox still reads as
connected — most often when the credential master key is rotated, or the provider
revokes the app password. Without a signal the mailbox silently protects nothing.
These columns let the worker flag it and the UI prompt a reconnect.

Revision ID: a1b2c3d4e5f6
Revises: f70819234a56
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "a1b2c3d4e5f6"
down_revision: str | None = "f70819234a56"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "mailboxes",
        sa.Column(
            "needs_reconnect",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "mailboxes",
        sa.Column("connection_error", sa.String(length=255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("mailboxes", "connection_error")
    op.drop_column("mailboxes", "needs_reconnect")
