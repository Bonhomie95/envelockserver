"""add mailbox_credentials.imap_security and imap_username

Transport security (ssl/starttls/none) and an optional login username, so IMAP
connections aren't limited to implicit-TLS/993 with the address as the username.

Revision ID: e5f607182934
Revises: d4e5f6071823
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "e5f607182934"
down_revision: str | None = "d4e5f6071823"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "mailbox_credentials",
        sa.Column("imap_security", sa.String(length=16), nullable=True, server_default="ssl"),
    )
    op.add_column(
        "mailbox_credentials",
        sa.Column("imap_username", sa.String(length=320), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("mailbox_credentials", "imap_username")
    op.drop_column("mailbox_credentials", "imap_security")
