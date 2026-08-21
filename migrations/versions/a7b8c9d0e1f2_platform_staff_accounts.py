"""Platform staff accounts and their own audit log.

Envelock's operators get their own table rather than rows in `users`. A platform
operator is not a member of any customer tenant, so modelling them as one would
mean either a fake tenant or a customer account that can read every other
customer — and it would put the two populations one bug apart.

Neither table is tenant-scoped, so neither gets an RLS policy: `staff_accounts`
holds Envelock's own people, and `staff_audit_events` is deliberately outside a
customer's reach. The RLS migrations apply only to tenant-scoped tables.

Revision ID: a7b8c9d0e1f2
Revises: c1d2e3f4a5b6
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "a7b8c9d0e1f2"
down_revision: str | None = "c1d2e3f4a5b6"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "staff_accounts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("name", sa.String(length=255)),
        sa.Column("password_hash", sa.String(length=255)),
        sa.Column("department", sa.String(length=32), nullable=False, server_default="support"),
        sa.Column(
            "granted_permissions",
            sa.ARRAY(sa.String()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "revoked_permissions",
            sa.ARRAY(sa.String()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column(
            "must_change_password", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.Column("totp_secret", sa.String(length=64)),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "recovery_hashes", sa.ARRAY(sa.String()), nullable=False, server_default="{}"
        ),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.Column("last_login_ip", sa.String(length=64)),
        sa.Column("created_by", sa.String(length=320)),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_staff_accounts_email", "staff_accounts", ["email"], unique=True
    )

    op.create_table(
        "staff_audit_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_email", sa.String(length=320), nullable=False),
        sa.Column("actor_id", sa.Uuid()),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target_type", sa.String(length=32)),
        sa.Column("target_id", sa.String(length=64)),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("ip", sa.String(length=64)),
        sa.Column("detail", JSONB(), nullable=False, server_default="{}"),
    )
    op.create_index("ix_staff_audit_events_actor_email", "staff_audit_events", ["actor_email"])
    op.create_index("ix_staff_audit_events_action", "staff_audit_events", ["action"])
    op.create_index("ix_staff_audit_events_tenant_id", "staff_audit_events", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_staff_audit_events_tenant_id", table_name="staff_audit_events")
    op.drop_index("ix_staff_audit_events_action", table_name="staff_audit_events")
    op.drop_index("ix_staff_audit_events_actor_email", table_name="staff_audit_events")
    op.drop_table("staff_audit_events")
    op.drop_index("ix_staff_accounts_email", table_name="staff_accounts")
    op.drop_table("staff_accounts")
