"""Row-level security policies (PRD §10, §11.1)

Multi-tenancy is enforced by the database, not only by application code. A
missed `WHERE tenant_id = ...` in one query would otherwise leak another
customer's mail — for a product holding hundreds of businesses' mailboxes that
is the whole company.

Postgres only; SQLite has no RLS, and dev/test rely on application scoping plus
the isolation tests.

Revision ID: b2c3d4e5f601
Revises: 9f9ed2127394
"""
from __future__ import annotations

from alembic import op

revision: str = "b2c3d4e5f601"
down_revision: str | None = "9f9ed2127394"
branch_labels = None
depends_on = None

#: Every tenant-scoped table. Tables deliberately excluded:
#:   domain_trial_ledger — cross-tenant by design; permanence IS the anti-abuse
#:                         mechanism (§12.7), and it holds no personal data.
TENANT_TABLES = (
    "domains",
    "users",
    "lookalike_domains",
    "mailboxes",
    "mailbox_credentials",
    "counterparties",
    "bank_records",
    "sender_profiles",
    "messages",
    "findings",
    "alerts",
    "notification_deliveries",
    "audit_events",
    "sensor_sessions",
    "push_subscriptions",
    "usage_meters",
    "invoices",
)


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return

    # The application connects as this role; it never bypasses RLS.
    op.execute("DO $$ BEGIN CREATE ROLE envelock_app NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;")

    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        # FORCE applies the policy to the table owner too, so a migration or an
        # admin session cannot silently read across tenants.
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {table}
            USING (tenant_id = current_setting('envelock.tenant_id', true)::uuid)
            WITH CHECK (tenant_id = current_setting('envelock.tenant_id', true)::uuid)
            """
        )
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO envelock_app")

    op.execute("GRANT SELECT, INSERT, UPDATE ON tenants TO envelock_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON domain_trial_ledger TO envelock_app")


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
