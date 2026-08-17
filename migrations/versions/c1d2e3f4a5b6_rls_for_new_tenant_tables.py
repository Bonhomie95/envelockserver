"""Row-level security for tenant-scoped tables added after the original RLS pass.

The initial RLS migration (b2c3d4e5f601) covered the tables that existed then.
Three tenant-scoped tables were added since — export_tokens, llm_usage,
webhook_endpoints — and without policies + grants here, enabling RLS (the app
connecting as the restricted `envelock_app` role) would DENY the app access to
them. This closes that gap so RLS can be turned on safely and completely.

graph_verdicts is intentionally excluded: it is the cross-tenant counterparty
graph (keyed by registrable_domain, no tenant_id), like domain_trial_ledger.

Revision ID: c1d2e3f4a5b6
Revises: 391f199da8a5
"""
from __future__ import annotations

from alembic import op

revision: str = "c1d2e3f4a5b6"
down_revision: str | None = "391f199da8a5"
branch_labels = None
depends_on = None

NEW_TENANT_TABLES = ("export_tokens", "llm_usage", "webhook_endpoints")


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    # RLS is opt-in (see b2c3d4e5f601) — only enable when explicitly requested, so a
    # plain `alembic upgrade head` can't brick an app that connects as the owner.
    import os

    if os.environ.get("ENVELOCK_APPLY_RLS", "").strip().lower() not in {"1", "true", "yes"}:
        return
    # The role is created by the original RLS migration; guard in case this runs
    # against a database where that role setup was applied out of band.
    op.execute(
        "DO $$ BEGIN CREATE ROLE envelock_app NOLOGIN; "
        "EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
    )
    for table in NEW_TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {table}
            USING (tenant_id = current_setting('envelock.tenant_id', true)::uuid)
            WITH CHECK (tenant_id = current_setting('envelock.tenant_id', true)::uuid)
            """
        )
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO envelock_app")


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table in NEW_TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
