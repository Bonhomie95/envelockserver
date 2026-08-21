"""Create the first Envelock operator.

The staff table starts empty, and creating an operator requires an operator — so
something has to break the circle. Two ways, both deliberate:

* **Break-glass.** An email in `ENVELOCK_SUPERADMIN_EMAILS` signs into the
  console with their normal Envelock account and has every permission. That path
  always works and is how a locked-out team gets back in.
* **This tool**, run on the server by whoever has shell access:

      python -m envelock.security.bootstrap_staff \\
          --email ada@envelock.io --name "Ada" --department leadership

  It prints a one-time password. Hand it over directly; the operator must replace
  it and enrol an authenticator before the console answers anything.

Both are outside the product: no request to a running Envelock can mint the first
operator, which is the property that makes the console's permission model worth
anything.
"""

from __future__ import annotations

import argparse
import asyncio

from sqlalchemy import select

from envelock.api.staff_auth import new_temporary_password
from envelock.auth.security import hash_password
from envelock.auth.staff import Department
from envelock.db import get_sessionmaker
from envelock.models import StaffAccount, StaffAuditEvent


async def create(
    *, email: str, name: str | None, department: str, reset: bool = False
) -> dict:
    email = email.lower().strip()
    temporary = new_temporary_password()
    async with get_sessionmaker()() as session:
        existing = (
            await session.execute(select(StaffAccount).where(StaffAccount.email == email))
        ).scalar_one_or_none()
        if existing is not None and not reset:
            return {
                "ok": False,
                "reason": f"{email} already exists — pass --reset to issue a new "
                "temporary password (this also clears their authenticator).",
            }

        if existing is not None:
            existing.password_hash = hash_password(temporary)
            existing.must_change_password = True
            existing.mfa_enabled = False
            existing.totp_secret = None
            existing.recovery_hashes = []
            existing.status = "active"
            existing.department = department
            account = existing
            action = "staff.bootstrap_reset"
        else:
            account = StaffAccount(
                email=email,
                name=name,
                password_hash=hash_password(temporary),
                department=department,
                status="active",
                must_change_password=True,
                created_by="bootstrap (shell)",
            )
            session.add(account)
            action = "staff.bootstrap_created"

        await session.flush()
        session.add(
            StaffAuditEvent(
                actor_email="bootstrap (shell)",
                action=action,
                target_type="staff",
                target_id=str(account.id),
                detail={"email": email, "department": department},
            )
        )
        await session.commit()
        return {"ok": True, "email": email, "temporary_password": temporary}


def main() -> None:
    parser = argparse.ArgumentParser(description="Create the first Envelock operator.")
    parser.add_argument("--email", required=True)
    parser.add_argument("--name", default=None)
    parser.add_argument(
        "--department",
        default=Department.LEADERSHIP.value,
        choices=[d.value for d in Department],
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="reissue a temporary password for an existing operator",
    )
    args = parser.parse_args()

    result = asyncio.run(
        create(
            email=args.email,
            name=args.name,
            department=args.department,
            reset=args.reset,
        )
    )
    if not result["ok"]:
        print(f"ERROR: {result['reason']}")
        raise SystemExit(1)
    print(f"Operator: {result['email']}  ({args.department})")
    print(f"One-time password: {result['temporary_password']}")
    print()
    print("Hand this over directly — it is not stored and will not be shown again.")
    print("They must set their own password and enrol an authenticator at sign-in.")


if __name__ == "__main__":
    main()
