"""Detection suite.

Importing this package registers **every** detection. That is deliberate: the
registry is populated by import side-effect, so leaving it to whichever module
happened to be imported first made the active detection set depend on import
order — a mailbox could silently run a subset of the suite while reporting full
coverage. Loading them here makes the registry deterministic.

`base.ensure_loaded()` imports this package, so `registry()`, `active_for()` and
`run_all()` are always complete no matter what the caller imported.
"""

from __future__ import annotations

from envelock.detections import content, identity, impersonation, sessions  # noqa: F401

__all__ = ["content", "identity", "impersonation", "sessions"]
