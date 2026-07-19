"""Capability derivation — the mechanism behind PRD P4 (never silently degrade).

These tests encode the PRD §4 coverage matrix. If one fails, either the matrix
changed or we introduced a coverage claim we cannot honour.
"""

from __future__ import annotations

from envelock.core.capabilities import (
    Capability,
    capabilities_for,
    protection_level,
)
from envelock.core.enums import ProtectionLevel, SourceMechanism


def test_tier1_m365_is_fully_protected() -> None:
    caps = capabilities_for(
        frozenset({SourceMechanism.GRAPH_API, SourceMechanism.ENTRA_LOGS})
    )
    assert protection_level(caps) is ProtectionLevel.FULL


def test_tier3_imap_with_sensor_reaches_full() -> None:
    """The central claim of PRD §7.7: the client sensor recovers the identity
    telemetry an ISP mailbox has no identity provider to supply."""
    caps = capabilities_for(
        frozenset({SourceMechanism.IMAP_IDLE, SourceMechanism.CLIENT_SENSOR})
    )
    assert Capability.READ_SESSIONS in caps
    assert Capability.MODIFY_MESSAGE in caps
    # Server-side rules remain unavailable over IMAP (PRD §7.4), so FULL is not
    # claimed — this asymmetry is deliberate and must not be "fixed".
    assert Capability.READ_SERVER_RULES not in caps
    assert protection_level(caps) is ProtectionLevel.STANDARD


def test_tier3_imap_restores_remediation() -> None:
    """IMAP MOVE works on a 1998 server, so Tier 3 can quarantine even though
    Tier 4 cannot. This is the upgrade argument in PRD §4 fn.3."""
    imap = capabilities_for(frozenset({SourceMechanism.IMAP_IDLE}))
    forwarding = capabilities_for(frozenset({SourceMechanism.FORWARD_INGEST}))

    assert Capability.MODIFY_MESSAGE in imap
    assert Capability.MODIFY_MESSAGE not in forwarding


def test_tier4_forwarding_is_limited_and_alert_only() -> None:
    caps = capabilities_for(frozenset({SourceMechanism.FORWARD_INGEST}))
    assert protection_level(caps) is ProtectionLevel.LIMITED
    assert Capability.READ_OUTBOUND not in caps


def test_monitored_polling_gives_up_remediation_not_visibility() -> None:
    """PRD §12.11D: Monitored mailboxes poll instead of holding IDLE. They keep
    content and flag visibility; they lose only real-time remediation."""
    caps = capabilities_for(frozenset({SourceMechanism.IMAP_POLL}))
    assert Capability.READ_INBOUND in caps
    assert Capability.READ_FLAGS in caps
    assert Capability.MODIFY_MESSAGE not in caps


def test_channel3_alone_needs_no_mailbox_access() -> None:
    """Guard (free forever) and the pre-sales demo in PRD S12."""
    caps = capabilities_for(
        frozenset({SourceMechanism.CERT_TRANSPARENCY, SourceMechanism.DMARC_RUA})
    )
    assert Capability.OBSERVE_DOMAIN in caps
    assert Capability.READ_INBOUND not in caps
    assert protection_level(caps) is ProtectionLevel.LIMITED


def test_registry_is_complete_regardless_of_import_order() -> None:
    """Regression: the registry was populated by import side-effect, so the
    active detection set depended on which module happened to be imported
    first. A mailbox could run a subset of the suite while reporting full
    coverage — exactly the failure P4 exists to prevent."""
    from envelock.detections.base import registry

    services = set(registry())
    for group, count in (("A", 14), ("B", 9), ("C", 14)):
        found = {s for s in services if s.startswith(group)}
        assert len(found) == count, f"group {group}: {sorted(found)}"


def test_every_detection_declares_capabilities_and_a_service_id() -> None:
    from envelock.detections.base import registry

    for service, detection in registry().items():
        assert service[0] in "ABCDE"
        assert service[1:].isdigit()
        assert isinstance(detection.requires, frozenset)
