"""Protection level is explained, not just labelled (P4/E7).

The user read a bare "Standard" as "broken". The level is correctly derived from
connected sources; these tests pin the *explainer* that tells the customer why
the level is what it is and exactly how to raise it — which is the actual fix.
"""

from __future__ import annotations

from envelock.core.capabilities import protection_advice
from envelock.core.enums import SourceMechanism


def test_imap_only_is_standard_with_a_path_to_full():
    advice = protection_advice(frozenset({SourceMechanism.IMAP_IDLE}))
    assert advice["level"] == "standard"
    assert advice["is_max"] is False
    assert advice["next_level"] == "full"
    caps = {g["capability"] for g in advice["missing"]}
    # IMAP can't see server rules or sessions — that's the honest gap to Full.
    assert "read_server_rules" in caps
    assert "read_sessions" in caps
    # Each gap explains what it unlocks and how to get it.
    sessions = next(g for g in advice["missing"] if g["capability"] == "read_sessions")
    assert "login" in sessions["unlocks"].lower()
    assert sessions["how"]
    assert "client_sensor" in sessions["provided_by"]


def test_oauth_plus_sensor_is_full_and_max():
    advice = protection_advice(
        frozenset({SourceMechanism.GRAPH_API, SourceMechanism.CLIENT_SENSOR})
    )
    assert advice["level"] == "full"
    assert advice["is_max"] is True
    assert advice["missing"] == []


def test_forwarding_is_limited_pointing_at_standard():
    advice = protection_advice(frozenset({SourceMechanism.FORWARD_INGEST}))
    assert advice["level"] == "limited"
    assert advice["next_level"] == "standard"
    caps = {g["capability"] for g in advice["missing"]}
    # Forwarding is post-delivery: it can't modify a message, so no quarantine.
    assert "modify_message" in caps
