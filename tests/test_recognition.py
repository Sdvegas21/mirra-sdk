"""Acceptance: Recognition (EVAL/06_HANDOFF.md §7).

The same agent, across two separate sessions, resolves to one stable identity
with a matching fingerprint; a different principal resolves to a different
identity. A damaged keystore raises instead of silently minting a new identity.
"""

import json

import pytest

from mirra.errors import IdentityError
from mirra.identity import LocalIdentityResolver


def test_same_principal_two_sessions_same_identity(sdk_home):
    first_session = LocalIdentityResolver(sdk_home).resolve_identity("team-key-1")
    second_session = LocalIdentityResolver(sdk_home).resolve_identity("team-key-1")

    assert first_session.agent_id == second_session.agent_id
    assert first_session.identity_pubkey == second_session.identity_pubkey
    assert first_session.soulprint_digest == second_session.soulprint_digest
    assert len(first_session.soulprint_digest) == 64  # SHA-256 fingerprint


def test_different_principal_different_identity(sdk_home):
    resolver = LocalIdentityResolver(sdk_home)
    a = resolver.resolve_identity("team-key-1")
    b = resolver.resolve_identity("team-key-2")

    assert a.agent_id != b.agent_id
    assert a.identity_pubkey != b.identity_pubkey
    assert a.soulprint_digest != b.soulprint_digest


def test_last_seen_updates_across_sessions(sdk_home):
    first = LocalIdentityResolver(sdk_home).resolve_identity("team-key-1")
    second = LocalIdentityResolver(sdk_home).resolve_identity("team-key-1")
    assert second.created_at == first.created_at
    assert second.last_seen >= first.last_seen


def test_missing_key_fails_closed_not_regenerated(sdk_home):
    resolver = LocalIdentityResolver(sdk_home)
    identity = resolver.resolve_identity("team-key-1")

    for key_file in (sdk_home / "identity").glob("*.key"):
        key_file.unlink()

    with pytest.raises(IdentityError):
        LocalIdentityResolver(sdk_home).resolve_identity("team-key-1")
    del identity


def test_tampered_record_fails_closed(sdk_home):
    resolver = LocalIdentityResolver(sdk_home)
    resolver.resolve_identity("team-key-1")

    record_file = next((sdk_home / "identity").glob("*.json"))
    record = json.loads(record_file.read_text())
    record["agent_id"] = "agent-imposter"
    record_file.write_text(json.dumps(record))

    with pytest.raises(IdentityError):
        LocalIdentityResolver(sdk_home).resolve_identity("team-key-1")
