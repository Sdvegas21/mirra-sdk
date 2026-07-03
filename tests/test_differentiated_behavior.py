"""Acceptance: Per-relationship behavior (EVAL/06_HANDOFF.md §7).

Wrapping the same agent and interacting as two different subjects produces
observably different context/behavior for each subject, driven by their
respective histories.
"""

import pytest

import mirra


@pytest.fixture()
def wrapped(sdk_home, echo_agent, monkeypatch):
    monkeypatch.setenv("QSEAL_SECRET", "test-secret-for-sdk-acceptance-suite")
    return mirra.wrap(echo_agent, principal="team-key-1", home=sdk_home)


def test_two_subjects_get_different_context(wrapped):
    wrapped.interact("alice", "my favorite color is green")
    wrapped.interact("alice", "I work in astrophysics")
    wrapped.interact("bob", "I only care about baseball")

    alice_context = wrapped.build_context("alice")
    bob_context = wrapped.build_context("bob")

    assert alice_context["subject_id"] == "alice"
    assert bob_context["subject_id"] == "bob"
    assert alice_context["history"] != bob_context["history"]
    assert len(alice_context["history"]) == 2
    assert len(bob_context["history"]) == 1
    assert any("astrophysics" in str(h) for h in alice_context["history"])
    assert not any("astrophysics" in str(h) for h in bob_context["history"])


def test_agent_response_reflects_subject_history(wrapped):
    first = wrapped.interact("alice", "hello")
    second = wrapped.interact("alice", "hello again")
    fresh = wrapped.interact("bob", "hello")

    # The echo agent surfaces how much history it was handed: alice's second
    # message sees more history than her first; bob starts fresh.
    assert "seen=0" in first
    assert "seen=1" in second
    assert "seen=0" in fresh


def test_provider_enrichment_reaches_context(sdk_home, echo_agent, monkeypatch):
    monkeypatch.setenv("QSEAL_SECRET", "test-secret-for-sdk-acceptance-suite")

    class TrustingProvider:
        """A minimal contract CapabilityProvider used as an injection test double."""

        def enrich_identity(self, identity):
            enriched = dict(identity.context or {})
            enriched["relationship_tone"] = "warm"
            import dataclasses

            return dataclasses.replace(identity, context=enriched)

        def verify_epistemic(self, intent):
            return 0.9

    wrapped = mirra.wrap(
        echo_agent, principal="team-key-1", home=sdk_home, providers=[TrustingProvider()]
    )
    context = wrapped.build_context("alice")
    assert context["identity_context"].get("relationship_tone") == "warm"
