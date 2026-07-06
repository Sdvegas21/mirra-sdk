"""MCP trust-boundary regression gate — the three guarantees, as failable tests.

When a remote AI writes to a user's signed store over MCP, the trust story lives
in three properties. Each test below is a NEGATIVE case that must fail the build
if the guarantee regresses:

  1. Per-subject recall isolation — an agent scoped to subject A gets ZERO of
     subject B's scrolls, and cannot even request B's history (no subject arg).
  2. Agent-attested provenance — MCP-written scrolls are marked mcp-agent in
     their SIGNED content, distinct from a human-authored memory, unforgeable.
  3. Fail-closed verify-on-read on the MCP read path — tampered scrolls are
     dropped; no backend means refuse, never pass.
"""

import pytest

import mirra
from mirra_mcp.scoped_memory import (
    ATTEST_AGENT,
    ATTEST_HUMAN,
    MemoryGateway,
    ScopedMemory,
    SubjectIsolationError,
    read_attestation,
    wrap_attested,
)


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("QSEAL_SECRET", "test-secret-for-mcp-trust")


@pytest.fixture()
def gateway(tmp_path):
    return MemoryGateway(app="mcp-test", home=str(tmp_path), people=False)


# --------------------------------------------------------------------------- #
# 1. Per-subject recall isolation                                             #
# --------------------------------------------------------------------------- #

def test_scope_cannot_read_another_subject(gateway):
    """A scope must return EXACTLY its own subject's scrolls and nothing else —
    checked in BOTH directions and against a third uninvolved subject, so a leak
    in any direction fails the test (not just one hand-picked pair)."""
    alice = gateway.scope("alice")
    bob = gateway.scope("bob")
    carol = gateway.scope("carol")
    alice.remember("alice salary secret")
    bob.remember("bob likes trains")
    carol.remember("carol's diary entry")

    alice_view = [m["content"] for m in alice.recall()]
    bob_view = [m["content"] for m in bob.recall()]

    # Each scope sees ONLY its own memory — no foreign content in either direction.
    assert alice_view == ["alice salary secret"], f"alice scope leaked: {alice_view}"
    assert bob_view == ["bob likes trains"], f"bob scope leaked: {bob_view}"
    # Explicit cross-checks (a leak in ANY direction must fail):
    for foreign in ("trains", "diary"):
        assert not any(foreign in c for c in alice_view), f"alice saw foreign '{foreign}'"
    for foreign in ("salary", "diary"):
        assert not any(foreign in c for c in bob_view), f"bob saw foreign '{foreign}'"


def test_recall_has_no_subject_argument(gateway):
    """The read path takes no subject id, so cross-subject recall is impossible
    by construction, not by a runtime check that could be bypassed."""
    import inspect

    params = list(inspect.signature(ScopedMemory.recall).parameters)
    assert "subject_id" not in params and "subject" not in params, (
        "recall() must not accept a subject argument — isolation is structural"
    )


def test_scope_requires_a_subject(gateway):
    with pytest.raises(SubjectIsolationError):
        gateway.scope("")


def test_empty_subject_scope_sees_nothing_cross_subject(gateway):
    a = gateway.scope("subject-A")
    a.remember("A only")
    c = gateway.scope("subject-C")   # never wrote anything
    assert c.recall() == [], "a fresh subject scope must not inherit others' history"


# --------------------------------------------------------------------------- #
# 2. Agent-attested provenance                                                #
# --------------------------------------------------------------------------- #

def test_mcp_written_scroll_is_agent_attested(gateway):
    alice = gateway.scope("alice")
    result = alice.remember("scheduled the 3pm call")
    assert result["attested_by"] == ATTEST_AGENT, (
        "a memory written via MCP must be marked agent-attested"
    )
    # And on read it still reports agent provenance.
    recalled = alice.recall()
    assert recalled and recalled[0]["attested_by"] == ATTEST_AGENT


def test_agent_and_human_attestation_are_distinguishable(gateway):
    # Human-authored content (written directly, unmarked) reads as human.
    human_marker, _ = read_attestation("a memory a human wrote directly")
    agent_marker, _ = read_attestation(wrap_attested("agent wrote this", ATTEST_AGENT))
    assert human_marker == ATTEST_HUMAN
    assert agent_marker == ATTEST_AGENT
    assert human_marker != agent_marker, "provenance must be distinguishable"


def test_attestation_is_inside_the_signed_payload(gateway):
    """The provenance marker is part of signed content, so stripping/altering it
    breaks verification — it cannot be forged after the fact."""
    alice = gateway.scope("alice")
    alice.remember("agent memory to check")
    # Reach the raw signed scroll and confirm the marker is in signed content,
    # then confirm a mutated copy fails verification.
    raw = alice._w.recall("alice")[0]
    assert str(raw.content).startswith("mirra.attest="), "marker must be in signed content"
    assert alice._w.verify(raw).verified is True
    raw.content = str(raw.content).replace("mcp-agent", "human")  # forge provenance
    assert alice._w.verify(raw).verified is False, (
        "altering the attestation marker must break the signature"
    )


# --------------------------------------------------------------------------- #
# 3. Fail-closed verify-on-read on the MCP path                               #
# --------------------------------------------------------------------------- #

def test_tampered_scroll_dropped_on_disk_tamper(gateway, tmp_path):
    """End-to-end: an attacker edits the scroll file on disk; it must not surface
    on MCP recall. (Defense in depth: both the store AND the MCP layer verify.)"""
    alice = gateway.scope("alice")
    alice.remember("the genuine memory")

    scrolls_dir = tmp_path / "memory" / "memories" / "scrolls"
    tampered = 0
    for f in scrolls_dir.glob("*.yaml"):
        text = f.read_text()
        if "the genuine memory" in text:
            f.write_text(text.replace("the genuine memory", "a forged memory"))
            tampered += 1
    assert tampered, "expected to find and tamper the scroll on disk"

    contents = [m["content"] for m in alice.recall()]
    assert not any("forged" in c for c in contents), (
        "a tampered scroll must be dropped on the MCP read path"
    )


def test_mcp_layer_verifies_independently_of_the_store(tmp_path, monkeypatch):
    """The MCP layer's OWN verify-on-read must drop an unverified scroll even if
    the backing store hands one back (e.g. a store swapped for one that doesn't
    verify). This proves the guarantee lives in the MCP layer, not only in the
    store. Disabling ScopedMemory's verify check must make this test fail.
    """
    monkeypatch.setenv("QSEAL_SECRET", "test-secret-for-mcp-trust")
    from mirra_core_contract import Scroll, VerificationResult
    from mirra_mcp.scoped_memory import ScopedMemory, wrap_attested

    class LyingStore:
        """A store that returns a scroll but whose verify() reports it invalid —
        i.e. a backend that does NOT drop tampered scrolls on recall."""
        agent_id = "agent-x"

        class _Id:
            agent_id = "agent-x"
        identity = _Id()
        _memory = object()   # non-None so ScopedMemory proceeds

        def recall(self, subject_id, query=None):
            return [Scroll(scroll_id="s1", agent_id="agent-x", subject_id=subject_id,
                           content=wrap_attested("unverified content"),
                           qseal_signature="deadbeef")]

        def verify(self, scroll):
            return VerificationResult(verified=False, reason="not verified")

    scope = ScopedMemory(LyingStore(), "alice")
    results = scope.recall()
    assert results == [], (
        "ScopedMemory must drop a scroll its own verify() rejects, even when the "
        "store returns it — verify-on-read is the MCP layer's responsibility too"
    )


def test_no_backend_is_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("QSEAL_SECRET", "test-secret-for-mcp-trust")
    # Build a wrapped agent with no memory backend and scope it.
    import mirra.memory as memory_module

    def broken(base_path, agent_id):
        raise mirra.MemoryUnavailable("backend gone")

    monkeypatch.setattr("mirra.wrapper.default_memory", broken)
    with pytest.raises(mirra.MemoryUnavailable):
        MemoryGateway(app="mcp-test", home=str(tmp_path), people=False)
