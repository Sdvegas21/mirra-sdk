"""Acceptance: Identity continuity (Identity Continuity Spec v0.2).

The agent that begins session N+1 is the agent that ended session N — restored
from a VERIFIED signed snapshot (never a blank default), accruing state
deterministically through sessions (baseline drift + pathway accrual),
narrated into signed memory, and reconstructible from an append-only signed
transition log.

Proven by injection, not assertion: forged snapshots, rolled-back snapshots,
truncated/re-chained logs, deleted state, and wrong identity keys are each
REFUSED — and the load-bearing tests show detection flows through the real
crypto checks (disable the check, the forgery slips past it).
"""

import hashlib
import json
import uuid

import pytest

import mirra
from mirra.continuity import (
    AUTOBIOGRAPHY_SUBJECT,
    ContinuityKernel,
    EmotionalBaseline,
    IdentityKeySigner,
    accrued_strength,
)

from mirra_core_contract import DecisionRecord, Scroll, VerificationResult


# -- contract-typed fakes (no backend dependency for kernel-level tests) --------


class InMemoryStore:
    """Minimal contract MemoryStore for narrative tests."""

    def __init__(self):
        self.scrolls = []

    def remember(self, agent_id, subject_id, content):
        scroll = Scroll(
            scroll_id=str(uuid.uuid4()),
            agent_id=agent_id,
            subject_id=subject_id,
            content=content,
            qseal_signature="test-signature",
        )
        self.scrolls.append(scroll)
        return scroll

    def recall(self, agent_id, subject_id, query=None):
        return [
            s
            for s in self.scrolls
            if s.agent_id == agent_id
            and s.subject_id == subject_id
            and (query is None or query in str(s.content))
        ]

    def verify(self, scroll):
        return VerificationResult(verified=True, scheme="test")


class CapturingAuthorizer:
    """Records the intent it authorizes so tests can inspect provenance."""

    def __init__(self):
        self.last_intent = None

    def authorize(self, intent, identity):
        self.last_intent = intent
        return DecisionRecord(
            request_id=intent.request_id,
            decision="block",
            reason_code="test_capture",
            policy_id="test",
            engine="test",
        )


def make_kernel(sdk_home, memory=None, **kwargs):
    return ContinuityKernel.bootstrap(sdk_home, principal="team-key-1", memory=memory, **kwargs)


# -- session lifecycle (§2) -----------------------------------------------------


def test_genesis_creates_signed_snapshot_and_log(sdk_home):
    kernel = make_kernel(sdk_home)
    with kernel.session() as s:
        assert s.continuity_verified is False  # nothing prior existed to verify
    snapshot = sdk_home / "continuity" / kernel.agent_id / "state.json"
    log = sdk_home / "continuity" / kernel.agent_id / "transitions.jsonl"
    assert snapshot.exists() and log.exists()
    document = json.loads(snapshot.read_text())
    assert document["scheme"] == "ed25519" and document["signature"]
    types = [e["transition_type"] for e in kernel.transition_log.entries()]
    assert types == ["genesis", "session_start", "session_end"]


def test_baseline_persists_across_sessions_not_reset(sdk_home):
    kernel = make_kernel(sdk_home)
    with kernel.session() as s:
        s.experience(engagement=0.9, activation=0.9, agency=0.8)
    shifted = kernel.identity_context()
    assert shifted["session_count"] == 1

    # A brand-new kernel over the same home (a "new process") restores, not resets.
    kernel2 = make_kernel(sdk_home)
    with kernel2.session() as s2:
        assert s2.continuity_verified is True
        assert s2.state.baseline.engagement > 0.0, "baseline must carry forward, not reset"
        assert s2.state.session_count == 1


def test_continuity_guarantee_exact_state_carryover(sdk_home):
    kernel = make_kernel(sdk_home)
    with kernel.session() as s:
        s.experience(engagement=0.5, activation=0.7, agency=0.1)
        s.activate_pathway("navigation")
    ended = s.state.to_dict()

    kernel2 = make_kernel(sdk_home)
    handle = kernel2.begin_session()
    assert handle.state.to_dict() == ended, "session N+1 must begin exactly where N ended"
    kernel2.end_session(handle)


def test_experience_shifts_baseline_and_tracks_drift(sdk_home):
    kernel = make_kernel(sdk_home)
    with kernel.session() as s:
        before = s.state.baseline.to_dict()
        s.experience(engagement=1.0, activation=1.0, agency=1.0)
    state = s.state
    assert state.baseline.to_dict() != before
    assert 0 < state.baseline.engagement < 1.0, "EWMA drifts, it does not jump"
    assert state.cumulative_drift > 0
    assert state.last_session_drift == pytest.approx(state.cumulative_drift)


def test_session_without_experience_leaves_baseline_untouched(sdk_home):
    kernel = make_kernel(sdk_home)
    with kernel.session():
        pass
    ctx = kernel.identity_context()
    assert ctx["session_count"] == 1
    kernel2 = make_kernel(sdk_home)
    handle = kernel2.begin_session()
    assert handle.state.baseline.to_dict() == EmotionalBaseline().to_dict()
    assert handle.state.cumulative_drift == 0.0
    kernel2.end_session(handle)


# -- developmental accrual (§5) ---------------------------------------------------


def test_pathway_accrual_strengthens_and_saturates(sdk_home):
    kernel = make_kernel(sdk_home)
    strengths = []
    for _ in range(3):
        with kernel.session() as s:
            for _ in range(4):
                s.activate_pathway("code_review")
        strengths.append(s.state.pathways["code_review"].strength)
    assert strengths == sorted(strengths), "strength must be monotonic"
    assert strengths[0] < strengths[-1] <= 1.0
    record = s.state.pathways["code_review"]
    assert record.activations == 12
    assert record.strength == pytest.approx(accrued_strength(12, kernel.pathway_tau))


def test_accrual_invariant_n_sessions_differ_from_zero(sdk_home, tmp_path):
    seasoned = make_kernel(sdk_home)
    for _ in range(3):
        with seasoned.session() as s:
            s.experience(engagement=0.6)
            s.activate_pathway("support")
    fresh = ContinuityKernel.bootstrap(tmp_path / "fresh-home", principal="team-key-1")
    handle = fresh.begin_session()
    seasoned_state = s.state.to_dict()
    fresh_state = handle.state.to_dict()
    assert seasoned_state["session_count"] == 3 and fresh_state["session_count"] == 0
    assert seasoned_state["pathways"] and not fresh_state["pathways"]
    assert seasoned_state["baseline"] != fresh_state["baseline"]
    fresh.end_session(handle)


def test_pathway_history_traceable_in_log(sdk_home):
    kernel = make_kernel(sdk_home)
    with kernel.session() as s:
        s.activate_pathway("navigation")
        s.activate_pathway("navigation")
    activations = kernel.transition_log.query(transition_type="pathway_activation")
    assert len(activations) == 2
    assert activations[0]["state_before"]["activations"] == 0
    assert activations[1]["state_after"]["activations"] == 2
    assert all(e["signature"] for e in activations)


# -- governed transitions (§6) ----------------------------------------------------


def test_transition_log_chain_verifies(sdk_home):
    kernel = make_kernel(sdk_home)
    for _ in range(2):
        with kernel.session() as s:
            s.experience(engagement=0.3)
            s.activate_pathway("navigation")
    report = kernel.transition_log.verify()
    assert report["verified"] is True
    assert report["entries"] >= 7  # genesis + 2×(start, activation, end)


def test_replay_reconstructs_state_from_log(sdk_home):
    kernel = make_kernel(sdk_home)
    for _ in range(2):
        with kernel.session() as s:
            s.experience(engagement=0.4, activation=0.6)
            s.activate_pathway("code_review")
    snapshot = json.loads(
        (sdk_home / "continuity" / kernel.agent_id / "state.json").read_text()
    )
    assert kernel.replay() == snapshot["state"]
    proof = kernel.verify_continuity()
    assert proof["verified"] is True, proof["reason"]
    assert proof["snapshot_verified"] and proof["log_verified"] and proof["replay_matches"]


def test_tampered_snapshot_refuses_restoration(sdk_home):
    kernel = make_kernel(sdk_home)
    with kernel.session() as s:
        s.experience(engagement=0.5)
    snapshot_path = sdk_home / "continuity" / kernel.agent_id / "state.json"
    document = json.loads(snapshot_path.read_text())
    document["state"]["session_count"] = 999  # forge a longer history
    snapshot_path.write_text(json.dumps(document, indent=2, sort_keys=True))

    kernel2 = make_kernel(sdk_home)
    with pytest.raises(mirra.ContinuityError):
        kernel2.begin_session()
    ctx = kernel2.identity_context()
    assert ctx["continuity_verified"] is False and ctx["trust_established"] is False


def test_tampered_log_detected(sdk_home):
    kernel = make_kernel(sdk_home)
    with kernel.session() as s:
        s.activate_pathway("navigation")
    log_path = sdk_home / "continuity" / kernel.agent_id / "transitions.jsonl"
    lines = log_path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["transition_type"] = "forged"
    lines[1] = json.dumps(entry, sort_keys=True)
    log_path.write_text("\n".join(lines) + "\n")

    report = kernel.transition_log.verify()
    assert report["verified"] is False
    assert kernel.verify_continuity()["verified"] is False
    with pytest.raises(mirra.ContinuityError, match="transition log failed verification"):
        make_kernel(sdk_home).begin_session()


# -- autobiographical memory (§4) ---------------------------------------------------


def test_autobiography_written_to_signed_memory(sdk_home):
    store = InMemoryStore()
    kernel = make_kernel(sdk_home, memory=store)
    with kernel.session() as s:
        s.experience(engagement=0.7)
        s.record_episode(
            "helped alice debug the deploy",
            learned="alice's deploys go out on Fridays",
            verbatim="alice: the deploy is broken again",
            significance=0.9,
        )
        s.note_relationship("alice", learning="prefers direct answers")
    assert len(store.scrolls) == 1
    assert store.scrolls[0].subject_id == AUTOBIOGRAPHY_SUBJECT

    records = kernel.recall_autobiography()
    assert len(records) == 1
    record = records[0]
    episodic, semantic = record["episodic"], record["semantic"]
    assert episodic[0]["what_happened"] == "helped alice debug the deploy"
    assert episodic[0]["verbatim"] == "alice: the deploy is broken again"
    assert episodic[0]["emotional_state"]["engagement"] == pytest.approx(0.7)
    assert semantic[0]["learned"] == "alice's deploys go out on Fridays"
    assert record["relationships"]["alice"]["learnings"] == ["prefers direct answers"]
    assert record["affect"]["baseline_before"] != record["affect"]["baseline_after"]


def test_autobiography_emotional_resonance_ordering(sdk_home):
    store = InMemoryStore()
    kernel = make_kernel(sdk_home, memory=store)
    with kernel.session() as s:
        s.experience(engagement=0.9, activation=0.9)
        s.record_episode("a high-energy session")
    with kernel.session() as s:
        s.experience(engagement=-0.8, activation=0.1)
        s.record_episode("a deflated session")
    probe = EmotionalBaseline(engagement=-0.9, activation=0.1, agency=0.0)
    by_resonance = kernel.recall_autobiography(affect=probe)
    assert by_resonance[0]["episodic"][0]["what_happened"] == "a deflated session"


# -- identity context & execution integration (§8) -----------------------------------


def test_identity_context_trust_threshold(sdk_home):
    kernel = make_kernel(sdk_home, trust_threshold=2)
    assert kernel.identity_context()["continuity_verified"] is False
    for expected_trust in (False, True, True):
        with kernel.session() as s:
            pass
        assert kernel.identity_context()["trust_established"] is expected_trust
    ctx = kernel.identity_context()
    assert ctx["continuity_verified"] is True
    assert ctx["session_count"] == 3
    assert ctx["identity_signature"]


def test_wrap_continuity_execute_carries_identity_context(sdk_home, echo_agent):
    store = InMemoryStore()
    authorizer = CapturingAuthorizer()
    wrapped = mirra.wrap(
        echo_agent,
        principal="team-key-1",
        home=sdk_home,
        memory=store,
        authorizer=authorizer,
    )
    assert wrapped.continuity is None  # off by default: fully backward-compatible

    wrapped = mirra.wrap(
        echo_agent,
        principal="team-key-1",
        home=sdk_home,
        memory=store,
        authorizer=authorizer,
        continuity=True,
    )
    with wrapped.session() as s:
        response = wrapped.interact("alice", "hello again")
        assert "alice" in response
        wrapped.execute("shell.exec", "ls")
        ctx = authorizer.last_intent.provenance["identity_context"]
        assert ctx["agent_id"] == wrapped.identity.agent_id
        assert ctx["continuity_verified"] is False  # genesis session
        assert s.identity_context() == ctx

    # interact() inside the session fed the autobiography.
    records = wrapped.continuity.recall_autobiography()
    assert records and "alice" in json.dumps(records[0]["relationships"])

    # Outside a session, execute() still carries persisted identity context.
    wrapped.execute("shell.exec", "ls")
    ctx = authorizer.last_intent.provenance["identity_context"]
    assert ctx["continuity_verified"] is True and ctx["session_count"] == 1


def test_session_requires_continuity_enabled(sdk_home, echo_agent):
    wrapped = mirra.wrap(echo_agent, principal="team-key-1", home=sdk_home, memory=InMemoryStore())
    with pytest.raises(mirra.ContinuityError):
        with wrapped.session():
            pass


# -- fail-closed edges ------------------------------------------------------------


def test_missing_identity_key_fail_closed(sdk_home):
    with pytest.raises(mirra.ContinuityError):
        ContinuityKernel(sdk_home, "agent-nonexistent")


def test_concurrent_session_refused(sdk_home):
    kernel = make_kernel(sdk_home)
    handle = kernel.begin_session()
    with pytest.raises(mirra.ContinuityError):
        kernel.begin_session()
    kernel.end_session(handle)
    with pytest.raises(mirra.ContinuityError):
        kernel.end_session(handle)  # already ended


# -- proven by injection: every guard must bite -----------------------------------


def _continuity_dir(sdk_home, kernel):
    return sdk_home / "continuity" / kernel.agent_id


def test_wrong_identity_key_refuses_restoration(sdk_home):
    kernel = make_kernel(sdk_home)
    with kernel.session():
        pass
    # An intruder holding a DIFFERENT valid identity key tries to open this
    # agent's state under its agent_id.
    from mirra.identity import LocalIdentityResolver

    intruder = LocalIdentityResolver(sdk_home).resolve_identity("intruder")
    intruder_signer = IdentityKeySigner.for_agent(sdk_home, intruder.agent_id)
    hijack = ContinuityKernel(sdk_home, kernel.agent_id, signer=intruder_signer)
    with pytest.raises(mirra.ContinuityError, match="different identity key"):
        hijack.begin_session()


def test_rollback_attack_refused_by_replay_guard(sdk_home):
    """Restoring an OLD but validly-signed snapshot must be refused. The
    signature guard cannot catch this (the signature is genuine) — only the
    replay guard can, which proves it bites independently."""
    kernel = make_kernel(sdk_home)
    with kernel.session() as s:
        s.experience(engagement=0.2)
    snapshot_path = _continuity_dir(sdk_home, kernel) / "state.json"
    old_snapshot = snapshot_path.read_text()  # genuine session-1 state
    with kernel.session() as s:
        s.experience(engagement=0.9)
        s.activate_pathway("navigation")
    snapshot_path.write_text(old_snapshot)  # roll the agent back in time

    with pytest.raises(mirra.ContinuityError, match="does not reproduce"):
        make_kernel(sdk_home).begin_session()
    report = make_kernel(sdk_home).verify_continuity()
    assert report["snapshot_verified"] is True, "rollback carries a VALID signature"
    assert report["log_verified"] is True
    assert report["replay_matches"] is False and report["verified"] is False


def test_truncated_log_refuses_restoration(sdk_home):
    kernel = make_kernel(sdk_home)
    with kernel.session():
        pass
    log_path = _continuity_dir(sdk_home, kernel) / "transitions.jsonl"
    session_one_log = log_path.read_text()  # a VALID chain prefix
    with kernel.session() as s:
        s.activate_pathway("navigation")
    log_path.write_text(session_one_log)  # cut history back to session 1

    with pytest.raises(mirra.ContinuityError, match="does not reproduce"):
        make_kernel(sdk_home).begin_session()


def test_deleted_snapshot_refuses_regenesis(sdk_home):
    kernel = make_kernel(sdk_home)
    with kernel.session() as s:
        s.experience(engagement=0.5)
    (_continuity_dir(sdk_home, kernel) / "state.json").unlink()
    with pytest.raises(mirra.ContinuityError, match="refusing to re-genesis"):
        make_kernel(sdk_home).begin_session()


def _rechain(entries):
    """Recompute the hash chain over tampered entries WITHOUT re-signing —
    exactly what an attacker who lacks the identity key can do."""
    prev = "genesis"
    lines = []
    for entry in entries:
        entry["prev_hash"] = prev
        line = json.dumps(entry, sort_keys=True)
        lines.append(line)
        prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
    return "\n".join(lines) + "\n"


def test_rechained_log_caught_by_signatures(sdk_home):
    """Tampering an entry AND recomputing the hash chain defeats the chain
    check — the per-entry signature is what catches it."""
    kernel = make_kernel(sdk_home)
    with kernel.session() as s:
        s.activate_pathway("navigation")
    log_path = _continuity_dir(sdk_home, kernel) / "transitions.jsonl"
    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    entries[1]["state_after"] = {"forged": True}
    log_path.write_text(_rechain(entries))

    report = kernel.transition_log.verify()
    assert report["verified"] is False
    assert "signature" in report["reason"], "the chain links; the SIGNATURE must catch it"
    with pytest.raises(mirra.ContinuityError, match="transition log failed verification"):
        make_kernel(sdk_home).begin_session()


def test_snapshot_signature_guard_is_load_bearing(sdk_home, monkeypatch):
    """Disable the Ed25519 check and the forgery slips past IT — proving the
    tamper tests' detection flows through the real crypto, not an accident.
    The independent replay guard must then still refuse restoration."""
    import mirra.continuity as continuity_module

    kernel = make_kernel(sdk_home)
    with kernel.session():
        pass
    snapshot_path = _continuity_dir(sdk_home, kernel) / "state.json"
    document = json.loads(snapshot_path.read_text())
    document["state"]["session_count"] = 999
    snapshot_path.write_text(json.dumps(document, indent=2, sort_keys=True))

    assert make_kernel(sdk_home).verify_continuity()["snapshot_verified"] is False

    monkeypatch.setattr(continuity_module, "verify_ed25519", lambda *a, **k: True)
    disabled = make_kernel(sdk_home).verify_continuity()
    assert disabled["snapshot_verified"] is True, "detection WAS the crypto check"
    assert disabled["replay_matches"] is False, "defense in depth: replay still bites"
    with pytest.raises(mirra.ContinuityError, match="does not reproduce"):
        make_kernel(sdk_home).begin_session()


def test_chain_signature_guard_is_load_bearing(sdk_home, monkeypatch):
    import mirra.continuity as continuity_module

    kernel = make_kernel(sdk_home)
    with kernel.session() as s:
        s.activate_pathway("navigation")
    log_path = _continuity_dir(sdk_home, kernel) / "transitions.jsonl"
    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    entries[1]["state_after"] = {"forged": True}
    log_path.write_text(_rechain(entries))

    assert kernel.transition_log.verify()["verified"] is False
    monkeypatch.setattr(continuity_module, "verify_ed25519", lambda *a, **k: True)
    assert kernel.transition_log.verify()["verified"] is True, (
        "with signatures disabled the re-chained forgery verifies — "
        "the signature check is the load-bearing guard"
    )


# -- recognition is ENFORCED, not just emitted (§8, real engine) --------------------


TRUSTED = {
    "source": "user_request",
    "taint_level": "trusted",
    "source_chain": ["user_request", "tool_call"],
}


def _wrap_continuous(sdk_home, echo_agent, principal):
    return mirra.wrap(
        echo_agent,
        principal=principal,
        home=sdk_home,
        profile="dev_balanced",
        memory=InMemoryStore(),
        continuity=True,
    )


def test_same_action_allowed_for_known_refused_for_stranger(sdk_home, echo_agent):
    """The thesis test: 'can't act without being known'. The SAME action with
    the SAME claimed provenance is allowed for an agent with established,
    verified continuity and refused for a stranger — enforced by the real
    engine (recognition gates trusted provenance; un-established continuity
    forces taint to untrusted). Remove the downgrade in execute() and this
    test goes red: the stranger would be allowed."""
    known = _wrap_continuous(sdk_home, echo_agent, "known-team-key")
    for _ in range(3):  # establish verified continuity (trust_threshold=3)
        with known.session():
            pass
    stranger = _wrap_continuous(sdk_home, echo_agent, "stranger-key")

    sink, target = "tool.custom", "summarize the quarterly report"
    known_record = known.execute(sink, target, provenance=dict(TRUSTED))
    stranger_record = stranger.execute(sink, target, provenance=dict(TRUSTED))
    assert known_record.decision == "allow"
    assert stranger_record.decision != "allow"
    assert stranger_record.reason_code == "CONTINUITY_NOT_ESTABLISHED", (
        "the refusal must be BECAUSE of recognition, not incidental policy"
    )

    # Behavioral: the same protected tool RUNS for known, REFUSES for stranger.
    ran = []

    def tool(x):
        ran.append(x)
        return "ok"

    assert known.protect_tool(tool, sink=sink, provenance=dict(TRUSTED))(target) == "ok"
    with pytest.raises(mirra.ExecutionRefused):
        stranger.protect_tool(tool, sink=sink, provenance=dict(TRUSTED))(target)
    assert ran == [target], "the stranger's tool must never run"

    # Critical sinks stay deterministically blocked for the stranger even when
    # it CLAIMS trusted provenance — the IFC invariant does the enforcing.
    hard = stranger.execute("shell.exec", "echo hello", provenance=dict(TRUSTED))
    assert hard.decision == "block"
    assert hard.reason_code == "UNTRUSTED_TO_CRITICAL_SINK"


def test_stranger_earns_the_same_allow_by_becoming_known(sdk_home, echo_agent):
    """Recognition, not identity strings: the gate opens through verified
    continuity, so yesterday's stranger passes after establishing it."""
    agent = _wrap_continuous(sdk_home, echo_agent, "newcomer-key")
    sink, target = "tool.custom", "summarize the quarterly report"

    refused = agent.execute(sink, target, provenance=dict(TRUSTED))
    assert refused.decision != "allow"
    assert refused.reason_code == "CONTINUITY_NOT_ESTABLISHED"

    for _ in range(3):
        with agent.session():
            pass

    earned = agent.execute(sink, target, provenance=dict(TRUSTED))
    assert earned.decision == "allow"


def test_deterministic_given_clock_and_inputs(sdk_home, tmp_path):
    def run(home):
        ticks = iter(f"2026-07-06T00:00:{i:02d}+00:00" for i in range(100))
        kernel = ContinuityKernel.bootstrap(
            home, principal="team-key-1", clock=lambda: next(ticks)
        )
        with kernel.session(session_id="session-fixed") as s:
            s.experience(engagement=0.25, activation=0.75, agency=-0.5)
            s.activate_pathway("navigation")
        return s.state.to_dict()

    assert run(sdk_home) == run(tmp_path / "other-home")
