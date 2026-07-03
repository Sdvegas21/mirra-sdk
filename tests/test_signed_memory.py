"""Acceptance: Portable signed memory (EVAL/06_HANDOFF.md §7).

A memory written in one session is recalled in a later session; recall verifies
signatures and returns only verified memories; content altered outside the API
fails verification on recall (fail-closed).
"""

import pytest

import mirra


@pytest.fixture()
def wrapped(sdk_home, echo_agent, monkeypatch):
    monkeypatch.setenv("QSEAL_SECRET", "test-secret-for-sdk-acceptance-suite")
    return mirra.wrap(echo_agent, principal="team-key-1", home=sdk_home)


def _rewrap(sdk_home, echo_agent):
    return mirra.wrap(echo_agent, principal="team-key-1", home=sdk_home)


def test_remember_then_recall_across_sessions(wrapped, sdk_home, echo_agent):
    scroll = wrapped.remember("alice", "alice prefers morning meetings")
    assert scroll.qseal_signature, "scroll must be signed on write"

    later_session = _rewrap(sdk_home, echo_agent)
    memories = later_session.recall("alice")
    contents = [str(getattr(s, "content", s)) for s in memories]
    assert any("morning meetings" in c for c in contents)


def test_recall_is_scoped_per_subject(wrapped):
    wrapped.remember("alice", "alice fact")
    wrapped.remember("bob", "bob fact")

    alice_memories = [str(s.content) for s in wrapped.recall("alice")]
    assert any("alice fact" in c for c in alice_memories)
    assert not any("bob fact" in c for c in alice_memories)


def test_verify_reports_real_signature(wrapped):
    scroll = wrapped.remember("alice", "a verifiable fact")
    result = wrapped.verify(scroll)
    assert result.verified is True
    assert result.scheme == "hmac-sha256"


def test_tampered_scroll_excluded_on_recall(wrapped, sdk_home):
    wrapped.remember("alice", "the original truth")

    scrolls_dir = sdk_home / "memory" / "memories" / "scrolls"
    tampered = 0
    for scroll_file in scrolls_dir.glob("*.yaml"):
        text = scroll_file.read_text()
        if "the original truth" in text:
            scroll_file.write_text(text.replace("the original truth", "a forged history"))
            tampered += 1
    assert tampered, "expected the scroll on disk to be found and altered"

    contents = [str(s.content) for s in wrapped.recall("alice")]
    assert not any("a forged history" in c for c in contents), "tampered scroll must be dropped"


def test_mutated_in_memory_scroll_fails_verify(wrapped):
    scroll = wrapped.remember("alice", "what actually happened")
    scroll.content = "what the attacker wishes had happened"
    result = wrapped.verify(scroll)
    assert result.verified is False


def test_no_backend_wrap_raises(sdk_home, echo_agent, monkeypatch):
    import mirra.memory as memory_module

    def broken(base_path, agent_id):
        raise mirra.MemoryUnavailable("backend gone")

    monkeypatch.setattr(memory_module, "default_memory", broken)
    monkeypatch.setattr("mirra.wrapper.default_memory", broken)
    with pytest.raises(mirra.MemoryUnavailable):
        mirra.wrap(echo_agent, principal="p2", home=sdk_home)
