"""Person recognition — the same human across devices/agents (the vision primitive).

Covers: minting a person, claiming device-local handles, cross-device recognition
via signed claims (verify-on-import, fail-closed), and the payoff — one portable
signed relationship history shared across a person's handles.
"""

import pytest

import mirra
from mirra.person import PersonClaim, PersonRegistry


def test_person_stable_id_and_fingerprint(sdk_home):
    reg = PersonRegistry(sdk_home)
    p = reg.create_person(display_name="Mom")
    assert p.person_id.startswith("person-")
    assert len(p.fingerprint) == 64
    # Re-reading returns the same person, same fingerprint.
    again = reg.get_person(p.person_id)
    assert again.fingerprint == p.fingerprint


def test_handles_resolve_to_one_person(sdk_home):
    reg = PersonRegistry(sdk_home)
    mom = reg.create_person(display_name="Mom")
    reg.claim_handle(mom.person_id, "car:driver-1")
    reg.claim_handle(mom.person_id, "robot:mom")
    reg.claim_handle(mom.person_id, "phone:user_42")

    for handle in ("car:driver-1", "robot:mom", "phone:user_42"):
        resolved = reg.resolve_handle(handle)
        assert resolved is not None and resolved.person_id == mom.person_id
    assert reg.resolve_handle("stranger") is None


def test_claim_verifies_and_tamper_is_rejected(sdk_home):
    reg = PersonRegistry(sdk_home)
    mom = reg.create_person(display_name="Mom")
    reg.claim_handle(mom.person_id, "car:driver-1")

    claim = reg.export_claim(mom.person_id)
    assert PersonRegistry.verify_claim(claim) is True

    # Tamper with a signed field -> verification fails.
    forged = PersonClaim.from_dict({**claim.to_dict(), "display_name": "Imposter"})
    assert PersonRegistry.verify_claim(forged) is False
    forged_handle = PersonClaim.from_dict(
        {**claim.to_dict(), "handles": claim.handles + ["robot:evil"]})
    assert PersonRegistry.verify_claim(forged_handle) is False


def test_cross_device_recognition(sdk_home, tmp_path):
    # Device A (phone) mints the person and enrolls handles.
    phone = PersonRegistry(tmp_path / "phone")
    mom = phone.create_person(display_name="Mom")
    phone.claim_handle(mom.person_id, "phone:user_42")
    phone.claim_handle(mom.person_id, "car:driver-1")
    claim = phone.export_claim(mom.person_id)

    # Device B (robot) has never seen her — imports the signed claim.
    robot = PersonRegistry(tmp_path / "robot")
    assert robot.resolve_handle("car:driver-1") is None       # unknown before
    recognized = robot.import_claim(claim)
    assert recognized.person_id == mom.person_id              # same human
    assert recognized.fingerprint == mom.fingerprint
    assert robot.resolve_handle("car:driver-1").person_id == mom.person_id

    # The robot recognizes her but holds no private key (cannot re-issue claims).
    with pytest.raises(mirra.IdentityError):
        robot.export_claim(mom.person_id)


def test_unverifiable_claim_refused_on_import(sdk_home, tmp_path):
    phone = PersonRegistry(tmp_path / "phone")
    mom = phone.create_person(display_name="Mom")
    claim = phone.export_claim(mom.person_id)
    tampered = PersonClaim.from_dict({**claim.to_dict(), "display_name": "Imposter"})

    robot = PersonRegistry(tmp_path / "robot")
    with pytest.raises(mirra.IdentityError):
        robot.import_claim(tampered)          # fail-closed


def test_shared_history_across_handles(sdk_home, monkeypatch):
    """The payoff: memory written under one of a person's handles is recalled
    under another — one relationship history, any device."""
    monkeypatch.setenv("QSEAL_SECRET", "test-secret-for-person")
    home = sdk_home
    reg = PersonRegistry(home)
    mom = reg.create_person(display_name="Mom")
    reg.claim_handle(mom.person_id, "car:driver-1")
    reg.claim_handle(mom.person_id, "robot:mom")

    agent = mirra.wrap(lambda m, c: "ok", principal="family-hub", home=str(home),
                       profile="dev_balanced", persons=reg)

    # Car remembers something about her.
    agent.remember("car:driver-1", "dropping the kids at school, running late")
    # Robot recalls it — different handle, same person, same signed history.
    recalled = [str(s.content) for s in agent.recall("robot:mom")]
    assert any("dropping the kids" in c for c in recalled)


def test_unclaimed_handle_is_backward_compatible(sdk_home, monkeypatch):
    """A handle not claimed into any person behaves exactly as before: its own
    silo, unaffected by the person layer."""
    monkeypatch.setenv("QSEAL_SECRET", "test-secret-for-person")
    reg = PersonRegistry(sdk_home)
    agent = mirra.wrap(lambda m, c: "ok", principal="hub", home=str(sdk_home),
                       profile="dev_balanced", persons=reg)
    agent.remember("random-user", "a private note")
    assert any("private note" in str(s.content) for s in agent.recall("random-user"))
    # A different unclaimed handle does not see it.
    assert agent.recall("other-user") == []


def test_context_surfaces_person(sdk_home, monkeypatch):
    monkeypatch.setenv("QSEAL_SECRET", "test-secret-for-person")
    reg = PersonRegistry(sdk_home)
    mom = reg.create_person(display_name="Mom")
    reg.claim_handle(mom.person_id, "car:driver-1")
    agent = mirra.wrap(lambda m, c: "ok", principal="hub", home=str(sdk_home),
                       profile="dev_balanced", persons=reg)
    ctx = agent.build_context("car:driver-1")
    assert ctx["person_id"] == mom.person_id
    assert ctx["person_name"] == "Mom"
    # unknown handle -> no person, still works
    assert agent.build_context("stranger")["person_id"] is None


def test_recognize_persons_flag_creates_registry(sdk_home, monkeypatch):
    monkeypatch.setenv("QSEAL_SECRET", "test-secret-for-person")
    agent = mirra.wrap(lambda m, c: "ok", principal="hub", home=str(sdk_home),
                       profile="dev_balanced", recognize_persons=True)
    assert agent._persons is not None
