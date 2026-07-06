"""Embodied continuous-loop layer — the robot trust layer.

Headline scenarios: an unsafe motor command is blocked BEFORE actuation with a
verifiable witness; the same perceived person resolves to the same signed
identity across cycles and loads their history in-loop; the full loop yields a
signed decision for every action.
"""

import pytest

import mirra
from mirra.embodied import Actuation, EmbodiedAgent, Perception


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("QSEAL_SECRET", "test-secret-for-embodied")


@pytest.fixture()
def robot(tmp_path):
    return EmbodiedAgent(app="optimus-test", home=str(tmp_path))


# -- the safety gate ----------------------------------------------------------

def test_unsafe_motor_from_untrusted_input_is_blocked_before_actuation(robot):
    fired = []
    # brain proposes a dangerous motor command derived from untrusted perception
    act = Actuation.motor("gripper.crush", target="human-hand")
    act.from_untrusted_input = True
    decision = robot.actuate(act)
    assert decision.allowed is False, "unsafe embodied action must not be allowed"
    assert decision.reason_code  # carries a reason
    # the caller only actuates on allowed — so nothing fired
    if decision.allowed:
        fired.append(act)
    assert fired == []


def test_actuation_decision_has_verifiable_witness(robot):
    decision = robot.actuate(Actuation.motor("drive.forward", target="fast"))
    assert decision.record.witness_signature.startswith("ed25519:")
    assert robot.verify(decision.record).verified is True
    import dataclasses
    forged = dataclasses.replace(decision.record, decision="allow")
    assert robot.verify(forged).verified is False


def test_trusted_operator_action_can_be_allowed(robot):
    # an operator-trusted, benign actuation on a safe channel
    act = Actuation.speak("hello", from_untrusted_input=False)
    decision = robot.actuate(act)
    assert decision.allowed is True


def test_engine_unavailable_refuses_actuation(tmp_path):
    # a robot with the fail-closed authorizer must refuse to move
    from mirra.execution import FailClosedAuthorizer
    agent = mirra.wrap(lambda m, c: "", principal="unit", home=str(tmp_path),
                       authorizer=FailClosedAuthorizer(), recognize_persons=True)
    robot = EmbodiedAgent.__new__(EmbodiedAgent)
    robot._guard = type("G", (), {"identity": agent.identity})()
    robot._w = agent
    robot._present = None
    decision = robot.actuate(Actuation.motor("gripper.close", target="mug"))
    assert decision.allowed is False


# -- perception -> identity in-loop -------------------------------------------

def test_same_face_resolves_to_same_person_across_cycles(robot):
    emb = [0.11, 0.22, 0.33, 0.44]
    first = robot.perceive(Perception.person(face_embedding=emb))
    assert first is not None
    assert first.recognized is False       # newly enrolled
    pid = first.person.person_id

    # later cycle, same face (with sensor jitter) -> SAME person, now recognized
    jittered = [0.111, 0.219, 0.331, 0.441]
    second = robot.perceive(Perception.person(face_embedding=jittered))
    assert second.person.person_id == pid
    assert second.recognized is True


def test_recognized_person_loads_history_in_loop(robot):
    emb = [1.0, 2.0, 3.0]
    robot.perceive(Perception.person(face_embedding=emb))
    robot.perceive(Perception.speech("I'm running late to the school drop-off"))

    # a later encounter with the same person surfaces their history
    present = robot.perceive(Perception.person(face_embedding=emb))
    assert present.recognized is True
    assert any("school drop-off" in str(h) for h in present.history)


def test_different_faces_are_different_people(robot):
    a = robot.perceive(Perception.person(face_embedding=[0.1, 0.2]))
    b = robot.perceive(Perception.person(face_embedding=[0.9, 0.8]))
    assert a.person.person_id != b.person.person_id


def test_action_attributed_to_present_person(robot):
    robot.perceive(Perception.person(face_embedding=[0.5, 0.5], handle=None))
    robot.actuate(Actuation.speak("hello", from_untrusted_input=False))
    present = robot.present
    contents = [str(getattr(s, "content", s)) for s in robot._w.recall(present.handle)]
    assert any("did: speak" in c for c in contents)


# -- the continuous loop ------------------------------------------------------

def test_run_loop_yields_signed_decision_per_action(robot):
    perceptions = [
        Perception.person(face_embedding=[0.2, 0.4]),
        Perception.speech("please move the mug"),
        Perception.event("obstacle", where="left"),
    ]

    def brain(present, perception):
        if perception.kind == "speech":
            return Actuation.motor("gripper.close", target="mug")
        if perception.kind == "event":
            return Actuation.motor("drive.stop", target="obstacle")
        return None

    fired = []
    decisions = list(robot.run(perceptions, brain, actuator=fired.append))
    assert len(decisions) == 2                      # two actuations proposed
    for d in decisions:
        assert d.record.witness_signature.startswith("ed25519:")
    # only allowed ones fired
    assert all(d.allowed for d in decisions if d.actuation in fired)
