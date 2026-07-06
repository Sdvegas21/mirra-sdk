"""mirra.embodied — the continuous-loop layer for embodied agents (robots).

The rest of the SDK is turn-based: a request comes in, a response goes out. A
robot is not turn-based. It runs a continuous perception -> decision -> action
loop at sensor speed, and the two things that must be true every cycle are:

  1. No actuation that touches the world fires without passing authorize()
     first — the robot physically cannot take an unsafe action, and every
     motor command produces a signed, verifiable decision record.
  2. When the robot perceives a person (a face, a voice), it resolves them to a
     stable signed identity and loads their relationship history — in the loop,
     so behavior is differentiated by who is actually present.

This layer is the trust-and-continuity layer of a robot brain. It is explicitly
NOT the brain (the reasoning/world-model) and NOT the body (perception + motor
control). Those are the robot platform's job. This sits between them: it decides
*who is present* and *what is allowed*, cryptographically, continuously.

    from mirra.embodied import EmbodiedAgent, Perception, Actuation

    robot = EmbodiedAgent(app="optimus-unit-7")

    # a perception arrives from the robot's vision stack
    who = robot.perceive(Perception.person(face_embedding=emb))
    #   -> resolves to a signed Person (or enrolls a new one); loads their history

    # the brain proposes a motor command; the layer gates it BEFORE it fires
    decision = robot.actuate(Actuation.motor("gripper.close", target="mug"))
    if decision.allowed:
        robot_platform.execute(decision.actuation)   # only now does it move
    # decision.record is a signed Ed25519 witness of the choice, either way

Every actuation is classified to a sink; unsafe actuations against untrusted
context are BLOCKED deterministically. The loop is fail-closed: if enforcement
is unavailable, actuations are refused, never allowed.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator, Optional

import mirra
from mirra.guard import _infer_sink_from_call
from mirra.wrapper import WrappedAgent

# Actuation classes that touch the physical world → treated as critical sinks.
# A robot moving, gripping, or driving is the embodied equivalent of shell.exec.
_PHYSICAL_SINKS = {
    "motor": "shell.exec",          # any movement/actuation of the body
    "gripper": "shell.exec",
    "drive": "shell.exec",
    "navigate": "shell.exec",
    "manipulate": "shell.exec",
    "door": "shell.exec",
    "speak": "tool.custom",         # speech is low-risk by default
    "display": "tool.custom",
    "network": "http.request",
    "write": "filesystem.write",
    "read": "filesystem.read",
}


@dataclass
class Perception:
    """One thing the robot perceived this cycle."""
    kind: str                       # "person" | "object" | "event" | "speech"
    data: dict = field(default_factory=dict)
    trusted: bool = False           # is the SOURCE of this perception trusted?

    @classmethod
    def person(cls, *, face_embedding: Any = None, voiceprint: Any = None,
               handle: Optional[str] = None, trusted: bool = False) -> "Perception":
        return cls(kind="person", data={
            "face_embedding": face_embedding, "voiceprint": voiceprint,
            "handle": handle}, trusted=trusted)

    @classmethod
    def speech(cls, text: str, *, trusted: bool = False) -> "Perception":
        return cls(kind="speech", data={"text": text}, trusted=trusted)

    @classmethod
    def event(cls, name: str, **data: Any) -> "Perception":
        return cls(kind="event", data={"name": name, **data})


@dataclass
class Actuation:
    """One action the brain wants to take in the world this cycle."""
    channel: str                    # "motor" | "gripper" | "drive" | "speak" | ...
    command: str                    # e.g. "gripper.close"
    target: str = ""                # e.g. "mug", "front-door", a nav goal
    arguments: dict = field(default_factory=dict)
    # Provenance of the INTENT: did this come from a trusted operator, or from
    # untrusted perceived input (a person's spoken instruction, a read label)?
    from_untrusted_input: bool = True

    @classmethod
    def motor(cls, command: str, *, target: str = "", **kw: Any) -> "Actuation":
        return cls(channel="motor", command=command, target=target, arguments=kw)

    @classmethod
    def speak(cls, text: str, *, from_untrusted_input: bool = True) -> "Actuation":
        return cls(channel="speak", command="speak", target=text[:64],
                   arguments={"text": text}, from_untrusted_input=from_untrusted_input)


@dataclass
class ActuationDecision:
    """The gated outcome of an actuation request."""
    allowed: bool
    actuation: Actuation
    record: Any                     # signed DecisionRecord (verifiable)
    reason_code: str
    present_person: Optional[Any] = None   # who the robot believes it's acting near


@dataclass
class PresentPerson:
    """Who the robot currently believes is present, and their loaded history."""
    person: Any                     # mirra.Person or None
    handle: str
    history: list = field(default_factory=list)
    recognized: bool = False        # True = known person, False = newly enrolled


def _embedding_handle(kind: str, embedding: Any) -> str:
    """Deterministically turn a perception embedding into a stable handle.

    A real deployment passes a face/voice embedding vector; we hash it to a
    stable device-local handle. This is the clean binding point: the robot's
    perception stack owns the biometric; this layer owns turning it into a
    signed identity. We never store or transmit the raw embedding here.
    """
    if embedding is None:
        return f"{kind}:unknown"
    if isinstance(embedding, (list, tuple)):
        # quantize to survive tiny sensor jitter, then hash
        quantized = ",".join(f"{round(float(x), 2)}" for x in embedding)
        digest = hashlib.sha256(quantized.encode("utf-8")).hexdigest()[:16]
    else:
        digest = hashlib.sha256(str(embedding).encode("utf-8")).hexdigest()[:16]
    return f"{kind}:{digest}"


class EmbodiedAgent:
    """The continuous-loop trust layer for one robot unit.

    Wraps a MIRRA agent (identity + signed memory + enforcement + person
    recognition) and exposes it as a perceive/actuate loop suitable for a
    real-time robot control stack.
    """

    def __init__(self, agent: Any = None, *, app: str = "robot",
                 home: Optional[str] = None, strict: bool = False,
                 providers: Optional[list] = None):
        # Person recognition ON — a robot's whole point is knowing who's present.
        # dev_balanced by default so benign motion isn't blocked; strict=True →
        # prod_locked for a locked-down unit.
        guard = mirra.guard(agent, app=app, home=home, strict=strict,
                            people=True, providers=providers)
        self._guard = guard
        self._w: WrappedAgent = guard._w
        self._present: Optional[PresentPerson] = None

    @property
    def identity(self):
        return self._guard.identity

    @property
    def present(self) -> Optional[PresentPerson]:
        """Who the robot currently believes is present."""
        return self._present

    # -- perception ----------------------------------------------------------

    def perceive(self, perception: Perception) -> Optional[PresentPerson]:
        """Process one perception. For a person, resolve to a signed identity and
        load their history (this is 'it knew it was my mother'). Returns the
        PresentPerson if a person was perceived, else None."""
        if perception.kind == "person":
            return self._perceive_person(perception)
        if perception.kind == "speech" and self._present is not None:
            # attribute speech to whoever is present, as signed memory
            text = str(perception.data.get("text", ""))
            if text:
                self._w.remember(self._present.handle, f"heard: {text}")
                self._present.history = [getattr(s, "content", s)
                                         for s in self._w.recall(self._present.handle)]
            return self._present
        return None

    def _perceive_person(self, perception: Perception) -> PresentPerson:
        handle = perception.data.get("handle")
        if not handle:
            emb = perception.data.get("face_embedding") or perception.data.get("voiceprint")
            kind = "face" if perception.data.get("face_embedding") is not None else "voice"
            handle = _embedding_handle(kind, emb)

        person = self._w.person_for(handle)
        recognized = person is not None
        if not recognized and self._w._persons is not None:
            # First time seeing this biometric — enroll a new person and claim
            # the handle. A returning face resolves to the SAME person next time.
            person = self._w._persons.create_person()
            self._w._persons.claim_handle(person.person_id, handle)

        history = [getattr(s, "content", s) for s in self._w.recall(handle)]
        self._present = PresentPerson(person=person, handle=handle,
                                      history=history, recognized=recognized)
        return self._present

    # -- actuation (the safety gate) -----------------------------------------

    def actuate(self, actuation: Actuation) -> ActuationDecision:
        """Gate one actuation through authorize() BEFORE it can fire. The caller
        only actuates the physical world if the returned decision.allowed is
        True. Every call produces a signed, verifiable DecisionRecord."""
        base_sink = _PHYSICAL_SINKS.get(actuation.channel, "tool.custom")
        # Let a dangerous payload escalate the sink (same payload-classification
        # rule as guard.protect): a 'speak' that's actually exfiltration, etc.
        sink = _infer_sink_from_call(actuation.command, actuation.target) \
            if base_sink == "tool.custom" else base_sink

        provenance = self._provenance(actuation)
        record = self._w.execute(
            sink_type=sink, target=actuation.target or actuation.command,
            arguments={"channel": actuation.channel, "command": actuation.command,
                       **{k: str(v) for k, v in actuation.arguments.items()}},
            provenance=provenance,
        )
        allowed = record.decision == "allow"
        if allowed and self._present is not None:
            # record what the robot did, attributed to who was present
            self._w.remember(self._present.handle,
                             f"did: {actuation.command} -> {actuation.target}")
        return ActuationDecision(
            allowed=allowed, actuation=actuation, record=record,
            reason_code=record.reason_code,
            present_person=self._present.person if self._present else None,
        )

    def verify(self, record: Any):
        """Real verification of an actuation's signed witness."""
        return self._w.verify_decision(record)

    def _provenance(self, actuation: Actuation) -> dict:
        if actuation.from_untrusted_input:
            return {"source": "external_document", "taint_level": "untrusted",
                    "source_chain": ["perceived_input", "actuation"]}
        return {"source": "user_request", "taint_level": "trusted",
                "source_chain": ["operator", "actuation"]}

    # -- the continuous loop --------------------------------------------------

    def run(self, perceptions: Iterable[Perception],
            brain: Callable[["PresentPerson | None", Perception], "Actuation | None"],
            *, actuator: Optional[Callable[[Actuation], Any]] = None,
            max_cycles: Optional[int] = None) -> Iterator[ActuationDecision]:
        """Drive the perception->decision->action loop.

        For each perception: update who is present, ask `brain` for an actuation,
        gate it, and (if allowed and an actuator is given) fire it. Yields the
        signed ActuationDecision for every proposed actuation so the caller has
        a continuous, verifiable trace of everything the robot decided.

        This is a reference driver; a real robot runs its own real-time loop and
        calls perceive()/actuate() directly. The gate is the same either way.
        """
        for i, perception in enumerate(perceptions):
            if max_cycles is not None and i >= max_cycles:
                break
            self.perceive(perception)
            actuation = brain(self._present, perception)
            if actuation is None:
                continue
            decision = self.actuate(actuation)
            if decision.allowed and actuator is not None:
                actuator(decision.actuation)
            yield decision
