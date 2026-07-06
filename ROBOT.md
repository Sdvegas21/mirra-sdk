# mirra.embodied — the trust layer for robots

**What it is:** the continuous-loop layer that sits between a robot's *brain*
(reasoning / world-model) and its *body* (perception + motor control), and makes
two things true every cycle:

1. **No action that touches the world fires without being authorized first** —
   the robot physically cannot take an unsafe action, and every motor command
   produces a signed, verifiable decision record.
2. **When the robot perceives a person, it resolves them to a stable signed
   identity and loads their relationship history** — so it recognizes who is
   present and behaves accordingly, across a continuous session, without anyone
   announcing who they are.

```python
from mirra.embodied import EmbodiedAgent, Perception, Actuation

robot = EmbodiedAgent(app="unit-7")

# perception arrives from the robot's vision/audio stack
present = robot.perceive(Perception.person(voiceprint=embedding))
#   -> same voice next time = same signed Person; their history is loaded

# the brain proposes a motor command; it is gated BEFORE it can fire
decision = robot.actuate(Actuation.motor("gripper.close", target="mug"))
if decision.allowed:
    robot_platform.execute(decision.actuation)   # only now does it move
# decision.record is a signed Ed25519 witness — verifiable either way
```

## The scene it makes real

Same device, one continuous session, nobody says who they are:

- Shawn speaks → new person enrolled, his turn saved (signed)
- Todd speaks → different voiceprint → different person
- Shawn speaks again → **recognized**, his prior history loaded
- Jill speaks → new person
- Todd again → **recognized**, his history loaded

Each person's memory is separate and every memory verifies cryptographically. No
"this is Todd" step. It knew.

## What it is NOT (read this before pitching it)

This layer is deliberately **not** the parts a robot platform already owns and is
best at:

- **Not the brain.** It does not reason, plan, or generate language. You wrap an
  LLM / world-model; this gates and remembers around it.
- **Not the body.** It does not do vision, audio, or motor control. The robot's
  perception stack produces the face/voice *embedding*; this layer turns that
  embedding into a signed identity. It never sees raw sensors.
- **Not "sentience."** It provides cryptographic *recognition, continuity, and
  provable safety* — the trust layer of an embodied agent. It does not claim
  awareness, and a pitch that does will fail the first technical question.

The honest one-line claim: **"it makes a robot recognize and remember the people
it lives with, and physically unable to take an action it shouldn't — with
cryptographic proof of every decision."** That is demonstrable today.

## How it composes

`EmbodiedAgent` wraps the same core as the rest of the SDK — identity, signed
memory (the portable scroll format), MVAR enforcement, and `Person` recognition
— and exposes it as `perceive()` / `actuate()` for a real-time control loop. An
actuation is classified to a sink (a motor command is a critical sink, like
`shell.exec`); unsafe actuations against untrusted perceived input are BLOCKED
deterministically and fail-closed (no engine → refuse to move).

The perceived person is bound by hashing the embedding to a stable handle (with
quantization so sensor jitter still resolves to the same person). The raw
biometric is never stored or transmitted by this layer — the robot's perception
stack owns it; this layer owns the signed identity it maps to.

## The gaps to a full on-device deployment (honest)

- **Cross-device sync** — a person recognized on the robot should be the same
  signed person on the phone and the car. The `Person` claim format supports
  this; the sync protocol is the remaining build.
- **Embedded packaging** — running with no network, resource-bounded. The device
  edge (`mirra_device`) already signs wire-compatible scrolls; finishing this is
  the path to on-robot deployment.

Neither blocks the demo above, which runs today on `pip install mirra-sdk`.
