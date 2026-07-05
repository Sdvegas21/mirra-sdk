# North Star — the undeniable system

**What it is when it's undeniable:** any agent, on any framework, on any device,
gets a recognized identity, tamper-evident memory it carries between vendors, and
execution that can't happen unverified — in **one line**, with the safe default
being the default. Not a product you evaluate; a thing you `pip install` and it
just works, and the security is on whether you configured it or not.

This document is the direction, not a task list. It says where the pieces point.

---

## The one line (the whole thesis, compressed)

```python
import mirra
agent = mirra.guard()
```

Everything below is in service of making that line mean more without making it
harder. The measure of progress is: *how much does a developer get for that one
line, and how little do they have to think.* OpenClaw's lesson is that adoption
follows ease, not features. The counter-lesson we hold is that ease must not cost
safety — so the default is fail-closed, and a hostile action is blocked before
the developer writes a second line.

## The four pillars (the yardstick)

Every change is judged by whether it advances one of these. Nothing ships that
doesn't.

1. **Recognition** — the agent knows *who* it's dealing with, across sessions and
   across devices. (`guard()` identity; `Person` cross-device claims.)
2. **History** — a tamper-evident, portable record of the relationship, that the
   *user* can carry between vendors. (Signed scrolls; `SCROLL_FORMAT.md`.)
3. **Differentiated interaction** — behavior shaped by *this* relationship's
   verified history, not a generic prompt. (Per-subject/per-person context.)
4. **Provable-safety** — nothing privileged happens without a verifiable,
   deterministic decision. (MVAR enforcement; Ed25519 witnesses.)

## What is already true (verified, on PyPI)

- `mirra.guard()` — one-line identity + signed memory + enforcement, hostile
  action blocked out of the box by **payload**, not tool name.
- Four framework adapters (LangChain, LlamaIndex, OpenAI Agents, CrewAI), each
  verified against the real library; all emit and verify the same scroll format.
- `Person` — the same human recognized across device handles via signed claims,
  one portable relationship history; fail-closed on tampered claims.
- `SCROLL_FORMAT.md` — the signed-memory format as an open spec with a 30-line
  framework-free reference verifier that validates real SDK scrolls.
- Three edges (SDK, gateway, on-device) over one frozen contract; a scroll signed
  on a stdlib device verifies on the server.

## Where it points next (in priority order, each downstream of a design partner)

**1. The scroll standard becomes real interop (the wedge that survives platforms).**
Publish `SCROLL_FORMAT.md` as a named spec. Get *one* other framework or tool to
emit a scroll another can verify. The moment a memory written by someone else's
agent verifies under ours (and vice versa), we're the interop layer, not a
competitor — the position OpenAI/Google shipping "good-enough memory" can't take,
because portable + signed + cross-vendor is the part they won't build.

**2. The person primitive becomes the "portable soul" product.**
A user owns their person key. Any AI they talk to — Claude, GPT, a local model,
a robot — can be granted scoped, signed access to their relationship history. The
user carries it between vendors; *the user holds the keys*, so it's
private-by-construction. This is the direct answer to "who owns my AI's memory of
me," and it's the consumer face of the car/robot/watch vision: the same human,
recognized, across everything, with proof.

**3. The regulated beachhead (own the 20% where "good enough" is illegal).**
Finance, healthcare, legal, eldercare, child-facing AI: cryptographic provenance
of every agent action isn't a feature there, it's a compliance requirement.
MVAR DecisionRecords + the scroll chain are a ready-made audit trail for the EU
AI Act / SOC2 / HIPAA conversation. "The compliance layer for agentic AI."

**4. Signed provenance for the agent-tool supply chain.**
Agent skill/tool marketplaces have no provenance layer (the OpenClaw CVE, 1,184
malicious skills, generalizes). Witnesses + SARIF already turn every tool call
into a signed, code-scanning-compatible record. Extend upstream: sign the skill
at publish, verify signature + capability manifest at install. "sigstore for
agent skills."

**5. On-device / the portable soul made literal.**
The device edge already signs wire-compatible scrolls. The remaining work is the
cross-device sync protocol and decoupling the private research substrate from its
sibling-path import (the one blocker for independent deploy). This is the
"robots that grow with you" story, ~70% built.

## The discipline that keeps it undeniable

- **Verify from the outside.** Every claim a stranger will test, we test the same
  way — from a clean `pip install`, not from the dev tree. Two real security bugs
  were caught this way that unit tests missed. This is non-negotiable.
- **Fail-closed, always.** No engine → block. No secret → refuse to sign. Tampered
  → verify=false. A regenerated key is a *different* identity. Ease never buys
  its convenience with a silent unsafe default.
- **Ship the truth.** The demo refuses to run on stale code rather than show a
  false green. Claims map to tests. No self-assigned valuations. The reproducible
  number does more than the impressive adjective.
- **One framework, all the way, before the next.** Depth that provably works beats
  breadth that half-works. That's how the graveyard is avoided.

## The one thing this document cannot do

It cannot be the reason not to send the email. The system is undeniable to the
degree a stranger can reproduce it — and they can, today, in one line. The next
move that matters is not in this file. It's in an outbox.
