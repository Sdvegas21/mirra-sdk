# mirra-mcp scope model — who decides which subject a session can touch

`ScopedMemory` enforces per-subject isolation perfectly *given* a subject
binding. This document answers the question a sharp reviewer asks next: **who
sets that binding, and can the connected agent forge or change it?** Getting this
wrong makes the isolation theater — an adversarial agent that can declare "I'm
scoped to alice" reads alice's history regardless of how good the scoping is.

## v1 decision: config-fixed scope (the only mode)

**The subject a session is bound to is read from server configuration at launch,
never from a tool argument or any agent-supplied value.** One running
`mirra-mcp` server instance is bound to exactly one subject, set in the config
block the user pastes into their MCP client:

```json
{
  "mcpServers": {
    "mirra-alice": {
      "command": "python", "args": ["-m", "mirra_mcp"],
      "env": { "QSEAL_SECRET": "…", "MIRRA_SUBJECT": "alice" }
    }
  }
}
```

There is **no tool, parameter, or code path** by which the connected agent can
change, override, or enumerate any subject other than its bound one. The agent
cannot express a different subject because no tool accepts one — isolation by
construction, not by validation.

Want memory for two people? Run two server instances with two `MIRRA_SUBJECT`
values. That's deliberate: the user, not the agent, decides the subjects.

### Why not "let the agent request a subject with a token" (v2, not built)

A dynamic model — the agent presents a capability token that binds the session
to a subject — is more flexible and has a much larger attack surface (it's only
as strong as token issuance). We are **not** building it speculatively. If a real
multi-subject-per-session need appears, that's a v2 spec with its own threat
model. Shipping the flexible one first would be the build-forever trap wearing a
security hat.

## What config-fixed scope protects against

- **A confused or adversarial agent reading the wrong person's history.** The
  agent has no way to name a subject. It can only `remember`/`recall` for the
  one subject the config pinned. Declaring "I'm alice" is impossible — there's no
  field to declare it in.
- **Silent scope drift.** The binding is set once at launch and cannot change
  mid-session.
- **Enumeration / discovery.** No tool lists subjects, lists scrolls across
  subjects, or reveals whether other subjects exist. The agent cannot learn what
  else is in the store.
- **Fail-open on misconfiguration.** With no `MIRRA_SUBJECT` set, the server
  refuses to start (same posture as a missing signing secret) — it never
  defaults to an ambiguous or "all subjects" scope.

## What it explicitly does NOT protect against (stated plainly, on purpose)

Config-fixed scope **trusts whoever wrote the config**. This is correct and
safe — the user chose the subject when they pasted the config block — but it
means the trust boundary is exactly the local machine:

- **It does not protect against an attacker who can edit the MCP config or the
  machine's environment.** Anyone who can change `MIRRA_SUBJECT` can rebind the
  scope. That is the same trust boundary as any local credential or config file;
  we do not claim to solve physical-machine security, and pretending to would be
  an overclaim.
- **It does not authenticate the *human* on the other side of the AI.** It binds
  a session to a subject the config named; it does not verify that the person
  talking to the agent *is* that subject. Person recognition (voice/face → signed
  Person) is a separate SDK capability; wiring it to the MCP scope binding is a
  future layer, not a v1 claim.
- **It does not protect memories at rest from someone with filesystem access.**
  Scrolls are integrity-protected (tamper-evident), not confidential — content is
  plaintext by design. A reader with disk access can read them; they just can't
  alter them without detection.

The honest one-line summary: **the subject scope is fixed by the user's config,
enforced so the agent cannot change or discover it; the remaining assumption is
that the machine running the client is the legitimate user's machine — the same
assumption as any locally-stored credential.**

## Guarantees, and their committed guards

Each is a failable regression test (`tests/test_mcp_scope_auth.py`), proven to
break the build if the guarantee regresses:

1. **No tool accepts a subject.** Every registered MCP tool's signature is free
   of any `subject`/`subject_id`/`user` parameter. Adding one turns the guard red.
2. **Scope comes only from config.** The server refuses to start with no
   `MIRRA_SUBJECT`; a server bound to `alice` can only ever touch `alice`.
3. **No enumeration.** No tool lists subjects, lists cross-subject scrolls, or
   reveals other subjects' existence.
