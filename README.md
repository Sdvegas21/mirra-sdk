# mirra-sdk

**One wrapper call gives any agent a persistent recognized identity, tamper-evident
portable memory of its relationships, behavior that adapts per relationship, and
execution that only happens when verified.**

```python
import mirra

wrapped = mirra.wrap(my_agent, principal="team-key-1", profile="dev_balanced")

wrapped.identity                     # recognized across sessions, not met fresh
wrapped.remember("alice", "…")       # signed scroll — verify-on-read, fail-closed
wrapped.recall("alice")              # only cryptographically verified memories
wrapped.interact("alice", "hi")      # context built from alice's own history
wrapped.execute("shell.exec", "…")   # deterministic, signed decision record
```

This is **Edge 1 (the SDK)** of the MIRRA platform's one-core/three-edges
architecture. The SDK speaks only the frozen v1 core contract
(`mirra-core-contract`); the enforcement engine (MVAR via ClawZero) and the
signed memory store (ClawSeal) plug in beneath it, and optional capability
providers can be injected at runtime for identity enrichment and epistemic
verification.

## The four pillars

| Pillar | API | Guarantee |
|---|---|---|
| Recognition | `wrapped.identity` | Same principal → same identity + fingerprint across sessions; keys generated on first run, never stored in a repo |
| Portable signed memory | `remember` / `recall` / `verify` | Sign-on-write, verify-on-read; tampered memories are dropped, never returned |
| Per-relationship behavior | `interact` / `build_context` | The agent sees each subject's own verified history |
| Permissioned execution | `execute` / `protect_tool` | Deterministic allow/block with an Ed25519-signed witness; forged records fail verification; no engine → refuse |

**Profiles:** build against `dev_balanced` (safe actions allow, hostile ones
block, risky ones step up). The default is `prod_locked` — the fail-closed
production posture where every action is refused unless the caller supplies
risk context or step-up approval. If you omit `profile` and everything blocks,
that is the lockdown working as designed.

## LangChain (whole-agent, not just tools)

Existing security adapters wrap individual *tools*. This wraps the whole
*agent* — identity, signed memory, per-user context, and enforcement — in
LangChain's own idioms:

```python
pip install "mirra-sdk[langchain]" mvar-security clawzero clawseal
```

```python
from mirra.adapters.langchain import wrap_agent, MirraChatMessageHistory

# per-user signed chat history (verify-on-read), for RunnableWithMessageHistory
history = MirraChatMessageHistory(principal="acme", subject_id="alice")

# or bind a whole chain: each .invoke resolves that subject's verified history,
# hands it to the chain, and records the exchange as a new signed scroll
bound = wrap_agent(my_chain, principal="acme")
bound.invoke("what did we discuss?", subject_id="alice")
safe_tool = bound.protect_tool(shell_tool, sink="shell.exec")   # reuses ClawZero
```

`MirraChatMessageHistory` is a real `BaseChatMessageHistory`, so it drops into
`RunnableWithMessageHistory` (and anywhere a chat-history store is accepted).
The adapter never imports LangChain at module load — only when you use it.

## Fail-closed by design

- No enforcement engine → every action is **blocked**, never silently allowed.
- No memory backend → `wrap()` **raises**, never runs with unsigned memory.
- Damaged identity keystore → **raises**, never silently mints a new identity.
- Tampered scroll or forged decision record → **fails verification**.

## Demo

Installed (pip):

```bash
mirra-demo                   # live 5-check report; run twice — the second run proves recognition
```

From a checkout:

```bash
python3 demo/demo_sdk.py     # narrative version of the same proof
```

See `DEMO.md` for the five-minute walkthrough.

## Tests

```bash
python3 -m pytest tests/ -q
```

The suite is organized by acceptance criterion: `test_recognition.py`,
`test_signed_memory.py`, `test_differentiated_behavior.py`,
`test_permissioned_execution.py`, `test_boundary.py` (public/private leak gate).
