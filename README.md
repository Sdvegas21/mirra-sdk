# mirra-sdk

**One wrapper call gives any agent a persistent recognized identity, tamper-evident
portable memory of its relationships, behavior that adapts per relationship, and
execution that only happens when verified.**

```python
import mirra

wrapped = mirra.wrap(my_agent, principal="team-key-1")

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

## Fail-closed by design

- No enforcement engine → every action is **blocked**, never silently allowed.
- No memory backend → `wrap()` **raises**, never runs with unsigned memory.
- Damaged identity keystore → **raises**, never silently mints a new identity.
- Tampered scroll or forged decision record → **fails verification**.

## Demo

```bash
python demo/demo_sdk.py     # run twice — the second run proves recognition
```

See `DEMO.md` for the five-minute walkthrough.

## Tests

```bash
python -m pytest tests/ -q
```

The suite is organized by acceptance criterion: `test_recognition.py`,
`test_signed_memory.py`, `test_differentiated_behavior.py`,
`test_permissioned_execution.py`, `test_boundary.py` (public/private leak gate).
