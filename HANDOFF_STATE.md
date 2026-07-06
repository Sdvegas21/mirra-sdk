# HANDOFF_STATE.md — where the MIRRA platform actually stands

**Read this file first.** It is the single honest snapshot of the platform for a
fresh session. Everything below is verified against disk, PyPI, and git as of the
last update — not from memory. Dates are absolute.

**Last updated:** 2026-07-06

---

## 0. One-paragraph truth

MIRRA is a signed identity + portable memory + provable-safe-execution layer any
AI agent plugs into. It is **shipped and reproducible from a clean `pip install`**
across five delivery surfaces (SDK, four framework adapters, robot loop, live
website playground, and an MCP server). Every security property has a **committed
test guard that has been proven to fail by injecting the exact bug it guards
against** — that "proven to bite" discipline is the reason the trust story
survives a sharp reviewer. The remaining work is not more building: it is
outreach (the demo has never been shown to the people who'd use it), plus a few
deliberately-deferred engineering items listed in §5.

---

## 1. What's shipped and reproducible from a clean install

All live on PyPI. A stranger reproduces every claim below with `pip install`.

```bash
pip install mirra-sdk mvar-security clawzero clawseal      # the platform
mirra-demo                                                 # 6/6 PASS report
```

| Surface | What it is | Entry point | Proof |
|---|---|---|---|
| **SDK / `guard()`** | One line: stable identity + signed memory + enforcement; hostile action blocked out of the box (by payload, not tool name) | `mirra.guard()` | `mirra-demo` → 6/6; `tests/test_guard.py` |
| **Framework adapters** | Whole-agent (identity + signed memory + enforcement) in each framework's own idioms; all emit/verify the same scroll format | `mirra.adapters.{langchain,llamaindex,openai_agents,crewai}` | verified against each real lib; `tests/test_*adapter*.py`, `test_adapters_import_guard.py` |
| **Robot / embodied loop** | Continuous perceive→decide→act: recognize a person by voice/face embedding, gate every motor command before it fires | `mirra.embodied.EmbodiedAgent` | `tests/test_embodied.py`; ROBOT.md |
| **Person recognition** | Same human across devices/handles via signed claims; one portable relationship history | `mirra.PersonRegistry` | `tests/test_person_recognition.py` |
| **Live website + playground** | Landing page with a real in-browser HMAC-SHA256 demo (recognize → sign → tamper→fail). Byte-identical signatures to the Python SDK (verified). | `site/index.html` → https://sdvegas21.github.io/mirra-sdk/ (HTTP 200) | GitHub Pages via `.github/workflows/pages.yml` |
| **mirra-mcp** | Signed memory for any MCP-speaking AI (Claude Desktop, Cursor, Claude Code) via one config block; config-fixed scope | `pip install "mirra-sdk[mcp]"` → `python -m mirra_mcp` | MCP.md, SCOPE_MODEL.md; `tests/test_mcp_*.py` |

Repos: `github.com/Sdvegas21/mirra-sdk` (this) · `github.com/Sdvegas21/mirra-core-contract` (frozen v1 contract + SCROLL_FORMAT.md).

---

## 2. Security properties → the committed guard for each

Every row has a test that **fails the build** if the property regresses, and each
was **proven to bite by injecting the exact breach** (documented in commit
messages). This is the standard: a guard you have watched fail in the way an
attacker would exploit, not one that merely passes.

| Property | What it guarantees | Guard test | Proven-to-bite breach |
|---|---|---|---|
| **Verify-on-read (real crypto)** | Genuine scroll passes; content-tamper, one-char change, forged sig, missing sig all FAIL | `MIRRA_LLM_BRIDGE_v1/tests/test_qseal_tamper_evidence.py` | injected hardcoded `qseal_verified=True` → 4 red |
| **Key dependence / fail-closed** | Wrong secret fails; no secret → module refuses to import (stronger than returning False) | same file | wrong-secret + no-secret cases |
| **Chain tamper-evidence** | 2nd scroll references 1st's signature hash; tampering the 1st breaks the chain; `verify_chain` rejects it | same file | broke the prev-link → red |
| **MCP per-subject isolation** | A scope returns exactly and only its own subject's scrolls (checked in every direction + a 3rd subject) | `tests/test_mcp_trust_boundary.py` | leak in either direction → red (a **first version missed one direction**; hardened + re-proven) |
| **Agent-attested provenance** | MCP-written scrolls marked `mcp-agent` inside signed payload; can't forge/strip without breaking verify | same file | strip attestation → red |
| **MCP verify-on-read (own layer)** | The MCP layer drops unverified scrolls independently of the store (proven via a lying-store stub) | same file | disable ScopedMemory verify → red (a **first version rode the store's check**; rewritten to target the MCP layer + re-proven) |
| **MCP config-fixed scope** | Subject comes only from `MIRRA_SUBJECT`; no tool accepts a subject; server fail-closed with none; no enumeration | `tests/test_mcp_scope_auth.py` | add subject param → 2 red; fail-open default → red; add `list_subjects` → red |

Full SDK suite: **112 passed, 1 skipped** (skip = a langchain-only path when the
lib is absent). Leak gate (public/private boundary) clean on every commit.

Run the suites:
```bash
# SDK (this repo)
QSEAL_SECRET=x .../.venv/bin/python -m pytest tests/ -q
# Bridge tamper-evidence guard
cd ../MIRRA_LLM_BRIDGE_v1 && QSEAL_SECRET=x PYTHONPATH=. .venv/bin/python -m pytest tests/test_qseal_tamper_evidence.py -q
```

---

## 3. Current versions & tags (verified)

| Package | PyPI | Git tag |
|---|---|---|
| mirra-sdk | **0.5.1** | v0.5.1 |
| mirra-core-contract | 1.0.0 | v1.0.0 |
| mvar-security | 1.5.4 | (bridge submodule) |
| clawzero | 0.4.1 | (bridge submodule) |
| clawseal | 1.1.7 | (mirra-second-brain) |

mirra-sdk version history: 0.1.x (SDK + LangChain) → 0.2.0 (Person + 3 more
adapters) → 0.3.x (`guard()` + payload-classified security fix) → 0.4.0 (embodied
robot loop) → 0.5.0 (mirra-mcp) → **0.5.1 (config-fixed MCP scope auth)**.

---

## 4. Working-tree hygiene state (READ — there is one open item)

**mirra-sdk repo: CLEAN.** No submodules. All work committed **file-by-file**
(never `git add -A` — this project has been bitten by that). `dist_release/` is
gitignored build output; ignore it. Commits use the `git commit-tree` +
`git update-ref` plumbing because `git commit` hangs in this environment (global
`core.editor=nano`, no TTY).

**MIRRA_LLM_BRIDGE_v1 repo (separate repo, branch `p0-signing-surface-unification`):
has UNRESOLVED `-dirty` submodule pointers** — this is the item the last review
flagged and it is **not yet resolved**:
```
 M clawzero  → 02f8c116…-dirty   (the clawzero 0.4.1 release commit, locally dirty)
 M mvar      → 3777667f…-dirty   (the mvar 1.5.4 release commit, locally dirty)
```
These are benign in origin (local builds of the published releases), but "benign
dirty submodule pointers sitting in the tree" is exactly the ambient state where a
future `git add -A` sweeps something unintended in. **Decision still owed:** either
commit these pointers to their clean release commits deliberately, or `git
submodule update` them back — pick one, don't leave it ambiguous. The bridge repo
also carries other intentional churn (a `utcnow` deprecation fix in a private-brain
integration module, and a packaging-glob widen in the bridge `pyproject.toml`)
that is real and fine to keep.

Also in the bridge repo: the v1 EOS MCP server file was **restored from the
archive** (the 4G graveyard sweep archived it by mistake; it's a live import
dependency of the v2 EOS MCP server that Claude Desktop runs). The desktop
`mirra-eos` MCP server is fixed and running — its config points at
`.venv/bin/python` (not the deleted `.venv_313`) with `QSEAL_SECRET` inline in
`~/Library/Application Support/Claude/claude_desktop_config.json`.

---

## 5. Deliberately deferred (documented decisions, not forgotten gaps)

1. **Dynamic / authenticated MCP scope = v2, intentionally not built.** v1 is
   config-fixed scope only (see SCOPE_MODEL.md). A token-based model where the
   agent requests a subject is more flexible and a much larger attack surface;
   build it only when a real multi-subject-per-session need appears. SCOPE_MODEL.md
   also states the honest limit: config-fixed scope trusts whoever wrote the
   config (same boundary as any local credential) — it does not authenticate the
   human or protect against an attacker who can edit the env.
2. **Private research-substrate decoupling (tracked as G-16).** ~44 files in the
   private `../MIRRA_PRIME` repo still hard-code the sibling bridge path via
   `sys.path.insert`. The 5 bridge *adapter* files were routed through a proper
   locator seam, but the research scripts were not. This is the critical-path
   blocker for a real on-device / independent deploy. Not started.
3. **Two MCP servers exist — know which is which.** `mirra-mcp` (this repo, new,
   thin, over the published SDK, config-fixed scope, the one to promote) vs. the
   old private EOS demo MCP server in the bridge repo (v1 demo code, raw YAML
   under `data/`, only un-broken for the desktop connection). Prefer `mirra-mcp`
   for anything new.
4. **Person→MCP binding.** Person recognition (voice/face→signed Person) is a
   separate SDK capability; wiring it to the MCP scope binding is a future layer,
   not a v1 claim.
5. **Private-brain test bit-rot.** Some tests in the private `MIRRA_LLM_BRIDGE_v1`
   brain fail on config drift; the *public* platform is clean, but the private
   brain needs a test-cleanup pass before reuse. Not blocking anything public.

---

## 6. The actual next move (unchanged for days)

Not a build. **Outreach.** The assets are all standing and reproducible:
- Live site: https://sdvegas21.github.io/mirra-sdk/
- `pip install mirra-sdk` (0.5.1)
- Drafted-and-ready: a Willison email, a Show HN post, and a 90-second video shot
  list (all in prior session history; each points at the live site + demo).

The gap between what exists and who knows it exists has never been wider. The
highest-leverage action on the board is telling one real person (Simon Willison
is the recommended first contact: distribution + credibility + the exact first-user
crowd, in one). Every "let's build X" has been real and valuable *and* a way to
defer the one open-loop act that tests whether anyone wants this. It's ready. It's
been ready.

---

## 7. Environment quick-reference

- **venvs:** `MIRRA_LLM_BRIDGE_v1/.venv` (Python 3.14, has `mcp`, `mirra` deps) is
  the workhorse. `.venv_313` is GONE (its bin is empty) — do not reference it.
- **QSEAL_SECRET:** required everywhere; in `~/.zshrc` (64-char hex). The desktop
  app can't read shell env, so the MCP config has it inline.
- **git:** `git commit` hangs — use `commit-tree`/`update-ref`. Stage file-by-file.
- **Contract path for tests:** conftest wires sibling repos onto sys.path via
  `MIRRA_CONTRACT_PATH`/`MVAR_PATH`/`CLAWZERO_PATH`/`CLAWSEAL_PATH` (defaults to the
  workspace layout).
