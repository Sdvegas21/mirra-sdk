# MIRRA over MCP — signed memory for any MCP-speaking AI

Give Claude Desktop, Cursor, Claude Code — any MCP client — signed, tamper-evident,
per-subject memory, with **one config block and no SDK code**.

## Install + configure

```bash
pip install "mirra-sdk[mcp]"
```

Add to your MCP client config (Claude Desktop shown). One server binds one
subject, set with `MIRRA_SUBJECT`:

```json
{
  "mcpServers": {
    "mirra-alice": {
      "command": "python",
      "args": ["-m", "mirra_mcp"],
      "env": {
        "QSEAL_SECRET": "<your 32-byte hex secret>",
        "MIRRA_SUBJECT": "alice"
      }
    }
  }
}
```

Generate a secret once: `openssl rand -hex 32`. Restart the client. Your AI now
has four memory tools, all bound to `alice`. Want memory for two people? Run two
server instances with two `MIRRA_SUBJECT` values — the user, not the agent,
decides the subjects (see [SCOPE_MODEL.md](SCOPE_MODEL.md)).

## Tools

None of these take a subject argument — the subject is fixed by config, so the
agent cannot name or reach another one.

| Tool | What it does |
|---|---|
| `remember(content)` | Save a signed, agent-attested memory about the configured subject |
| `recall(query?)` | Return only the configured subject's verified memories |
| `verify_memory()` | Report how many memories pass real crypto verification |
| `whoami()` | The memory agent's stable identity (does not reveal the subject) |

## The trust boundary (enforced server-side, not hoped-for)

When a remote AI writes to your signed store, three guarantees hold — each with a
committed regression test that fails the build if it breaks
(`tests/test_mcp_trust_boundary.py`):

1. **Per-subject recall isolation, config-fixed.** One server binds one subject,
   read from `MIRRA_SUBJECT` at launch — the agent has no tool, argument, or path
   to name, change, or enumerate another subject. Isolation is by construction:
   there is no subject parameter to abuse. Full model and its explicit limits in
   [SCOPE_MODEL.md](SCOPE_MODEL.md).

2. **Agent-attested provenance.** Every memory written over MCP is marked
   `mcp-agent` *inside its signed content* — so a memory an AI wrote is
   cryptographically distinguishable from one a human authored, and the marker
   can't be forged or stripped without breaking verification.

3. **Fail-closed verify-on-read.** Reads return only scrolls whose signatures
   verify; tampered scrolls are dropped; no signing secret means the server
   refuses to run at all. There is no keyless or unverified path.

## Notes

- Memories are stored under `~/.mirra-mcp` (override with `MIRRA_MCP_HOME`), as
  signed scrolls in the open [scroll format](https://github.com/Sdvegas21/mirra-core-contract/blob/main/SCROLL_FORMAT.md).
- The secret in the config signs your memories; keep it private, and use the same
  secret across sessions so existing memories keep verifying.
