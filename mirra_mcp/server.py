"""mirra-mcp — MIRRA signed memory for any MCP-speaking AI, one config block.

Point Claude Desktop, Cursor, Claude Code, or any MCP client at this server and
the AI gains signed, tamper-evident, per-subject memory — no SDK code required:

    {
      "mcpServers": {
        "mirra": {
          "command": "python", "args": ["-m", "mirra_mcp"],
          "env": {"QSEAL_SECRET": "<your 32-byte hex secret>"}
        }
      }
    }

The trust boundary is enforced server-side (mirra_mcp.scoped_memory), not hoped
for in the client:
  - recall is per-subject isolated (an agent cannot read another subject's history)
  - every written memory is agent-attested inside its signed payload
  - reads are verify-on-read, fail-closed

Tools exposed: remember, recall, verify_memory, whoami.
"""

from __future__ import annotations

import os
from typing import Optional

from .scoped_memory import MemoryGateway


def build_server(home: Optional[str] = None, app: str = "mirra-mcp",
                 profile: str = "dev_balanced"):
    """Construct the FastMCP server. Separated from run() so tests can drive it."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("mirra")
    home = home or os.environ.get("MIRRA_MCP_HOME") or os.path.expanduser("~/.mirra-mcp")
    gateway = MemoryGateway(app=app, home=home, profile=profile, people=True)

    @mcp.tool()
    def remember(subject_id: str, content: str) -> dict:
        """Save a signed, agent-attested memory ABOUT subject_id.

        subject_id is who the memory is about (a person / relationship). The
        memory is cryptographically signed and marked as written by an AI agent.
        """
        return gateway.scope(subject_id).remember(content)

    @mcp.tool()
    def recall(subject_id: str, query: str = "") -> dict:
        """Recall verified memories about subject_id (only that subject's, only
        verified). Returns memories with their provenance (agent vs human)."""
        scope = gateway.scope(subject_id)
        memories = scope.recall(query or None)
        return {"subject_id": subject_id, "count": len(memories), "memories": memories}

    @mcp.tool()
    def verify_memory(subject_id: str) -> dict:
        """Verify every stored memory for subject_id; report how many pass real
        cryptographic verification (tamper-evidence check)."""
        return gateway.scope(subject_id).verify_all()

    @mcp.tool()
    def whoami() -> dict:
        """Return this memory agent's stable identity."""
        return {"agent_id": gateway.agent_id}

    return mcp


def run() -> None:
    build_server().run()   # stdio transport by default


if __name__ == "__main__":
    run()
