"""mirra-mcp — MIRRA signed memory for any MCP-speaking AI, one config block.

Point Claude Desktop, Cursor, Claude Code, or any MCP client at this server and
the AI gains signed, tamper-evident memory for ONE configured subject — no SDK
code required:

    {
      "mcpServers": {
        "mirra-alice": {
          "command": "python", "args": ["-m", "mirra_mcp"],
          "env": {
            "QSEAL_SECRET": "<32-byte hex>",
            "MIRRA_SUBJECT": "alice"
          }
        }
      }
    }

Scope is CONFIG-FIXED (see SCOPE_MODEL.md): the subject is read from
MIRRA_SUBJECT at launch and the connected agent has no tool, argument, or code
path to change, override, or enumerate any other subject. Isolation is by
construction — the tools do not accept a subject at all.

The trust boundary is enforced server-side (mirra_mcp.scoped_memory):
  - one server instance = one subject; cross-subject access is structurally
    impossible (no subject parameter exists)
  - every written memory is agent-attested inside its signed payload
  - reads are verify-on-read, fail-closed

Tools exposed: remember, recall, verify_memory, whoami.
"""

from __future__ import annotations

import os
from typing import Optional

from .scoped_memory import MemoryGateway, ScopedMemory


class ScopeNotConfigured(RuntimeError):
    """Raised when the server is started with no MIRRA_SUBJECT — fail-closed."""


def resolve_subject(explicit: Optional[str] = None) -> str:
    """The bound subject comes ONLY from config/env (or an explicit arg for
    tests). With none set, refuse to start — never default to an ambiguous or
    all-subjects scope. Same fail-closed posture as a missing signing secret.
    """
    subject = explicit if explicit is not None else os.environ.get("MIRRA_SUBJECT")
    if not subject or not str(subject).strip():
        raise ScopeNotConfigured(
            "MIRRA_SUBJECT is not set. mirra-mcp binds one server to one subject; "
            "set MIRRA_SUBJECT in the server config (e.g. \"alice\"). Refusing to "
            "start with an unset or all-subjects scope (fail-closed)."
        )
    return str(subject).strip()


def build_server(home: Optional[str] = None, app: str = "mirra-mcp",
                 profile: str = "dev_balanced", subject: Optional[str] = None):
    """Construct the FastMCP server bound to ONE config-fixed subject.

    Separated from run() so tests can drive it. `subject` is for tests only; in
    deployment it comes from MIRRA_SUBJECT via resolve_subject().
    """
    from mcp.server.fastmcp import FastMCP

    bound_subject = resolve_subject(subject)   # fail-closed if unset
    mcp = FastMCP("mirra")
    home = home or os.environ.get("MIRRA_MCP_HOME") or os.path.expanduser("~/.mirra-mcp")
    gateway = MemoryGateway(app=app, home=home, profile=profile, people=True)
    scope: ScopedMemory = gateway.scope(bound_subject)

    # NOTE: none of these tools accept a subject/subject_id/user parameter. The
    # bound subject is closed over from config; the agent cannot name another.
    # This is the load-bearing invariant (SCOPE_MODEL.md guarantee 1) and it is
    # asserted structurally in tests/test_mcp_scope_auth.py.

    @mcp.tool()
    def remember(content: str) -> dict:
        """Save a signed, agent-attested memory about the configured subject."""
        return scope.remember(content)

    @mcp.tool()
    def recall(query: str = "") -> dict:
        """Recall verified memories about the configured subject (only that
        subject's, only verified). Returns memories with provenance."""
        memories = scope.recall(query or None)
        return {"subject_bound": True, "count": len(memories), "memories": memories}

    @mcp.tool()
    def verify_memory() -> dict:
        """Verify every stored memory for the configured subject; report how many
        pass real cryptographic verification."""
        return scope.verify_all()

    @mcp.tool()
    def whoami() -> dict:
        """Return this memory agent's stable identity. Does NOT reveal the bound
        subject value or any other subject — no enumeration."""
        return {"agent_id": gateway.agent_id, "scope": "config-fixed"}

    return mcp


def run() -> None:
    build_server().run()   # stdio transport by default


if __name__ == "__main__":
    run()
