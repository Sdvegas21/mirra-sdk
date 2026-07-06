"""mirra_mcp — MIRRA signed memory as an MCP server, plus its trust boundary.

    python -m mirra_mcp        # run the server (stdio)

See scoped_memory.ScopedMemory for the server-side trust guarantees
(per-subject isolation, agent-attested provenance, fail-closed verify-on-read).
"""

from .scoped_memory import (
    ATTEST_AGENT,
    ATTEST_HUMAN,
    MemoryGateway,
    ScopedMemory,
    SubjectIsolationError,
)

__all__ = [
    "MemoryGateway",
    "ScopedMemory",
    "SubjectIsolationError",
    "ATTEST_AGENT",
    "ATTEST_HUMAN",
]
