"""mirra-mcp server: builds, registers tools, and round-trips with isolation.

The trust-boundary guarantees are proven in test_mcp_trust_boundary.py; here we
confirm the FastMCP server wires the scoped core correctly and speaks MCP.
"""

import json
import os
import subprocess
import sys

import pytest


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("QSEAL_SECRET", "test-secret-for-mcp-server")


def test_server_builds_and_registers_tools(tmp_path):
    from mirra_mcp.server import build_server

    mcp = build_server(home=str(tmp_path))
    # FastMCP exposes registered tools; confirm ours are present.
    import anyio

    tools = anyio.run(mcp.list_tools)
    names = {t.name for t in tools}
    assert {"remember", "recall", "verify_memory", "whoami"} <= names


def test_speaks_mcp_over_stdio(tmp_path):
    """Launch `python -m mirra_mcp` exactly as an MCP client would and confirm
    the initialize handshake + tools/list respond."""
    # Build PYTHONPATH from the component source paths (mirrors a real install,
    # where mirra-core-contract / clawzero / clawseal are importable deps).
    import sys as _sys
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    paths = [p for p in _sys.path if any(
        name in p for name in ("mirra-sdk", "mirra-core-contract", "clawzero", "mirra-second-brain", "mvar")
    )]
    env = dict(os.environ)
    env["QSEAL_SECRET"] = "test-secret-for-mcp-server"
    env["MIRRA_MCP_HOME"] = str(tmp_path)
    env["PYTHONPATH"] = os.pathsep.join([repo, *paths, env.get("PYTHONPATH", "")])

    msgs = (
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"1.0"}}}\n'
        '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
        '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n'
    )
    proc = subprocess.run([sys.executable, "-m", "mirra_mcp"], input=msgs, env=env,
                          cwd=repo, capture_output=True, text=True, timeout=60)
    responses = [json.loads(l) for l in proc.stdout.splitlines() if l.strip().startswith("{")]
    init = next((r for r in responses if r.get("id") == 1), None)
    tools = next((r for r in responses if r.get("id") == 2), None)
    assert init and init["result"]["serverInfo"]["name"] == "mirra", proc.stderr[-500:]
    assert tools and len(tools["result"]["tools"]) >= 4


def test_round_trip_through_tools_preserves_isolation(tmp_path):
    """Exercise the tool callables directly: remember for two subjects, recall
    each, and confirm neither sees the other."""
    from mirra_mcp.scoped_memory import MemoryGateway

    gw = MemoryGateway(app="srv-test", home=str(tmp_path), people=False)
    gw.scope("alice").remember("alice fact")
    gw.scope("bob").remember("bob fact")

    alice = gw.scope("alice").recall()
    bob = gw.scope("bob").recall()
    assert [m["content"] for m in alice] == ["alice fact"]
    assert [m["content"] for m in bob] == ["bob fact"]
    assert all(m["attested_by"] == "mcp-agent" for m in alice + bob)
