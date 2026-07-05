"""CrewAI adapter — enforced tools + signed per-person memory.

    from mirra.adapters.crewai import protect_tool, wrap_agent

    safe_tool = protect_tool(my_crewai_tool, sink="shell.exec")   # enforced BaseTool
    bound = wrap_agent(crew_or_agent, principal="acme")           # identity + memory

`protect_tool` returns a CrewAI `BaseTool` whose `_run` is gated by MIRRA
enforcement — a blocked call raises mirra.ExecutionRefused and the tool never
executes. `wrap_agent` binds a crew/agent to a MIRRA identity with signed,
per-subject (and per-person) memory.

Import-guarded: importing this module never requires crewai. Verified against
crewai 1.15.x.
"""

from __future__ import annotations

from typing import Any, Optional

import mirra
from mirra.wrapper import WrappedAgent

_HINT = (
    "crewai is not installed. Install it with `pip install crewai` "
    "(or `pip install \"mirra-sdk[crewai]\"`) to use this adapter."
)


def _require_crewai():
    try:
        import crewai  # noqa: F401
    except Exception as exc:
        raise ImportError(_HINT) from exc


def _infer_sink(name: str) -> str:
    n = name.lower()
    if any(k in n for k in ("bash", "shell", "exec", "command", "run")):
        return "shell.exec"
    if any(k in n for k in ("write", "save", "delete", "create")):
        return "filesystem.write"
    if any(k in n for k in ("read", "open", "load", "file")):
        return "filesystem.read"
    if any(k in n for k in ("http", "fetch", "url", "web", "request", "search")):
        return "http.request"
    if any(k in n for k in ("credential", "secret", "token", "password")):
        return "credentials.access"
    return "tool.custom"


def protect_tool(tool: Any, *, sink: Optional[str] = None,
                 wrapped: Optional[WrappedAgent] = None, principal: Any = None,
                 home: Optional[str] = None, profile: str = "dev_balanced",
                 provenance: Optional[dict] = None) -> Any:
    """Wrap a CrewAI BaseTool so MIRRA authorizes each call before `_run`.

    Returns a new BaseTool subclass instance with the same name/description; a
    blocked decision raises mirra.ExecutionRefused (the tool body never runs).
    """
    _require_crewai()
    from crewai.tools import BaseTool

    if wrapped is None:
        if principal is None:
            raise ValueError("provide either `wrapped` or `principal`")
        wrapped = mirra.wrap(lambda m, c: "", principal=principal, home=home, profile=profile)

    tool_name = getattr(tool, "name", getattr(tool, "__name__", "crewai_tool"))
    sink_type = sink or _infer_sink(str(tool_name))
    description = getattr(tool, "description", f"MIRRA-protected {tool_name}")

    from mirra.wrapper import TRUSTED_PROVENANCE

    # Bind closure values to locals pydantic won't see as fields, then set the
    # `name`/`description` fields at instantiation (not as class-body defaults,
    # which can't reference these closure variables under pydantic).
    _orig_tool = tool
    _sink = sink_type
    _prov = provenance or dict(TRUSTED_PROVENANCE)
    _wrapped = wrapped
    _label = str(tool_name)

    class _ProtectedTool(BaseTool):
        def _run(self, *args: Any, **kwargs: Any) -> Any:
            target = kwargs.get("target") or (str(args[0]) if args else _label)
            record = _wrapped.execute(
                sink_type=_sink, target=target,
                arguments={"args": [str(a) for a in args],
                           "kwargs": {k: str(v) for k, v in kwargs.items()}},
                provenance=dict(_prov),
            )
            if record.decision != "allow":
                raise mirra.ExecutionRefused(
                    f"{_sink} refused ({record.decision}): {record.reason_code}", record)
            if hasattr(_orig_tool, "_run"):
                return _orig_tool._run(*args, **kwargs)
            if hasattr(_orig_tool, "run"):
                return _orig_tool.run(*args, **kwargs)
            if callable(_orig_tool):
                return _orig_tool(*args, **kwargs)
            raise TypeError(f"cannot invoke wrapped CrewAI tool '{_label}'")

    return _ProtectedTool(name=str(tool_name), description=str(description))


class MirraCrewAIAgent:
    """A CrewAI crew/agent bound to a MIRRA identity + signed per-person memory."""

    def __init__(self, crew: Any, wrapped: WrappedAgent):
        self._crew = crew
        self._mirra = wrapped

    @property
    def identity(self):
        return self._mirra.identity

    def remember(self, subject_id: str, content: Any):
        return self._mirra.remember(subject_id, content)

    def recall(self, subject_id: str, query: Optional[str] = None):
        return self._mirra.recall(subject_id, query)

    def context_for(self, subject_id: str) -> dict:
        """Verified per-person context to inject into a crew's task/agent prompt."""
        return self._mirra.build_context(subject_id)

    def protect_tool(self, tool: Any, sink: Optional[str] = None,
                     provenance: Optional[dict] = None) -> Any:
        return protect_tool(tool, sink=sink, wrapped=self._mirra, provenance=provenance)

    def verify_decision(self, record):
        return self._mirra.verify_decision(record)


def wrap_agent(crew: Any, *, principal: Any, home: Optional[str] = None,
               profile: str = "dev_balanced", providers: Optional[list] = None,
               persons: Any = None, recognize_persons: bool = False) -> MirraCrewAIAgent:
    wrapped = mirra.wrap(crew, principal=principal, home=home, profile=profile,
                         providers=providers, persons=persons,
                         recognize_persons=recognize_persons)
    return MirraCrewAIAgent(crew, wrapped)
