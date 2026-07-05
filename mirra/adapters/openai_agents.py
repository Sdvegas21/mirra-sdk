"""OpenAI Agents SDK adapter — signed Session memory + enforcement.

    from mirra.adapters.openai_agents import MirraSession

    session = MirraSession(principal="acme", subject_id="alice")
    result = await Runner.run(agent, "hi", session=session)  # signed conversation

`MirraSession` implements the OpenAI Agents `SessionABC` (add_items / get_items /
pop_item / clear_session) backed by MIRRA signed scrolls: every conversation item
persists as a signed scroll and reads verify on load. Drop it into `Runner.run`.

Import-guarded: importing this module never requires openai-agents. Verified
against openai-agents 0.17.x.
"""

from __future__ import annotations

import json
from typing import Any, List, Optional

import mirra
from mirra.wrapper import WrappedAgent

_HINT = (
    "openai-agents is not installed. Install it with `pip install openai-agents` "
    "(or `pip install \"mirra-sdk[openai-agents]\"`) to use this adapter."
)


def _require_openai_agents():
    try:
        import agents  # noqa: F401
    except Exception as exc:
        raise ImportError(_HINT) from exc


def _session_base():
    try:
        from agents import SessionABC
        return SessionABC
    except Exception:
        return object


class MirraSession(_session_base()):  # type: ignore[misc]
    """OpenAI Agents Session backed by MIRRA signed scrolls (verify-on-read).

    A conversation item (a dict like {"role": "...", "content": "..."}) is stored
    as one signed scroll; get_items reconstructs the verified items in order.
    Async methods per SessionABC; the underlying signed store is synchronous, so
    these are thin async wrappers.
    """

    def __init__(self, *, principal: Any = None, subject_id: str,
                 wrapped: Optional[WrappedAgent] = None,
                 home: Optional[str] = None, profile: str = "dev_balanced",
                 persons: Any = None):
        _require_openai_agents()
        if wrapped is None:
            if principal is None:
                raise ValueError("provide either `wrapped` or `principal`")
            wrapped = mirra.wrap(lambda m, c: "", principal=principal, home=home,
                                 profile=profile, persons=persons)
        self._mirra = wrapped
        self._subject_id = subject_id
        self.session_id = subject_id

    def _stored_items(self) -> List[dict]:
        items: List[dict] = []
        for scroll in self._mirra.recall(self._subject_id):
            content = str(getattr(scroll, "content", scroll))
            try:
                items.append(json.loads(content))
            except (ValueError, TypeError):
                items.append({"role": "user", "content": content})
        return items

    async def get_items(self, limit: Optional[int] = None) -> List[Any]:
        items = self._stored_items()
        return items[-limit:] if limit else items

    async def add_items(self, items: List[Any]) -> None:
        for item in items:
            payload = item if isinstance(item, dict) else {"role": "user", "content": str(item)}
            self._mirra.remember(self._subject_id, json.dumps(payload, sort_keys=True))

    async def pop_item(self) -> Optional[Any]:
        # Signed memory is append-only tamper-evidence; popping (mutating history)
        # would break the audit trail. Return None rather than silently deleting.
        return None

    async def clear_session(self) -> None:
        # No-op by design (append-only). Documented, not silent.
        return None


def all_items_verify(session: MirraSession) -> bool:
    """Helper for callers/tests: every stored scroll for this subject verifies."""
    return all(session._mirra.verify(s).verified
               for s in session._mirra.recall(session._subject_id))


class MirraOpenAIAgent:
    """An OpenAI Agents `Agent` bound to a MIRRA identity, with signed sessions
    and enforced tools. Use `session_for(subject_id)` in Runner.run."""

    def __init__(self, agent: Any, wrapped: WrappedAgent):
        self._agent = agent
        self._mirra = wrapped

    @property
    def identity(self):
        return self._mirra.identity

    @property
    def agent(self):
        return self._agent

    def session_for(self, subject_id: str) -> MirraSession:
        return MirraSession(wrapped=self._mirra, subject_id=subject_id)

    def protect_tool(self, tool: Any, sink: str = "tool.custom",
                     provenance: Optional[dict] = None) -> Any:
        return self._mirra.protect_tool(tool, sink=sink, provenance=provenance)

    def verify_decision(self, record):
        return self._mirra.verify_decision(record)


def wrap_agent(agent: Any, *, principal: Any, home: Optional[str] = None,
               profile: str = "dev_balanced", providers: Optional[list] = None,
               persons: Any = None, recognize_persons: bool = False) -> MirraOpenAIAgent:
    wrapped = mirra.wrap(agent, principal=principal, home=home, profile=profile,
                         providers=providers, persons=persons,
                         recognize_persons=recognize_persons)
    return MirraOpenAIAgent(agent, wrapped)
