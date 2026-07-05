"""LlamaIndex adapter — signed per-person memory + enforcement, LlamaIndex idioms.

    from mirra.adapters.llamaindex import MirraLlamaIndexMemory, wrap_agent

    memory = MirraLlamaIndexMemory(principal="acme", subject_id="alice")
    # put() persists a signed scroll; get()/get_all() return verified ChatMessages

`MirraLlamaIndexMemory` implements the LlamaIndex memory surface
(put / get / get_all / set / reset) backed by MIRRA signed scrolls, so it drops
into a chat engine's `memory=`. Verify-on-read means only cryptographically
verified turns are returned.

Import-guarded: importing this module never requires llama-index. Verified
against llama-index-core 0.14.x.
"""

from __future__ import annotations

from typing import Any, List, Optional

import mirra
from mirra.adapters.base import SignedMemoryMixin, build_wrapped
from mirra.wrapper import WrappedAgent

_HINT = (
    "LlamaIndex is not installed. Install it with `pip install llama-index-core` "
    "(or `pip install \"mirra-sdk[llamaindex]\"`) to use this adapter."
)


def _require_llamaindex():
    try:
        import llama_index.core  # noqa: F401
    except Exception as exc:
        raise ImportError(_HINT) from exc


def _to_chat_message(role: str, text: str):
    from llama_index.core.llms import ChatMessage, MessageRole

    role_map = {
        "user": MessageRole.USER,
        "human": MessageRole.USER,
        "assistant": MessageRole.ASSISTANT,
        "ai": MessageRole.ASSISTANT,
        "system": MessageRole.SYSTEM,
    }
    return ChatMessage(role=role_map.get(role, MessageRole.USER), content=text)


def _role_str(message: Any) -> str:
    role = getattr(message, "role", "user")
    value = getattr(role, "value", str(role)).lower()
    return "assistant" if value in ("assistant", "chatbot", "model") else (
        "system" if value == "system" else "user")


class MirraLlamaIndexMemory(SignedMemoryMixin):
    """LlamaIndex-compatible chat memory backed by MIRRA signed scrolls.

    Not a subclass of BaseMemory (a pydantic component with a rigid field model);
    instead it implements the same call surface, which is what chat engines use.
    Duck-typing here is deliberate — it avoids pydantic field collisions while
    remaining a drop-in for `memory=`.
    """

    def __init__(self, *, principal: Any = None, subject_id: str,
                 wrapped: Optional[WrappedAgent] = None,
                 home: Optional[str] = None, profile: str = "dev_balanced",
                 persons: Any = None):
        _require_llamaindex()
        if wrapped is None:
            if principal is None:
                raise ValueError("provide either `wrapped` or `principal`")
            wrapped = mirra.wrap(lambda m, c: "", principal=principal, home=home,
                                 profile=profile, persons=persons)
        self._mirra = wrapped
        self._subject_id = subject_id

    # -- LlamaIndex memory surface -------------------------------------------

    def put(self, message: Any) -> None:
        self._store_turn(_role_str(message), getattr(message, "content", str(message)))

    def get(self, **kwargs: Any) -> List[Any]:
        return [_to_chat_message(role, text) for role, text in self._verified_turns()]

    def get_all(self) -> List[Any]:
        return self.get()

    def set(self, messages: List[Any]) -> None:
        # Append-only tamper-evidence: 'set' persists any not-yet-stored turns
        # rather than replacing (clearing would defeat the audit trail).
        for message in messages:
            self.put(message)

    def reset(self) -> None:
        # No-op by design (signed memory is append-only). Documented, not silent.
        return None


class MirraLlamaIndexAgent:
    """A LlamaIndex chat engine / callable bound to a MIRRA identity + signed memory."""

    def __init__(self, engine: Any, wrapped: WrappedAgent):
        self._engine = engine
        self._mirra = wrapped

    @property
    def identity(self):
        return self._mirra.identity

    def chat(self, message: str, subject_id: str, *, remember: bool = True) -> Any:
        context = self._mirra.build_context(subject_id)
        history = "\n".join(str(h) for h in context["history"])
        prompt = f"{history}\n\nuser: {message}" if history else message
        if hasattr(self._engine, "chat"):
            response = self._engine.chat(prompt)
        elif callable(self._engine):
            response = self._engine(prompt)
        else:
            raise TypeError("wrapped LlamaIndex object must be a chat engine or callable")
        if remember:
            self._mirra.remember(subject_id, f"user: {message}\nassistant: {response}")
        return response

    def memory_for(self, subject_id: str) -> MirraLlamaIndexMemory:
        return MirraLlamaIndexMemory(wrapped=self._mirra, subject_id=subject_id)

    def protect_tool(self, tool: Any, sink: str = "tool.custom",
                     provenance: Optional[dict] = None) -> Any:
        return self._mirra.protect_tool(tool, sink=sink, provenance=provenance)

    def verify_decision(self, record):
        return self._mirra.verify_decision(record)


def wrap_agent(engine: Any, *, principal: Any, home: Optional[str] = None,
               profile: str = "dev_balanced", providers: Optional[list] = None,
               persons: Any = None, recognize_persons: bool = False) -> MirraLlamaIndexAgent:
    wrapped = build_wrapped(engine, principal=principal, home=home, profile=profile,
                            providers=providers, persons=persons,
                            recognize_persons=recognize_persons)
    return MirraLlamaIndexAgent(engine, wrapped)
