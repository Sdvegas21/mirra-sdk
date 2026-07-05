"""Whole-agent LangChain adapter — all four pillars in LangChain's own idioms.

The existing `clawzero.protect_langchain_tool` enforces individual tools. This
adapter gives a LangChain agent the whole platform:

    from mirra.adapters.langchain import wrap_agent

    bound = wrap_agent(my_chain, principal="acme-tenant")
    reply = bound.invoke("remind me what we discussed", subject_id="alice")
    #   -> alice is recognized across sessions (stable identity)
    #   -> her prior turns are recalled from SIGNED memory (verify-on-read)
    #   -> the chain sees only alice's verified history as context
    #   -> the exchange is written back as a new signed scroll

And a signed-memory chat history for the modern LangChain idiom
(`RunnableWithMessageHistory`):

    from mirra.adapters.langchain import MirraChatMessageHistory

    history = MirraChatMessageHistory(principal="acme", subject_id="alice")
    chain_with_memory = RunnableWithMessageHistory(
        chain, lambda session_id: MirraChatMessageHistory(
            principal="acme", subject_id=session_id),
        input_messages_key="input", history_messages_key="history",
    )
    # every turn is persisted as a signed scroll; reads verify on load.
    # (MirraChatMessageHistory is also a plain BaseChatMessageHistory, so it
    # works anywhere one is accepted, including LangGraph checkpoint stores.)

Plus tool enforcement that reuses the proven ClawZero path:

    safe_tool = bound.protect_tool(shell_tool, sink="shell.exec")

Nothing here imports langchain at module load. `MirraChatMessageHistory`
subclasses LangChain's `BaseChatMessageHistory` only when langchain is
installed; otherwise a clear ImportError is raised on use, never on import.
"""

from __future__ import annotations

from typing import Any, List, Optional

import mirra
from mirra.wrapper import WrappedAgent

_LANGCHAIN_HINT = (
    "LangChain is not installed. Install it with `pip install langchain` "
    "(or `pip install \"mirra-sdk[langchain]\"`) to use this adapter."
)


def _require_langchain():
    try:
        import langchain_core  # noqa: F401  (>=0.1 split package)
    except Exception:
        try:
            import langchain  # noqa: F401  (older monolith)
        except Exception as exc:
            raise ImportError(_LANGCHAIN_HINT) from exc


class MirraLangChainAgent:
    """A LangChain runnable/chain bound to a MIRRA identity + signed memory.

    Wraps `.invoke()` so each call resolves per-subject signed history, hands it
    to the chain as context, and records the exchange as a new signed scroll.
    Tools are enforced through the reused ClawZero path.
    """

    def __init__(self, chain: Any, wrapped: WrappedAgent, history_key: str = "history"):
        self._chain = chain
        self._mirra = wrapped
        self._history_key = history_key

    # -- recognition ---------------------------------------------------------

    @property
    def identity(self):
        return self._mirra.identity

    # -- the four-pillar invoke ----------------------------------------------

    def invoke(self, message: str, subject_id: str, *, remember: bool = True,
               config: Optional[dict] = None) -> Any:
        """Run the chain for `subject_id` with their verified history as context."""
        context = self._mirra.build_context(subject_id)
        history_text = self._render_history(context["history"])

        payload = {
            "input": message,
            self._history_key: history_text,
            "mirra_context": context,
        }
        response = self._invoke_chain(payload, config)

        if remember:
            self._mirra.remember(subject_id, f"user: {message}\nagent: {self._as_text(response)}")
        return response

    async def ainvoke(self, message: str, subject_id: str, *, remember: bool = True,
                      config: Optional[dict] = None) -> Any:
        context = self._mirra.build_context(subject_id)
        payload = {
            "input": message,
            self._history_key: self._render_history(context["history"]),
            "mirra_context": context,
        }
        if hasattr(self._chain, "ainvoke"):
            response = await self._chain.ainvoke(payload, config=config)
        else:
            response = self._invoke_chain(payload, config)
        if remember:
            self._mirra.remember(subject_id, f"user: {message}\nagent: {self._as_text(response)}")
        return response

    def _invoke_chain(self, payload: dict, config: Optional[dict]) -> Any:
        if hasattr(self._chain, "invoke"):
            return self._chain.invoke(payload, config=config)
        if callable(self._chain):
            return self._chain(payload)
        raise TypeError("wrapped LangChain object must be a Runnable or callable")

    # -- signed memory, exposed as LangChain chat history --------------------

    def as_chat_history(self, subject_id: str) -> "MirraChatMessageHistory":
        """A LangChain BaseChatMessageHistory backed by this agent's signed store,
        scoped to `subject_id`. Use with RunnableWithMessageHistory."""
        return MirraChatMessageHistory(wrapped=self._mirra, subject_id=subject_id)

    # -- provable-safety: enforced tools -------------------------------------

    def protect_tool(self, tool: Any, sink: str = "tool.custom",
                     provenance: Optional[dict] = None) -> Any:
        """Enforce a LangChain tool through the SDK's execution authorizer.
        Blocked calls raise mirra.ExecutionRefused; the tool never runs."""
        return self._mirra.protect_tool(tool, sink=sink, provenance=provenance)

    def verify_decision(self, record):
        return self._mirra.verify_decision(record)

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _render_history(history: List[Any]) -> str:
        return "\n".join(str(h) for h in history)

    @staticmethod
    def _as_text(response: Any) -> str:
        for attr in ("content", "text"):
            value = getattr(response, attr, None)
            if isinstance(value, str):
                return value
        if isinstance(response, dict):
            for key in ("output", "text", "response", "content"):
                if isinstance(response.get(key), str):
                    return response[key]
        return str(response)


def wrap_agent(
    chain: Any,
    *,
    principal: Any,
    home: Optional[str] = None,
    profile: str = "dev_balanced",
    providers: Optional[list] = None,
    history_key: str = "history",
) -> MirraLangChainAgent:
    """Bind a LangChain chain/runnable to a MIRRA identity + signed memory +
    enforcement. `principal` anchors the stable identity; `subject_id` per
    `.invoke()` selects whose signed history becomes context."""
    wrapped = mirra.wrap(
        chain, principal=principal, home=home, profile=profile, providers=providers,
    )
    return MirraLangChainAgent(chain, wrapped, history_key=history_key)


def _chat_history_base():
    """Return LangChain's BaseChatMessageHistory, or `object` if langchain is
    absent. Deferred so importing this module never requires langchain.
    """
    try:
        from langchain_core.chat_history import BaseChatMessageHistory
        return BaseChatMessageHistory
    except Exception:
        return object


class MirraChatMessageHistory(_chat_history_base()):  # type: ignore[misc]
    """LangChain BaseChatMessageHistory backed by MIRRA signed scrolls.

    `messages` returns only cryptographically verified history for `subject_id`
    (verify-on-read); `add_message` persists a new signed scroll. Drop into
    RunnableWithMessageHistory to give any chain tamper-evident per-user memory.

    A scroll stores one turn as "role: content"; on read it is reconstructed
    into the matching LangChain message type.
    """

    def __init__(self, *, principal: Any = None, subject_id: str,
                 wrapped: Optional[WrappedAgent] = None,
                 home: Optional[str] = None, profile: str = "dev_balanced"):
        _require_langchain()
        if wrapped is None:
            if principal is None:
                raise ValueError("provide either `wrapped` or `principal`")
            wrapped = mirra.wrap(lambda m, c: "", principal=principal,
                                 home=home, profile=profile)
        self._mirra = wrapped
        self._subject_id = subject_id

    @property
    def messages(self) -> List[Any]:
        from langchain_core.messages import AIMessage, HumanMessage

        out: List[Any] = []
        for scroll in self._mirra.recall(self._subject_id):
            content = str(getattr(scroll, "content", scroll))
            role, _, text = content.partition(": ")
            if role == "ai":
                out.append(AIMessage(content=text))
            else:
                out.append(HumanMessage(content=text))
        return out

    def add_message(self, message: Any) -> None:
        role = "ai" if message.__class__.__name__.startswith("AI") else "human"
        text = getattr(message, "content", str(message))
        self._mirra.remember(self._subject_id, f"{role}: {text}")

    def clear(self) -> None:
        # Signed memory is append-only tamper-evidence; clearing would defeat the
        # audit trail. No-op by design (documented, not silent).
        return None
