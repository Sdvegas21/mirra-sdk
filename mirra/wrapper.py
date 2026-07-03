"""mirra.wrap(agent) — Edge 1 of the platform (the SDK).

One call gives any agent the four pillars, all through the frozen v1 contract:

    wrapped = mirra.wrap(my_agent, principal="team-key-1")

    wrapped.identity                      # Recognition: stable across sessions
    wrapped.remember("alice", "...")      # History: signed scroll, verify-on-read
    wrapped.recall("alice")               # only verified memories come back
    wrapped.interact("alice", "hi")       # Differentiated: context = alice's history
    wrapped.execute("shell.exec", "...")  # Provable-safety: signed decision record
    safe = wrapped.protect_tool(fn, sink="filesystem.read")

The SDK speaks ONLY `mirra_core_contract` types. Concrete components (enforcement
runtime, memory store, capability providers) are injected or constructed from the
default backends. If an optional capability provider is registered it enriches
identity context and scores intents; with none, the core runs enforcement +
memory only.
"""

from __future__ import annotations

import inspect
import uuid
from pathlib import Path
from typing import Any, Callable, Iterable, List, Optional

from mirra_core_contract import (
    AgentIdentity,
    Decision,
    DecisionRecord,
    ExecutionIntent,
    Scroll,
    VerificationResult,
)

from .errors import ExecutionRefused, MemoryUnavailable
from .execution import default_authorizer
from .identity import LocalIdentityResolver
from .memory import default_memory

DEFAULT_HOME = Path.home() / ".mirra"

TRUSTED_PROVENANCE = {
    "source": "user_request",
    "taint_level": "trusted",
    "source_chain": ["user_request", "tool_call"],
}


class WrappedAgent:
    """An agent wearing the platform: identity + memory + behavior + enforcement."""

    def __init__(
        self,
        agent: Any,
        identity: AgentIdentity,
        memory,
        authorizer,
        providers: List[Any],
    ):
        self._agent = agent
        self._memory = memory
        self._authorizer = authorizer
        self._providers = providers
        self.identity = self._enriched(identity)

    # -- Recognition ---------------------------------------------------------

    def _enriched(self, identity: AgentIdentity) -> AgentIdentity:
        for provider in self._providers:
            try:
                identity = provider.enrich_identity(identity) or identity
            except Exception:
                continue  # a broken provider never takes down the core
        return identity

    # -- History (portable signed memory) -------------------------------------

    def remember(self, subject_id: str, content: Any) -> Scroll:
        if self._memory is None:
            raise MemoryUnavailable("no memory backend configured")
        return self._memory.remember(self.identity.agent_id, subject_id, content)

    def recall(self, subject_id: str, query: Optional[str] = None) -> List[Scroll]:
        if self._memory is None:
            raise MemoryUnavailable("no memory backend configured")
        return self._memory.recall(self.identity.agent_id, subject_id, query)

    def verify(self, scroll: Scroll) -> VerificationResult:
        if self._memory is None:
            raise MemoryUnavailable("no memory backend configured")
        return self._memory.verify(scroll)

    # -- Differentiated interaction --------------------------------------------

    def build_context(self, subject_id: str) -> dict[str, Any]:
        """The per-relationship context handed to the agent: this subject's verified
        history plus any provider-supplied identity context."""
        history = self.recall(subject_id) if self._memory is not None else []
        return {
            "agent_id": self.identity.agent_id,
            "subject_id": subject_id,
            "history": [getattr(s, "content", s) for s in history],
            "identity_context": dict(self.identity.context or {}),
        }

    def interact(self, subject_id: str, message: str, remember: bool = True) -> Any:
        context = self.build_context(subject_id)
        response = self._call_agent(message, context)
        if remember and self._memory is not None:
            self.remember(subject_id, f"user: {message} | agent: {response}")
        return response

    def _call_agent(self, message: str, context: dict[str, Any]) -> Any:
        agent = self._agent
        call = agent if callable(agent) else getattr(agent, "respond", None)
        if call is None:
            raise TypeError("wrapped agent must be callable or expose .respond()")
        try:
            takes = len(inspect.signature(call).parameters)
        except (TypeError, ValueError):
            takes = 2
        return call(message, context) if takes >= 2 else call(message)

    # -- Provable-safety (permissioned execution) -------------------------------

    def execute(
        self,
        sink_type: str,
        target: str,
        arguments: Optional[dict[str, Any]] = None,
        provenance: Optional[dict[str, Any]] = None,
    ) -> DecisionRecord:
        """Authorize a privileged action. Returns the signed DecisionRecord;
        the caller acts only on decision == "allow"."""
        intent = ExecutionIntent(
            request_id=str(uuid.uuid4()),
            agent_id=self.identity.agent_id,
            sink_type=sink_type,
            target=target,
            arguments=arguments or {},
            provenance=provenance or {},
        )
        for provider in self._providers:
            try:
                confidence = provider.verify_epistemic(intent)
                intent.provenance.setdefault("epistemic_confidence", float(confidence))
            except Exception:
                continue
        return self._authorizer.authorize(intent, self.identity)

    def verify_decision(self, record: DecisionRecord) -> VerificationResult:
        verifier = getattr(self._authorizer, "verify_decision", None)
        if verifier is None:
            return VerificationResult(verified=False, reason="authorizer cannot verify records")
        return verifier(record)

    def protect_tool(
        self,
        tool: Callable,
        sink: str = "tool.custom",
        provenance: Optional[dict[str, Any]] = None,
    ) -> Callable:
        """Wrap a callable so it only runs when authorized (the protect() pattern
        expressed through the contract). Blocked calls raise ExecutionRefused."""

        def protected(*args: Any, **kwargs: Any) -> Any:
            target = kwargs.get("target") or (str(args[0]) if args else tool.__name__)
            record = self.execute(
                sink_type=sink,
                target=target,
                arguments={"args": [str(a) for a in args], "kwargs": {k: str(v) for k, v in kwargs.items()}},
                provenance=provenance or dict(TRUSTED_PROVENANCE),
            )
            if record.decision != Decision.ALLOW.value:
                raise ExecutionRefused(
                    f"{sink} refused ({record.decision}): {record.reason_code}", record
                )
            return tool(*args, **kwargs)

        protected.__name__ = f"protected_{getattr(tool, '__name__', 'tool')}"
        return protected


def wrap(
    agent: Any,
    *,
    principal: Any,
    home: Path | str | None = None,
    profile: str = "prod_locked",
    providers: Optional[Iterable[Any]] = None,
    identity_resolver=None,
    memory=None,
    authorizer=None,
) -> WrappedAgent:
    """Wrap an agent with recognition, signed memory, per-relationship behavior,
    and permissioned execution.

    Args:
        agent: a callable `(message, context) -> response` (or `(message)`), or an
            object exposing `.respond(...)`.
        principal: the stable handle this agent's identity is anchored to.
        home: SDK state directory (identity keystore, scroll store, witness chain).
            Defaults to ~/.mirra. Never inside a repository.
        profile: enforcement policy profile (default prod_locked).
        providers: optional contract CapabilityProviders, injected at runtime.
        identity_resolver / memory / authorizer: contract-typed overrides.
    """
    home_path = Path(home) if home is not None else DEFAULT_HOME
    home_path.mkdir(parents=True, exist_ok=True)

    resolver = identity_resolver or LocalIdentityResolver(home_path)
    identity = resolver.resolve_identity(principal)

    if memory is None:
        memory = default_memory(home_path / "memory", identity.agent_id)
    if authorizer is None:
        authorizer = default_authorizer(home_path / "witnesses", profile=profile)

    return WrappedAgent(
        agent=agent,
        identity=identity,
        memory=memory,
        authorizer=authorizer,
        providers=list(providers or []),
    )
