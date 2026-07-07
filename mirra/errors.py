"""SDK error types. Every error here is fail-closed: raised instead of degrading."""

from __future__ import annotations


class MirraError(Exception):
    """Base class for all SDK errors."""


class IdentityError(MirraError):
    """Identity could not be resolved safely (corrupt keystore, unreadable key).

    Never silently regenerate an identity: doing so would break recognition and
    hand the same principal a brand-new agent identity.
    """


class MemoryUnavailable(MirraError):
    """No signed-memory backend is available. remember/recall refuse to run."""


class ContinuityError(MirraError):
    """Identity continuity could not be established safely (unverifiable
    snapshot, broken transition chain, missing identity key).

    Never silently restart an agent from zero: an unverifiable state is
    refused, not replaced — a fresh state wearing an old agent_id would be
    a different agent claiming its history.
    """


class ExecutionRefused(MirraError):
    """A privileged action was refused (blocked by policy, or the enforcement
    engine was unavailable — both refuse, never allow)."""

    def __init__(self, message: str, record=None):
        super().__init__(message)
        self.record = record
