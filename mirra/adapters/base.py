"""Shared four-pillar plumbing for framework adapters.

Every framework adapter needs the same core moves — resolve a subject's verified
signed history, hand it to the framework, record the exchange as a new signed
scroll, and enforce tools through the proven path. This module factors those so
each framework file is thin glue over its own idioms, not a reimplementation.
"""

from __future__ import annotations

from typing import Any, List, Optional

import mirra
from mirra.wrapper import WrappedAgent


def build_wrapped(chain_or_agent: Any, *, principal: Any, home: Optional[str],
                  profile: str, providers: Optional[list], persons: Any,
                  recognize_persons: bool) -> WrappedAgent:
    return mirra.wrap(
        chain_or_agent, principal=principal, home=home, profile=profile,
        providers=providers, persons=persons, recognize_persons=recognize_persons,
    )


class SignedMemoryMixin:
    """Give a framework-memory object MIRRA signed-scroll persistence.

    The host class supplies `self._mirra` (a WrappedAgent) and `self._subject_id`.
    Turns are stored as "role: content" scrolls; roles round-trip so the memory
    can rebuild native message objects on read (verify-on-read is enforced by the
    underlying store — only verified scrolls come back).
    """

    _mirra: WrappedAgent
    _subject_id: str

    def _store_turn(self, role: str, text: str) -> None:
        self._mirra.remember(self._subject_id, f"{role}: {text}")

    def _verified_turns(self) -> List[tuple]:
        turns: List[tuple] = []
        for scroll in self._mirra.recall(self._subject_id):
            content = str(getattr(scroll, "content", scroll))
            role, _, text = content.partition(": ")
            turns.append((role or "user", text))
        return turns

    def _all_verified(self) -> bool:
        return all(self._mirra.verify(s).verified
                   for s in self._mirra.recall(self._subject_id))


def render_history(turns: List[tuple]) -> str:
    return "\n".join(f"{role}: {text}" for role, text in turns)
