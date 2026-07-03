"""Portable signed memory (contract: MemoryStore) — the History pillar.

Default backend: ClawSeal's contract adapter (sign-on-write, verify-on-read,
fail-closed). If no memory backend can be constructed and none is injected,
wrap() raises MemoryUnavailable rather than running with silent, unsigned memory.
"""

from __future__ import annotations

from pathlib import Path

from .errors import MemoryUnavailable


def default_memory(base_path: Path | str, agent_id: str):
    """ClawSeal-backed contract MemoryStore, or raise MemoryUnavailable."""
    try:
        from clawseal_core.contract_adapter import ClawSealMemoryStore
    except Exception as exc:
        raise MemoryUnavailable(
            "no signed-memory backend available (clawseal_core not importable); "
            "install the memory component or pass memory= to mirra.wrap()"
        ) from exc
    return ClawSealMemoryStore(base_path=str(base_path), agent_id=agent_id)
