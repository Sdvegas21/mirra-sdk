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
        # Installed wheel name first, then the development checkout layout.
        try:
            from clawseal.contract_adapter import ClawSealMemoryStore
        except ImportError:
            from clawseal_core.contract_adapter import ClawSealMemoryStore
    except Exception as exc:
        raise MemoryUnavailable(
            "no signed-memory backend available (clawseal not importable); "
            "install the memory component (pip install clawseal) or pass "
            "memory= to mirra.wrap()"
        ) from exc
    return ClawSealMemoryStore(base_path=str(base_path), agent_id=agent_id)
