"""DeviceMemoryStore — the contract's MemoryStore on a constrained target.

JSON files + stdlib QSEAL signatures. Same guarantees as the big edges:
sign-on-write, verify-on-read, tampered scrolls dropped, fail-closed without a
secret. Scroll dicts here verify under the memory core's verifier and vice
versa (see qseal_lite).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

from mirra_core_contract import Scroll, SignatureScheme, VerificationResult

from .qseal_lite import sign_scroll, verify_scroll


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DeviceMemoryStore:
    def __init__(self, home: Path | str, agent_id: str, secret: Optional[str] = None):
        self._dir = Path(home) / "scrolls"
        self._dir.mkdir(parents=True, exist_ok=True)
        self._agent_id = agent_id
        self._secret = secret  # None -> QSEAL_SECRET env (qseal_lite resolves)

    # -- contract surface ------------------------------------------------------

    def remember(self, agent_id: str, subject_id: str, content: Any) -> Scroll:
        entry = {
            "scroll_id": f"DEV_{uuid.uuid4().hex[:12]}",
            "agent_id": agent_id,
            "user_id": subject_id,          # same key the memory core uses
            "content": str(content),
            "timestamp": _now(),
        }
        signed = sign_scroll(entry, self._secret)  # raises without a secret (fail-closed)
        path = self._dir / f"{signed['scroll_id']}.json"
        path.write_text(json.dumps(signed, ensure_ascii=False, indent=1), encoding="utf-8")
        return self._to_contract(signed)

    def recall(self, agent_id: str, subject_id: str, query: Optional[str] = None) -> List[Scroll]:
        results: List[Scroll] = []
        for entry in self._iter_entries():
            if entry.get("user_id") != subject_id:
                continue
            if not verify_scroll(entry, self._secret):
                continue  # tampered or unverifiable -> dropped, never returned
            if query and query.lower() not in str(entry.get("content", "")).lower():
                continue
            results.append(self._to_contract(entry))
        results.sort(key=lambda s: s.created_at)
        return results

    def verify(self, scroll: Scroll) -> VerificationResult:
        stored = self._load(getattr(scroll, "scroll_id", ""))
        if stored is None:
            return VerificationResult(verified=False, reason="scroll not found in device store")
        if not verify_scroll(stored, self._secret):
            return VerificationResult(
                verified=False,
                scheme=SignatureScheme.HMAC_SHA256.value,
                reason="signature verification failed",
            )
        if getattr(scroll, "content", None) is not None and str(scroll.content) != str(
            stored.get("content")
        ):
            return VerificationResult(
                verified=False,
                scheme=SignatureScheme.HMAC_SHA256.value,
                reason="in-memory content differs from signed scroll",
            )
        return VerificationResult(verified=True, scheme=SignatureScheme.HMAC_SHA256.value)

    # -- sync support ----------------------------------------------------------

    def raw_entries(self) -> List[dict]:
        """Signed scroll dicts as stored (for export bundles)."""
        return list(self._iter_entries())

    def accept_entry(self, entry: dict) -> bool:
        """Store an externally-signed entry IF it verifies (fail-closed) and is new."""
        if not verify_scroll(entry, self._secret):
            return False
        scroll_id = str(entry.get("scroll_id", ""))
        if not scroll_id:
            return False
        path = self._dir / f"{scroll_id}.json"
        if path.exists():
            return True  # already present (idempotent sync)
        path.write_text(json.dumps(entry, ensure_ascii=False, indent=1), encoding="utf-8")
        return True

    # -- internals --------------------------------------------------------------

    def _iter_entries(self):
        for path in sorted(self._dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(data, dict):
                yield data

    def _load(self, scroll_id: str) -> Optional[dict]:
        for entry in self._iter_entries():
            if entry.get("scroll_id") == scroll_id:
                return entry
        return None

    def _to_contract(self, entry: dict) -> Scroll:
        return Scroll(
            scroll_id=str(entry.get("scroll_id", "")),
            agent_id=str(entry.get("agent_id", self._agent_id)),
            subject_id=str(entry.get("user_id", "")),
            content=entry.get("content"),
            qseal_signature=str(entry.get("qseal_signature", "")),
            qseal_prev_signature=str(entry.get("qseal_prev_signature", "")),
            qseal_scheme=SignatureScheme.HMAC_SHA256.value,
            created_at=str(entry.get("timestamp", "")),
        )
