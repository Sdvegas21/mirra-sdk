"""Mission Control adapter (G-20) — signed decision telemetry for operators.

Consumes contract DecisionRecords at the gateway and POSTs them to a Mission
Control endpoint as task metadata. Two honesty rules:

1. Only VERIFIED records are marked verified — the emitter re-states the
   verification result it was handed, never invents one.
2. Emission is observability, not enforcement: a Mission Control outage never
   blocks or fails an authorization (errors are recorded and swallowed).

Stdlib urllib only — no HTTP client dependency.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import urllib.error
import urllib.request
from typing import Optional

from mirra_core_contract import DecisionRecord, VerificationResult

logger = logging.getLogger(__name__)


class MissionControlEmitter:
    def __init__(self, url: str, api_key: str, timeout_seconds: float = 3.0):
        """url: Mission Control ingest endpoint (e.g. http://127.0.0.1:3000/api/tasks)."""
        self._url = url
        self._api_key = api_key
        self._timeout = timeout_seconds
        self.emitted = 0
        self.failed = 0

    def emit(
        self,
        tenant_id: str,
        record: DecisionRecord,
        verification: Optional[VerificationResult] = None,
    ) -> bool:
        payload = {
            "source": "mirra-gateway",
            "tenant_id": tenant_id,
            "decision_record": dataclasses.asdict(record),
            "signature_verified": bool(verification.verified) if verification else False,
            "verification_reason": (verification.reason if verification else "not verified"),
        }
        request = urllib.request.Request(
            self._url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                ok = 200 <= response.status < 300
        except (urllib.error.URLError, OSError, ValueError) as exc:
            logger.warning("Mission Control emit failed: %s", exc)
            self.failed += 1
            return False
        self.emitted += 1 if ok else 0
        self.failed += 0 if ok else 1
        return ok
