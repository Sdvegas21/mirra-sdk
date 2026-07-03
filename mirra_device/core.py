"""DeviceCore — identity + memory + local permissioned execution for one device.

Identity: stable per-principal identity anchored in a device keystore file.
On a constrained target (no asymmetric-crypto extension available) the identity
is anchored to a random 32-byte device key; the published fingerprint is its
SHA-256. Distributable Ed25519 identity proofs remain the job of the SDK and
gateway edges — this edge's signatures are the same-owner HMAC scheme the
contract designates for symmetric memory.

Execution: deny-by-default. An action is allowed only when (a) it matches an
explicit owner allowlist entry AND (b) the core invariant holds — untrusted
input to a critical sink is ALWAYS blocked, allowlisted or not. Every decision
carries a same-owner HMAC witness signature over its canonical payload, so an
altered or fabricated record fails verification on this device.
"""

from __future__ import annotations

import hashlib
import json
import secrets as _secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, List, Optional

from mirra_core_contract import (
    AgentIdentity,
    Decision,
    DecisionRecord,
    ExecutionIntent,
    Scroll,
    SignatureScheme,
    VerificationResult,
)

from .qseal_lite import generate_signature, verify_scroll
from .store import DeviceMemoryStore

CRITICAL_SINKS = {"shell.exec", "process.spawn", "filesystem.write", "credentials.read"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DeviceIdentityResolver:
    """File-backed identity for constrained targets (stdlib only)."""

    def __init__(self, home: Path | str):
        self._dir = Path(home) / "identity"
        self._dir.mkdir(parents=True, exist_ok=True)

    def resolve_identity(self, principal: Any) -> AgentIdentity:
        slot = hashlib.sha256(str(principal).encode("utf-8")).hexdigest()[:16]
        record_path = self._dir / f"{slot}.json"
        if record_path.exists():
            record = json.loads(record_path.read_text(encoding="utf-8"))
        else:
            device_key = _secrets.token_bytes(32)
            key_path = self._dir / f"{slot}.key"
            key_path.write_bytes(device_key)
            key_path.chmod(0o600)
            anchor = hashlib.sha256(device_key).hexdigest()
            agent_id = f"agent-{slot}"
            record = {
                "agent_id": agent_id,
                "identity_pubkey": anchor,  # public fingerprint of the device key
                "soulprint_digest": hashlib.sha256(f"{agent_id}:{anchor}".encode()).hexdigest(),
                "created_at": _now(),
                "last_seen": _now(),
            }
        record["last_seen"] = _now()
        record_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        return AgentIdentity(**record)


class DeviceAuthorizer:
    """Deny-by-default local authorizer with HMAC-witnessed decisions."""

    def __init__(self, home: Path | str, allowlist: Optional[Iterable[tuple[str, str]]] = None,
                 secret: Optional[str] = None):
        """allowlist: (sink_type, target_prefix) pairs the owner explicitly permits."""
        self._witness_dir = Path(home) / "witnesses"
        self._witness_dir.mkdir(parents=True, exist_ok=True)
        self._allowlist = list(allowlist or [])
        self._secret = secret

    def authorize(self, intent: ExecutionIntent, identity: AgentIdentity) -> DecisionRecord:
        taint = str((intent.provenance or {}).get("taint_level", "untrusted")).lower()

        if taint != "trusted" and intent.sink_type in CRITICAL_SINKS:
            decision, reason = Decision.BLOCK.value, "UNTRUSTED_TO_CRITICAL_SINK"
        elif any(
            intent.sink_type == sink and str(intent.target).startswith(prefix)
            for sink, prefix in self._allowlist
        ):
            decision, reason = Decision.ALLOW.value, "DEVICE_ALLOWLIST"
        else:
            decision, reason = Decision.BLOCK.value, "DEVICE_DENY_BY_DEFAULT"

        payload = {
            "request_id": intent.request_id,
            "agent_id": intent.agent_id,
            "sink_type": intent.sink_type,
            "target": intent.target,
            "decision": decision,
            "reason_code": reason,
            "policy_id": "mirra-device.v1",
            "engine": "mirra-device",
            "timestamp": _now(),
        }
        try:
            signature = generate_signature(payload, self._secret)
        except Exception:
            # No secret -> cannot witness -> refuse the action entirely.
            return DecisionRecord(
                request_id=intent.request_id,
                decision=Decision.BLOCK.value,
                reason_code="witness_unavailable",
                policy_id="mirra-device.v1",
                engine="mirra-device",
            )
        payload["qseal_signature"] = signature
        witness_path = self._witness_dir / f"{intent.request_id or uuid.uuid4().hex}.json"
        witness_path.write_text(json.dumps(payload, indent=1), encoding="utf-8")

        return DecisionRecord(
            request_id=intent.request_id,
            decision=decision,
            reason_code=reason,
            policy_id="mirra-device.v1",
            engine="mirra-device",
            witness_signature=signature,
            witness_scheme=SignatureScheme.HMAC_SHA256.value,
        )

    def verify_decision(self, record: DecisionRecord) -> VerificationResult:
        witness_path = self._witness_dir / f"{record.request_id}.json"
        if not witness_path.exists():
            return VerificationResult(verified=False, reason="no witness for request_id")
        witness = json.loads(witness_path.read_text(encoding="utf-8"))
        if not verify_scroll(witness, self._secret):
            return VerificationResult(
                verified=False, scheme=SignatureScheme.HMAC_SHA256.value,
                reason="witness signature verification failed",
            )
        for field_name in ("decision", "reason_code", "witness_signature"):
            witness_key = "qseal_signature" if field_name == "witness_signature" else field_name
            if str(getattr(record, field_name, "")) != str(witness.get(witness_key, "")):
                return VerificationResult(
                    verified=False, scheme=SignatureScheme.HMAC_SHA256.value,
                    reason=f"record field '{field_name}' does not match the signed witness",
                )
        return VerificationResult(verified=True, scheme=SignatureScheme.HMAC_SHA256.value)


class DeviceCore:
    """The composed on-device edge: identity + signed memory + local enforcement."""

    def __init__(self, home: Path | str, principal: Any, device_id: str,
                 allowlist: Optional[Iterable[tuple[str, str]]] = None,
                 secret: Optional[str] = None):
        self.home = Path(home)
        self.device_id = device_id
        self.identity = DeviceIdentityResolver(self.home).resolve_identity(principal)
        self.memory = DeviceMemoryStore(self.home, agent_id=self.identity.agent_id, secret=secret)
        self.authorizer = DeviceAuthorizer(self.home, allowlist=allowlist, secret=secret)

    def remember(self, subject_id: str, content: Any) -> Scroll:
        return self.memory.remember(self.identity.agent_id, subject_id, content)

    def recall(self, subject_id: str, query: Optional[str] = None) -> List[Scroll]:
        return self.memory.recall(self.identity.agent_id, subject_id, query)

    def verify(self, scroll: Scroll) -> VerificationResult:
        return self.memory.verify(scroll)

    def execute(self, sink_type: str, target: str,
                arguments: Optional[dict] = None,
                provenance: Optional[dict] = None) -> DecisionRecord:
        intent = ExecutionIntent(
            request_id=uuid.uuid4().hex,
            agent_id=self.identity.agent_id,
            sink_type=sink_type,
            target=target,
            arguments=arguments or {},
            provenance=provenance or {},
        )
        return self.authorizer.authorize(intent, self.identity)

    def verify_decision(self, record: DecisionRecord) -> VerificationResult:
        return self.authorizer.verify_decision(record)
