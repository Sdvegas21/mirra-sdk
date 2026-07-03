"""Permissioned execution (contract: ExecutionAuthorizer) — the Provable-safety pillar.

Default backend: the ClawZero runtime (which is powered by the MVAR enforcement
engine). Every authorization emits a signed witness to the SDK home's witness
directory; `verify_decision()` re-checks a DecisionRecord against that signed
witness with a REAL Ed25519 signature check — an altered or fabricated record
fails verification.

Fail-closed rules (contract §3.3):
- backend import fails            -> every authorize() returns BLOCK
- backend raises during evaluate  -> BLOCK
- decision cannot be normalized   -> BLOCK
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from mirra_core_contract import (
    AgentIdentity,
    Decision,
    DecisionRecord,
    ExecutionIntent,
    VerificationResult,
)

REASON_ENGINE_UNAVAILABLE = "enforcement_engine_unavailable"


def _blocked(request_id: str, reason: str) -> DecisionRecord:
    return DecisionRecord(
        request_id=request_id,
        decision=Decision.BLOCK.value,
        reason_code=reason,
        policy_id="mirra-sdk-fail-closed",
        engine="mirra-sdk-fail-closed",
    )


class FailClosedAuthorizer:
    """The authorizer of last resort: no engine means no execution, ever."""

    def authorize(self, intent: ExecutionIntent, identity: AgentIdentity) -> DecisionRecord:
        return _blocked(getattr(intent, "request_id", ""), REASON_ENGINE_UNAVAILABLE)

    def verify_decision(self, record: DecisionRecord) -> VerificationResult:
        return VerificationResult(verified=False, reason=REASON_ENGINE_UNAVAILABLE)


class ClawZeroExecutionAuthorizer:
    """Contract ExecutionAuthorizer over the ClawZero runtime (MVAR engine).

    witness_dir receives one signed witness JSON per decision; the witness embeds
    the Ed25519 public key so any party can verify without shared secrets.
    """

    def __init__(self, witness_dir: Path | str, profile: str = "prod_locked"):
        import os

        from clawzero.runtime import MVARRuntime  # soft dependency; wrap() catches ImportError

        self._witness_dir = Path(witness_dir)
        self._witness_dir.mkdir(parents=True, exist_ok=True)
        # Keep engine state (one-time-token nonce log) inside the SDK home instead
        # of littering the developer's working directory. Respect an explicit
        # override if the operator already set one.
        os.environ.setdefault(
            "MVAR_EXEC_TOKEN_NONCE_STORE",
            str(self._witness_dir.parent / "engine" / "execution_token_nonces.jsonl"),
        )
        self._runtime = MVARRuntime(profile=profile, witness_dir=self._witness_dir)
        self._profile = profile

    def authorize(self, intent: ExecutionIntent, identity: AgentIdentity) -> DecisionRecord:
        request_id = getattr(intent, "request_id", "")
        try:
            from clawzero.contracts import ActionRequest

            provenance = dict(getattr(intent, "provenance", None) or {})
            # Unstated provenance is treated as untrusted — the conservative default.
            provenance.setdefault("source", "external_document")
            provenance.setdefault("taint_level", "untrusted")
            provenance.setdefault("source_chain", [provenance["source"], "tool_call"])

            request = ActionRequest(
                request_id=request_id,
                framework="mirra-sdk",
                action_type="tool_call",
                sink_type=intent.sink_type,
                tool_name=intent.sink_type,
                target=intent.target,
                arguments=dict(intent.arguments or {}),
                input_class=(
                    "trusted" if provenance.get("taint_level") == "trusted" else "untrusted"
                ),
                prompt_provenance=provenance,
                policy_profile=self._profile,
            )
            decision = self._runtime.evaluate(request)
        except Exception as exc:
            return _blocked(request_id, f"engine_error: {exc}")

        decision_value = str(getattr(decision, "decision", "block")).lower()
        if decision_value not in {"allow", "block", "annotate"}:
            return _blocked(request_id, "unnormalizable_decision")

        witness = self._find_witness(request_id)
        return DecisionRecord(
            request_id=request_id,
            decision=decision_value,
            reason_code=str(getattr(decision, "reason_code", "")),
            policy_id=str(getattr(decision, "policy_id", "")),
            engine=str(getattr(decision, "engine", "")),
            witness_signature=str((witness or {}).get("witness_signature", "")),
            witness_public_key=(witness or {}).get("witness_public_key"),
        )

    def verify_decision(self, record: DecisionRecord) -> VerificationResult:
        """Real verification: the record must match a signed witness AND the witness's
        Ed25519 signature must verify against its embedded public key."""
        witness = self._find_witness(getattr(record, "request_id", ""))
        if witness is None:
            return VerificationResult(verified=False, reason="no witness for request_id")

        try:
            from clawzero.witnesses.verify import verify_witness_object

            result = verify_witness_object(witness, require_chain=False)
        except Exception as exc:
            return VerificationResult(verified=False, reason=f"verifier unavailable: {exc}")

        if not result.valid:
            return VerificationResult(
                verified=False, scheme="ed25519", reason="; ".join(result.reasons)
            )

        for field_name, witness_key in (
            ("decision", "decision"),
            ("reason_code", "reason_code"),
            ("witness_signature", "witness_signature"),
        ):
            if str(getattr(record, field_name, "")) != str(witness.get(witness_key, "")):
                return VerificationResult(
                    verified=False,
                    scheme="ed25519",
                    reason=f"record field '{field_name}' does not match the signed witness",
                )
        return VerificationResult(verified=True, scheme="ed25519", reason="")

    def _find_witness(self, request_id: str) -> Optional[dict[str, Any]]:
        if not request_id:
            return None
        for path in sorted(self._witness_dir.glob("witness_*.json"), reverse=True):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if data.get("request_id") == request_id:
                return data
        return None


def default_authorizer(witness_dir: Path | str, profile: str = "prod_locked"):
    """ClawZero runtime if importable; otherwise the fail-closed stand-in."""
    try:
        return ClawZeroExecutionAuthorizer(witness_dir=witness_dir, profile=profile)
    except Exception:
        return FailClosedAuthorizer()
