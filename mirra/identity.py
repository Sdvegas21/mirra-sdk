"""Local identity resolution (contract: IdentityResolver) — the Recognition pillar.

A principal (any stable caller-supplied handle: an API key owner, a device id, a
user id) resolves to ONE AgentIdentity that is stable across sessions:

- agent_id           derived deterministically from the principal
- identity_pubkey    Ed25519 public key, generated on first run
- soulprint_digest   SHA-256 fingerprint over (agent_id + identity_pubkey)

Keys are generated on first resolve and stored OUTSIDE any repository, in the
SDK home directory (default ~/.mirra) with 0600 permissions. Only the public key
is ever placed in an AgentIdentity. A corrupt or unreadable keystore raises
IdentityError — it is never silently regenerated, because a regenerated key
would be a different identity wearing the same name.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mirra_core_contract import AgentIdentity

from .errors import IdentityError


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class LocalIdentityResolver:
    """File-backed IdentityResolver for the SDK edge."""

    def __init__(self, home: Path | str):
        self._dir = Path(home) / "identity"
        self._dir.mkdir(parents=True, exist_ok=True)

    def _slot(self, principal: Any) -> str:
        return hashlib.sha256(str(principal).encode("utf-8")).hexdigest()[:16]

    def resolve_identity(self, principal: Any) -> AgentIdentity:
        slot = self._slot(principal)
        record_path = self._dir / f"{slot}.json"
        key_path = self._dir / f"{slot}.key"

        if record_path.exists():
            record = self._load_existing(record_path, key_path)
        else:
            record = self._create(slot, record_path, key_path)

        record["last_seen"] = _now()
        record_path.write_text(json.dumps(record, indent=2), encoding="utf-8")

        return AgentIdentity(
            agent_id=record["agent_id"],
            identity_pubkey=record["identity_pubkey"],
            soulprint_digest=record["soulprint_digest"],
            created_at=record["created_at"],
            last_seen=record["last_seen"],
        )

    def _load_existing(self, record_path: Path, key_path: Path) -> dict:
        try:
            record = json.loads(record_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise IdentityError(f"identity record unreadable: {record_path} ({exc})") from exc
        if not key_path.exists():
            raise IdentityError(f"identity key missing for {record_path} — refusing to regenerate")
        pubkey = self._pubkey_hex(key_path)
        if pubkey != record.get("identity_pubkey"):
            raise IdentityError(f"identity key does not match record for {record_path}")
        expected = _fingerprint(record["agent_id"], pubkey)
        if record.get("soulprint_digest") != expected:
            raise IdentityError(f"identity fingerprint mismatch for {record_path}")
        return record

    def _create(self, slot: str, record_path: Path, key_path: Path) -> dict:
        private_key = Ed25519PrivateKey.generate()
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(pem)
        key_path.chmod(0o600)

        pubkey = self._pubkey_hex(key_path)
        agent_id = f"agent-{slot}"
        record = {
            "agent_id": agent_id,
            "identity_pubkey": pubkey,
            "soulprint_digest": _fingerprint(agent_id, pubkey),
            "created_at": _now(),
            "last_seen": _now(),
        }
        record_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        return record

    @staticmethod
    def _pubkey_hex(key_path: Path) -> str:
        try:
            private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        except Exception as exc:
            raise IdentityError(f"identity key unreadable: {key_path} ({exc})") from exc
        public = private_key.public_key()
        raw = public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()


def _fingerprint(agent_id: str, pubkey_hex: str) -> str:
    return hashlib.sha256(f"{agent_id}:{pubkey_hex}".encode("utf-8")).hexdigest()
