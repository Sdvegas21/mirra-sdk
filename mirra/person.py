"""Person identity — recognizing the same HUMAN across devices and agents.

The Recognition pillar so far answers "who is this agent." This answers the
other half the platform vision needs: "who is this *person* the agent is
talking to, and is it the same person I met on another device?"

A `subject_id` alone is just a per-app string — the car might call her "alice",
the phone "user_42", the robot "mom". Those are three silos. A `Person` ties
them together:

- person_id        stable, derived from a person key (not from any one handle)
- person_pubkey    Ed25519 public key; the same person carries the same key
- fingerprint      SHA-256 over (person_id + person_pubkey) — the recognizable
                   "this is the same human" token that travels between devices
- handles          the device/app-local subject_ids claimed into this person

The seam that makes it cross-device: a Person can be EXPORTED as a signed
identity claim (person_id + pubkey + fingerprint, signed by the person key) and
IMPORTED on another device, which then recognizes any of that person's handles
as the same human — carrying one portable, signed relationship history.

Honest scope: this is cryptographic *recognition and continuity*, not identity
verification of a biometric. Binding a real-world human (a voiceprint, a face,
a login) to a person key is the caller's enrollment step; this module gives that
binding a stable, portable, tamper-evident home.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import IdentityError


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fingerprint(person_id: str, pubkey_hex: str) -> str:
    return hashlib.sha256(f"{person_id}:{pubkey_hex}".encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Person:
    """A human subject, recognizable as the same person across devices/agents."""
    person_id: str
    person_pubkey: str            # Ed25519 public key (hex)
    fingerprint: str              # SHA-256 over (person_id + pubkey)
    handles: tuple = ()           # device/app-local subject_ids claimed into this person
    display_name: str = ""
    created_at: str = ""
    last_seen: str = ""

    def recognizes(self, handle: str) -> bool:
        return handle in self.handles


@dataclass
class PersonClaim:
    """A signed, portable assertion of a person's identity — the cross-device seam.

    Carries the public identity (never the private key) plus a signature over it
    by the person key. Any device can verify it against the embedded pubkey and
    then recognize this person's handles as the same human.
    """
    person_id: str
    person_pubkey: str
    fingerprint: str
    handles: List[str]
    display_name: str
    signature: str                # hex Ed25519 signature over the canonical claim
    issued_at: str = ""

    def to_dict(self) -> dict:
        return {
            "person_id": self.person_id,
            "person_pubkey": self.person_pubkey,
            "fingerprint": self.fingerprint,
            "handles": list(self.handles),
            "display_name": self.display_name,
            "signature": self.signature,
            "issued_at": self.issued_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PersonClaim":
        return cls(
            person_id=str(data["person_id"]),
            person_pubkey=str(data["person_pubkey"]),
            fingerprint=str(data["fingerprint"]),
            handles=[str(h) for h in data.get("handles", [])],
            display_name=str(data.get("display_name", "")),
            signature=str(data["signature"]),
            issued_at=str(data.get("issued_at", "")),
        )


def _canonical_claim_bytes(person_id: str, person_pubkey: str, fingerprint: str,
                           handles: List[str], display_name: str) -> bytes:
    # Signature covers identity + handles + name; NOT issued_at/signature itself.
    payload = {
        "person_id": person_id,
        "person_pubkey": person_pubkey,
        "fingerprint": fingerprint,
        "handles": sorted(handles),
        "display_name": display_name,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class PersonRegistry:
    """File-backed registry of Persons, with cross-device signed claims.

    Keys live under <home>/persons, 0600, never in a repo. Only public keys and
    signatures leave via claims. A corrupt record raises rather than silently
    minting a new person (same fail-closed rule as agent identity).
    """

    def __init__(self, home: Path | str):
        self._dir = Path(home) / "persons"
        self._dir.mkdir(parents=True, exist_ok=True)

    # -- creation / lookup ---------------------------------------------------

    def _paths(self, person_id: str) -> tuple[Path, Path]:
        return self._dir / f"{person_id}.json", self._dir / f"{person_id}.key"

    def create_person(self, display_name: str = "",
                      handles: Optional[List[str]] = None) -> Person:
        """Mint a new Person with a fresh Ed25519 person key."""
        private_key = Ed25519PrivateKey.generate()
        pub_hex = self._pubkey_hex_from_private(private_key)
        person_id = "person-" + hashlib.sha256(pub_hex.encode()).hexdigest()[:16]
        record_path, key_path = self._paths(person_id)

        key_path.write_bytes(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        key_path.chmod(0o600)

        record = {
            "person_id": person_id,
            "person_pubkey": pub_hex,
            "fingerprint": _fingerprint(person_id, pub_hex),
            "handles": list(handles or []),
            "display_name": display_name,
            "created_at": _now(),
            "last_seen": _now(),
        }
        record_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        return self._to_person(record)

    def get_person(self, person_id: str) -> Optional[Person]:
        record_path, _ = self._paths(person_id)
        if not record_path.exists():
            return None
        return self._to_person(self._load(record_path))

    def resolve_handle(self, handle: str) -> Optional[Person]:
        """Return the Person who has claimed this device/app-local handle."""
        for record_path in self._dir.glob("person-*.json"):
            record = self._load(record_path)
            if handle in record.get("handles", []):
                return self._to_person(record)
        return None

    def claim_handle(self, person_id: str, handle: str) -> Person:
        """Attach a device/app-local subject_id to a person (enrollment)."""
        record_path, _ = self._paths(person_id)
        if not record_path.exists():
            raise IdentityError(f"unknown person: {person_id}")
        record = self._load(record_path)
        if handle not in record["handles"]:
            record["handles"].append(handle)
        record["last_seen"] = _now()
        record_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        return self._to_person(record)

    # -- cross-device seam: signed claims ------------------------------------

    def export_claim(self, person_id: str) -> PersonClaim:
        """Produce a signed, portable identity claim for another device."""
        record_path, key_path = self._paths(person_id)
        if not record_path.exists() or not key_path.exists():
            raise IdentityError(f"cannot export unknown/incomplete person: {person_id}")
        record = self._load(record_path)
        private_key = self._load_private(key_path)

        message = _canonical_claim_bytes(
            record["person_id"], record["person_pubkey"], record["fingerprint"],
            record["handles"], record["display_name"],
        )
        signature = private_key.sign(message).hex()
        return PersonClaim(
            person_id=record["person_id"],
            person_pubkey=record["person_pubkey"],
            fingerprint=record["fingerprint"],
            handles=list(record["handles"]),
            display_name=record["display_name"],
            signature=signature,
            issued_at=_now(),
        )

    @staticmethod
    def verify_claim(claim: PersonClaim) -> bool:
        """Real Ed25519 verification of a claim against its embedded pubkey,
        plus fingerprint consistency. No trust in unsigned fields."""
        expected_fp = _fingerprint(claim.person_id, claim.person_pubkey)
        if claim.fingerprint != expected_fp:
            return False
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(claim.person_pubkey))
            message = _canonical_claim_bytes(
                claim.person_id, claim.person_pubkey, claim.fingerprint,
                claim.handles, claim.display_name,
            )
            pub.verify(bytes.fromhex(claim.signature), message)
            return True
        except (InvalidSignature, ValueError):
            return False

    def import_claim(self, claim: PersonClaim) -> Person:
        """Recognize a person from another device: verify the claim, then store
        the PUBLIC record locally (no private key — this device can recognize
        the person and read their portable history, but cannot re-issue claims).
        Fails closed: an unverifiable claim is refused."""
        if not self.verify_claim(claim):
            raise IdentityError("person claim failed verification (fail-closed)")
        record_path, _ = self._paths(claim.person_id)
        existing = self._load(record_path) if record_path.exists() else {}
        merged_handles = sorted(set(existing.get("handles", [])) | set(claim.handles))
        record = {
            "person_id": claim.person_id,
            "person_pubkey": claim.person_pubkey,
            "fingerprint": claim.fingerprint,
            "handles": merged_handles,
            "display_name": claim.display_name or existing.get("display_name", ""),
            "created_at": existing.get("created_at", _now()),
            "last_seen": _now(),
            "imported": True,   # recognized-from-claim, no local private key
        }
        record_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        return self._to_person(record)

    # -- internals -----------------------------------------------------------

    def _load(self, record_path: Path) -> dict:
        try:
            return json.loads(record_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise IdentityError(f"person record unreadable: {record_path} ({exc})") from exc

    @staticmethod
    def _load_private(key_path: Path) -> Ed25519PrivateKey:
        try:
            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        except Exception as exc:
            raise IdentityError(f"person key unreadable: {key_path} ({exc})") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise IdentityError(f"person key is not Ed25519: {key_path}")
        return key

    @staticmethod
    def _pubkey_hex_from_private(private_key: Ed25519PrivateKey) -> str:
        raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()

    @staticmethod
    def _to_person(record: dict) -> Person:
        return Person(
            person_id=record["person_id"],
            person_pubkey=record["person_pubkey"],
            fingerprint=record["fingerprint"],
            handles=tuple(record.get("handles", [])),
            display_name=record.get("display_name", ""),
            created_at=record.get("created_at", ""),
            last_seen=record.get("last_seen", ""),
        )
