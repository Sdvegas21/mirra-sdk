"""Stdlib implementation of the canonical QSEAL scroll signature (G-15).

Byte-for-byte compatible with the memory core's HMAC-SHA256 scheme:

    signature = base64( HMAC-SHA256( secret,
        json.dumps({entry minus qseal_* fields}, sort_keys=True, ensure_ascii=False) ) )

This compatibility is the whole point of the on-device edge: a scroll signed
here verifies on any other edge that shares the owner's secret, and vice versa.

Fail-closed: a missing secret raises — nothing is ever signed with a default.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Optional

# Fields excluded from the signed payload (identical to the memory core).
_EXCLUDED = {"qseal_signature", "qseal_verified", "qseal_meta_hash", "qseal_prev_signature"}


class SigningUnavailable(RuntimeError):
    """No signing secret available — refuse to sign (never default)."""


def _secret(explicit: Optional[str] = None) -> str:
    secret = explicit or os.environ.get("QSEAL_SECRET", "")
    if not secret:
        raise SigningUnavailable(
            "QSEAL_SECRET is not set; refusing to sign or verify with a default secret"
        )
    return secret


def canonical_payload(entry: dict) -> str:
    filtered = {k: v for k, v in entry.items() if k not in _EXCLUDED}
    return json.dumps(filtered, sort_keys=True, ensure_ascii=False)


def generate_signature(entry: dict, secret: Optional[str] = None) -> str:
    digest = hmac.new(
        _secret(secret).encode("utf-8"),
        canonical_payload(entry).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.b64encode(digest).decode("utf-8")


def sign_scroll(entry: dict, secret: Optional[str] = None) -> dict:
    signed = dict(entry)
    signed["qseal_signature"] = generate_signature(signed, secret)
    return signed


def verify_scroll(entry: dict, secret: Optional[str] = None) -> bool:
    provided = entry.get("qseal_signature")
    if not provided:
        return False
    try:
        expected = generate_signature(entry, secret)
    except SigningUnavailable:
        return False  # cannot verify -> not verified (fail-closed)
    return hmac.compare_digest(provided, expected)
