"""Tenant registry, bearer-key auth, and rate limiting for the gateway edge.

Keys are never stored: the registry holds only SHA-256 hashes of tenant API
keys. Each tenant gets an isolated state directory (identity keystore, scroll
store, witness chain), so one tenant's agents, memories, and decisions are
invisible to every other tenant by construction.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Tenant:
    tenant_id: str
    key_hash: str
    home: Path


class TenantRegistry:
    """tenant_id -> hashed key + isolated home directory."""

    def __init__(self, base_home: Path | str):
        self._base = Path(base_home)
        self._tenants: dict[str, Tenant] = {}

    def add_tenant(self, tenant_id: str, key_hash: str) -> Tenant:
        if not tenant_id.replace("-", "").replace("_", "").isalnum():
            raise ValueError(f"invalid tenant_id: {tenant_id!r}")
        tenant = Tenant(
            tenant_id=tenant_id,
            key_hash=key_hash,
            home=self._base / "tenants" / tenant_id,
        )
        self._tenants[tenant_id] = tenant
        return tenant

    def authenticate(self, bearer_key: Optional[str]) -> Optional[Tenant]:
        """Resolve a presented bearer key to a tenant; None = reject (fail-closed)."""
        if not bearer_key:
            return None
        presented = hash_api_key(bearer_key)
        for tenant in self._tenants.values():
            if _hmac.compare_digest(tenant.key_hash, presented):
                return tenant
        return None

    @classmethod
    def from_config(cls, config_path: Path | str) -> "TenantRegistry":
        """Load {"base_home": "...", "tenants": [{"tenant_id", "key_hash"}]} JSON."""
        config = json.loads(Path(config_path).read_text(encoding="utf-8"))
        registry = cls(base_home=Path(config["base_home"]).expanduser())
        for entry in config.get("tenants", []):
            registry.add_tenant(entry["tenant_id"], entry["key_hash"])
        return registry


class RateLimiter:
    """Per-tenant token bucket. Refuses (True at capacity) rather than queueing."""

    def __init__(self, capacity: int = 30, refill_per_second: float = 10.0):
        self._capacity = capacity
        self._refill = refill_per_second
        self._buckets: dict[str, tuple[float, float]] = {}  # tenant -> (tokens, stamp)
        self._lock = threading.Lock()

    def allow(self, tenant_id: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, stamp = self._buckets.get(tenant_id, (float(self._capacity), now))
            tokens = min(self._capacity, tokens + (now - stamp) * self._refill)
            if tokens < 1.0:
                self._buckets[tenant_id] = (tokens, now)
                return False
            self._buckets[tenant_id] = (tokens - 1.0, now)
            return True
