"""Cross-device signed-memory sync — the "portable soul" protocol.

A bundle is a plain JSON envelope of signed scroll entries. The receiving
device verifies EVERY entry against the owner's secret before accepting it:
a tampered scroll, or a bundle from a different owner, is rejected entry by
entry with a reason — never silently stored.
"""

from __future__ import annotations

from typing import Optional

from .qseal_lite import verify_scroll
from .store import DeviceMemoryStore

BUNDLE_VERSION = "1"


def export_bundle(store: DeviceMemoryStore, device_id: str, subject_id: Optional[str] = None) -> dict:
    """Export this device's signed scrolls (optionally one relationship only)."""
    entries = store.raw_entries()
    if subject_id is not None:
        entries = [e for e in entries if e.get("user_id") == subject_id]
    return {
        "bundle_version": BUNDLE_VERSION,
        "device_id": device_id,
        "scheme": "hmac-sha256",
        "scrolls": entries,
    }


def import_bundle(store: DeviceMemoryStore, bundle: dict) -> dict:
    """Verify-then-accept every scroll in a bundle. Fail-closed per entry."""
    accepted: list[str] = []
    rejected: list[dict] = []

    for entry in bundle.get("scrolls", []):
        scroll_id = str(entry.get("scroll_id", "<missing id>"))
        if not isinstance(entry, dict) or not entry.get("scroll_id"):
            rejected.append({"scroll_id": scroll_id, "reason": "malformed entry"})
            continue
        if not verify_scroll(entry, store._secret):
            rejected.append({"scroll_id": scroll_id, "reason": "signature verification failed"})
            continue
        if store.accept_entry(entry):
            accepted.append(scroll_id)
        else:
            rejected.append({"scroll_id": scroll_id, "reason": "store refused entry"})

    return {
        "from_device": bundle.get("device_id", ""),
        "accepted": accepted,
        "rejected": rejected,
    }
