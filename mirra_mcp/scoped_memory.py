"""ScopedMemory — the trust boundary for MIRRA over MCP.

When a remote AI writes to a user's signed memory store over MCP, verify-on-read
protects against *tampering* — but MCP introduces a different threat: a confused
or adversarial agent writing the wrong thing about the wrong person, or reading
across subject boundaries. This layer makes three guarantees the raw SDK does
not enforce on its own, and enforces them SERVER-SIDE where a tool argument
cannot bypass them:

  1. Per-subject recall isolation. A ScopedMemory is bound to exactly ONE
     subject at construction; remember/recall physically cannot touch another
     subject's scrolls. There is no subject argument on the read path to abuse.

  2. Agent-attested provenance. Every scroll written through here is tagged in
     its SIGNED content as attested_by="mcp-agent" — so a memory a remote agent
     wrote is cryptographically distinguishable from one a human authored. The
     tag is inside the signed payload, so it cannot be forged or stripped
     without breaking verification.

  3. Fail-closed verify-on-read. Reads return only scrolls whose signatures
     verify; the underlying store drops tampered scrolls, and this layer refuses
     to operate at all if the memory backend is unavailable.

These are enforced here, not hoped-for downstream. The negative tests
(tests/test_mcp_trust_boundary.py) prove each one can fail.
"""

from __future__ import annotations

import json
from typing import Any, List, Optional

import mirra

# Provenance marker embedded in the SIGNED content of every MCP-written scroll.
ATTEST_AGENT = "mcp-agent"
ATTEST_HUMAN = "human"
_ATTEST_PREFIX = "mirra.attest="   # "mirra.attest=mcp-agent | <content>"


def wrap_attested(content: str, attested_by: str = ATTEST_AGENT) -> str:
    """Prefix content with a provenance marker that becomes part of the signed
    payload. Because it is signed, it cannot be altered without breaking verify."""
    return f"{_ATTEST_PREFIX}{attested_by} | {content}"


def read_attestation(content: Any) -> tuple[str, str]:
    """Return (attested_by, original_content). Unmarked content reads as human."""
    s = str(content)
    if s.startswith(_ATTEST_PREFIX):
        body = s[len(_ATTEST_PREFIX):]
        marker, _, rest = body.partition(" | ")
        return marker.strip(), rest
    return ATTEST_HUMAN, s


class SubjectIsolationError(mirra.MirraError):
    """Raised when an operation would cross the bound subject boundary."""


class ScopedMemory:
    """A memory handle bound to ONE agent identity and ONE subject.

    The bound subject is fixed at construction. remember() and recall() take no
    subject argument — they operate only on the bound subject — so a remote
    agent cannot request another subject's history by passing a different id.
    """

    def __init__(self, wrapped, subject_id: str):
        if not subject_id or not str(subject_id).strip():
            raise SubjectIsolationError("a ScopedMemory must be bound to a non-empty subject")
        self._w = wrapped
        self._subject = str(subject_id)

    @property
    def subject_id(self) -> str:
        return self._subject

    @property
    def agent_id(self) -> str:
        return self._w.identity.agent_id

    # -- write (always agent-attested) ---------------------------------------

    def remember(self, content: str) -> dict:
        """Write a signed, agent-attested memory for the bound subject."""
        if self._w._memory is None:
            raise mirra.MemoryUnavailable("no signed-memory backend (fail-closed)")
        marked = wrap_attested(str(content), ATTEST_AGENT)
        scroll = self._w.remember(self._subject, marked)
        attested_by, original = read_attestation(getattr(scroll, "content", marked))
        return {
            "scroll_id": getattr(scroll, "scroll_id", ""),
            "subject_id": self._subject,
            "attested_by": attested_by,
            "signed": bool(getattr(scroll, "qseal_signature", "")),
            "scheme": getattr(scroll, "qseal_scheme", ""),
        }

    # -- read (isolated + verify-on-read) ------------------------------------

    def recall(self, query: Optional[str] = None) -> List[dict]:
        """Return ONLY the bound subject's verified scrolls. No subject argument
        exists, so cross-subject recall is impossible by construction."""
        if self._w._memory is None:
            raise mirra.MemoryUnavailable("no signed-memory backend (fail-closed)")
        out: List[dict] = []
        for scroll in self._w.recall(self._subject, query):
            # Defense in depth: the store already scopes by subject, but assert it.
            if str(getattr(scroll, "subject_id", self._subject)) != self._subject:
                # A scroll from another subject must never surface here.
                continue
            verified = self._w.verify(scroll).verified
            if not verified:
                continue  # verify-on-read, fail-closed
            attested_by, original = read_attestation(getattr(scroll, "content", ""))
            out.append({
                "scroll_id": getattr(scroll, "scroll_id", ""),
                "content": original,
                "attested_by": attested_by,
                "verified": True,
            })
        return out

    def verify_all(self) -> dict:
        """Verify every scroll for the bound subject; report counts."""
        if self._w._memory is None:
            raise mirra.MemoryUnavailable("no signed-memory backend (fail-closed)")
        scrolls = self._w.recall(self._subject)
        verified = sum(1 for s in scrolls if self._w.verify(s).verified)
        return {"subject_id": self._subject, "total": len(scrolls), "verified": verified}


class MemoryGateway:
    """Issues per-subject ScopedMemory handles over ONE agent identity.

    An MCP session resolves a subject once and gets a ScopedMemory; every tool
    call in that session goes through the bound handle. Person recognition
    (voice/face handles resolving to a stable subject) is available via the
    underlying wrap when enabled.
    """

    def __init__(self, *, app: str = "mirra-mcp", home: Optional[str] = None,
                 profile: str = "dev_balanced", people: bool = True,
                 principal: Optional[str] = None):
        self._w = mirra.wrap(
            lambda m, c: "", principal=principal or f"app:{app}",
            home=home, profile=profile, recognize_persons=people,
        )

    @property
    def agent_id(self) -> str:
        return self._w.identity.agent_id

    def scope(self, subject_id: str) -> ScopedMemory:
        return ScopedMemory(self._w, subject_id)
