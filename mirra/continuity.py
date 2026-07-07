"""mirra.continuity — the statefulness layer (Identity Continuity Spec v0.2).

Bridges the gap between a stateless model call and a stateful agent. A
ContinuityKernel gives any agent a sessioned life: state that is restored at
session start (verified, never silently reset), developed during the session,
and persisted at session end — signed, hash-chained, and replayable.

    kernel = ContinuityKernel.bootstrap(home, principal="team-key-1")
    with kernel.session() as s:                 # restore → verify → live
        s.experience(engagement=0.4, activation=0.6)
        s.activate_pathway("code_review")
        s.record_episode("Reviewed the auth PR", learned="prefers short diffs")
    # exit → baseline folded in, accrual persisted, narrative scroll written,
    # snapshot signed, transitions logged. Session N+1 begins as session N ended.

Everything is fail-closed and verifiable:

- The state snapshot is Ed25519-signed with the agent's own identity key. A
  snapshot that fails verification REFUSES restoration (ContinuityError) —
  a continuity kernel never silently starts an agent over from zero.
- Every state change is a governed transition in an append-only, hash-chained,
  per-entry-signed log (transitions.jsonl).
- Current state is reconstructible from the log alone (replay), and
  verify_continuity() proves snapshot + chain + replay agreement.

Vocabulary is deliberately neutral (engagement / activation / agency): this is
public infrastructure. Richer private state attaches behind the contract's
CapabilityProvider, never here.
"""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import ContinuityError

CONTRACT_VERSION = "v1"
SCHEME_ED25519 = "ed25519"
GENESIS_HASH = "genesis"

# Reserved subject for the agent's own narrative memory. Ordinary relationship
# memory is keyed per subject; the autobiography is the agent's memory of itself.
AUTOBIOGRAPHY_SUBJECT = "self.autobiography"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical(obj: Any) -> bytes:
    """Canonical JSON bytes — the ONE serialization every signature covers."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_ed25519(pubkey_hex: str, payload: bytes, signature_hex: str) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        key.verify(bytes.fromhex(signature_hex), payload)
        return True
    except Exception:
        return False


class IdentityKeySigner:
    """Signs continuity artifacts with the agent's existing identity key.

    The key is the one LocalIdentityResolver minted for this agent — continuity
    proofs are anchored to the SAME identity that recognition is. This class
    never generates keys: a missing or unreadable key is a hard stop, because a
    fresh key would sign a different agent's history.
    """

    def __init__(self, key_path: Path | str):
        path = Path(key_path)
        if not path.exists():
            raise ContinuityError(
                f"identity key missing: {path} — continuity requires the agent's "
                "identity key and never generates one"
            )
        try:
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        except Exception as exc:
            raise ContinuityError(f"identity key unreadable: {path} ({exc})") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise ContinuityError(f"identity key is not Ed25519: {path}")
        self._key = key
        raw = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        self._pubkey_hex = raw.hex()

    @classmethod
    def for_agent(cls, home: Path | str, agent_id: str) -> "IdentityKeySigner":
        slot = agent_id[len("agent-"):] if agent_id.startswith("agent-") else agent_id
        return cls(Path(home) / "identity" / f"{slot}.key")

    @property
    def public_key_hex(self) -> str:
        return self._pubkey_hex

    def sign(self, payload: bytes) -> str:
        return self._key.sign(payload).hex()


# ---------------------------------------------------------------------------
# State model (Identity Continuity Spec §1, §3, §5)
# ---------------------------------------------------------------------------


@dataclass
class EmotionalBaseline:
    """Affective baseline: engagement (valence), activation (arousal), agency
    (dominance). Persisted at session end, restored at session start — it
    shifts through experience and never resets to factory default."""

    engagement: float = 0.0  # [-1.0, 1.0]
    activation: float = 0.5  # [0.0, 1.0]
    agency: float = 0.0      # [-1.0, 1.0]

    def clamped(self) -> "EmotionalBaseline":
        return EmotionalBaseline(
            engagement=max(-1.0, min(1.0, self.engagement)),
            activation=max(0.0, min(1.0, self.activation)),
            agency=max(-1.0, min(1.0, self.agency)),
        )

    def blend(self, other: "EmotionalBaseline", rate: float) -> "EmotionalBaseline":
        """Exponential moving average toward `other`: baseline drifts, it does
        not jump. rate=0 keeps the baseline; rate=1 replaces it."""
        return EmotionalBaseline(
            engagement=(1 - rate) * self.engagement + rate * other.engagement,
            activation=(1 - rate) * self.activation + rate * other.activation,
            agency=(1 - rate) * self.agency + rate * other.agency,
        ).clamped()

    def distance(self, other: "EmotionalBaseline") -> float:
        return math.sqrt(
            (self.engagement - other.engagement) ** 2
            + (self.activation - other.activation) ** 2
            + (self.agency - other.agency) ** 2
        )

    def to_dict(self) -> dict[str, float]:
        return {
            "engagement": self.engagement,
            "activation": self.activation,
            "agency": self.agency,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EmotionalBaseline":
        return cls(
            engagement=float(data.get("engagement", 0.0)),
            activation=float(data.get("activation", 0.5)),
            agency=float(data.get("agency", 0.0)),
        )


@dataclass
class PathwayRecord:
    """Pathway accrual (§5): repeated activation strengthens a pathway's
    record. Strength saturates toward 1.0 — accrual is monotonic and bounded."""

    pathway_id: str
    activations: int = 0
    strength: float = 0.0
    first_activated: str = ""
    last_activated: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pathway_id": self.pathway_id,
            "activations": self.activations,
            "strength": self.strength,
            "first_activated": self.first_activated,
            "last_activated": self.last_activated,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PathwayRecord":
        return cls(
            pathway_id=str(data["pathway_id"]),
            activations=int(data.get("activations", 0)),
            strength=float(data.get("strength", 0.0)),
            first_activated=str(data.get("first_activated", "")),
            last_activated=str(data.get("last_activated", "")),
        )


def accrued_strength(activations: int, tau: float) -> float:
    """Saturating accrual: 1 - e^(-n/τ). Monotonic, bounded, auditable."""
    return 1.0 - math.exp(-activations / tau)


@dataclass
class ContinuityState:
    """The identity state that makes session N+1 the same agent as session N."""

    agent_id: str
    session_count: int = 0
    last_session_id: str = ""
    baseline: EmotionalBaseline = field(default_factory=EmotionalBaseline)
    long_term_baseline: EmotionalBaseline = field(default_factory=EmotionalBaseline)
    cumulative_drift: float = 0.0
    last_session_drift: float = 0.0
    pathways: dict[str, PathwayRecord] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": CONTRACT_VERSION,
            "agent_id": self.agent_id,
            "session_count": self.session_count,
            "last_session_id": self.last_session_id,
            "baseline": self.baseline.to_dict(),
            "long_term_baseline": self.long_term_baseline.to_dict(),
            "cumulative_drift": self.cumulative_drift,
            "last_session_drift": self.last_session_drift,
            "pathways": {pid: rec.to_dict() for pid, rec in sorted(self.pathways.items())},
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ContinuityState":
        return cls(
            agent_id=str(data["agent_id"]),
            session_count=int(data.get("session_count", 0)),
            last_session_id=str(data.get("last_session_id", "")),
            baseline=EmotionalBaseline.from_dict(data.get("baseline", {})),
            long_term_baseline=EmotionalBaseline.from_dict(data.get("long_term_baseline", {})),
            cumulative_drift=float(data.get("cumulative_drift", 0.0)),
            last_session_drift=float(data.get("last_session_drift", 0.0)),
            pathways={
                pid: PathwayRecord.from_dict(rec)
                for pid, rec in (data.get("pathways") or {}).items()
            },
            created_at=str(data.get("created_at", "")),
            updated_at=str(data.get("updated_at", "")),
        )


# ---------------------------------------------------------------------------
# Governed transitions (§6): append-only, hash-chained, per-entry signed
# ---------------------------------------------------------------------------


class TransitionLog:
    """Append-only signed transition log. Every entry carries the SHA-256 of
    the previous raw line (hash chain) and an Ed25519 signature over its own
    canonical form — tampering with any line breaks the chain behind it."""

    def __init__(self, path: Path, agent_id: str, signer: IdentityKeySigner, clock: Callable[[], str]):
        self._path = path
        self._agent_id = agent_id
        self._signer = signer
        self._clock = clock
        self._prev_hash = self._tail_hash()

    def _tail_hash(self) -> str:
        if not self._path.exists():
            return GENESIS_HASH
        last = None
        with self._path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = line
        if last is None:
            return GENESIS_HASH
        return hashlib.sha256(last.encode("utf-8")).hexdigest()

    def append(
        self,
        transition_type: str,
        session_id: str,
        state_before: Optional[dict[str, Any]],
        state_after: Optional[dict[str, Any]],
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "contract_version": CONTRACT_VERSION,
            "transition_id": str(uuid.uuid4()),
            "agent_id": self._agent_id,
            "session_id": session_id,
            "transition_type": transition_type,
            "state_before": state_before,
            "state_after": state_after,
            "timestamp": self._clock(),
            "prev_hash": self._prev_hash,
            "pubkey": self._signer.public_key_hex,
            "scheme": SCHEME_ED25519,
        }
        entry["signature"] = self._signer.sign(canonical(entry))
        line = json.dumps(entry, sort_keys=True)
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        self._prev_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
        return entry

    def entries(self) -> list[dict[str, Any]]:
        if not self._path.exists():
            return []
        out = []
        with self._path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def query(
        self,
        session_id: Optional[str] = None,
        transition_type: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        result = []
        for entry in self.entries():
            if session_id is not None and entry.get("session_id") != session_id:
                continue
            if transition_type is not None and entry.get("transition_type") != transition_type:
                continue
            ts = entry.get("timestamp", "")
            if since is not None and ts < since:
                continue
            if until is not None and ts > until:
                continue
            result.append(entry)
        return result

    def verify(self) -> dict[str, Any]:
        """Walk the chain: every prev_hash must link, every signature must hold."""
        if not self._path.exists():
            return {"verified": True, "entries": 0, "reason": "empty log"}
        prev_hash = GENESIS_HASH
        count = 0
        with self._path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except Exception:
                    return {"verified": False, "entries": count, "reason": f"line {lineno}: unparseable"}
                if entry.get("prev_hash") != prev_hash:
                    return {"verified": False, "entries": count, "reason": f"line {lineno}: chain break"}
                signature = entry.pop("signature", "")
                if not verify_ed25519(entry.get("pubkey", ""), canonical(entry), signature):
                    return {"verified": False, "entries": count, "reason": f"line {lineno}: bad signature"}
                prev_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
                count += 1
        return {"verified": True, "entries": count, "reason": ""}


# ---------------------------------------------------------------------------
# Session handle (the live state between begin_session and end_session)
# ---------------------------------------------------------------------------


class ContinuitySession:
    """One lived session. Accumulates experience, pathway activations, and
    episodes; the kernel folds it all into persistent state at end_session."""

    def __init__(
        self,
        kernel: "ContinuityKernel",
        state: ContinuityState,
        session_id: str,
        continuity_verified: bool,
        snapshot_signature: str,
        started_at: str,
    ):
        self._kernel = kernel
        self.state = state
        self.session_id = session_id
        self.continuity_verified = continuity_verified
        self.snapshot_signature = snapshot_signature
        self.started_at = started_at
        self.closed = False
        self._samples: list[dict[str, Any]] = []
        self._pathway_buffer: dict[str, dict[str, Any]] = {}
        self._episodic: list[dict[str, Any]] = []
        self._semantic: list[dict[str, Any]] = []
        self._relationships: dict[str, dict[str, Any]] = {}

    # -- lived experience -----------------------------------------------------

    def current_affect(self) -> EmotionalBaseline:
        """Where the agent is right now: the latest sample, or the restored
        baseline if nothing has happened yet this session."""
        if self._samples:
            return EmotionalBaseline.from_dict(self._samples[-1])
        return self.state.baseline

    def experience(
        self,
        engagement: Optional[float] = None,
        activation: Optional[float] = None,
        agency: Optional[float] = None,
        weight: float = 1.0,
    ) -> EmotionalBaseline:
        """Record an affect sample. Unspecified dimensions hold their current
        value — an experience can move one axis without inventing the others."""
        current = self.current_affect()
        sample = EmotionalBaseline(
            engagement=current.engagement if engagement is None else float(engagement),
            activation=current.activation if activation is None else float(activation),
            agency=current.agency if agency is None else float(agency),
        ).clamped()
        self._samples.append(
            {**sample.to_dict(), "weight": max(0.0, float(weight)), "at": self._kernel.clock()}
        )
        return sample

    def activate_pathway(self, pathway_id: str) -> PathwayRecord:
        """Pathway accrual (§5): each activation strengthens the pathway record.
        Logged immediately as a governed transition; folded into persistent
        state at session end."""
        now = self._kernel.clock()
        buf = self._pathway_buffer.setdefault(pathway_id, {"count": 0, "first_at": now})
        persisted = self.state.pathways.get(pathway_id)
        before_activations = (persisted.activations if persisted else 0) + buf["count"]
        buf["count"] += 1
        buf["last_at"] = now
        after_activations = before_activations + 1
        projected = PathwayRecord(
            pathway_id=pathway_id,
            activations=after_activations,
            strength=accrued_strength(after_activations, self._kernel.pathway_tau),
            first_activated=(persisted.first_activated if persisted else buf["first_at"]),
            last_activated=now,
        )
        self._kernel._log.append(
            "pathway_activation",
            self.session_id,
            state_before={
                "pathway_id": pathway_id,
                "activations": before_activations,
                "strength": accrued_strength(before_activations, self._kernel.pathway_tau),
            },
            state_after=projected.to_dict(),
        )
        return projected

    def record_episode(
        self,
        what_happened: str,
        learned: Optional[str] = None,
        verbatim: Optional[str] = None,
        significance: float = 0.5,
    ) -> None:
        """Autobiographical memory formation (§4): episodic (what happened,
        with verbatim preserved separately) and semantic (what was learned),
        each tagged with the emotional state at formation time."""
        now = self._kernel.clock()
        affect = self.current_affect().to_dict()
        self._episodic.append(
            {
                "what_happened": what_happened,
                "verbatim": verbatim,
                "significance": max(0.0, min(1.0, float(significance))),
                "at": now,
                "emotional_state": affect,
            }
        )
        if learned:
            self._semantic.append({"learned": learned, "at": now, "emotional_state": affect})

    def note_relationship(self, subject_id: str, learning: Optional[str] = None) -> None:
        """Relational context (§2.1.4): who this session was lived with, and
        what was learned about them."""
        rel = self._relationships.setdefault(subject_id, {"touches": 0, "learnings": []})
        rel["touches"] += 1
        if learning:
            rel["learnings"].append(learning)

    # -- verifiable identity context (§8) --------------------------------------

    def identity_context(self) -> dict[str, Any]:
        return {
            "agent_id": self.state.agent_id,
            "continuity_verified": self.continuity_verified,
            "session_count": self.state.session_count,
            "identity_signature": self.snapshot_signature,
            "trust_established": (
                self.continuity_verified
                and self.state.session_count >= self._kernel.trust_threshold
            ),
        }

    # -- internal: session arithmetic ------------------------------------------

    def _session_mean(self) -> Optional[EmotionalBaseline]:
        if not self._samples:
            return None
        total = sum(s["weight"] for s in self._samples)
        if total <= 0:
            return None
        return EmotionalBaseline(
            engagement=sum(s["engagement"] * s["weight"] for s in self._samples) / total,
            activation=sum(s["activation"] * s["weight"] for s in self._samples) / total,
            agency=sum(s["agency"] * s["weight"] for s in self._samples) / total,
        )

    def _within_session_rate(self) -> float:
        """Mean step-to-step affect movement within the session (§3.2)."""
        if len(self._samples) < 2:
            return 0.0
        steps = []
        for prev, cur in zip(self._samples, self._samples[1:]):
            steps.append(
                EmotionalBaseline.from_dict(prev).distance(EmotionalBaseline.from_dict(cur))
            )
        return sum(steps) / len(steps)


# ---------------------------------------------------------------------------
# The kernel
# ---------------------------------------------------------------------------


class ContinuityKernel:
    """The session lifecycle engine that makes an agent identity-continuous.

    begin_session(): load the signed snapshot, VERIFY it (snapshot signature,
    transition chain, replay agreement — all fail-closed), restore state —
    never a blank default. end_session(): fold the session's affect samples
    into the baseline, persist pathway accrual, write the autobiographical
    narrative to signed memory, sign a new snapshot, and log the transition.

    The guarantee: the agent that begins session N+1 is the agent that ended
    session N — and `verify_continuity()` proves it from the artifacts alone.
    """

    def __init__(
        self,
        home: Path | str,
        agent_id: str,
        *,
        signer: Optional[IdentityKeySigner] = None,
        memory: Any = None,
        learning_rate: float = 0.15,
        longterm_rate: float = 0.02,
        trust_threshold: int = 3,
        pathway_tau: float = 8.0,
        clock: Optional[Callable[[], str]] = None,
    ):
        self._home = Path(home)
        self.agent_id = agent_id
        self._dir = self._home / "continuity" / agent_id
        self._dir.mkdir(parents=True, exist_ok=True)
        self._signer = signer or IdentityKeySigner.for_agent(self._home, agent_id)
        self._memory = memory
        self.learning_rate = learning_rate
        self.longterm_rate = longterm_rate
        self.trust_threshold = trust_threshold
        self.pathway_tau = pathway_tau
        self.clock = clock or _now
        self._snapshot_path = self._dir / "state.json"
        self._log = TransitionLog(self._dir / "transitions.jsonl", agent_id, self._signer, self.clock)
        self._active: Optional[ContinuitySession] = None

    @classmethod
    def bootstrap(cls, home: Path | str, principal: Any, **kwargs: Any) -> "ContinuityKernel":
        """Standalone entry point for any agent: mint (or load) the identity
        for this principal, then build its continuity kernel."""
        from .identity import LocalIdentityResolver

        identity = LocalIdentityResolver(home).resolve_identity(principal)
        return cls(home, identity.agent_id, **kwargs)

    @property
    def transition_log(self) -> TransitionLog:
        return self._log

    # -- snapshot I/O -----------------------------------------------------------

    def _write_snapshot(self, state: ContinuityState) -> str:
        state_dict = state.to_dict()
        signature = self._signer.sign(canonical(state_dict))
        document = {
            "contract_version": CONTRACT_VERSION,
            "state": state_dict,
            "scheme": SCHEME_ED25519,
            "pubkey": self._signer.public_key_hex,
            "signature": signature,
        }
        self._snapshot_path.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
        return signature

    def _read_snapshot(self) -> Optional[tuple[ContinuityState, str]]:
        """Load and VERIFY the snapshot. Returns None when no state exists yet
        (genesis). Raises ContinuityError on any verification failure — a state
        that cannot be verified is never restored."""
        if not self._snapshot_path.exists():
            return None
        try:
            document = json.loads(self._snapshot_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ContinuityError(f"continuity snapshot unreadable: {self._snapshot_path} ({exc})") from exc
        state_dict = document.get("state")
        signature = document.get("signature", "")
        pubkey = document.get("pubkey", "")
        if not isinstance(state_dict, dict) or not signature:
            raise ContinuityError(f"continuity snapshot malformed: {self._snapshot_path}")
        if pubkey != self._signer.public_key_hex:
            raise ContinuityError(
                "continuity snapshot was signed by a different identity key — refusing restoration"
            )
        if not verify_ed25519(pubkey, canonical(state_dict), signature):
            raise ContinuityError(
                "continuity snapshot failed signature verification — refusing restoration"
            )
        return ContinuityState.from_dict(state_dict), signature

    # -- session lifecycle (§2) ---------------------------------------------------

    def begin_session(self, session_id: Optional[str] = None) -> ContinuitySession:
        if self._active is not None:
            raise ContinuityError("a session is already active for this kernel")
        loaded = self._read_snapshot()
        if loaded is None:
            if self._log.entries():
                raise ContinuityError(
                    "transition log exists but snapshot is missing — refusing to "
                    "re-genesis over an agent's history"
                )
            now = self.clock()
            state = ContinuityState(agent_id=self.agent_id, created_at=now, updated_at=now)
            signature = self._write_snapshot(state)
            self._log.append("genesis", "", state_before=None, state_after=state.to_dict())
            continuity_verified = False  # nothing prior existed to verify
        else:
            state, signature = loaded
            # Restoration verifies the whole record, not just the snapshot:
            # the chain must hold and must reproduce the exact snapshot state.
            # This refuses rollback (an old-but-validly-signed snapshot) and
            # truncation, not only direct forgery.
            log_report = self._log.verify()
            if not log_report["verified"]:
                raise ContinuityError(
                    f"transition log failed verification — refusing restoration "
                    f"({log_report['reason']})"
                )
            if self.replay() != state.to_dict():
                raise ContinuityError(
                    "transition log does not reproduce the snapshot — refusing "
                    "restoration (possible rollback or truncation)"
                )
            continuity_verified = True
        sid = session_id or f"session-{uuid.uuid4().hex[:12]}"
        self._log.append(
            "session_start",
            sid,
            state_before=None,
            state_after={
                "continuity_ref": state.last_session_id,
                "continuity_verified": continuity_verified,
                "session_count": state.session_count,
            },
        )
        handle = ContinuitySession(
            kernel=self,
            state=state,
            session_id=sid,
            continuity_verified=continuity_verified,
            snapshot_signature=signature,
            started_at=self.clock(),
        )
        self._active = handle
        return handle

    def end_session(self, handle: ContinuitySession) -> ContinuityState:
        if handle.closed:
            raise ContinuityError("session already ended")
        if handle is not self._active:
            raise ContinuityError("session handle is not the active session for this kernel")
        state = handle.state
        now = self.clock()
        before = {
            "session_count": state.session_count,
            "baseline": state.baseline.to_dict(),
            "cumulative_drift": state.cumulative_drift,
        }

        # 1. Fold lived affect into the baseline (EWMA drift, never a jump).
        baseline_before = state.baseline
        session_mean = handle._session_mean()
        if session_mean is not None:
            state.baseline = state.baseline.blend(session_mean, self.learning_rate)
            state.long_term_baseline = state.long_term_baseline.blend(
                state.baseline, self.longterm_rate
            )
        drift_step = baseline_before.distance(state.baseline)
        state.cumulative_drift += drift_step
        state.last_session_drift = drift_step

        # 2. Persist pathway accrual (buffered activations → records).
        for pathway_id, buf in handle._pathway_buffer.items():
            record = state.pathways.get(pathway_id) or PathwayRecord(
                pathway_id=pathway_id, first_activated=buf["first_at"]
            )
            record.activations += buf["count"]
            record.strength = accrued_strength(record.activations, self.pathway_tau)
            record.last_activated = buf.get("last_at", now)
            state.pathways[pathway_id] = record

        # 3. Session bookkeeping.
        state.session_count += 1
        state.last_session_id = handle.session_id
        state.updated_at = now

        # 4. Autobiographical narrative → signed memory (if a store is attached).
        if self._memory is not None:
            narrative = {
                "kind": "autobiographical_session",
                "session_id": handle.session_id,
                "session_index": state.session_count,
                "started_at": handle.started_at,
                "ended_at": now,
                "episodic": handle._episodic,
                "semantic": handle._semantic,
                "relationships": handle._relationships,
                "affect": {
                    "baseline_before": baseline_before.to_dict(),
                    "baseline_after": state.baseline.to_dict(),
                    "session_drift": drift_step,
                    "within_session_rate": handle._within_session_rate(),
                },
                "pathways_activated": {
                    pid: buf["count"] for pid, buf in sorted(handle._pathway_buffer.items())
                },
            }
            self._memory.remember(
                self.agent_id,
                AUTOBIOGRAPHY_SUBJECT,
                json.dumps(narrative, sort_keys=True),
            )

        # 5. Sign the new snapshot, then log the governed transition.
        handle.snapshot_signature = self._write_snapshot(state)
        self._log.append("session_end", handle.session_id, state_before=before, state_after=state.to_dict())
        handle.closed = True
        self._active = None
        return state

    @contextmanager
    def session(self, session_id: Optional[str] = None):
        handle = self.begin_session(session_id)
        try:
            yield handle
        finally:
            if not handle.closed:
                self.end_session(handle)

    # -- inspection & verification -------------------------------------------------

    def identity_context(self) -> dict[str, Any]:
        """Spec §8 identity context from persisted state, without opening a
        session. Advisory read: an unverifiable snapshot reports untrusted
        (restoration, by contrast, hard-fails)."""
        try:
            loaded = self._read_snapshot()
        except ContinuityError as exc:
            return {
                "agent_id": self.agent_id,
                "continuity_verified": False,
                "session_count": 0,
                "identity_signature": "",
                "trust_established": False,
                "reason": str(exc),
            }
        if loaded is None:
            return {
                "agent_id": self.agent_id,
                "continuity_verified": False,
                "session_count": 0,
                "identity_signature": "",
                "trust_established": False,
            }
        state, signature = loaded
        return {
            "agent_id": self.agent_id,
            "continuity_verified": True,
            "session_count": state.session_count,
            "identity_signature": signature,
            "trust_established": state.session_count >= self.trust_threshold,
        }

    def recall_autobiography(
        self,
        query: Optional[str] = None,
        affect: Optional[EmotionalBaseline] = None,
        limit: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """Retrieve the agent's narrative (§4.1.4): backend query for semantic
        match, recency ordering by default, emotional-resonance ordering when
        an affect probe is given. Only verified scrolls are ever returned —
        recall is verify-on-read in the underlying store."""
        if self._memory is None:
            return []
        scrolls = self._memory.recall(self.agent_id, AUTOBIOGRAPHY_SUBJECT, query)
        records = []
        for scroll in scrolls:
            try:
                record = json.loads(str(getattr(scroll, "content", scroll)))
            except Exception:
                continue
            if isinstance(record, dict) and record.get("kind") == "autobiographical_session":
                records.append(record)
        if affect is not None:
            def resonance(record: dict[str, Any]) -> float:
                tagged = EmotionalBaseline.from_dict(
                    (record.get("affect") or {}).get("baseline_after", {})
                )
                return affect.distance(tagged)

            records.sort(key=resonance)
        else:
            records.sort(key=lambda r: r.get("ended_at", ""), reverse=True)
        return records[:limit] if limit else records

    def replay(self) -> Optional[dict[str, Any]]:
        """Reconstruct current state from the transition log alone (§6.2.3).
        Full-state transitions (genesis, session_end) carry the complete state;
        per-activation entries are the audit trail of how it got there."""
        state_dict: Optional[dict[str, Any]] = None
        for entry in self._log.entries():
            if entry.get("transition_type") in ("genesis", "session_end"):
                state_dict = entry.get("state_after")
        return state_dict

    def verify_continuity(self) -> dict[str, Any]:
        """The continuity proof: snapshot signature holds, transition chain
        holds, and replaying the log reproduces the exact current state."""
        report: dict[str, Any] = {
            "agent_id": self.agent_id,
            "snapshot_verified": False,
            "log_verified": False,
            "log_entries": 0,
            "replay_matches": False,
            "session_count": 0,
            "verified": False,
            "reason": "",
        }
        if not self._snapshot_path.exists():
            report["reason"] = "no continuity state exists yet"
            return report
        try:
            document = json.loads(self._snapshot_path.read_text(encoding="utf-8"))
            state_dict = document.get("state") or {}
            snapshot_ok = verify_ed25519(
                document.get("pubkey", ""), canonical(state_dict), document.get("signature", "")
            )
        except Exception as exc:
            report["reason"] = f"snapshot unreadable: {exc}"
            return report
        report["snapshot_verified"] = snapshot_ok
        report["session_count"] = int(state_dict.get("session_count", 0))

        log_report = self._log.verify()
        report["log_verified"] = bool(log_report["verified"])
        report["log_entries"] = int(log_report["entries"])

        replayed = self.replay() if report["log_verified"] else None
        report["replay_matches"] = replayed is not None and replayed == state_dict

        report["verified"] = (
            report["snapshot_verified"] and report["log_verified"] and report["replay_matches"]
        )
        if not report["verified"]:
            reasons = []
            if not report["snapshot_verified"]:
                reasons.append("snapshot signature invalid")
            if not report["log_verified"]:
                reasons.append(f"transition log: {log_report['reason']}")
            if not report["replay_matches"]:
                reasons.append("replayed state does not match snapshot")
            report["reason"] = "; ".join(reasons)
        return report
