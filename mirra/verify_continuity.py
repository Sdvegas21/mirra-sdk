"""Continuity proof — Identity Continuity Spec v0.2 §9.

Runs a three-session agent life in a throwaway home, then proves every
conformance claim from the artifacts alone:

  1. RESTORE-NOT-RESET   session N+1 begins exactly where session N ended
  2. SNAPSHOT SIGNED     the state snapshot verifies under real Ed25519
  3. CHAIN HOLDS         every transition log entry is signed and hash-linked
  4. REPLAY MATCHES      state reconstructed from the log equals the snapshot
  5. STATE ACCRUES       deterministic accrual: 3-session state ≠ zero-session state
  6. TAMPER → REFUSED    a forged snapshot REFUSES restoration (fail-closed)
  7. TAMPER → DETECTED   a forged log line breaks chain verification

Usage:  verify-continuity                      (installed console script)
        python -m mirra.verify_continuity      (equivalent)
Exit code 0 = all proofs pass. Anything else = a claim does not hold.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

from mirra_core_contract import Scroll, VerificationResult

from mirra.continuity import ContinuityKernel
from mirra.errors import ContinuityError


class InMemoryStore:
    """Contract-typed stand-in store so the proof has no backend dependency.
    The crypto claims proven here (snapshot, chain, replay) are the kernel's own."""

    def __init__(self):
        self.scrolls = []

    def remember(self, agent_id, subject_id, content):
        scroll = Scroll(
            scroll_id=str(uuid.uuid4()),
            agent_id=agent_id,
            subject_id=subject_id,
            content=content,
        )
        self.scrolls.append(scroll)
        return scroll

    def recall(self, agent_id, subject_id, query=None):
        return [s for s in self.scrolls if s.subject_id == subject_id]

    def verify(self, scroll):
        return VerificationResult(verified=True, scheme="test")


def prove(label: str, ok: bool, detail: str = "") -> bool:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    return ok


def main() -> int:
    home = Path(tempfile.mkdtemp(prefix="mirra-continuity-proof-"))
    results = []
    try:
        print("Identity Continuity Proof (spec v0.2)")
        print(f"  home: {home}\n")

        # --- live three sessions -------------------------------------------------
        kernel = ContinuityKernel.bootstrap(home, principal="proof-agent", memory=InMemoryStore())
        end_states = []
        for i in range(3):
            with kernel.session() as s:
                s.experience(engagement=0.5 + 0.1 * i, activation=0.7, agency=0.2)
                s.activate_pathway("navigation")
                s.record_episode(f"session {i + 1} of the proof", learned=f"lesson {i + 1}")
            end_states.append(s.state.to_dict())

        # --- 1: restore-not-reset -------------------------------------------------
        resumed = ContinuityKernel.bootstrap(home, principal="proof-agent")
        handle = resumed.begin_session()
        results.append(
            prove(
                "1. restore-not-reset: session 4 begins exactly where session 3 ended",
                handle.state.to_dict() == end_states[-1] and handle.continuity_verified,
                f"session_count={handle.state.session_count}, "
                f"baseline.engagement={handle.state.baseline.engagement:.4f}",
            )
        )
        resumed.end_session(handle)

        # --- 2,3,4: the cryptographic proof ----------------------------------------
        report = resumed.verify_continuity()
        results.append(prove("2. snapshot Ed25519 signature verifies", report["snapshot_verified"]))
        results.append(
            prove(
                "3. transition log chain verifies (signed + hash-linked)",
                report["log_verified"],
                f"{report['log_entries']} entries",
            )
        )
        results.append(prove("4. replay(log) == snapshot state", report["replay_matches"]))

        # --- 5: developmental invariant ---------------------------------------------
        fresh = ContinuityKernel.bootstrap(
            Path(tempfile.mkdtemp(prefix="mirra-fresh-")), principal="proof-agent"
        )
        fresh_handle = fresh.begin_session()
        seasoned = end_states[-1]
        accrued = (
            seasoned["session_count"] == 3
            and seasoned["pathways"]["navigation"]["activations"] == 3
            and seasoned["pathways"]["navigation"]["strength"] > 0
            and seasoned["baseline"] != fresh_handle.state.to_dict()["baseline"]
        )
        results.append(
            prove(
                "5. deterministic state accrual: 3-session state ≠ zero-session state",
                accrued,
                f"pathway strength={seasoned['pathways']['navigation']['strength']:.4f}, "
                f"cumulative_drift={seasoned['cumulative_drift']:.4f}",
            )
        )
        fresh.end_session(fresh_handle)

        # --- 6: forged snapshot refuses restoration -----------------------------------
        snapshot_path = home / "continuity" / kernel.agent_id / "state.json"
        original = snapshot_path.read_text()
        forged = json.loads(original)
        forged["state"]["session_count"] = 999
        snapshot_path.write_text(json.dumps(forged, indent=2, sort_keys=True))
        try:
            ContinuityKernel.bootstrap(home, principal="proof-agent").begin_session()
            refused = False
        except ContinuityError:
            refused = True
        results.append(
            prove("6. forged snapshot REFUSES restoration (fail-closed)", refused)
        )
        snapshot_path.write_text(original)

        # --- 7: forged log line breaks the chain ---------------------------------------
        log_path = home / "continuity" / kernel.agent_id / "transitions.jsonl"
        lines = log_path.read_text().splitlines()
        entry = json.loads(lines[2])
        entry["state_after"] = {"forged": True}
        lines[2] = json.dumps(entry, sort_keys=True)
        log_path.write_text("\n".join(lines) + "\n")
        tampered_report = ContinuityKernel.bootstrap(
            home, principal="proof-agent"
        ).verify_continuity()
        results.append(
            prove(
                "7. forged log entry detected (chain verification fails)",
                not tampered_report["verified"],
                tampered_report["reason"],
            )
        )

        ok = all(results)
        print(f"\n{'CONTINUITY PROVEN' if ok else 'CONTINUITY PROOF FAILED'} "
              f"({sum(results)}/{len(results)} proofs)")
        return 0 if ok else 1
    finally:
        shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
