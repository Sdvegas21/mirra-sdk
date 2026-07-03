"""Acceptance: Boundary integrity — the public/private leak gate passes on the SDK."""

import os
import subprocess
import sys
from pathlib import Path

SDK_REPO = Path(__file__).resolve().parents[1]
GATE = Path(
    os.environ.get("MIRRA_CONTRACT_PATH", SDK_REPO.parent / "mirra-core-contract")
) / "scripts" / "check_public_private_boundary.py"


def _run_gate(*targets: Path):
    return subprocess.run(
        [sys.executable, str(GATE), *map(str, targets)],
        capture_output=True,
        text=True,
    )


def test_leak_gate_passes_on_sdk_package():
    assert GATE.exists(), f"leak gate script not found at {GATE}"
    result = _run_gate(SDK_REPO / "mirra")
    assert result.returncode == 0, f"leak gate failed:\n{result.stdout}\n{result.stderr}"


def test_leak_gate_passes_on_all_public_surfaces():
    result = _run_gate(SDK_REPO / "mirra", SDK_REPO / "mirra_gateway",
                       SDK_REPO / "mirra_device", SDK_REPO / "tests", SDK_REPO / "demo")
    assert result.returncode == 0, f"leak gate failed:\n{result.stdout}\n{result.stderr}"
