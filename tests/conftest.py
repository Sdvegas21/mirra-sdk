"""Test wiring: put the core components on sys.path.

During the restructure the components live as sibling repos. Each location is
overridable via environment variable so CI can point anywhere. This is test
scaffolding only — the SDK itself never assumes folder layout; it imports
installed packages.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_SDK_REPO = Path(__file__).resolve().parents[1]
_WORKSPACE = _SDK_REPO.parent

_COMPONENT_PATHS = [
    ("MIRRA_CONTRACT_PATH", _WORKSPACE / "mirra-core-contract"),
    ("MVAR_PATH", _WORKSPACE / "MIRRA_LLM_BRIDGE_v1" / "mvar"),
    ("CLAWZERO_PATH", _WORKSPACE / "MIRRA_LLM_BRIDGE_v1" / "clawzero" / "src"),
    ("CLAWSEAL_PATH", _WORKSPACE / "mirra-second-brain"),
]

for env_name, default in _COMPONENT_PATHS:
    candidate = Path(os.environ.get(env_name, default))
    if candidate.exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

if str(_SDK_REPO) not in sys.path:
    sys.path.insert(0, str(_SDK_REPO))


@pytest.fixture()
def sdk_home(tmp_path):
    """A throwaway SDK home so tests never touch ~/.mirra."""
    return tmp_path / "mirra-home"


@pytest.fixture()
def echo_agent():
    def agent(message, context):
        return f"echo({context['subject_id']}, seen={len(context['history'])}): {message}"

    return agent
