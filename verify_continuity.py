#!/usr/bin/env python
"""Continuity proof — Identity Continuity Spec v0.2 §9.

Checkout-layout shim. The proof itself lives in the installable package as
`mirra.verify_continuity` (console script: `verify-continuity`); this file
keeps the documented `python verify_continuity.py` invocation working from a
repo checkout, where the sibling `mirra-core-contract` repo may not be
pip-installed.

Usage:  python verify_continuity.py            (repo checkout)
        verify-continuity                      (installed from the wheel)
Exit code 0 = all seven proofs pass. Anything else = a claim does not hold.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))
try:
    import mirra_core_contract  # noqa: F401
except ImportError:  # sibling-repo layout during the restructure
    sys.path.insert(0, str(_REPO.parent / "mirra-core-contract"))

from mirra.verify_continuity import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
