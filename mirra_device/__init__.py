"""mirra_device — Edge 3 of the platform (on-device / embedded substrate).

The same frozen v1 contract, resource-bounded: Python stdlib ONLY (no engine
runtime, no web framework, no crypto extension modules), suitable for a
constrained target. Two things make this the "portable soul" edge:

1. Signature-compatible scrolls — the device store signs and verifies with the
   exact canonical QSEAL HMAC-SHA256 scheme the memory core uses, so a scroll
   signed on a device verifies on the SDK/gateway edges and vice versa.
2. Cross-device sync — export_bundle / import_bundle move signed scrolls
   between a user's devices; every scroll is verified on import, fail-closed.

Execution on-device is deny-by-default: an explicit owner allowlist, with the
core invariant (untrusted input + critical sink -> BLOCK) enforced locally and
every decision witnessed with a same-owner HMAC signature.
"""

from .core import DeviceAuthorizer, DeviceCore, DeviceIdentityResolver
from .qseal_lite import sign_scroll, verify_scroll
from .store import DeviceMemoryStore
from .sync import export_bundle, import_bundle

__version__ = "0.1.0"

__all__ = [
    "DeviceCore",
    "DeviceMemoryStore",
    "DeviceAuthorizer",
    "DeviceIdentityResolver",
    "sign_scroll",
    "verify_scroll",
    "export_bundle",
    "import_bundle",
    "__version__",
]
