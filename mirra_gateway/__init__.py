"""mirra_gateway — Edge 2 of the platform (the hosted gateway).

The SAME core as the SDK edge, worn over a network boundary: agents call the
frozen v1 contract over HTTP with bearer-key auth, tenant isolation, and rate
limits. A scroll signed through the SDK verifies through the gateway and vice
versa — the signed portable memory unit is the seam.

    python -m mirra_gateway --config gateway.json

Fail-closed at the edge, same as the core: unauthenticated → 401, unknown
tenant → 401, over-limit → 429, engine missing → the decision is BLOCK.
"""

from .server import GatewayServer, make_server
from .tenants import RateLimiter, TenantRegistry, hash_api_key

__version__ = "0.1.0"

__all__ = [
    "GatewayServer",
    "make_server",
    "TenantRegistry",
    "RateLimiter",
    "hash_api_key",
    "__version__",
]
