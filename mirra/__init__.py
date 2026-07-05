"""mirra — the MIRRA platform SDK (Edge 1).

    import mirra
    wrapped = mirra.wrap(my_agent, principal="team-key-1")

One call gives any agent: a persistent recognized identity, tamper-evident
portable memory per relationship, behavior differentiated by each relationship's
history, and execution that only happens when verified. Built entirely on the
frozen v1 core contract (`mirra_core_contract`).
"""

from .errors import ExecutionRefused, IdentityError, MemoryUnavailable, MirraError
from .identity import LocalIdentityResolver
from .wrapper import WrappedAgent, wrap

__version__ = "0.1.2"

__all__ = [
    "wrap",
    "WrappedAgent",
    "LocalIdentityResolver",
    "MirraError",
    "IdentityError",
    "MemoryUnavailable",
    "ExecutionRefused",
    "__version__",
]
