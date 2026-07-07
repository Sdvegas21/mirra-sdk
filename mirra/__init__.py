"""mirra — the MIRRA platform SDK (Edge 1).

    import mirra
    wrapped = mirra.wrap(my_agent, principal="team-key-1")

One call gives any agent: a persistent recognized identity, tamper-evident
portable memory per relationship, behavior differentiated by each relationship's
history, and execution that only happens when verified. Built entirely on the
frozen v1 core contract (`mirra_core_contract`).
"""

from .continuity import ContinuityKernel, ContinuitySession, EmotionalBaseline
from .embodied import Actuation, ActuationDecision, EmbodiedAgent, Perception, PresentPerson
from .errors import ContinuityError, ExecutionRefused, IdentityError, MemoryUnavailable, MirraError
from .guard import GuardedAgent, guard
from .identity import LocalIdentityResolver
from .person import Person, PersonClaim, PersonRegistry
from .wrapper import WrappedAgent, wrap

__version__ = "0.7.0"

__all__ = [
    "guard",
    "GuardedAgent",
    "EmbodiedAgent",
    "Perception",
    "Actuation",
    "ActuationDecision",
    "PresentPerson",
    "wrap",
    "WrappedAgent",
    "LocalIdentityResolver",
    "ContinuityKernel",
    "ContinuitySession",
    "EmotionalBaseline",
    "Person",
    "PersonClaim",
    "PersonRegistry",
    "MirraError",
    "IdentityError",
    "MemoryUnavailable",
    "ContinuityError",
    "ExecutionRefused",
    "__version__",
]
