"""Framework adapters — give a whole agent the four pillars in its native idioms.

The public enforcement adapters (ClawZero, MVAR) wrap individual *tools* for
block/allow. These adapters wrap the whole *agent*: recognition, signed memory,
per-relationship behavior, AND enforcement, composed over the same frozen v1
contract the SDK speaks.

Each framework's adapter is import-guarded — importing this package never
requires the framework to be installed. Ask for the one you use:

    from mirra.adapters.langchain import wrap_agent
"""

__all__ = ["langchain", "llamaindex", "openai_agents", "crewai"]
