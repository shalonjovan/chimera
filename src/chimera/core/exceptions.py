class ChimeraError(Exception):
    """Base exception for all Chimera errors."""


class ConfigError(ChimeraError):
    """Configuration loading or validation error."""


class PluginError(ChimeraError):
    """Plugin loading or execution error."""


class PluginNotFoundError(PluginError):
    """Requested plugin is not registered."""


class ToolExecutionError(ChimeraError):
    """Tool execution failed."""


class SandboxError(ChimeraError):
    """Sandbox environment error."""


class MemoryError(ChimeraError):
    """Memory engine error."""


class KnowledgeError(ChimeraError):
    """Knowledge system error."""


class PlannerError(ChimeraError):
    """Planner error."""


class ChallengeError(ChimeraError):
    """Challenge lifecycle error."""


class ValidationError(ChimeraError):
    """Data validation error."""
