"""
Aegis-2B Package Root
Sub-Second Safety Circuit Breaker for Autonomous Cloud Ops Agents.
"""

from patterns.guardrails import (
    BlastRadius,
    DeciderCloudGuardrail,
    DeciderResult,
    DeciderState,
    GuardrailAction,
    GuardrailBlockedError,
    load_policy_as_code,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "BlastRadius",
    "DeciderCloudGuardrail",
    "DeciderResult",
    "DeciderState",
    "GuardrailAction",
    "GuardrailBlockedError",
    "load_policy_as_code",
]
