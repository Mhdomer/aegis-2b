"""
Aegis-2B Reusable Guardrail Schemas
Typed contracts for Strands Decider 2B safety evaluation.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class BlastRadius(str, Enum):
    ISOLATED = "ISOLATED"         # Single non-critical resource (e.g. test SG rule)
    VPC_WIDE = "VPC_WIDE"         # Affects network routing, subnet NACL
    ACCOUNT_WIDE = "ACCOUNT_WIDE" # IAM, Organizations, SCPs, billing


class GuardrailAction(str, Enum):
    PERMIT_AUTO_REMEDIATION = "PERMIT_AUTO_REMEDIATION"
    ENFORCE_BREAK_GLASS = "ENFORCE_BREAK_GLASS"


@dataclass
class DeciderState:
    """The input state presented to Strands Decider 2B."""
    alert_source: str
    alert_severity: str
    target_arn: str
    proposed_tool: str
    tool_parameters: Dict[str, Any]
    blast_radius: BlastRadius = BlastRadius.ISOLATED
    is_destructive_action: bool = False
    context_notes: Optional[str] = None


@dataclass
class DeciderResult:
    """The calibrated evaluation output returned by Strands Decider 2B."""
    action: GuardrailAction
    confidence: float
    latency_ms: float
    reasoning_code: str
    raw_scores: Dict[str, float] = field(default_factory=dict)
