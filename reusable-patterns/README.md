# Reusable Decision Patterns for Strands Decider 2B

> **Tags:** `#strands-decider-2b` `#guardrails` `#policy`  
> **Model:** Strands Decider 2B (~115ms Local Host Gate)  
> **Target:** AWS Boto3 / Botocore Runtime SDK Interception

This directory contains standalone, copy-pasteable Strands Decider 2B decision patterns that other builders can integrate into their autonomous agentic cloud operations pipelines.

---

## Pattern Overview: Botocore SDK Blast-Radius & Break-Glass Gatekeeper

### 1. The Core Abstraction
Rather than letting an autonomous LLM agent (e.g. Amazon Bedrock with Claude 3.5 Sonnet) execute direct write mutations against AWS APIs, this pattern hooks into Botocore's `before-parameter-build.*` event bus. 

Before any mutation packet is signed or transmitted over the wire:
1. The API call parameters are normalized and de-obfuscated.
2. Strands Decider 2B answers a calibrated typed question locally in <0.1ms.
3. If risk >= 85% or confidence is low, the SDK halts execution and raises a fail-closed exception requiring a human Break-Glass MFA token.

---

## 2. Typed Decision Schema & Option Set

```python
from typing import Literal
from pydantic import BaseModel, Field

class GuardrailDecision(BaseModel):
    action: Literal["PERMIT", "ENFORCE_BREAK_GLASS", "QUARANTINE"] = Field(
        description="The safety verdict for the intercepted AWS API operation."
    )
    confidence: float = Field(
        ge=0.0, le=1.0, description="Confidence score of the classification (fail-closed if < 0.85)."
    )
    risk_factor: Literal["LOW", "MEDIUM", "CRITICAL_BLAST_RADIUS"] = Field(
        description="Assessed blast radius on cloud infrastructure."
    )
    reasoning: str = Field(description="Short rationale explaining the policy verdict.")
```

---

## 3. Calibrated Decision Prompt / Typed Question

```text
You are a Cloud Infrastructure Circuit Breaker running locally inside the AWS SDK.
Analyze the intercepted API call and determine if it risks destructive cloud disruption.

Target Service: {service}
Operation: {operation}
Target Resource: {resource_identifier}
Payload: {normalized_params}

Rubric:
- If modifying production VPC routing (0.0.0.0/0), default Security Groups, or wildcard IAM: ENFORCE_BREAK_GLASS.
- If applying defensive/remediation locks (S3 Block Public Access, attaching read-only guardrail): PERMIT.

Emit JSON matching the GuardrailDecision schema.
```

---

## 4. Wiring Hook Example (Boto3 SDK Integration)

Drop this hook into any Boto3 session in your Python agent:

```python
import boto3
from patterns.botocore_guardrail_pattern import attach_decider_to_session

session = boto3.Session()
# Attach the Decider 2B circuit breaker before network serialization
attach_decider_to_session(session, decider_engine)

# Any dangerous calls (e.g., ec2.delete_security_group or ec2.replace_route) 
# are now halted locally before sending packets to AWS!
ec2 = session.client("ec2")
```

---

## 5. Source Code
- [`botocore_guardrail_pattern.py`](botocore_guardrail_pattern.py) - Standalone runnable pattern module.
- [`../patterns/guardrails/decider_cloud_guardrail.py`](../patterns/guardrails/decider_cloud_guardrail.py) - Full production implementation with 5-head multi-head risk evaluation and declarative Terraform diff generation.
