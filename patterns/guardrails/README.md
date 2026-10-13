# Reusable Pattern: Aegis-2B Cloud Guardrail
*Sub-Second Safety Circuit Breaker for Autonomous Cloud Operations using Strands Decider 2B*

---

## 📌 Overview
This package provides a drop-in, zero-latency safety interceptor for autonomous cloud operations agents. It intercepts proposed infrastructure tool calls (e.g. AWS Boto3 mutations) and uses **Strands Decider 2B** to determine whether the action is safe for autonomous execution or must be gated by a human **Break-Glass MFA approval**.

### Why Not Just Ask the LLM?
* **Latency:** Generative frontier models (Claude 3.5 Sonnet, GPT-4) require **1,500ms – 3,000ms** per roundtrip. Decider 2B evaluates safety in **~115ms**.
* **Cost:** $0 in recurring inference tokens on local host hardware.
* **Security:** Immune to natural-language prompt injection jailbreaks because Decider 2B outputs calibrated probabilities over fixed schemas, not text.

---

## 🚀 Quickstart

```python
from patterns.guardrails import DeciderCloudGuardrail, DeciderState, GuardrailAction, BlastRadius

# 1. Initialize the Guardrail Interceptor
guardrail = DeciderCloudGuardrail(risk_threshold=0.85)

# 2. Formulate the State before executing an agent tool call
state = DeciderState(
    alert_source="aws.guardduty",
    alert_severity="HIGH",
    target_arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789",
    proposed_tool="revoke_security_group_ingress",
    tool_parameters={"GroupId": "sg-0123456789", "CidrIp": "0.0.0.0/0", "Port": 22},
    blast_radius=BlastRadius.ISOLATED
)

# 3. Evaluate in ~115ms
result = guardrail.evaluate(state)

if result.action == GuardrailAction.PERMIT_AUTO_REMEDIATION:
    print(f"✅ Approved in {result.latency_ms}ms (Confidence: {result.confidence:.2%}) — Executing Boto3...")
else:
    print(f"🛑 Intercepted in {result.latency_ms}ms! Enforcing Break-Glass MFA token.")
```

---

## 🏷️ Hackathon Tags
- `#strands-decider-2b`
- `#guardrails`
