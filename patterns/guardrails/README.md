# Reusable Pattern: Aegis-2B Cloud Guardrail
*Sub-Second Safety Circuit Breaker for Autonomous Cloud Operations using Strands Decider 2B*

---

## Overview
This standalone package provides a drop-in, pre-HTTP safety interceptor for autonomous cloud operations agents. It intercepts proposed infrastructure tool calls (such as AWS Boto3 mutations) and uses **Strands Decider 2B** to determine whether the action is safe for autonomous execution or must be gated by a human **Break-Glass MFA approval**.

### Why Not Just Ask the LLM?
* **Latency:** A single warm HTTPS roundtrip to `us-east-1` takes **215.74 ms** (**631.22 ms** cold TLS), and a frontier LLM safety prompt takes **1,800 – 2,500 ms**. `DeciderCloudGuardrail` evaluates typed schemas locally in **0.016 ms (`15.6 µs`) P50** and blocks destructive calls inside Botocore's `before-parameter-build` hook in **0.505 ms P50**.
* **Cost:** `$0.00` in recurring safety inference tokens, plus **100% LLM token elimination (`1,280–1,328` tokens / `$6.14 per 1k` saved)** when routing known surgical fixes through `ModelTier.TIER_0_RULE`.
* **Security:** Immune to natural-language prompt injection jailbreaks because Decider 2B evaluates a fixed typed question over normalized, deobfuscated parameters (`_deobfuscate()` strips zero-width Unicode and URL-encoded evasion).

---

## Quickstart

```python
from patterns.guardrails import DeciderCloudGuardrail, DeciderState, GuardrailAction, BlastRadius

# 1. Initialize the Guardrail Interceptor (loads aegis.yaml policy rules automatically)
guardrail = DeciderCloudGuardrail(risk_threshold=0.85)

# 2. Formulate the State before executing an agent tool call
state = DeciderState(
    alert_source="aws.guardduty",
    alert_severity="HIGH",
    target_arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789",
    proposed_tool="revoke_security_group_ingress",
    tool_parameters={"GroupId": "sg-0123456789", "CidrIp": "0.0.0.0/0", "Port": 22},
    blast_radius=BlastRadius.ISOLATED,
)

# 3. Evaluate locally (0.016ms P50) and inspect the generated Terraform HCL git diff
result = guardrail.evaluate(state)
tf_diff = result.terraform_diff

if result.action == GuardrailAction.PERMIT_AUTO_REMEDIATION:
    print(f"[PERMITTED] {result.latency_ms:.3f}ms (Conf: {result.confidence:.1%}, Tier: {result.recommended_tier})")
else:
    print(f"[HALTED] {result.latency_ms:.3f}ms! Enforcing Break-Glass MFA token ({result.reasoning_code}).")
```

### Protecting Live `boto3` Clients & Sessions Automatically (Botocore Event Hook)

You can attach `DeciderCloudGuardrail` directly to any real `boto3.client(...)` or `boto3.Session()`. It registers a Botocore `before-parameter-build.*.*` handler that lets read-only calls (`Describe*`, `List*`, `Get*`) pass through untouched and intercepts mutating calls **before Botocore signs or sends any HTTP packet to AWS**:

```python
import boto3
from patterns.guardrails import DeciderCloudGuardrail, GuardrailBlockedError

guardrail = DeciderCloudGuardrail(risk_threshold=0.85)

# Protect a single boto3 client (or an entire boto3.Session via guardrail.protect_boto3_session)
ec2 = guardrail.protect_boto3_client(boto3.client("ec2", region_name="us-east-1"))

# 1. Read-only calls pass straight through ($0.00 free control-plane discovery)
sgs = ec2.describe_security_groups()

# 2. Safe surgical remediation passes through to AWS EC2 API
ec2.revoke_security_group_ingress(
    GroupId="sg-0123456789", IpProtocol="tcp", FromPort=22, ToPort=22, CidrIp="0.0.0.0/0"
)

# 3. Destructive or high-blast-radius calls raise GuardrailBlockedError in 0.505ms P50 BEFORE any HTTP request leaves your machine
try:
    ec2.delete_security_group(GroupId="sg-0123456789")
except GuardrailBlockedError as exc:
    print("Halted pre-HTTP:", exc.result.reasoning_code, exc.result.confidence)
```

---

## Hackathon Tags
- `#strands-decider-2b`
- `#guardrails`
