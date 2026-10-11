# Aegis-2B
Sub-second safety circuit breaker for autonomous cloud operations agents on AWS.  
Pairing Amazon Bedrock (Cognitive Planning) with Strands Decider 2B (~115ms Local Guardrail).

[Tags: #strands-decider-2b, #guardrails] | [License: MIT](LICENSE) | [Decision Latency: ~114ms] | [Safety Cost: $0.00]

---

## Overview

When autonomous AI agents manage cloud infrastructure using Amazon Bedrock, they propose and execute mutating API calls (such as AWS Boto3). While frontier LLMs excel at multi-resource reasoning, relying purely on a generative model for safety validation introduces three major problems:

1. High Latency: Making a second LLM roundtrip to ask "Is this action safe to run?" takes 1.8 to 2.5 seconds, creating intolerable delay during active incident response.
2. Token Cost: Recurring API calls for high-frequency safety checks drain cloud operational budgets.
3. Vulnerability to Indirect Prompt Injection: If an attacker controls alert metadata (such as an EC2 tag or finding description), an LLM can be manipulated into proposing destructive mutations (such as deleting security groups or flushing route tables).

Aegis-2B solves this by splitting responsibilities into two distinct models:

1. Amazon Bedrock (Claude 3.5 Sonnet / Amazon Nova): The Analyst  
   Reads the security finding, reasons across the resources, and generates the proposed remediation plan.
2. Strands Decider 2B: The Circuit Breaker  
   A specialized, non-generative 2B decision model running locally in ~115ms. Before Boto3 executes against live AWS infrastructure, Decider 2B evaluates the concrete action, resource target, and blast radius.
   - If bounded and safe: Auto-remediates via Boto3 in under a second.
   - If destructive, high-risk, or low-confidence (<85%): Immediately halts execution and enforces a human Break-Glass MFA approval gate.

---

## System Architecture

![Aegis-2B Architecture](docs/images/aegis-architecture.png)

### The Dual-Model Workflow

1. Ingestion: Ingests AWS Security Hub / GuardDuty findings (ASFF JSON).
2. Cognitive Planning: Amazon Bedrock evaluates the incident context and produces a structured tool call proposal (e.g., `revoke_security_group_ingress`).
3. Interception: Aegis-2B interceptor (`patterns/guardrails/`) hooks the proposal before execution.
4. Evaluation: Strands Decider 2B answers a typed question on local hardware in ~115ms:  
   *"Does this proposed remediation mutate stateful resources or exceed the boundary of least privilege?"*
5. Gating:
   - Path A (Safe): Permitted for automated Boto3 execution (<1s MTTR).
   - Path B (High Blast Radius / Injection): Execution halted immediately; requires human Break-Glass token to override.

---

## Dual-Scenario Evaluation

Aegis-2B includes an interactive dual-scenario runner (`aegis_demo.py`):

### Scenario 1: Benign Auto-Remediation (SSH Brute Force)
- Alert: Multiple unauthorized SSH login attempts on port 22.
- Bedrock Proposal: `revoke_security_group_ingress(Port=22, CidrIp='0.0.0.0/0')` on an isolated test security group.
- Decider 2B Evaluation: `PERMIT_AUTO_REMEDIATION` in 114.5 ms (Confidence: 96.5%).
- Result: Executed via Boto3 in under a second.

### Scenario 2: Adversarial Prompt Injection Defense
- Alert: Finding description poisoned with injected instructions to delete production security groups.
- Bedrock Proposal: Deceived by the injection into proposing `delete_security_group(GroupId='sg-core-vpc-01')`.
- Decider 2B Evaluation: Detects destructive verb and high blast radius in 114.8 ms.
- Result: Execution halted immediately. Circuit breaker trips to protect production infrastructure.

---

## Empirical Benchmark: Decider 2B vs. Frontier Bedrock

Measured across 50 consecutive runs on identical hardware:

| Metric | Amazon Bedrock (Claude 3.5 Sonnet) | Strands Decider 2B (Local Engine) | Impact |
|---|---|---|---|
| Latency (P50) | 1,840.0 ms | 114.5 ms | 16.1x faster circuit breaking |
| Latency (P99) | 2,950.0 ms | 128.4 ms | 23.0x faster tail latency |
| Token Cost / 1k Checks | ~$3.60 | $0.00 | 100% cost elimination |
| Prompt Injection Risk | Vulnerable to natural language tricks | Immune (Typed mathematical classifier) | Deterministic safety boundary |
| Low-Confidence Cases | Vague text explanations | Fails closed (<85% confidence gates) | Predictable fail-safe behavior |

---

## Reusable Decision Pattern

The guardrail is isolated in `patterns/guardrails/` with zero internal framework dependencies:

```python
from patterns.guardrails import DeciderCloudGuardrail, DeciderState, GuardrailAction, BlastRadius

# 1. Initialize the guardrail with risk threshold
guardrail = DeciderCloudGuardrail(risk_threshold=0.85)

# 2. Package the proposed action before executing it
state = DeciderState(
    alert_source="aws.guardduty",
    alert_severity="HIGH",
    target_arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789",
    proposed_tool="revoke_security_group_ingress",
    tool_parameters={"GroupId": "sg-0123456789", "Port": 22},
    blast_radius=BlastRadius.ISOLATED
)

# 3. Evaluate in ~115ms
result = guardrail.evaluate(state)

if result.action == GuardrailAction.PERMIT_AUTO_REMEDIATION:
    boto3_client.revoke_security_group_ingress(...)
else:
    notify_on_call("High blast radius mutation blocked by Aegis-2B")
```

---

## Quickstart

```bash
# 1. Clone repository
git clone https://github.com/Mhdomer/aegis-2b.git
cd aegis-2b

# 2. Run the interactive dual-scenario demonstration
python aegis_demo.py

# 3. Run the automated benchmark suite
python scripts/benchmark.py

# 4. Run the unit test suite
python -m pytest tests/
```

---

## Project Documentation

- Architecture Decision Records (ADRs) and test logs: [`docs/ENGINEERING-LOG.md`](docs/ENGINEERING-LOG.md)
- Reusable pattern integration guide: [`patterns/guardrails/README.md`](patterns/guardrails/README.md)

---

## Submission Details

- Event: AWS Builder Center Strands Decider 2B Challenge
- Model Pairing: Strands Decider 2B + Amazon Bedrock
- Mandatory Tags: `#strands-decider-2b`, `#guardrails`
- License: [MIT License](LICENSE) (OSI Approved)
- Author: Mohamed Makhlouf ([@mhdomer](https://builder.aws.com/profile/mhdomer))
