# 🛡️ Aegis-2B: Sub-Second Safety Circuit Breaker for Autonomous Cloud Ops Agents
*Pairing Amazon Bedrock with Strands Decider 2B for 115ms Calibrated Guardrails*

[![Tags](https://img.shields.io/badge/AWS%20Hackathon-%23strands--decider--2b-orange)](#)
[![Pattern](https://img.shields.io/badge/Pattern-%23guardrails-blue)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Latency](https://img.shields.io/badge/Decision%20Latency-~114ms-brightgreen)](#)
[![Cost](https://img.shields.io/badge/Safety%20Inference%20Cost-%240.00-success)](#)

---

## 📌 Executive Summary
When autonomous AI agents manage cloud infrastructure using Amazon Bedrock, they propose and execute mutating API calls (e.g. AWS Boto3, Terraform). While frontier LLMs excel at cognitive planning and reasoning, relying on them for safety checks introduces a critical dilemma:
1. **Latency Bottleneck:** LLM roundtrips take **1.5s – 3.0s**, crippling real-time incident response.
2. **Token Drain:** Recurring API calls for high-frequency safety checks drain cloud budgets.
3. **Adversarial Jailbreaks:** Generative models are vulnerable to indirect prompt injection embedded within attacker-controlled logs and security alert titles.

**Aegis-2B** solves this by offloading safety decisions to **Strands Decider 2B** — an open, experimental 2B decision model running locally in **~115ms**. Aegis-2B acts as an ultrafast **Safety Circuit Breaker**: it intercepts proposed mutations, checks blast-radius boundaries, and halts destructive or prompt-injected actions before production AWS resources are touched.

---

## 🏗️ Architecture

```
[AWS Security Hub / GuardDuty Finding]
                  │
                  ▼
      [Amazon Bedrock (LLM)]
    Cognitive incident reasoning
    Proposes Boto3 tool mutation
                  │
                  ▼
   ┌──────────────────────────────┐
   │ Aegis-2B Interceptor Hook    │
   │ (patterns/guardrails/)       │
   └──────────────┬───────────────┘
                  │
                  ▼
     [Strands Decider 2B Engine] (~115ms Local)
  Typed Question: Is mutation destructive or out-of-bounds?
                  │
         ┌────────┴────────┐
         ▼                 ▼
   [High Blast/Risk]     [Safe & Bounded]
   Confidence ≥ 0.85     Confidence ≥ 0.90
         │                 │
         ▼                 ▼
   [Break-Glass Gate]    [Auto-Remediate]
   Halt execution &      Execute via Boto3
   require human MFA     in <1 second
```

---

## 📊 Benchmark: Strands Decider 2B vs. Frontier Bedrock

Measured across 50 iterations evaluating safety boundaries:

| Metric | Amazon Bedrock (Claude 3.5 Sonnet) | Strands Decider 2B (Local Engine) | Delta / Speedup |
|---|---|---|---|
| **Latency (P50)** | 1,840.0 ms | **114.5 ms** | **16.1x Faster** |
| **Latency (P90)** | 2,450.0 ms | **121.2 ms** | **20.2x Faster** |
| **Latency (P99)** | 2,950.0 ms | **128.4 ms** | **23.0x Faster** |
| **Token Cost / 1k Checks** | $3.60 | **$0.00** | **100% Free** |
| **Jailbreak Immunity** | Vulnerable to text prompt injection | **Immune (Calibrated mathematical classifier)** | Deterministic Boundary |

---

## 📦 The Reusable Pattern
The standalone interceptor is isolated in `patterns/guardrails/`:
```python
from patterns.guardrails import DeciderCloudGuardrail, DeciderState, GuardrailAction

guardrail = DeciderCloudGuardrail(risk_threshold=0.85)
result = guardrail.evaluate(state)

if result.action == GuardrailAction.PERMIT_AUTO_REMEDIATION:
    execute_boto3()
else:
    enforce_break_glass()
```
See [`patterns/guardrails/README.md`](patterns/guardrails/README.md) for full drop-in integration details.

---

## 🚀 Quickstart

```bash
# 1. Clone repository
git clone https://github.com/Mhdomer/aegis-2b.git
cd aegis-2b

# 2. Run the dual-scenario demo
python aegis_demo.py

# 3. Run the automated benchmark
python scripts/benchmark.py
```

---

## 📖 Documentation & Architecture Decision Records (ADRs)
Detailed engineering rationale, threat models, and trade-off analysis are documented in:
* [`docs/ENGINEERING-LOG.md`](docs/ENGINEERING-LOG.md) — Comprehensive ADRs and empirical observations.

