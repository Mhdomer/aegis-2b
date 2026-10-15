# Aegis-2B — Builder Log & Engineering Notes
Author: Mohamed Makhlouf (Cloud & DevSecOps)

---

## 1. Background & Motivation

In autonomous cloud incident response, using generative models (like Claude 3.5 Sonnet on Amazon Bedrock) to directly mutate live infrastructure creates critical reliability and security challenges:

1. Latency: Making a secondary LLM roundtrip to verify safety adds 1.8 to 2.5 seconds of latency per check, compounding delays during active incidents.
2. Cost: High-frequency alert triage rapidly accumulates API token costs for simple binary decisions.
3. Indirect Prompt Injection: In testing, adversarial instructions embedded in untrusted finding descriptions (e.g., instructions attempting to delete core security groups) successfully manipulated generative planners into proposing destructive mutations.

Aegis-2B addresses this by decoupling cognitive planning from safety verification. Generative models handle diagnostic reasoning and remediation proposals, while an offline, non-generative 2B decision model (Strands Decider 2B) evaluates safety boundaries in ~115ms before AWS SDK calls execute.

---

## 2. Decision Log & Architecture Choices

### Decision 1: Model Responsibility Split
- Generative Layer (Amazon Bedrock): Ingests telemetry, reasons across context, and proposes structured Boto3 actions.
- Decision Layer (Strands Decider 2B): Evaluates the structured action and blast radius locally in sub-second time.
- Rationale: Decider 2B evaluates typed parameters directly, eliminating natural language jailbreak surfaces at the execution boundary.

### Decision 2: Fail-Closed Boundary Gating
- Rule: If Decider 2B identifies an action as destructive or exceeding resource boundaries with confidence >= 0.85, execution halts immediately.
- Fallback: Any runtime exceptions, timeouts, or low-confidence results (< 0.85) automatically default to `ENFORCE_BREAK_GLASS`.
- Recovery: Requires human Break-Glass MFA approval to proceed.

### Decision 3: Framework-Agnostic Pattern Design
- Structure: The guardrail logic is fully contained within `patterns/guardrails/` using standard Python dataclasses (`DeciderState`, `DeciderResult`).
- Integration: Can be imported into custom Boto3 dispatchers, Strands InterventionHandlers, or LangChain agents without proprietary dependencies.

---

## 3. Empirical Benchmark Observations

Measured across 50 consecutive safety evaluations on identical hardware:

- Amazon Bedrock (Claude 3.5 Sonnet): Average latency of 1,840.0 ms (P99: 2,950.0 ms), ~$3.60 per 1,000 checks.
- Strands Decider 2B (Local Commodity Host): Average latency of 114.5 ms (P99: 128.4 ms), $0.00 compute cost.
- Net Outcome: 16.1x faster circuit breaking with complete cost elimination for recurring safety checks.

---

## 4. Key Takeaways

Offloading high-frequency safety gates from frontier generative models to small, calibrated decision models provides a deterministic safety boundary for autonomous cloud operations without introducing roundtrip latency or recurring token expense.
