# Aegis-2B - Builder Log & Empirical Engineering Notes
Author: Mohamed Makhlouf (Cloud & DevSecOps)

---

## 1. Background & Problem Statement

When building autonomous cloud remediation workflows on AWS, relying on a single frontier LLM (such as Claude 3.5 Sonnet on Amazon Bedrock) for both alert analysis and direct Boto3 execution introduces three concrete engineering problems:

1. **Network & Inference Latency:** Even before LLM token generation, a single HTTPS control-plane call from a local workstation to `us-east-1` requires `211–244 ms` over a warm TLS connection (`631–670 ms` on a cold TLS handshake). Adding a secondary cloud LLM safety check adds another `1.8–2.5 s` roundtrip.
2. **Token Spend on Known Signatures:** Sending the full system prompt, 6 Boto3 tool schemas (`3,420` bytes), and raw ASFF finding JSON (`963–1,154` bytes) to a frontier model consumes `1,280–1,328` tokens per alert (`$6.14` per 1,000 alerts on Claude 3.5 Sonnet), even when the remediation is a deterministic rule like closing world-open SSH port 22.
3. **Indirect Prompt Injection & State Drift:** Adversarial instructions embedded inside untrusted finding descriptions can trick a generative planner into proposing `ec2:DeleteSecurityGroup` on core VPC resources. Furthermore, mutating live AWS resources via Boto3 without updating Terraform HCL causes out-of-band Infrastructure-as-Code (IaC) state drift.

Aegis-2B solves these by placing a local, non-generative classifier and 3-tier router (`patterns/guardrails/`) directly inside Botocore's `before-parameter-build` event loop, paired with automatic Terraform `git diff` generation (`aegis remediate --iac`).

---

## 2. Architecture & Design Decisions

### Decision 1: 3-Tier Decider Router (`tier_0_rule` / `tier_1_fast` / `tier_2_heavy`)
- **`tier_0_rule` (Direct Boto3 / Runbook - `0` LLM tokens, `$0.00`):** Isolated, non-destructive fixes in `aegis.yaml` (`auto_permit`, such as `revoke_security_group_ingress` on port 22) bypass Bedrock completely.
- **`tier_1_fast` (Amazon Nova Micro / Haiku):** Routine single-resource configuration updates strip the multi-tool reasoning prompt and send only the compact state (~80% token reduction).
- **`tier_2_heavy` (Claude 3.5 Sonnet + Break-Glass MFA Gate):** High-blast-radius VPC route changes (`replace_route`), IAM policy mutations (`attach_role_policy`), or alerts with prompt-injection anomalies halt immediately at the circuit breaker and require a human MFA token.

### Decision 2: Multi-Head Calibrated Risk Evaluation & Deobfuscation
- `DeciderCloudGuardrail` normalizes all inputs via `_deobfuscate()` (stripping zero-width Unicode characters `U+200B–U+200F`, `U+FEFF` and decoding URL-encoded `%30.0.0.0%2f0` payloads) before scoring 5 structural risk heads:
  1. `destructive_mutation`: Destructive API verbs (`delete`, `terminate`, `drop`, `detach`, `flush`) and `always_halt` policy rules.
  2. `privilege_escalation`: IAM/STS role policy attachments (`attach_role_policy`, `AdministratorAccess`, wildcard grants).
  3. `network_exposure`: VPC route-table mutations (`replace_route`) and world-open `0.0.0.0/0` ingress authorizations.
  4. `blast_radius_risk`: Resource scope (`ISOLATED` vs `VPC_WIDE` vs `ACCOUNT_WIDE`) and core production ARNs.
  5. `injection_anomaly`: Indirect prompt injection signatures inside untrusted alert descriptions or parameters.
- **Fail-Closed Invariant:** Any runtime exception or confidence score below `0.85` automatically defaults to `ENFORCE_BREAK_GLASS`.

### Decision 3: Declarative Terraform Patch Mode (`--iac`)
- Every evaluated `DeciderState` generates a corresponding Terraform HCL `git diff` (`infra/security_groups.tf`, `infra/vpc_routing.tf`, `infra/iam.tf`) via `DeciderCloudGuardrail.generate_terraform_diff(state)` so operators can commit the declarative fix to Git alongside or instead of runtime Boto3 execution.

---

## 3. Empirical Benchmark Log (Measured 2026-10-17)

All numbers below were measured directly on our local host (**CachyOS Linux, Kernel 6.13+, Python 3.14.7**) against our live configured AWS account (`3273****1586`, region `us-east-1`) using `time.perf_counter_ns()` with `simulate_local_latency=False` (zero artificial `time.sleep` delays). Reproducible at any time via `uv run aegis benchmark`.

### 3.1 Latency Measurements (Local CPU / Botocore Hook vs. Live AWS `us-east-1` HTTPS RTT)

| Measurement Vector | Sample Size | P50 (Median) | P90 | P99 / Max | Notes |
|---|---|---|---|---|---|
| **Direct Schema Evaluator (`guardrail.evaluate`)** | 200 runs | **0.016 ms** (`15.6 µs`) | **0.020 ms** (`20.0 µs`) | **0.037 ms** | Pure Python + Pydantic typed multi-head evaluation |
| **Botocore Pre-HTTP Hook (`ec2.delete_security_group`)** | 100 runs | **0.505 ms** (`505.2 µs`) | **0.599 ms** (`599.0 µs`) | **6.770 ms** | Full `boto3` call -> `before-parameter-build` -> `GuardrailBlockedError` |
| **Live AWS `us-east-1` Warm HTTPS RTT (`DescribeSecurityGroups`)** | 10 runs | **215.74 ms** | **241.60 ms** | **244.13 ms** | Reused TLS session pool to `ec2.us-east-1.amazonaws.com` |
| **Live AWS `us-east-1` Cold TLS + SigV4 Handshake** | 1st call | **631.22 ms** | - | **669.89 ms** | Initial DNS + TCP + TLS 1.3 handshake + SigV4 signing |

- **Empirical Speedup:** Blocking a destructive or prompt-injected call inside the local Botocore `before-parameter-build` hook (`0.505 ms` P50) is **427x faster** than a single warm HTTPS roundtrip to `us-east-1` (`215.74 ms`) and **1,054x faster** than a cold TLS connection (`631.22 ms`), with zero packets leaving the host.

### 3.2 Real Payload Token & Cost Measurements (`scenarios/fixtures/*.json`)

Token counts are computed directly from the byte length of each ASFF finding fixture plus the `3,420`-character system prompt and 6 Boto3 remediation tool JSON schemas (`4 chars/token` + `185` output tokens for the structured tool call), priced at AWS Bedrock's published `us-east-1` on-demand rates for Claude 3.5 Sonnet (`$0.003 / 1K input tokens`, `$0.015 / 1K output tokens`):

| Fixture File | File Size | Input Tokens | Output Tokens | Total Tokens | Sonnet Cost / 1k Alerts | Tier 0 Local Cost |
|---|---|---|---|---|---|---|
| `benign_ssh_finding.json` | 963 B | 1,095 | 185 | **1,280** | `$6.06` | **`$0.00`** (`1,280` tok saved) |
| `high_blast_radius_route_table.json` | 1,083 B | 1,125 | 185 | **1,310** | `$6.15` | Routed to Tier 2 + MFA Gate |
| `malicious_prompt_injection.json` | 1,154 B | 1,143 | 185 | **1,328** | `$6.20` | Halted pre-HTTP (`GuardrailBlockedError`) |
| **Average across fixtures** | **1,067 B** | **1,121** | **185** | **1,306** | **`$6.14 / 1k`** (`$614 / 100k`) | **`$0.00` on Tier 0** |

### 3.3 Live AWS Account (`3273****1586`, `us-east-1`) Verification Log

Executed via `uv run aegis test-aws` and `uv run aegis remediate --iac` against live account resources (`$0.00` read-only discovery + pre-HTTP mutation interception):

- **Discovered Live Resources:**
  - Security Group: `sg-008c3f4e07a0ff172 (default)` in `vpc-0046642b621cf7ef1`
  - Route Table: `rtb-067d049b3b998fcd3` (`172.31.0.0/16 -> local`, `0.0.0.0/0 -> igw-06f2b36103b0f5610`)
  - IAM Role: `AWSServiceRoleForAccessAnalyzer` (among 9 account roles)
- **Live Interception Results:**
  - `LIVE-01` (`revoke_security_group_ingress` port 22 on `sg-008c3f4e07a0ff172`): Classified as `tier_0_rule` (`LOW` risk, `PERMIT_AUTO_REMEDIATION`, `1,115` tokens saved, `infra/security_groups.tf` diff generated).
  - `LIVE-02` (`delete_security_group` on `sg-008c3f4e07a0ff172` with injected alert): Classified as `tier_2_heavy` (`CRITICAL` risk, `ENFORCE_BREAK_GLASS`), blocked pre-HTTP by Botocore in `0.51 ms`.
  - `LIVE-03` (`replace_route` `0.0.0.0/0` on `rtb-067d049b3b998fcd3`): Classified as `tier_2_heavy` (`HIGH` risk, `ENFORCE_BREAK_GLASS`), gated for Break-Glass MFA (`infra/vpc_routing.tf` diff generated).
  - `LIVE-04` (`attach_role_policy` `AdministratorAccess` on `AWSServiceRoleForAccessAnalyzer`): Classified as `tier_2_heavy` (`CRITICAL` risk, `ENFORCE_BREAK_GLASS`), blocked pre-HTTP (`infra/iam.tf` diff generated).
- **10-Vector Security Self-Audit (`uv run aegis audit`):** `10/10` checks passed in **`0.62 ms`** total wall-clock time (`SEC-01` through `SEC-10`, SHA-256 receipts verified).
