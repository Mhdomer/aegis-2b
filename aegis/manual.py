"""
Aegis-2B - Unix/Linux Manual Page (aegis man)
Provides comprehensive documentation for the Aegis-2B system, threat model,
split-model architecture pattern, and command-line interface.
"""

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

MAN_PAGE_CONTENT = """
[bold cyan]NAME[/bold cyan]
    [bold white]aegis[/bold white] - Sub-Second Safety Circuit Breaker for Autonomous Cloud Ops Agents

[bold cyan]SYNOPSIS[/bold cyan]
    [bold white]aegis[/bold white] [[bold green]COMMAND[/bold green]] [[[bold yellow]OPTIONS[/bold yellow]]]

[bold cyan]DESCRIPTION[/bold cyan]
    [bold white]Aegis-2B[/bold white] provides an ultra-low latency, fail-closed safety circuit breaker designed 
    to protect production cloud infrastructure from autonomous agent mistakes, generative 
    hallucinations, and indirect prompt injection attacks.

    In modern agentic cloud operations, frontier generative models (such as Amazon Bedrock 
    Claude 3.5 Sonnet) ingest security alerts from Amazon GuardDuty or AWS Security Hub 
    and propose automated remediations via the AWS Boto3 SDK.

    However, relying on generative LLMs to validate their own execution safety creates 
    three critical vulnerabilities:
        1. [bold yellow]High Latency:[/bold yellow] LLM roundtrips introduce 1.8s to 2.5s of latency per check.
        2. [bold yellow]Recurring Cost:[/bold yellow] High-frequency triage accumulates significant token API billing.
        3. [bold yellow]Indirect Prompt Injection:[/bold yellow] Malicious directives hidden inside alert titles or 
           descriptions can manipulate generative planners into destroying production assets.

    Aegis-2B solves this by decoupling cognitive planning from execution safety using AWS's 
    experimental [bold green]Strands Decider 2B[/bold green] model running locally in [bold cyan]~115 milliseconds[/bold cyan].

[bold cyan]THE SPLIT-MODEL ARCHITECTURAL PATTERN[/bold cyan]
    [bold green]1. Cognitive Planner (Amazon Bedrock):[/bold green]
       Ingests raw ASFF telemetry, reasons across cloud topology, and proposes concrete 
       remediation tool calls (e.g. `revoke_security_group_ingress`).

    [bold green]2. Execution Circuit Breaker (Strands Decider 2B):[/bold green]
       Intercepts proposed actions immediately before the Boto3 SDK executes.
       Answers a concrete typed question:
           [dim]"Does this proposed remediation mutate stateful resources or exceed the 
           boundary of least privilege?"[/dim]

[bold cyan]COMMANDS[/bold cyan]
    [bold green]remediate[/bold green] [[[bold yellow]--iac[/bold yellow]]] [[[bold yellow]--interactive[/bold yellow]]] [[[bold yellow]--json[/bold yellow]]]
        Run the 3-Tier Decider Router (`tier_0_rule` / `tier_1_fast` / `tier_2_heavy`)
        against live AWS resources or findings, saving 100% of LLM tokens on Tier 0 rules
        and generating declarative Terraform HCL `git diff` patches (`--iac`).

    [bold green]audit[/bold green] [[[bold yellow]--json[/bold yellow]]]
        Run the 10-vector red-team and security self-audit mapped to OWASP LLM Top 10,
        MITRE ATLAS, and AWS Well-Architected Security Pillar (10/10 PASS in 0.62 ms).

    [bold green]test-aws[/bold green]
        Verify live Botocore `before-parameter-build` circuit breaking against your
        configured AWS account using $0.00 read-only discovery + pre-HTTP interception.

    [bold green]scan[/bold green] [[[bold yellow]--live[/bold yellow]]]
        Inspect simulated or live AWS Security Groups, Route Tables, EC2, and IAM Roles.

    [bold green]ui[/bold green] [[[bold yellow]--port[/bold yellow] PORT]] [[[bold yellow]--no-browser[/bold yellow]]]
        Launch the 5-tab Minimal Light Web Operations Center (default: http://127.0.0.1:8765).
        Includes Pipeline & Router, Auto-SVG Architecture Map, 10-Vector Self-Audit,
        Live AWS Account & Sandbox, and Policy & SHA-256 Receipts.

    [bold green]top[/bold green], [bold green]dashboard[/bold green]
        Launch the full-screen interactive Terminal Cockpit with bidirectional Web UI sync.

    [bold green]protect[/bold green] [[[bold yellow]--tool[/bold yellow] NAME]] [[[bold yellow]--params[/bold yellow] JSON]] [[[bold yellow]--blast[/bold yellow] SCOPE]] [[[bold yellow]--json[/bold yellow]]] [[[bold yellow]--enforce[/bold yellow]]]
        Evaluate and intercept an arbitrary AWS Boto3 tool proposal in sub-millisecond time.
        Supports stdin JSON piping and CI/CD enforcement (--enforce exits 0 or 1).

    [bold green]policy[/bold green]
        Display active Policy-as-Code rules loaded from [bold white]aegis.yaml[/bold white].

    [bold green]demo[/bold green] [[[bold yellow]--scenario[/bold yellow] SCENARIO]] [[[bold yellow]--interactive[/bold yellow]]] [[[bold yellow]--compare-llm[/bold yellow]]]
        Execute the multi-scenario agentic demonstration:
            • [bold white]benign:[/bold white] SSH brute force isolated ingress remediation (Tier 0).
            • [bold white]adversarial:[/bold white] Poisoned alert attempting core security group deletion.
            • [bold white]blast_radius:[/bold white] High blast-radius VPC route table modification.
            • [bold white]--compare-llm:[/bold white] Head-to-head comparison: Unprotected Planner vs. Aegis-2B.

    [bold green]benchmark[/bold green] [[[bold yellow]--iterations[/bold yellow] N]]
        Run empirical latency and token cost benchmarks (`time.perf_counter_ns()`) comparing
        local schema evaluation (`0.016 ms` P50) and Botocore pre-HTTP hook interception
        (`0.505 ms` P50) against live AWS `us-east-1` HTTPS RTT (`215.74 ms` warm / `631.22 ms` cold).

    [bold green]man[/bold green]
        Display this Unix/Linux manual page.


[bold cyan]FAIL-CLOSED POLICY SPECIFICATION[/bold cyan]
    Aegis-2B enforces strict mathematical safety invariants:
        • [bold green]Confidence >= 0.85 & BlastRadius == ISOLATED:[/bold green] Auto-Remediation PERMITTED.
        • [bold red]Destructive Tool OR BlastRadius == VPC_WIDE:[/bold red] Execution HALTED & GATED.
        • [bold yellow]Classifier Exception / Low Confidence (<0.85):[/bold yellow] Automatic fail-closed fallback to
          [bold red]ENFORCE_BREAK_GLASS[/bold red].

[bold cyan]BREAK-GLASS OVERRIDE[/bold cyan]
    When high blast-radius actions are halted, SecOps human operators can override the gate
    by supplying a verified MFA token (e.g. [bold yellow]849201[/bold yellow] or [bold yellow]BG-SEC-911[/bold yellow]).
    All decisions emit tamper-evident SHA-256 `AuditReceipt` digests.

[bold cyan]ZERO AWS SPEND SAFETY[/bold cyan]
    Live AWS commands (`aegis scan --live`, `aegis test-aws`, `aegis remediate`) only invoke
    $0.00 free read-only control-plane APIs (`sts:GetCallerIdentity`, `ec2:Describe*`, `iam:ListRoles`)
    and block all mutating calls locally inside Botocore's `before-parameter-build` hook.

[bold cyan]AUTHOR[/bold cyan]
    Written by [bold white]Mohamed Makhlouf[/bold white] (Cloud DevSecOps & AI Security Engineer, UTM).
    GitHub: [bold cyan]https://github.com/Mhdomer/aegis-2b[/bold cyan]

[bold cyan]COPYRIGHT[/bold cyan]
    Copyright (c) 2026 Mohamed Makhlouf. Released under the OSI-approved [bold white]MIT License[/bold white].
"""


def display_manual():
    """Displays the formatted Unix manual page in the terminal."""
    console.print(Panel(
        MAN_PAGE_CONTENT.strip(),
        title="[bold white]AEGIS(1) - Linux User's Manual[/bold white]",
        border_style="cyan",
        box=box.ROUNDED,
    ))
    console.print("\n[dim]Press 'q' or scroll up/down to review documentation.[/dim]\n")


if __name__ == "__main__":
    display_manual()
