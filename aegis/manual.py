"""
Aegis-2B — Unix/Linux Manual Page (aegis man)
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
    [bold white]aegis[/bold white] — Sub-Second Safety Circuit Breaker for Autonomous Cloud Ops Agents

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
    [bold green]top[/bold green], [bold green]dashboard[/bold green]
        Launch the live, full-screen [bold white]k9s-style interactive Terminal Cockpit[/bold white].
        Monitors simulated cloud resources, displays real-time telemetry gauges, and 
        features live hotkeys ([1] Benign, [2] Injection, [3] Blast Radius, [B] MFA).

    [bold green]ui[/bold green] [[[bold yellow]--port[/bold yellow] PORT]] [[[bold yellow]--no-browser[/bold yellow]]]
        Launch the interactive [bold white]Web Operations Center[/bold white] (default: http://127.0.0.1:8765).
        Features dynamic SVG topology canvas, synthesized Web Audio SFX, and real-time REST API.

    [bold green]demo[/bold green] [[[bold yellow]--scenario[/bold yellow] SCENARIO]] [[[bold yellow]--interactive[/bold yellow]]] [[[bold yellow]--compare-llm[/bold yellow]]]
        Execute the multi-scenario agentic demonstration:
            • [bold white]benign:[/bold white] SSH brute force isolated ingress remediation (<120ms).
            • [bold white]adversarial:[/bold white] Poisoned alert attempting core security group deletion.
            • [bold white]blast_radius:[/bold white] High blast-radius VPC route table modification.
            • [bold white]--compare-llm:[/bold white] Live head-to-head battle: Vanilla Bedrock vs. Aegis-2B.

    [bold green]benchmark[/bold green] [[[bold yellow]--iterations[/bold yellow] N]]
        Run statistical latency and token cost benchmarks comparing local Decider 2B 
        against live Amazon Bedrock API calls. Reports P50, P90, P99, and cost delta.

    [bold green]man[/bold green]
        Display this comprehensive Unix/Linux manual page.

[bold cyan]FAIL-CLOSED POLICY SPECIFICATION[/bold cyan]
    Aegis-2B enforces strict mathematical safety invariants:
        • [bold green]Confidence ≥ 0.90 & BlastRadius == ISOLATED:[/bold green] Auto-Remediation PERMITTED.
        • [bold red]Destructive Tool OR BlastRadius == VPC_WIDE:[/bold red] Execution HALTED & GATED.
        • [bold yellow]Inference Timeout / Low Confidence (<0.85):[/bold yellow] Automatic fail-closed fallback to 
          [bold red]ENFORCE_BREAK_GLASS[/bold red].

[bold cyan]BREAK-GLASS OVERRIDE[/bold cyan]
    When high blast-radius actions are halted, SecOps human operators can override the gate 
    by supplying a cryptographically verified MFA token (e.g. [bold yellow]849201[/bold yellow] or [bold yellow]BG-SEC-911[/bold yellow]).
    All override actions are logged to immutable execution receipts with masked token signatures.

[bold cyan]TARGET ISOLATION[/bold cyan]
    Target AWS Account: [bold yellow]111122223333[/bold yellow] (Sandboxed / Isolated dummy environment).
    No real AWS credentials, customer data, or production infrastructure are touched.

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
        title="[bold white]AEGIS(1) — Linux User's Manual[/bold white]",
        border_style="cyan",
        box=box.ROUNDED,
    ))
    console.print("\n[dim]Press 'q' or scroll up/down to review documentation.[/dim]\n")


if __name__ == "__main__":
    display_manual()
