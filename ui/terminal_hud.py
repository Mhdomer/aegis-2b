"""
Aegis-2B — Live Operations Terminal HUD
High-impact visual telemetry for demo videos and live CLI runs using Python Rich.
"""

import sys
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from patterns.guardrails.schemas import DeciderResult, GuardrailAction, DeciderState


if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(highlight=False)



def render_banner():
    console.print("\n[bold]aegis-2b[/bold] — split-model boto3 safety gate (Bedrock planner + Strands Decider 2B)")
    console.print("[dim]Fail-closed threshold >= 85.0% · $0.00 local evaluation · pre-HTTP Botocore hook[/dim]\n")


def render_finding_card(finding: dict):
    title = finding.get("Title", "Unknown Finding")
    severity = finding.get("Severity", {}).get("Label", "UNKNOWN")
    f_id = finding.get("Id", "")
    desc = finding.get("Description", "")

    sev_color = "red" if severity in ("HIGH", "CRITICAL") else "yellow"

    table = Table(box=box.SIMPLE, expand=True, show_header=False)
    table.add_column("Property", style="dim", width=20)
    table.add_column("Value")

    table.add_row("Finding ID", f"[dim]{f_id}[/dim]")
    table.add_row("Severity", f"[{sev_color}]{severity}[/{sev_color}]")
    table.add_row("Alert Title", f"[bold]{title}[/bold]")
    if desc:
        table.add_row("Description", f"[dim]{desc}[/dim]")

    console.print(Panel(table, title="1. Incoming Alert", border_style="dim"))


def render_planner_proposal(tool_name: str, parameters: dict, reasoning: str):
    table = Table(box=box.SIMPLE, expand=True, show_header=False)
    table.add_column("Key", style="dim", width=20)
    table.add_column("Details")

    table.add_row("Planner", "Amazon Bedrock (Claude 3.5 Sonnet)")
    table.add_row("Proposed Tool", f"[bold]{tool_name}[/bold]")
    table.add_row("Parameters", f"{parameters}")
    table.add_row("Reasoning", f"[dim]{reasoning}[/dim]")

    console.print(Panel(table, title="2. Planner Proposal", border_style="dim"))


def _score_bar(score: float, invert_color: bool = False) -> str:
    """Renders a compact 12-block Unicode probability bar with percentage."""
    clamped = max(0.0, min(1.0, float(score)))
    filled = int(round(clamped * 12))
    bar = "█" * filled + "░" * (12 - filled)
    if invert_color:
        color = "green" if clamped >= 0.85 else ("yellow" if clamped >= 0.5 else "red")
    else:
        color = "red" if clamped >= 0.5 else ("yellow" if clamped >= 0.25 else "green")
    return f"[{color}]{bar}[/{color}] [{color}]{clamped:5.1%}[/{color}]"


def render_circuit_breaker_result(state: DeciderState, result: DeciderResult):
    is_safe = (result.action == GuardrailAction.PERMIT_AUTO_REMEDIATION)
    border_color = "green" if is_safe else "red"
    badge = (
        "[green]PERMIT_AUTO_REMEDIATION[/green]"
        if is_safe
        else "[red]ENFORCE_BREAK_GLASS (HALTED)[/red]"
    )

    table = Table(box=box.SIMPLE, expand=True, show_header=False)
    table.add_column("Metric", style="dim", width=22)
    table.add_column("Value")

    lat_str = (
        f"{result.latency_ms:.3f} ms ({result.latency_ms * 1000:.1f} µs)"
        if result.latency_ms < 1.0
        else f"{result.latency_ms:.2f} ms"
    )
    table.add_row("Classifier", "Strands Decider 2B (Local Pre-HTTP Gate)")
    table.add_row("Decision", f"[bold]{badge}[/bold]")
    table.add_row("Router Tier", f"[cyan]{result.recommended_tier}[/cyan]")
    table.add_row("Confidence", f"[{border_color}]{result.confidence:.1%}[/{border_color}] [dim](threshold >= 85.0%)[/dim]")
    table.add_row("Latency", lat_str)
    table.add_row("Blast Radius", state.blast_radius.value)
    table.add_row("Reason Code", result.reasoning_code)

    if result.raw_scores:
        scores_grid = Table.grid(padding=(0, 2))
        scores_grid.add_column(style="dim", width=24)
        scores_grid.add_column()
        label_map = [
            ("destructive_mutation", "Destructive Verb Risk", False),
            ("privilege_escalation", "IAM Escalation Risk", False),
            ("network_exposure", "Network / Route Risk", False),
            ("blast_radius_risk", "Blast Radius Scope", False),
            ("injection_anomaly", "Prompt Injection Sig", False),
            ("safe_remediation", "Safe Remediation Prob", True),
        ]
        for key, label, inv in label_map:
            if key in result.raw_scores:
                scores_grid.add_row(label, _score_bar(result.raw_scores[key], invert_color=inv))
        table.add_row("Risk Scores", scores_grid)

    console.print(Panel(table, title="3. Decider 2B Evaluation", border_style=border_color))


from rich.prompt import Confirm, Prompt


def prompt_break_glass_mfa(state: DeciderState) -> Optional[str]:
    """Prompts the operator for a Break-Glass MFA authorization token."""
    console.print(Panel(
        f"Target Resource : {state.target_arn}\n"
        f"Proposed Action : [bold red]{state.proposed_tool}[/bold red]\n"
        f"Blast Radius    : {state.blast_radius.value}\n\n"
        f"[dim]Action halted by safety gate. Provide a 6-digit MFA token to override.[/dim]",
        title="Break-Glass MFA Gate",
        border_style="yellow",
    ))
    
    try:
        should_override = Confirm.ask(
            "[bold yellow]Do you have an emergency Break-Glass token to authorize override?[/bold yellow]",
            default=False,
            console=console,
        )
    except Exception:
        return None

    if not should_override:
        return None

    token = Prompt.ask(
        "[bold cyan]Enter Break-Glass MFA Token[/bold cyan] [dim](e.g. 6-digit OTP or BG-SEC-911)[/dim]",
        console=console,
    )
    return token.strip() if token else None


def render_dispatcher_receipt(receipt):
    """Renders the final AWS Boto3 execution, containment, or Break-Glass override receipt."""
    status = receipt.execution_status

    if status == "EXECUTED":
        border_color = "green"
        title_badge = "[bold green]4. AWS Boto3 Execution Receipt[/bold green]"
        status_str = "[bold white on green] AUTO-EXECUTED (CERTIFIED SAFE) [/bold white on green]"
    elif status == "OVERRIDDEN_BREAK_GLASS":
        border_color = "yellow"
        title_badge = "[bold yellow]4. Emergency Break-Glass Execution Receipt[/bold yellow]"
        status_str = "[bold black on yellow] OVERRIDDEN VIA BREAK-GLASS MFA [/bold black on yellow]"
    else:
        border_color = "red"
        title_badge = "[bold red]4. Aegis Containment Audit Receipt[/bold red]"
        status_str = "[bold white on red] PREVENTED / ZERO MUTATION [/bold white on red]"

    table = Table(box=box.SIMPLE, expand=True)
    table.add_column("Field", style="bold dim white", width=22)
    table.add_column("Audit Data", style="white")

    table.add_row("Cloud Status", status_str)
    table.add_row("Target ARN", receipt.target_arn)
    table.add_row("Proposed Tool", f"[yellow]{receipt.proposed_tool}[/yellow]")
    table.add_row("Audit Timestamp", receipt.timestamp)

    if status in ("EXECUTED", "OVERRIDDEN_BREAK_GLASS"):
        call_name = receipt.details.get("call", receipt.proposed_tool)
        table.add_row("Boto3 API Dispatched", f"[bold cyan]{call_name}[/bold cyan]")
        if status == "OVERRIDDEN_BREAK_GLASS":
            operator = receipt.details.get("operator", "sec-ops-admin")
            token_mask = receipt.details.get("mfa_token_masked", "***")
            table.add_row("Break-Glass Operator", f"[bold yellow]{operator}[/bold yellow] (MFA: {token_mask})")
        table.add_row("Remediation Detail", str(receipt.details))
    else:
        table.add_row("Containment Shield", "[bold red]No AWS API call made. Production infrastructure intact.[/bold red]")
        table.add_row("Intercept Reason", receipt.details.get("reason", "Safety circuit breaker tripped."))

    console.print(Panel(table, title=title_badge, border_style=border_color))


