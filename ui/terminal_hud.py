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
    banner = Text()
    banner.append("🛡️  AEGIS-2B ", style="bold cyan")
    banner.append("│ Sub-Second Cloud Safety Circuit Breaker\n", style="bold white")
    banner.append("   Bedrock (Claude 3.5 Sonnet) ", style="dim yellow")
    banner.append("+ ", style="white")
    banner.append("Strands Decider 2B (~115ms Local Host)", style="bold green")
    
    panel = Panel(banner, border_style="cyan", box=box.ROUNDED)
    console.print(panel)


def render_finding_card(finding: dict):
    title = finding.get("Title", "Unknown Finding")
    severity = finding.get("Severity", {}).get("Label", "UNKNOWN")
    f_id = finding.get("Id", "")
    
    sev_color = "red" if severity in ("HIGH", "CRITICAL") else "yellow"
    
    table = Table(box=box.SIMPLE_HEAD, expand=True)
    table.add_column("Property", style="bold dim white", width=18)
    table.add_column("Value", style="white")
    
    table.add_row("Finding ID", f_id)
    table.add_row("Severity", f"[{sev_color}]{severity}[/{sev_color}]")
    table.add_row("Title", title)
    
    console.print(Panel(table, title="[bold blue]1. Telemetry Ingested[/bold blue]", border_style="blue"))


def render_planner_proposal(tool_name: str, parameters: dict, reasoning: str):
    table = Table(box=box.SIMPLE, expand=True)
    table.add_column("Key", style="dim", width=18)
    table.add_column("Details", style="cyan")
    
    table.add_row("Cognitive Model", "Amazon Bedrock (Claude 3.5 Sonnet)")
    table.add_row("Proposed Tool", f"[bold yellow]{tool_name}[/bold yellow]")
    table.add_row("Arguments", str(parameters))
    table.add_row("Reasoning", f"[italic]{reasoning}[/italic]")
    
    console.print(Panel(table, title="[bold yellow]2. Generative Planning & Proposal[/bold yellow]", border_style="yellow"))


def render_circuit_breaker_result(state: DeciderState, result: DeciderResult):
    is_safe = (result.action == GuardrailAction.PERMIT_AUTO_REMEDIATION)
    border_color = "green" if is_safe else "red"
    badge = "[bold white on green] PERMITTED [/bold white on green]" if is_safe else "[bold white on red] HALTED & GATED [/bold white on red]"
    
    table = Table(box=box.ROUNDED, expand=True)
    table.add_column("Metric", style="bold dim white", width=22)
    table.add_column("Telemetry", style="white")
    
    table.add_row("Model", "Strands Decider 2B (Local Engine)")
    table.add_row("Decision", badge)
    table.add_row("Calibrated Confidence", f"[bold {border_color}]{result.confidence:.1%}[/bold {border_color}]")
    table.add_row("Gate Latency", f"[bold green]{result.latency_ms} ms[/bold green] [dim](target <130ms)[/dim]")
    table.add_row("Blast Radius Category", state.blast_radius.value)
    table.add_row("Circuit Reasoning", result.reasoning_code)
    
    title_text = f"[bold {border_color}]3. Aegis-2B Circuit Breaker Evaluation[/bold {border_color}]"
    console.print(Panel(table, title=title_text, border_style=border_color))
    
    if not is_safe:
        console.print(Panel(
            "[bold red]🛑 HIGH BLAST RADIUS / ADVERSARIAL ACTION PREVENTED![/bold red]\n"
            "Execution blocked. Break-Glass MFA Token required to override.",
            border_style="red",
            box=box.HEAVY
        ))
    else:
        console.print(Panel(
            "[bold green]✅ SAFE ISOLATED MUTATION VERIFIED[/bold green]\n"
            "Dispatched to Boto3 SDK for automated remediation in <1 second.",
            border_style="green",
            box=box.HEAVY
        ))


from rich.prompt import Confirm, Prompt


def prompt_break_glass_mfa(state: DeciderState) -> Optional[str]:
    """
    Renders an interactive high-impact Break-Glass modal in the terminal,
    prompting the SecOps operator for an emergency MFA authorization token.
    """
    console.print(Panel(
        f"[bold yellow]⚠️  EMERGENCY BREAK-GLASS HUMAN OVERRIDE GATEWAY[/bold yellow]\n\n"
        f"Target Resource : [cyan]{state.target_arn}[/cyan]\n"
        f"Proposed Action : [bold red]{state.proposed_tool}[/bold red]\n"
        f"Blast Radius    : [bold red]{state.blast_radius.value}[/bold red]\n\n"
        f"[dim]The 115ms Safety Circuit Breaker halted this action to prevent destructive impact.\n"
        f"To force execution against AWS Boto3, provide an authorized Break-Glass MFA token.[/dim]",
        title="[bold yellow]🛡️  Break-Glass MFA Authorization Gate[/bold yellow]",
        border_style="yellow",
        box=box.ROUNDED,
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


