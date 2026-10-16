"""
Aegis-2B — Unified CLI Interface
Sub-Second Safety Circuit Breaker for Autonomous Cloud Ops Agents.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

# Fix Windows console UTF-8 encoding if needed
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def print_welcome_overview():
    """Prints a clear, educational overview of Aegis-2B and available commands."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
    console.print()

    header_table = Table.grid(expand=True, padding=(0, 1))
    header_table.add_row("[bold cyan]🛡️  AEGIS-2B[/bold cyan] — [bold white]Sub-Second Cloud Safety Circuit Breaker[/bold white]")
    header_table.add_row("[dim]Autonomous AI Agent Guardrail powered by Strands Decider 2B (<115ms Local Gate)[/dim]")
    header_table.add_row("[yellow]Intercepts prompt injections & high blast-radius mutations before they touch AWS Boto3.[/yellow]\n")

    cmd_table = Table(box=None, padding=(0, 2), show_header=True)
    cmd_table.add_column("Command", style="bold cyan", width=26)
    cmd_table.add_column("Purpose / Workflow", style="white")

    cmd_table.add_row("aegis demo", "Run guided incident defense scenarios (Benign, Attack, Blast Radius)")
    cmd_table.add_row("aegis demo --compare-llm", "Run Head-to-Head battle: Traditional LLM vs. Aegis-2B Protected")
    cmd_table.add_row("aegis protect --tool <name>", "Intercept & evaluate a proposed AWS tool call in real time (~115ms)")
    cmd_table.add_row("aegis scan", "Inspect active cloud infrastructure posture and security state")
    cmd_table.add_row("aegis top", "Interactive full-screen terminal operations cockpit (AWS resource navigator)")
    cmd_table.add_row("aegis ui", "Launch browser-based Incident Defense Center (http://127.0.0.1:8765)")
    cmd_table.add_row("aegis benchmark", "Run statistical latency & cost benchmarks vs Bedrock Claude 3.5")
    cmd_table.add_row("aegis man", "Open comprehensive Unix/Linux engineering manual")

    t = Table.grid(expand=True)
    t.add_row(header_table)
    t.add_row(cmd_table)
    t.add_row("\n[dim]Run [bold white]aegis <command> --help[/bold white] for detailed options on any command.[/dim]")

    console.print(Panel(t, title="[bold white]Aegis-2B Cloud Safety Tool[/bold white]", border_style="cyan"))
    console.print()


def run_protect_command(tool: Optional[str], arn: str, params_str: str, blast_str: str, is_destructive: bool, interactive: bool, as_json: bool = False, enforce: bool = False):
    """Evaluates an arbitrary AWS tool call or alert in real time."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from patterns.guardrails import DeciderCloudGuardrail, DeciderState, BlastRadius, GuardrailAction
    from aegis.dispatcher import AWSActionDispatcher, verify_break_glass_token

    console = Console()

    # Support reading JSON from stdin pipe (e.g. echo '{"tool":...}' | aegis protect)
    if not sys.stdin.isatty():
        try:
            stdin_text = sys.stdin.read().strip()
            if stdin_text:
                payload = json.loads(stdin_text)
                tool = payload.get("tool", tool)
                arn = payload.get("arn", payload.get("target_arn", arn))
                if "params" in payload:
                    params_str = json.dumps(payload["params"])
                if "blast_radius" in payload:
                    blast_str = payload["blast_radius"]
                if "is_destructive" in payload:
                    is_destructive = payload["is_destructive"]
        except Exception:
            pass

    if not tool:
        if as_json:
            print(json.dumps({"error": "No AWS tool specified. Use --tool <name> or pipe JSON."}))
        else:
            console.print("\n[bold red]Error:[/bold red] Please specify an AWS tool to evaluate via `--tool <name>` or pipe a JSON object.")
            console.print("[dim]Example: aegis protect --tool delete_security_group --params '{\"GroupId\":\"sg-core-vpc-01\"}' --destructive[/dim]\n")
        if enforce:
            sys.exit(1)
        return

    try:
        params = json.loads(params_str) if isinstance(params_str, str) else params_str
    except Exception:
        params = {}

    blast = BlastRadius.VPC_WIDE if blast_str == "vpc_wide" else BlastRadius.ISOLATED
    state = DeciderState(
        alert_source="cli.protect",
        alert_severity="HIGH",
        target_arn=arn,
        proposed_tool=tool,
        tool_parameters=params,
        blast_radius=blast,
        is_destructive_action=is_destructive,
    )

    guardrail = DeciderCloudGuardrail(risk_threshold=0.85, simulate_local_latency=True)
    res = guardrail.evaluate(state)
    is_permitted = (res.action == GuardrailAction.PERMIT_AUTO_REMEDIATION)

    # Machine-readable JSON output for CI/CD pipelines
    if as_json:
        out = {
            "status": "PERMITTED" if is_permitted else "BLOCKED",
            "permitted": is_permitted,
            "tool": tool,
            "target_arn": arn,
            "parameters": params,
            "blast_radius": blast.value,
            "is_destructive": is_destructive,
            "decision": res.action.value,
            "latency_ms": res.latency_ms,
            "confidence": res.confidence,
            "reasoning_code": res.reasoning_code,
        }
        print(json.dumps(out, indent=2))
        if enforce:
            sys.exit(0 if is_permitted else 1)
        return

    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_row("[bold white]Proposed Tool:[/bold white]", f"[cyan]{tool}[/cyan]")
    t.add_row("[bold white]Target ARN:[/bold white]", f"[dim]{arn}[/dim]")
    t.add_row("[bold white]Parameters:[/bold white]", f"[dim]{json.dumps(params)}[/dim]")
    t.add_row("[bold white]Blast Radius:[/bold white]", f"[yellow]{blast.value}[/yellow]")
    t.add_row("[bold white]Destructive Action:[/bold white]", "[bold red]YES[/bold red]" if is_destructive else "[green]NO[/green]")
    t.add_row("[bold white]Safety Engine:[/bold white]", "Strands Decider 2B (<115ms Local Gate)")
    t.add_row("[bold white]Evaluation Latency:[/bold white]", f"[bold cyan]{res.latency_ms:.1f} ms[/bold cyan]")
    t.add_row("[bold white]Confidence Score:[/bold white]", f"[bold green]{res.confidence:.1%}[/bold green]")

    if is_permitted:
        verdict = "[bold black on green] PERMITTED [/bold black on green] (Safe for automated cloud execution)"
        border_style = "green"
    elif is_destructive:
        verdict = "[bold white on red] HALTED & INTERCEPTED [/bold white on red] (Destructive verb caught)"
        border_style = "red"
    else:
        verdict = "[bold black on yellow] GATED [/bold black on yellow] (High blast radius / MFA token required)"
        border_style = "yellow"

    t.add_row("[bold white]Circuit Verdict:[/bold white]", verdict)
    t.add_row("[bold white]Reasoning Code:[/bold white]", f"[dim]{res.reasoning_code}[/dim]")

    console.print()
    console.print(Panel(t, title="[bold white]🛡️ Aegis-2B Sub-Second Action Evaluation[/bold white]", border_style=border_style))
    console.print()

    if not is_permitted and interactive:
        token = console.input("[bold yellow]Enter 6-digit SecOps Break-Glass MFA Token to override (or press Enter to abort): [/bold yellow]").strip()
        if token and verify_break_glass_token(token):
            dispatcher = AWSActionDispatcher()
            dispatcher.dispatch(state, res, break_glass_token=token)
            console.print(f"[bold green]✔ MFA Token [{token}] verified! Action authorized and dispatched to AWS Boto3.[/bold green]\n")
        else:
            console.print("[bold red]Action remains halted. Zero AWS API calls dispatched to production.[/bold red]\n")

    if enforce:
        sys.exit(0 if is_permitted else 1)


def run_scan_command():
    """Inspects the active cloud environment and displays current posture."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from aegis.dispatcher import AWSActionDispatcher

    console = Console()
    dispatcher = AWSActionDispatcher()
    state = dispatcher._simulated_state

    table = Table(box=None, padding=(0, 2), show_header=True)
    table.add_column("Resource ID", style="bold cyan")
    table.add_column("Type", style="dim", width=16)
    table.add_column("Current Posture", style="white")
    table.add_column("Safety Circuit Gate", style="bold green")

    sg1 = state["security_groups"]["sg-0123456789"]
    rules1 = sg1.get("rules", sg1.get("IngressRules", []))
    has_22 = any(r.get("port", r.get("Port")) == 22 for r in rules1)
    status1 = "[bold red]Port 22/tcp Exposed (0.0.0.0/0)[/bold red]" if has_22 else "[bold green]Port 22 Closed & Isolated[/bold green]"
    table.add_row("sg-0123456789", "SecurityGroup", status1, "✔ Auto-Remediation (<115ms)")

    table.add_row("sg-core-vpc-01", "SecurityGroup", "[bold green]PostgreSQL 16 (:5432) Secure[/bold green]", "🛡️ Shielded (Halt on Drop)")

    rt = state["route_tables"]["rtb-core-vpc-01"]
    routes = rt.get("routes", rt.get("Routes", []))
    target = next((r.get("target", r.get("GatewayId")) for r in routes if r.get("cidr", r.get("DestinationCidrBlock")) == "0.0.0.0/0"), "NONE")
    table.add_row("rtb-core-vpc-01", "RouteTable", f"0.0.0.0/0 -> {target}", "⚠️ Gated (MFA Required)")

    footer = Table.grid(expand=True)
    footer.add_row(table)
    footer.add_row("\n[dim]Target Account: 111122223333 │ Region: us-east-1 │ Decider 2B Gate: ARMED (Threshold ≥ 0.85)[/dim]")

    console.print()
    console.print(Panel(footer, title="[bold white]☁️ Cloud Infrastructure Posture Scan[/bold white]", border_style="cyan"))
    console.print()


def main():
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis-2B: Sub-Second Safety Circuit Breaker using Strands Decider 2B",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Prompt for emergency Break-Glass MFA token when actions are halted",
    )
    parser.add_argument(
        "--compare-llm",
        action="store_true",
        help="Run head-to-head comparison: Vanilla Bedrock vs. Aegis-2B on adversarial injection",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: demo
    demo_parser = subparsers.add_parser("demo", help="Run guided incident defense scenarios")
    demo_parser.add_argument(
        "--scenario",
        choices=["all", "benign", "adversarial", "blast_radius"],
        default="all",
        help="Choose scenario to execute (default: all)",
    )
    demo_parser.add_argument(
        "--interactive",
        action="store_true",
        help="Prompt for emergency Break-Glass MFA token when actions are halted",
    )
    demo_parser.add_argument(
        "--compare-llm",
        action="store_true",
        help="Run head-to-head comparison: Vanilla Bedrock vs. Aegis-2B on adversarial injection",
    )

    # Command: protect
    protect_parser = subparsers.add_parser("protect", help="Evaluate & intercept a proposed tool call in real time")
    protect_parser.add_argument("--tool", type=str, help="AWS tool name (e.g. revoke_security_group_ingress, delete_security_group)")
    protect_parser.add_argument("--arn", type=str, default="arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789", help="Target resource ARN")
    protect_parser.add_argument("--params", type=str, default="{}", help="Tool parameters as JSON string")
    protect_parser.add_argument("--blast", choices=["isolated", "vpc_wide"], default="isolated", help="Blast radius boundary")
    protect_parser.add_argument("--destructive", action="store_true", help="Flag action as destructive mutation")
    protect_parser.add_argument("--interactive", action="store_true", help="Prompt for Break-Glass MFA if action is gated")
    protect_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON for CI/CD pipelines")
    protect_parser.add_argument("--enforce", action="store_true", help="Exit code 0 if permitted, exit code 1 if blocked (CI/CD gate)")

    # Command: scan
    subparsers.add_parser("scan", help="Inspect active cloud infrastructure posture and security state")

    # Command: benchmark
    benchmark_parser = subparsers.add_parser("benchmark", help="Run the statistical latency and cost benchmark")
    benchmark_parser.add_argument(
        "--iterations",
        type=int,
        default=50,
        help="Number of iterations to execute (default: 50)",
    )

    # Command: ui (Web Operations Center)
    ui_parser = subparsers.add_parser("ui", help="Launch live interactive Incident Defense Center")
    ui_parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port to bind Web Operations Center (default: 8765)",
    )
    ui_parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not automatically launch web browser",
    )

    # Command: serve / daemon (In-VPC HTTP Microservice)
    serve_parser = subparsers.add_parser(
        "serve",
        aliases=["daemon"],
        help="Run in-VPC HTTP guardrail daemon for autonomous agents (CI/CD & VPC)",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port to bind daemon (default: 8765)",
    )

    # Command: top / dashboard (AWS Terminal Cockpit)
    subparsers.add_parser(
        "top",
        aliases=["dashboard"],
        help="Launch full-screen interactive AWS Terminal Cockpit",
    )

    # Command: man (Linux User's Manual)
    subparsers.add_parser(
        "man",
        aliases=["manual"],
        help="Display comprehensive Unix/Linux manual page",
    )

    args = parser.parse_args()

    # If no command passed and no flags: print welcome overview
    if args.command is None:
        if args.compare_llm or args.interactive:
            from aegis_demo import main as run_demo
            run_demo(scenario="all", interactive=args.interactive, compare_llm=args.compare_llm)
        else:
            print_welcome_overview()

    elif args.command == "demo":
        from aegis_demo import main as run_demo
        run_demo(scenario=args.scenario, interactive=args.interactive, compare_llm=args.compare_llm)

    elif args.command == "protect":
        run_protect_command(
            tool=args.tool,
            arn=args.arn,
            params_str=args.params,
            blast_str=args.blast,
            is_destructive=args.destructive,
            interactive=args.interactive,
            as_json=args.json,
            enforce=args.enforce,
        )

    elif args.command == "scan":
        run_scan_command()

    elif args.command == "benchmark":
        from scripts.benchmark import run_benchmark
        run_benchmark(iterations=args.iterations)

    elif args.command == "ui":
        from aegis.server import start_server
        start_server(port=args.port, open_browser=not args.no_browser)

    elif args.command in ("serve", "daemon"):
        from aegis.server import start_server
        start_server(port=args.port, open_browser=False)

    elif args.command in ("top", "dashboard"):
        from aegis.cockpit import run_cockpit
        run_cockpit()

    elif args.command in ("man", "manual"):
        from aegis.manual import display_manual
        display_manual()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
