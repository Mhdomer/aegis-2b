"""
Aegis-2B - Unified CLI Interface
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
    """Prints a clean overview of aegis-2b commands."""
    from rich.console import Console
    from rich.table import Table
    from rich import box

    console = Console()
    console.print()
    console.print("[bold]aegis-2b[/bold] - local boto3 safety gate using Strands Decider 2B")
    console.print("[dim]Intercepts destructive API calls, prompt injections, and wide blast-radius mutations before HTTP execution.[/dim]\n")

    cmd_table = Table(box=box.SIMPLE, padding=(0, 2), show_header=True)
    cmd_table.add_column("Command", style="bold", width=26)
    cmd_table.add_column("Description")

    cmd_table.add_row("aegis remediate [--iac]", "Tiered Decider 2B router (Tier 0/1/2) + Boto3 or Terraform git diff")
    cmd_table.add_row("aegis test-aws", "Run live Botocore interception check against configured AWS credentials")
    cmd_table.add_row("aegis audit", "Run 10-vector security & fail-closed self-audit")
    cmd_table.add_row("aegis scan [--live]", "List VPC security groups, route tables, and IAM roles")
    cmd_table.add_row("aegis protect --tool <op>", "Evaluate a proposed Boto3 operation from CLI or CI/CD")
    cmd_table.add_row("aegis demo", "Run the 3 sample incident cases (SSH rule, prompt injection, route change)")
    cmd_table.add_row("aegis ui", "Start local web console on http://127.0.0.1:8765")
    cmd_table.add_row("aegis policy", "Show active policy rules from aegis.yaml")
    cmd_table.add_row("aegis benchmark", "Measure local classifier latency vs remote LLM roundtrip")
    cmd_table.add_row("aegis top", "Open terminal resource viewer")
    cmd_table.add_row("aegis man", "Show manual page")

    console.print(cmd_table)
    console.print("\n[dim]Run 'aegis <command> --help' for command flags.[/dim]\n")


def run_protect_command(
    tool: Optional[str],
    arn: str,
    params_str: str,
    blast_str: str,
    is_destructive: bool,
    interactive: bool,
    as_json: bool = False,
    enforce: bool = False,
    notes: Optional[str] = None,
):
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
                if "notes" in payload or "context_notes" in payload:
                    notes = payload.get("notes", payload.get("context_notes", notes))
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

    if blast_str == "account_wide":
        blast = BlastRadius.ACCOUNT_WIDE
    elif blast_str == "vpc_wide":
        blast = BlastRadius.VPC_WIDE
    else:
        blast = BlastRadius.ISOLATED

    state = DeciderState(
        alert_source="cli.protect",
        alert_severity="HIGH",
        target_arn=arn,
        proposed_tool=tool,
        tool_parameters=params,
        blast_radius=blast,
        is_destructive_action=is_destructive,
        context_notes=notes,
    )

    guardrail = DeciderCloudGuardrail(risk_threshold=0.85, simulate_local_latency=False)
    res = guardrail.evaluate(state)
    is_permitted = (res.action == GuardrailAction.PERMIT_AUTO_REMEDIATION)

    try:
        from aegis.aws_live import broadcast_live_event_to_ui
        broadcast_live_event_to_ui({
            "scenario": "cli_protect",
            "title": f"CLI Gate: {tool}",
            "finding": {
                "Title": f"CLI Protection Gate ({tool})",
                "Description": notes or f"CLI evaluation via `aegis protect --tool {tool}`",
            },
            "proposed_tool": tool,
            "parameters": params,
            "blast_radius": blast.value,
            "is_destructive": is_destructive,
            "typed_question": DeciderCloudGuardrail.TYPED_QUESTION,
            "decider_state": state.to_dict(),
            "decision": res.action.value,
            "confidence": round(res.confidence, 4),
            "confidence_percent": f"{res.confidence:.1%}",
            "latency_ms": res.latency_ms,
            "reasoning_code": res.reasoning_code,
            "raw_scores": res.raw_scores,
            "execution_status": "EXECUTED" if is_permitted else "BLOCKED",
        })
    except Exception:
        pass

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
            "raw_scores": res.raw_scores,
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
    t.add_row("[bold white]Destructive Flag:[/bold white]", "[bold red]YES[/bold red]" if is_destructive else "[green]NO[/green]")
    t.add_row("[bold white]Safety Engine:[/bold white]", "Strands Decider 2B (Local Gate)")
    t.add_row("[bold white]Typed Question:[/bold white]", f"[italic dim]{DeciderCloudGuardrail.TYPED_QUESTION}[/italic dim]")
    t.add_row("[bold white]Evaluation Latency:[/bold white]", f"[bold cyan]{res.latency_ms:.3f} ms[/bold cyan]")
    t.add_row("[bold white]Confidence Score:[/bold white]", f"[bold green]{res.confidence:.1%}[/bold green] [dim](Threshold ≥ 85.0%)[/dim]")

    if is_permitted:
        verdict = "[bold black on green] PERMITTED [/bold black on green] (Safe for automated cloud execution)"
        border_style = "green"
    elif is_destructive or res.raw_scores.get("destructive_mutation", 0) >= 0.5:
        verdict = "[bold white on red] HALTED & INTERCEPTED [/bold white on red] (Destructive action blocked)"
        border_style = "red"
    else:
        verdict = "[bold black on yellow] GATED [/bold black on yellow] (High blast radius / MFA token required)"
        border_style = "yellow"

    t.add_row("[bold white]Circuit Verdict:[/bold white]", verdict)
    t.add_row("[bold white]Reasoning Code:[/bold white]", f"[bold white]{res.reasoning_code}[/bold white]")

    console.print()
    console.print(Panel(t, title="[bold white]Aegis-2B Sub-Second Action Evaluation[/bold white]", border_style=border_style))
    console.print()

    if not is_permitted and interactive:
        token = console.input("[bold yellow]Enter 6-digit SecOps Break-Glass MFA Token to override (or press Enter to abort): [/bold yellow]").strip()
        if token and verify_break_glass_token(token):
            dispatcher = AWSActionDispatcher()
            dispatcher.dispatch(state, res, break_glass_token=token)
            console.print(f"[bold green]MFA Token [{token}] verified! Action authorized and dispatched to AWS Boto3.[/bold green]\n")
        else:
            console.print("[bold red]Action remains halted. Zero AWS API calls dispatched to production.[/bold red]\n")

    if enforce:
        sys.exit(0 if is_permitted else 1)


def run_scan_command(
    live: bool = False,
    sandbox: bool = False,
    profile: Optional[str] = None,
    region: Optional[str] = None,
):
    """Inspects the active cloud environment (live AWS account if configured, or offline sandbox)."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from aegis.dispatcher import AWSActionDispatcher
    from aegis.aws_live import get_live_aws_session, run_live_aws_scan

    console = Console()

    # If --live was explicitly requested, or if --sandbox was NOT forced and live AWS credentials exist
    if live:
        run_live_aws_scan(profile=profile, region=region, console=console)
        return

    if not sandbox:
        conn = get_live_aws_session(profile=profile, region=region)
        if conn["connected"]:
            run_live_aws_scan(profile=profile, region=region, console=console)
            return

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
    table.add_row("sg-0123456789", "SecurityGroup", status1, "Auto-Remediation (Local Gate)")

    table.add_row("sg-core-vpc-01", "SecurityGroup", "[bold green]PostgreSQL 16 (:5432) Secure[/bold green]", "Shielded (Halt on Drop)")

    rt = state["route_tables"]["rtb-core-vpc-01"]
    routes = rt.get("routes", rt.get("Routes", []))
    target = next((r.get("target", r.get("GatewayId")) for r in routes if r.get("cidr", r.get("DestinationCidrBlock")) == "0.0.0.0/0"), "NONE")
    table.add_row("rtb-core-vpc-01", "RouteTable", f"0.0.0.0/0 -> {target}", "Gated (MFA Required)")
    table.add_row("patient-records-prod", "S3 Bucket", "[bold green]AES256 Encrypted (Private)[/bold green]", "Shielded (Halt on Delete)")

    footer = Table.grid(expand=True)
    footer.add_row(table)
    footer.add_row(
        "\n[dim]Mode: Offline Sandbox (Account 111122223333) │ Configure `aws configure` or pass `--live` to scan your real AWS account[/dim]"
    )

    console.print()
    console.print(Panel(footer, title="[bold white]Cloud Infrastructure Posture Scan (Sandbox Fallback)[/bold white]", border_style="cyan"))
    console.print()


def run_policy_command():
    """Displays the active Policy-as-Code configuration from aegis.yaml."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from patterns.guardrails import DeciderCloudGuardrail, load_policy_as_code

    console = Console()
    pol = load_policy_as_code()

    t = Table(box=None, padding=(0, 2), show_header=True)
    t.add_column("Policy Category", style="bold cyan", width=30)
    t.add_column("Configured Rules / Boundaries", style="white")

    t.add_row("Model & Gate Threshold", f"Strands Decider 2B (Fail-Closed Confidence ≥ {pol.get('risk_threshold', 0.85):.0%})")
    t.add_row("Typed Question Contract", f"[italic]{DeciderCloudGuardrail.TYPED_QUESTION}[/italic]")
    t.add_row(
        "[bold green]1. Auto-Permit (Fast-Lane)[/bold green]",
        ", ".join(sorted(a for a in pol.get("auto_permit", []) if ":" in a)) or "ec2:RevokeSecurityGroupIngress",
    )
    t.add_row(
        "[bold red]2. Always Halt (Destructive)[/bold red]",
        ", ".join(sorted(a for a in pol.get("always_halt", []) if ":" in a)) or "ec2:DeleteSecurityGroup",
    )
    t.add_row(
        "[bold yellow]3. Require Break-Glass MFA[/bold yellow]",
        ", ".join(sorted(a for a in pol.get("require_break_glass_mfa", []) if ":" in a)) or "ec2:ReplaceRoute",
    )

    console.print()
    console.print(Panel(t, title="[bold white]Aegis-2B Policy-as-Code (aegis.yaml)[/bold white]", border_style="cyan"))
    console.print()


def main():
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis-2B: Sub-Second Safety Circuit Breaker using Strands Decider 2B",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="aegis-2b 0.2.0",
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
    protect_parser.add_argument("--blast", choices=["isolated", "vpc_wide", "account_wide"], default="isolated", help="Blast radius boundary")
    protect_parser.add_argument("--destructive", action="store_true", help="Flag action as destructive mutation")
    protect_parser.add_argument("--notes", type=str, default=None, help="Optional alert context or untrusted description")
    protect_parser.add_argument("--interactive", action="store_true", help="Prompt for Break-Glass MFA if action is gated")
    protect_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON for CI/CD pipelines")
    protect_parser.add_argument("--enforce", action="store_true", help="Exit code 0 if permitted, exit code 1 if blocked (CI/CD gate)")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Inspect active cloud infrastructure posture and security state")
    scan_parser.add_argument("--live", action="store_true", help="Force live AWS account scan using `aws configure` credentials")
    scan_parser.add_argument("--sandbox", action="store_true", help="Force offline sandbox scan (Account 111122223333)")
    scan_parser.add_argument("--profile", type=str, default=None, help="AWS CLI profile name from ~/.aws/credentials")
    scan_parser.add_argument("--region", type=str, default=None, help="AWS region override (e.g. us-east-1, me-central-1)")

    # Command: test-aws
    test_aws_parser = subparsers.add_parser(
        "test-aws",
        help="Verify real Botocore circuit breaking against your live AWS account",
    )
    test_aws_parser.add_argument("--profile", type=str, default=None, help="AWS CLI profile name from ~/.aws/credentials")
    test_aws_parser.add_argument("--region", type=str, default=None, help="AWS region override (e.g. us-east-1, me-central-1)")
    test_aws_parser.add_argument(
        "--create-test-sg",
        action="store_true",
        help="Create an ephemeral Security Group in your default VPC, remediate Port 22 live, block delete, and clean up ($0 cost)",
    )
    test_aws_parser.add_argument(
        "--interactive",
        action="store_true",
        help="Prompt for Break-Glass MFA token during ephemeral Security Group cleanup",
    )

    # Command: policy
    subparsers.add_parser("policy", help="Display active Policy-as-Code rules (aegis.yaml)")

    # Command: remediate (3-Tier Router + Interactive [y/N/diff/iac] + Terraform Diff)
    remediate_parser = subparsers.add_parser(
        "remediate",
        help="Run 3-tier Decider 2B routing & remediate findings via Boto3 or Terraform git diff",
    )
    remediate_parser.add_argument("--input", "--alert", dest="input", type=str, default=None, help="Path to Security Hub, GuardDuty, or Prowler JSON findings file")
    remediate_parser.add_argument("--profile", type=str, default=None, help="AWS CLI profile name")
    remediate_parser.add_argument("--region", type=str, default=None, help="AWS region override")
    remediate_parser.add_argument("--interactive", action="store_true", help="Interactive [y/N/diff/iac] approval prompt for each finding")
    remediate_parser.add_argument("--dry-run", action="store_true", help="Evaluate alert with Decider 2B without executing any Boto3 mutation")
    remediate_parser.add_argument("--iac", action="store_true", help="Output declarative Terraform HCL git diffs to prevent state drift")
    remediate_parser.add_argument("--json", action="store_true", help="Output structured JSON router schema")

    # Command: audit (10-Vector Security Self-Audit)
    audit_parser = subparsers.add_parser(
        "audit",
        help="Run 10-vector live red-team & security self-audit against Aegis-2B",
    )
    audit_parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON security audit scorecard",
    )

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
            notes=args.notes,
        )

    elif args.command == "scan":
        run_scan_command(
            live=args.live,
            sandbox=args.sandbox,
            profile=args.profile,
            region=args.region,
        )

    elif args.command == "test-aws":
        from aegis.aws_live import run_live_aws_test
        ok = run_live_aws_test(
            profile=args.profile,
            region=args.region,
            create_ephemeral_sg=args.create_test_sg,
            interactive=args.interactive,
        )
        if not ok:
            sys.exit(1)

    elif args.command == "policy":
        run_policy_command()

    elif args.command == "remediate":
        from aegis.remediate import run_remediate_cli
        run_remediate_cli(
            input_path=args.input,
            profile=args.profile,
            region=args.region,
            interactive=args.interactive,
            show_iac=args.iac,
            as_json=args.json,
            dry_run=args.dry_run,
        )

    elif args.command == "audit":
        from aegis.security_audit import run_security_audit_cli
        ok = run_security_audit_cli(as_json=args.json)
        if not ok:
            sys.exit(1)

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

