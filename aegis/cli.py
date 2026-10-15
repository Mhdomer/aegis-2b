"""
Aegis-2B — Unified CLI Interface
Sub-Second Safety Circuit Breaker for Autonomous Cloud Ops Agents.
"""

import argparse
import sys
from pathlib import Path

# Fix Windows console UTF-8 encoding if needed
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


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
    demo_parser = subparsers.add_parser("demo", help="Run the interactive multi-scenario demonstration")
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

    # Command: benchmark
    benchmark_parser = subparsers.add_parser("benchmark", help="Run the statistical latency and cost benchmark")
    benchmark_parser.add_argument(
        "--iterations",
        type=int,
        default=50,
        help="Number of iterations to execute (default: 50)",
    )

    # Command: ui (Web Operations Center)
    ui_parser = subparsers.add_parser("ui", help="Launch live interactive Web Operations Center")
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

    # Command: top / dashboard (k9s-style Cockpit)
    subparsers.add_parser(
        "top",
        aliases=["dashboard"],
        help="Launch full-screen k9s-style interactive Terminal Cockpit",
    )

    # Command: man (Linux User's Manual)
    subparsers.add_parser(
        "man",
        aliases=["manual"],
        help="Display comprehensive Unix/Linux manual page",
    )

    args = parser.parse_args()

    # Default action if no sub-command passed: run full demo
    if args.command is None or args.command == "demo":
        from aegis_demo import main as run_demo
        scenario_to_run = getattr(args, "scenario", "all")
        is_interactive = getattr(args, "interactive", False)
        is_compare = getattr(args, "compare_llm", False)
        run_demo(scenario=scenario_to_run, interactive=is_interactive, compare_llm=is_compare)

    elif args.command == "benchmark":
        from scripts.benchmark import run_benchmark
        run_benchmark(iterations=args.iterations)

    elif args.command == "ui":
        from aegis.server import start_server
        start_server(port=args.port, open_browser=not args.no_browser)

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
