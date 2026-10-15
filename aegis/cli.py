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

    # Command: benchmark
    benchmark_parser = subparsers.add_parser("benchmark", help="Run the statistical latency and cost benchmark")
    benchmark_parser.add_argument(
        "--iterations",
        type=int,
        default=50,
        help="Number of iterations to execute (default: 50)",
    )

    args = parser.parse_args()

    # Default action if no sub-command passed: run full demo
    if args.command is None or args.command == "demo":
        from aegis_demo import main as run_demo
        scenario_to_run = getattr(args, "scenario", "all")
        is_interactive = getattr(args, "interactive", False)
        run_demo(scenario=scenario_to_run, interactive=is_interactive)
    elif args.command == "benchmark":


        from scripts.benchmark import run_benchmark
        run_benchmark(iterations=args.iterations)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
