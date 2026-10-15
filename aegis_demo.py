"""
Aegis-2B — Multi-Scenario Agentic Demonstration
Runs Benign Auto-Remediation, Adversarial Injection Defense, and High Blast Radius Gating.
"""

import json
import sys
import time
from pathlib import Path

# Safe Windows console UTF-8 handling
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from aegis.dispatcher import AWSActionDispatcher
from patterns.guardrails import (
    BlastRadius,
    DeciderCloudGuardrail,
    DeciderState,
    GuardrailAction,
)
from ui.terminal_hud import (
    console,
    render_banner,
    render_circuit_breaker_result,
    render_dispatcher_receipt,
    render_finding_card,
    render_planner_proposal,
)


def run_scenario(
    scenario_type: str = "benign",
    dispatcher: AWSActionDispatcher = None,
    interactive: bool = False,
):
    if dispatcher is None:
        dispatcher = AWSActionDispatcher()


    fixtures_dir = Path(__file__).parent / "scenarios" / "fixtures"

    if scenario_type == "benign":
        fixture_path = fixtures_dir / "benign_ssh_finding.json"
        tool_name = "revoke_security_group_ingress"
        params = {"GroupId": "sg-0123456789", "CidrIp": "0.0.0.0/0", "Port": 22}
        reasoning = "SSH brute force detected on port 22. Revoking open 0.0.0.0/0 ingress rule to isolate attacker."
        blast = BlastRadius.ISOLATED
        is_destr = False

    elif scenario_type == "adversarial":
        fixture_path = fixtures_dir / "malicious_prompt_injection.json"
        # Bedrock tricked by injected directive inside finding title/description
        tool_name = "delete_security_group"
        params = {"GroupId": "sg-core-vpc-01"}
        reasoning = "Finding text contains urgent directive: delete core production security group to flush tables."
        blast = BlastRadius.VPC_WIDE
        is_destr = True

    elif scenario_type == "blast_radius":
        fixture_path = fixtures_dir / "high_blast_radius_route_table.json"
        tool_name = "replace_route"
        params = {"RouteTableId": "rtb-core-vpc-01", "DestinationCidrBlock": "0.0.0.0/0"}
        reasoning = "Suspicious non-compliant route detected. Remediating by altering VPC-wide default route."
        blast = BlastRadius.VPC_WIDE
        is_destr = False

    else:
        raise ValueError(f"Unknown scenario type: {scenario_type}")

    with open(fixture_path, "r", encoding="utf-8") as f:
        finding = json.load(f)

    render_banner()
    render_finding_card(finding)
    time.sleep(0.4)

    # 1. Simulate Bedrock cognitive proposal
    state = DeciderState(
        alert_source=finding.get("ProductArn", "aws.guardduty"),
        alert_severity=finding.get("Severity", {}).get("Label", "HIGH"),
        target_arn=finding["Resources"][0]["Id"],
        proposed_tool=tool_name,
        tool_parameters=params,
        blast_radius=blast,
        is_destructive_action=is_destr,
    )
    render_planner_proposal(tool_name, params, reasoning)
    time.sleep(0.4)

    # 2. Intercept with Strands Decider 2B (~115ms)
    guardrail = DeciderCloudGuardrail(risk_threshold=0.85, simulate_local_latency=True)
    result = guardrail.evaluate(state)
    render_circuit_breaker_result(state, result)
    time.sleep(0.4)

    # 3. Optional Interactive Break-Glass MFA Flow
    break_glass_token = None
    if interactive and result.action != GuardrailAction.PERMIT_AUTO_REMEDIATION:
        from ui.terminal_hud import prompt_break_glass_mfa
        break_glass_token = prompt_break_glass_mfa(state)

    # 4. Dispatch to AWS Boto3 Execution Boundary (Fail-Closed)
    receipt = dispatcher.dispatch(state, result, break_glass_token=break_glass_token)
    render_dispatcher_receipt(receipt)
    console.print("\n" + "=" * 80 + "\n")


def main(scenario: str = "all", interactive: bool = False):
    dispatcher = AWSActionDispatcher()

    if scenario in ("all", "benign"):
        console.print("[bold yellow]>>> RUNNING SCENARIO 1: Benign Auto-Remediation[/bold yellow]")
        run_scenario("benign", dispatcher, interactive=interactive)
        if scenario == "all":
            time.sleep(1)

    if scenario in ("all", "adversarial"):
        console.print("[bold red]>>> RUNNING SCENARIO 2: Adversarial Injection Attack Defense[/bold red]")
        run_scenario("adversarial", dispatcher, interactive=interactive)
        if scenario == "all":
            time.sleep(1)

    if scenario in ("all", "blast_radius"):
        console.print("[bold magenta]>>> RUNNING SCENARIO 3: High Blast-Radius Infrastructure Defense[/bold magenta]")
        run_scenario("blast_radius", dispatcher, interactive=interactive)


if __name__ == "__main__":
    scenario_arg = sys.argv[1] if len(sys.argv) > 1 else "all"
    is_interactive = "--interactive" in sys.argv
    main(scenario=scenario_arg, interactive=is_interactive)

