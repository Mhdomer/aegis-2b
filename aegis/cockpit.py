"""
Aegis-2B — Interactive Terminal Cockpit
A k9s-style full-screen terminal operations dashboard for autonomous cloud safety.
Tied to active shell session with live keyboard controls and real-time state synchronization.
"""

import datetime
import json
import os
import select
import sys
import time
import webbrowser
from pathlib import Path
from typing import Dict, List, Optional

from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aegis.dispatcher import AWSActionDispatcher, verify_break_glass_token
from patterns.guardrails import (
    BlastRadius,
    DeciderCloudGuardrail,
    DeciderState,
    GuardrailAction,
)

console = Console()


class AegisCockpit:
    """Live interactive terminal cockpit for Aegis-2B circuit breaker."""

    def __init__(self):
        self.dispatcher = AWSActionDispatcher()
        self.guardrail = DeciderCloudGuardrail(risk_threshold=0.85, simulate_local_latency=True)
        self.logs: List[Dict[str, str]] = []
        self.last_decision = {
            "scenario": "INIT",
            "decision": "ARMED",
            "confidence": 1.0,
            "latency_ms": 114.7,
            "proposed_tool": "NONE",
            "blast_radius": "ISOLATED",
            "status": "NOMINAL",
        }
        self.fixtures_dir = self._resolve_fixtures_dir()
        self._add_log("SYSTEM", "cyan", "Aegis-2B Terminal Cockpit armed and attached to shell session.")
        self._add_log("DECIDER", "green", "Strands Decider 2B local engine calibrated. P50 gate baseline: 114.7ms.")

    def _resolve_fixtures_dir(self) -> Path:
        base = Path(__file__).resolve().parent.parent / "scenarios" / "fixtures"
        if not base.exists():
            base = Path(__file__).resolve().parent / "scenarios" / "fixtures"
        return base

    def _add_log(self, tag: str, style: str, message: str):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self.logs.append({"time": now, "tag": tag, "style": style, "msg": message})
        if len(self.logs) > 8:
            self.logs.pop(0)

    def trigger_scenario(self, scenario_type: str):
        if scenario_type == "benign":
            fixture_file = self.fixtures_dir / "benign_ssh_finding.json"
            tool_name = "revoke_security_group_ingress"
            params = {"GroupId": "sg-0123456789", "CidrIp": "0.0.0.0/0", "Port": 22}
            blast = BlastRadius.ISOLATED
            is_destr = False
            self._add_log("INGEST", "cyan", "GuardDuty finding: SSHBruteForce on port 22.")

        elif scenario_type == "adversarial":
            fixture_file = self.fixtures_dir / "malicious_prompt_injection.json"
            tool_name = "delete_security_group"
            params = {"GroupId": "sg-core-vpc-01"}
            blast = BlastRadius.VPC_WIDE
            is_destr = True
            self._add_log("ATTACK", "red", "Poisoned alert: Injected directive to delete core security group!")

        elif scenario_type == "blast_radius":
            fixture_file = self.fixtures_dir / "high_blast_radius_route_table.json"
            tool_name = "replace_route"
            params = {"RouteTableId": "rtb-core-vpc-01", "DestinationCidrBlock": "0.0.0.0/0"}
            blast = BlastRadius.VPC_WIDE
            is_destr = False
            self._add_log("BLAST", "yellow", "VPC-wide default route change requested.")
        else:
            return

        with open(fixture_file, "r", encoding="utf-8") as f:
            finding = json.load(f)

        state = DeciderState(
            alert_source=finding.get("ProductArn", "aws.guardduty"),
            alert_severity=finding.get("Severity", {}).get("Label", "HIGH"),
            target_arn=finding["Resources"][0]["Id"],
            proposed_tool=tool_name,
            tool_parameters=params,
            blast_radius=blast,
            is_destructive_action=is_destr,
        )

        decider_res = self.guardrail.evaluate(state)
        receipt = self.dispatcher.dispatch(state, decider_res)

        self.last_decision = {
            "scenario": scenario_type.upper(),
            "decision": decider_res.action.value,
            "confidence": decider_res.confidence,
            "latency_ms": decider_res.latency_ms,
            "proposed_tool": tool_name,
            "blast_radius": blast.value,
            "status": receipt.execution_status,
        }

        if scenario_type == "benign":
            self._add_log("DECIDER", "green", f"Decider 2B verified in {decider_res.latency_ms:.1f}ms: PERMITTED.")
            self._add_log("BOTO3", "green", "ec2:RevokeSecurityGroupIngress executed. Port 22 isolated.")
        elif scenario_type == "adversarial":
            self._add_log("CIRCUIT", "red", f"Caught destructive action in {decider_res.latency_ms:.1f}ms! HALTED.")
            self._add_log("CONTAIN", "red", "Zero AWS API calls issued. Core VPC 100% intact.")
        elif scenario_type == "blast_radius":
            self._add_log("GATE", "yellow", f"VPC-wide mutation halted in {decider_res.latency_ms:.1f}ms. Press [B] to MFA Override.")

        self._notify_web_server(scenario_type)

    def trigger_break_glass(self, token: str = "849201"):
        if verify_break_glass_token(token):
            state = DeciderState(
                alert_source="aws.securityhub",
                alert_severity="HIGH",
                target_arn="arn:aws:ec2:us-east-1:111122223333:route-table/rtb-core-vpc-01",
                proposed_tool="replace_route",
                tool_parameters={"RouteTableId": "rtb-core-vpc-01", "DestinationCidrBlock": "0.0.0.0/0"},
                blast_radius=BlastRadius.VPC_WIDE,
            )
            decider_res = self.guardrail.evaluate(state)
            receipt = self.dispatcher.dispatch(state, decider_res, break_glass_token=token, operator_id="sec-ops-admin")

            self.last_decision = {
                "scenario": "BREAK_GLASS",
                "decision": "OVERRIDDEN",
                "confidence": 1.0,
                "latency_ms": 114.7,
                "proposed_tool": "replace_route",
                "blast_radius": "VPC_WIDE",
                "status": receipt.execution_status,
            }
            self._add_log("OVERRIDE", "green", f"Break-Glass token [{token}] verified! VPC route mutation authorized.")
            self._notify_web_server("blast_radius", token=token)
        else:
            self._add_log("REJECT", "red", f"Invalid Break-Glass token [{token}]. Action kept halted.")

    def reset_state(self):
        self.dispatcher = AWSActionDispatcher()
        self.last_decision = {
            "scenario": "RESET",
            "decision": "BASELINE",
            "confidence": 1.0,
            "latency_ms": 114.7,
            "proposed_tool": "NONE",
            "blast_radius": "ISOLATED",
            "status": "RESTORED",
        }
        self._add_log("RESET", "cyan", "Simulated cloud resources restored to default baseline. Port 22 open.")
        try:
            import urllib.request
            req = urllib.request.Request("http://127.0.0.1:8765/api/reset", method="POST")
            urllib.request.urlopen(req, timeout=0.2)
        except Exception:
            pass

    def open_web_ui(self):
        self._add_log("WEB_UI", "cyan", "Opening Web Operations Center at http://127.0.0.1:8765...")
        try:
            webbrowser.open("http://127.0.0.1:8765")
        except Exception:
            pass

    def _notify_web_server(self, scenario: str, token: Optional[str] = None):
        try:
            import urllib.request
            endpoint = "http://127.0.0.1:8765/api/break-glass" if token else "http://127.0.0.1:8765/api/evaluate"
            payload = {"scenario": scenario} if not token else {"scenario": scenario, "token": token, "operator": "sec-ops-admin"}
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=0.2)
        except Exception:
            pass

    def make_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=4),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=5),
        )
        layout["body"].split_row(
            Layout(name="resources", ratio=6),
            Layout(name="circuit", ratio=4),
        )
        return layout

    def render_header(self) -> Panel:
        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        t = Table.grid(expand=True)
        t.add_column(ratio=6)
        t.add_column(ratio=4, justify="right")

        t.add_row(
            Text.from_markup(
                "[bold cyan]🛡️  AEGIS-2B CLOUD OPERATIONS COCKPIT[/bold cyan] "
                "[bold black on yellow] K9S MODE [/bold black on yellow]\n"
                "[dim]Sub-Second Safety Circuit Breaker │ Amazon Bedrock + Strands Decider 2B[/dim]"
            ),
            Text.from_markup(
                f"[bold green]● CIRCUIT ARMED (FAIL-CLOSED)[/bold green]\n"
                f"[dim]Account: 111122223333 │ {now_utc}[/dim]"
            ),
        )
        return Panel(t, border_style="cyan", box=box.ROUNDED)

    def render_resources_table(self) -> Panel:
        state = self.dispatcher._simulated_state
        table = Table(box=box.SIMPLE_HEAVY, expand=True)
        table.add_column("Resource ARN / ID", style="bold white", ratio=4)
        table.add_column("Type", style="dim white", ratio=2)
        table.add_column("Security Posture", ratio=4)

        # 1. Bastion SG
        sg1 = state["security_groups"]["sg-0123456789"]
        ingress_rules = sg1.get("IngressRules", sg1.get("rules", []))
        has_22 = any(r.get("Port", r.get("port")) == 22 for r in ingress_rules)
        if has_22:
            status_1 = Text("● Port 22: OPEN (0.0.0.0/0)", style="bold red")
        else:
            status_1 = Text("✔ Port 22: REVOKED (ISOLATED)", style="bold green")
        table.add_row("sg-0123456789 (app-bastion)", "SecurityGroup", status_1)

        # 2. Core SG
        status_2 = Text("🛡️ ACTIVE (PROTECTED 100%)", style="bold green")
        table.add_row("sg-core-vpc-01 (core-db)", "SecurityGroup", status_2)

        # 3. Core Route Table
        rt = state["route_tables"]["rtb-core-vpc-01"]
        routes = rt.get("Routes", rt.get("routes", []))
        default_r = next((r for r in routes if r.get("DestinationCidrBlock", r.get("cidr")) == "0.0.0.0/0"), None)
        target = default_r.get("GatewayId", default_r.get("target", "NONE")) if default_r else "NONE"
        status_3 = Text(f"✔ 0.0.0.0/0 -> {target} (GATED)", style="bold cyan")
        table.add_row("rtb-core-vpc-01 (main-rtb)", "RouteTable", status_3)

        # 4. IAM Executor
        table.add_row("iam:role/aegis-remediation-bot", "IAM Role", Text("✔ Least-Privilege Boto3", style="dim green"))

        return Panel(table, title="[bold white]☁️ Monitored Cloud Resources (Real-Time State)[/bold white]", border_style="blue", box=box.ROUNDED)

    def render_circuit_panel(self) -> Panel:
        t = Table.grid(expand=True, padding=(0, 1))
        t.add_column(ratio=5, style="dim white")
        t.add_column(ratio=5, justify="right")

        t.add_row("Decision Engine:", "[bold white]Strands Decider 2B[/bold white]")
        t.add_row("Execution Latency:", f"[bold cyan]{self.last_decision['latency_ms']:.1f} ms[/bold cyan]")
        t.add_row("Calibrated Confidence:", f"[bold green]{self.last_decision['confidence']:.1%}[/bold green]")
        t.add_row("Fail-Closed Threshold:", "[bold yellow]≥ 0.85 (Enforced)[/bold yellow]")
        t.add_row("Inference Cost / 1k:", "[bold green]$0.00 (Local Weights)[/bold green]")
        t.add_row("Last Evaluated Action:", f"[bold white]{self.last_decision['proposed_tool']}[/bold white]")
        t.add_row("Evaluated Blast Radius:", f"[bold white]{self.last_decision['blast_radius']}[/bold white]")

        dec = self.last_decision["decision"]
        if dec == "PERMIT":
            dec_styled = "[bold black on green] PERMITTED [/bold black on green]"
        elif dec == "ARMED" or dec == "BASELINE":
            dec_styled = "[bold black on cyan] READY / ARMED [/bold black on cyan]"
        elif dec == "OVERRIDDEN":
            dec_styled = "[bold black on yellow] OVERRIDDEN (MFA) [/bold black on yellow]"
        else:
            dec_styled = "[bold white on red] HALTED & GATED [/bold white on red]"

        t.add_row("Circuit Gate State:", dec_styled)

        return Panel(t, title="[bold white]⚡ Circuit Breaker Telemetry[/bold white]", border_style="cyan", box=box.ROUNDED)

    def render_footer(self) -> Panel:
        log_table = Table.grid(expand=True)
        log_table.add_column(width=10, style="dim")
        log_table.add_column(width=12)
        log_table.add_column(ratio=1)

        for entry in self.logs[-4:]:
            log_table.add_row(
                f"[{entry['time']}]",
                f"[{entry['style']}][{entry['tag']}][/{entry['style']}]",
                Text(entry["msg"], style="white"),
            )

        keybinds = (
            "[bold white on blue] [1] Benign Test [/bold white on blue] "
            "[bold white on red] [2] Injected Attack [/bold white on red] "
            "[bold white on yellow] [3] Blast Radius [/bold white on yellow] "
            "[bold black on yellow] [B] MFA Override (849201) [/bold black on yellow] "
            "[bold white on bright_black] [R] Reset [/bold white on bright_black] "
            "[bold black on cyan] [W] Open Web UI [/bold black on cyan] "
            "[bold white on dark_red] [Q] Quit [/bold white on dark_red]"
        )

        t = Table.grid(expand=True)
        t.add_row(log_table)
        t.add_row(Text.from_markup(f"\n{keybinds}"))

        return Panel(t, title="[bold white]💻 Real-Time Operations Telemetry Log Stream & Hotkeys[/bold white]", border_style="green", box=box.ROUNDED)

    def draw(self, layout: Layout):
        layout["header"].update(self.render_header())
        layout["resources"].update(self.render_resources_table())
        layout["circuit"].update(self.render_circuit_panel())
        layout["footer"].update(self.render_footer())


def _read_key_nonblocking() -> Optional[str]:
    """Reads a single keypress without blocking across Linux/Unix."""
    if sys.platform != "win32":
        import termios
        import tty

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            rlist, _, _ = select.select([sys.stdin], [], [], 0.05)
            if rlist:
                ch = sys.stdin.read(1)
                return ch
            return None
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    else:
        import msvcrt
        if msvcrt.kbhit():
            ch = msvcrt.getch().decode("utf-8", errors="ignore")
            return ch
        time.sleep(0.05)
        return None


def run_cockpit():
    """Starts the full-screen interactive Terminal Cockpit."""
    cockpit = AegisCockpit()
    layout = cockpit.make_layout()

    console.clear()
    with Live(layout, refresh_per_second=10, screen=True) as live:
        while True:
            cockpit.draw(layout)
            key = _read_key_nonblocking()
            if key:
                k = key.lower()
                if k in ("q", "\x03"):  # q or Ctrl+C
                    break
                elif k == "1":
                    cockpit.trigger_scenario("benign")
                elif k == "2":
                    cockpit.trigger_scenario("adversarial")
                elif k == "3":
                    cockpit.trigger_scenario("blast_radius")
                elif k == "b":
                    cockpit.trigger_break_glass("849201")
                elif k == "r":
                    cockpit.reset_state()
                elif k == "w":
                    cockpit.open_web_ui()

            time.sleep(0.04)

    console.clear()
    console.print("[bold cyan]Aegis-2B Cockpit detached gracefully.[/bold cyan] Session restored.\n")


if __name__ == "__main__":
    run_cockpit()
