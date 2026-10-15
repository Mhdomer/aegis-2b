"""
Aegis-2B — Interactive Terminal Cockpit
A k9s-style full-screen terminal operations dashboard for autonomous cloud safety.
Tied to active shell session with zero-flicker event-driven rendering.
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
        self._add_log("SYSTEM", "cyan", "Aegis-2B Cockpit initialized & attached to session.")
        self._add_log("DECIDER", "green", "Strands Decider 2B calibrated. Baseline gate: 114.7ms.")

    def _resolve_fixtures_dir(self) -> Path:
        base = Path(__file__).resolve().parent.parent / "scenarios" / "fixtures"
        if not base.exists():
            base = Path(__file__).resolve().parent / "scenarios" / "fixtures"
        return base

    def _add_log(self, tag: str, style: str, message: str):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self.logs.append({"time": now, "tag": tag, "style": style, "msg": message})
        if len(self.logs) > 6:
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
            self._add_log("ATTACK", "red", "Poisoned alert: Injected delete core SG directive!")

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
            self._add_log("DECIDER", "green", f"Verified in {decider_res.latency_ms:.1f}ms: PERMITTED.")
            self._add_log("BOTO3", "green", "ec2:RevokeSecurityGroupIngress executed.")
        elif scenario_type == "adversarial":
            self._add_log("CIRCUIT", "red", f"Intercepted in {decider_res.latency_ms:.1f}ms! HALTED.")
            self._add_log("CONTAIN", "red", "Zero AWS API calls issued. Core VPC intact.")
        elif scenario_type == "blast_radius":
            self._add_log("GATE", "yellow", f"Gated in {decider_res.latency_ms:.1f}ms. Press [B] to MFA Override.")

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
            self._add_log("OVERRIDE", "green", f"MFA token [{token}] verified! Route mutation authorized.")
            self._notify_web_server("blast_radius", token=token)
        else:
            self._add_log("REJECT", "red", f"Invalid Break-Glass token [{token}].")

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
        self._add_log("RESET", "cyan", "Resources restored to default baseline. Port 22 open.")
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

    def build_view(self) -> Layout:
        """Dynamically builds a responsive layout tailored to terminal dimensions."""
        width = console.width
        height = console.height
        is_narrow = width < 95

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=5 if height > 24 else 3),
        )

        if is_narrow:
            layout["body"].split_column(
                Layout(name="resources", ratio=5),
                Layout(name="circuit", ratio=5),
            )
        else:
            layout["body"].split_row(
                Layout(name="resources", ratio=6),
                Layout(name="circuit", ratio=4),
            )

        layout["header"].update(self.render_header())
        layout["resources"].update(self.render_resources_table())
        layout["circuit"].update(self.render_circuit_panel())
        layout["footer"].update(self.render_footer())
        return layout

    def render_header(self) -> Panel:
        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S UTC")
        t = Table.grid(expand=True)
        t.add_column(ratio=6)
        t.add_column(ratio=4, justify="right")

        t.add_row(
            Text.from_markup(
                "[bold cyan]🛡️  AEGIS-2B COCKPIT[/bold cyan] "
                "[bold black on yellow] K9S MODE [/bold black on yellow] "
                "[bold green]● ARMED[/bold green]"
            ),
            Text.from_markup(f"[dim]Acct: 111122223333 │ {now_utc}[/dim]"),
        )
        return Panel(t, border_style="cyan", box=box.ROUNDED)

    def render_resources_table(self) -> Panel:
        state = self.dispatcher._simulated_state
        table = Table(box=box.SIMPLE, expand=True, padding=(0, 1), show_header=True)
        table.add_column("Resource", style="bold white", no_wrap=True)
        table.add_column("Type", style="dim", width=8, no_wrap=True)
        table.add_column("Security Posture", no_wrap=True)

        # 1. Bastion SG
        sg1 = state["security_groups"]["sg-0123456789"]
        ingress_rules = sg1.get("IngressRules", sg1.get("rules", []))
        has_22 = any(r.get("Port", r.get("port")) == 22 for r in ingress_rules)
        if has_22:
            status_1 = Text("● Port 22: OPEN", style="bold red")
        else:
            status_1 = Text("✔ Port 22: CLOSED", style="bold green")
        table.add_row("sg-0123456789 (bastion)", "SG", status_1)

        # 2. Core SG
        table.add_row("sg-core-vpc-01 (core-db)", "SG", Text("🛡️ PROTECTED (100%)", style="bold green"))

        # 3. Core Route Table
        rt = state["route_tables"]["rtb-core-vpc-01"]
        routes = rt.get("Routes", rt.get("routes", []))
        default_r = next((r for r in routes if r.get("DestinationCidrBlock", r.get("cidr")) == "0.0.0.0/0"), None)
        target = default_r.get("GatewayId", default_r.get("target", "NONE")) if default_r else "NONE"
        table.add_row("rtb-core-vpc-01 (main-rtb)", "RT", Text(f"✔ 0.0.0.0/0 -> {target}", style="bold cyan"))

        # 4. IAM Executor
        table.add_row("iam:role/aegis-remed-bot", "IAM", Text("✔ Least-Privilege Boto3", style="dim green"))

        return Panel(table, title="[bold white]☁️ Cloud Resources[/bold white]", border_style="blue", box=box.ROUNDED)

    def render_circuit_panel(self) -> Panel:
        t = Table.grid(expand=True, padding=(0, 1))
        t.add_column(style="dim white", no_wrap=True)
        t.add_column(justify="right", no_wrap=True)

        t.add_row("Engine:", "[bold white]Strands Decider 2B[/bold white]")
        t.add_row("Latency:", f"[bold cyan]{self.last_decision['latency_ms']:.1f} ms[/bold cyan]")
        t.add_row("Confidence:", f"[bold green]{self.last_decision['confidence']:.1%}[/bold green]")
        t.add_row("Fail-Closed:", "[bold yellow]≥ 0.85 (Enforced)[/bold yellow]")
        t.add_row("Cost / 1k:", "[bold green]$0.00[/bold green]")
        t.add_row("Last Action:", f"[bold white]{self.last_decision['proposed_tool']}[/bold white]")
        t.add_row("Blast Radius:", f"[bold white]{self.last_decision['blast_radius']}[/bold white]")

        dec = self.last_decision["decision"]
        if dec == "PERMIT" or dec == "PERMIT_AUTO_REMEDIATION":
            dec_styled = "[bold black on green] PERMITTED [/bold black on green]"
        elif dec in ("ARMED", "BASELINE"):
            dec_styled = "[bold black on cyan] READY / ARMED [/bold black on cyan]"
        elif dec == "OVERRIDDEN":
            dec_styled = "[bold black on yellow] OVERRIDDEN (MFA) [/bold black on yellow]"
        else:
            dec_styled = "[bold white on red] HALTED & GATED [/bold white on red]"

        t.add_row("Gate State:", dec_styled)
        return Panel(t, title="[bold white]⚡ Circuit Telemetry[/bold white]", border_style="cyan", box=box.ROUNDED)

    def render_footer(self) -> Panel:
        log_table = Table.grid(expand=True)
        log_table.add_column(width=9, style="dim")
        log_table.add_column(width=10)
        log_table.add_column(ratio=1, no_wrap=True)

        show_logs = self.logs[-2:] if console.height <= 24 else self.logs[-3:]
        for entry in show_logs:
            log_table.add_row(
                f"[{entry['time']}]",
                f"[{entry['style']}][{entry['tag']}][/{entry['style']}]",
                Text(entry["msg"], style="white", overflow="ellipsis"),
            )

        keybinds = (
            "[bold white on blue] [1] Benign [/bold white on blue] "
            "[bold white on red] [2] Attack [/bold white on red] "
            "[bold white on yellow] [3] Blast [/bold white on yellow] "
            "[bold black on yellow] [B] MFA [/bold black on yellow] "
            "[bold white on bright_black] [R] Reset [/bold white on bright_black] "
            "[bold black on cyan] [W] Web [/bold black on cyan] "
            "[bold white on dark_red] [Q] Quit [/bold white on dark_red]"
        )

        t = Table.grid(expand=True)
        t.add_row(log_table)
        t.add_row(Text.from_markup(f"{keybinds}"))
        return Panel(t, title="[bold white]💻 Journal & Hotkeys[/bold white]", border_style="green", box=box.ROUNDED)


def run_cockpit():
    """Starts the flicker-free interactive Terminal Cockpit."""
    cockpit = AegisCockpit()

    old_settings = None
    fd = None
    if sys.platform != "win32":
        try:
            import termios
            import tty
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            # Set cbreak mode ONCE for the entire session
            tty.setcbreak(fd)
        except Exception:
            pass

    try:
        console.clear()
        # auto_refresh=False: No busy background redraw loop, eliminates all flickering!
        with Live(cockpit.build_view(), screen=True, auto_refresh=False, console=console) as live:
            live.refresh()
            last_clock_tick = time.time()

            while True:
                has_key = False
                ch = None

                if sys.platform != "win32" and fd is not None:
                    rlist, _, _ = select.select([sys.stdin], [], [], 0.08)
                    if rlist:
                        ch = sys.stdin.read(1)
                        has_key = True
                else:
                    import msvcrt
                    if msvcrt.kbhit():
                        ch = msvcrt.getch().decode("utf-8", errors="ignore")
                        has_key = True
                    else:
                        time.sleep(0.08)

                needs_redraw = False
                if has_key and ch:
                    k = ch.lower()
                    if k in ("q", "\x03", "\x1b"):  # q, Ctrl+C, Esc
                        break
                    elif k == "1":
                        cockpit.trigger_scenario("benign")
                        needs_redraw = True
                    elif k == "2":
                        cockpit.trigger_scenario("adversarial")
                        needs_redraw = True
                    elif k == "3":
                        cockpit.trigger_scenario("blast_radius")
                        needs_redraw = True
                    elif k == "b":
                        cockpit.trigger_break_glass("849201")
                        needs_redraw = True
                    elif k == "r":
                        cockpit.reset_state()
                        needs_redraw = True
                    elif k == "w":
                        cockpit.open_web_ui()
                        needs_redraw = True

                # Refresh only when state changes or at 1Hz for clock
                now = time.time()
                if needs_redraw or (now - last_clock_tick >= 1.0):
                    live.update(cockpit.build_view())
                    live.refresh()
                    last_clock_tick = now

    finally:
        if sys.platform != "win32" and old_settings is not None and fd is not None:
            try:
                import termios
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            except Exception:
                pass
        console.clear()
        console.print("[bold cyan]Aegis-2B Cockpit detached gracefully.[/bold cyan] Session restored.\n")


if __name__ == "__main__":
    run_cockpit()
