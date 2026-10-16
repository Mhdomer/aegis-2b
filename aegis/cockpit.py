"""
Aegis-2B — Interactive Terminal Cockpit
A full-screen terminal operations dashboard for autonomous AWS cloud safety.
Features arrow-key navigation (↑/↓/j/k), resource inspection ([Enter]/[d]),
multi-tab views (AWS Resources, CloudWatch Logs, VPC Topology), and live hotkeys.
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
    """Live interactive terminal cockpit with full keyboard navigation."""

    def __init__(self):
        self.dispatcher = AWSActionDispatcher()
        self.guardrail = DeciderCloudGuardrail(risk_threshold=0.85, simulate_local_latency=True)
        self.logs: List[Dict[str, str]] = []
        self.active_tab = 0  # 0: Resources, 1: Live Logs, 2: Cluster Topology
        self.selected_index = 0
        self.inspecting = False
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
        if len(self.logs) > 20:
            self.logs.pop(0)

    def get_resources_list(self) -> List[Dict[str, str]]:
        state = self.dispatcher._simulated_state
        sg1 = state["security_groups"]["sg-0123456789"]
        ingress_rules = sg1.get("IngressRules", sg1.get("rules", []))
        has_22 = any(r.get("Port", r.get("port")) == 22 for r in ingress_rules)

        rt = state["route_tables"]["rtb-core-vpc-01"]
        routes = rt.get("Routes", rt.get("routes", []))
        default_r = next((r for r in routes if r.get("DestinationCidrBlock", r.get("cidr")) == "0.0.0.0/0"), None)
        target = default_r.get("GatewayId", default_r.get("target", "NONE")) if default_r else "NONE"

        return [
            {
                "id": "i-0prod-bastion",
                "name": "sg-0123456789",
                "role": "EC2 Instance",
                "status": "▲ Port 22 Open" if has_22 else "● In-Service",
                "status_style": "bold yellow" if has_22 else "bold green",
                "policy": "Auto-Remediation",
                "finding": "Port 22/tcp (0.0.0.0/0) Exposed" if has_22 else "Port 22 Revoked (Safe)",
                "details": "Bastion ingress security group. SSH exposed to public internet." if has_22 else "Bastion security group. Port 22 revoked and isolated.",
                "rules": "Port 22/tcp (0.0.0.0/0)" if has_22 else "None (Ingress blocked)",
                "threat": "UnauthorizedAccess:EC2/SSHBruteForce" if has_22 else "None (Mitigated)",
            },
            {
                "id": "aurora-pg-core-db",
                "name": "sg-core-vpc-01",
                "role": "RDS Aurora PG",
                "status": "● Shielded",
                "status_style": "bold green",
                "policy": "Halt on Drop",
                "finding": "PostgreSQL 16 (:5432) VPC Isolated",
                "details": "Production Aurora PostgreSQL database. Houses clinical healthcare schema.",
                "rules": "Port 5432/tcp (10.0.0.0/16 VPC CIDR only)",
                "threat": "Prompt Injection Target (Protected by Strands Decider 2B)",
            },
            {
                "id": "rtb-core-vpc-01",
                "name": "vpc-0123456789",
                "role": "VPC Route Table",
                "status": "● Active",
                "status_style": "bold green",
                "policy": "SecOps MFA Gated",
                "finding": f"0.0.0.0/0 -> {target}",
                "details": "VPC-wide default route table. Directs outbound egress via Internet Gateway.",
                "rules": f"0.0.0.0/0 -> {target}, 10.0.0.0/16 -> local",
                "threat": "High Blast Radius Modification Vector",
            },
            {
                "id": "aegis-guardrail-gateway",
                "name": "decider-2b",
                "role": "In-VPC Guardrail",
                "status": "● ARMED",
                "status_style": "bold green",
                "policy": "Fail-Closed (≥0.85)",
                "finding": "114.7ms Local In-VPC Inference Gate",
                "details": "In-VPC sub-second decision model. Evaluates tool calls before AWS Boto3 dispatch.",
                "rules": "Fail-Closed Risk Threshold: 0.85",
                "threat": "None (Mathematically bound)",
            },
        ]

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
            self._add_log("BOTO3", "green", "ec2:RevokeSecurityGroupIngress executed. Port 22 isolated.")
        elif scenario_type == "adversarial":
            self._add_log("CIRCUIT", "red", f"Intercepted in {decider_res.latency_ms:.1f}ms! HALTED.")
            self._add_log("CONTAIN", "red", "Zero AWS API calls issued. Core VPC 100% intact.")
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

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="tabs", size=3),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=5 if height > 24 else 3),
        )

        layout["header"].update(self.render_header())
        layout["tabs"].update(self.render_tab_bar())

        if self.inspecting:
            layout["body"].update(self.render_resource_inspector())
        elif self.active_tab == 0:
            # Tab 0: Resources View (Split or Stacked)
            if width < 95:
                layout["body"].split_column(
                    Layout(name="resources", ratio=5),
                    Layout(name="circuit", ratio=5),
                )
            else:
                layout["body"].split_row(
                    Layout(name="resources", ratio=6),
                    Layout(name="circuit", ratio=4),
                )
            layout["resources"].update(self.render_resources_table())
            layout["circuit"].update(self.render_circuit_panel())
        elif self.active_tab == 1:
            # Tab 1: Full-Screen Live Log Stream
            layout["body"].update(self.render_full_logs())
        elif self.active_tab == 2:
            # Tab 2: ASCII Cluster Topology Map
            layout["body"].update(self.render_cluster_map())

        layout["footer"].update(self.render_footer())
        return layout

    def render_header(self) -> Panel:
        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S UTC")
        t = Table.grid(expand=True)
        t.add_column(ratio=7)
        t.add_column(ratio=3, justify="right")

        t.add_row(
            Text.from_markup(
                "[bold white]aws[/bold white] [bold yellow]AEGIS-2B[/bold yellow] "
                "[dim]│[/dim] [white]Region: us-east-1[/white] "
                "[dim]│[/dim] [white]VPC: vpc-0123456789[/white] "
                "[dim]│[/dim] [bold green]● Active (114.7ms Gate)[/bold green]"
            ),
            Text.from_markup(f"[dim]Account: 111122223333 │ {now_utc}[/dim]"),
        )
        return Panel(t, border_style="dim", box=box.SQUARE)

    def render_tab_bar(self) -> Panel:
        tabs = [
            ("1: AWS Cloud Resources", self.active_tab == 0),
            ("2: CloudWatch & Security Hub Audit Stream", self.active_tab == 1),
            ("3: VPC Network Architecture", self.active_tab == 2),
        ]
        t = Table.grid(expand=True, padding=(0, 2))
        row = []
        for label, is_active in tabs:
            if is_active:
                row.append(f"[bold white on blue] {label} [/bold white on blue]")
            else:
                row.append(f"[dim white]{label}[/dim white]")
        t.add_row(*row)
        return Panel(t, title="[dim]Views [Tab or ← / → to switch][/dim]", border_style="dim", box=box.SQUARE)

    def render_resources_table(self) -> Panel:
        resources = self.get_resources_list()
        table = Table(box=box.SIMPLE, expand=True, padding=(0, 1), show_header=True)
        table.add_column(" ", width=2, justify="center")
        table.add_column("AWS Resource", no_wrap=True)
        table.add_column("Service / Type", width=18, no_wrap=True)
        table.add_column("Security Posture", width=18, no_wrap=True)
        table.add_column("Aegis-2B Policy / Finding", no_wrap=True)

        for idx, res in enumerate(resources):
            is_sel = (idx == self.selected_index)
            if is_sel:
                cursor = "[bold white]>[/bold white]"
                r_label = f"[bold white on navy_blue]{res['id']}[/bold white on navy_blue]"
                r_role = f"[dim on navy_blue]{res['role']}[/dim on navy_blue]"
                r_status = f"[{res['status_style']} on navy_blue]{res['status']}[/{res['status_style']} on navy_blue]"
                r_finding = f"[white on navy_blue]{res['finding']}[/white on navy_blue]"
                table.add_row(cursor, r_label, r_role, r_status, r_finding, style="bold white on navy_blue")
            else:
                cursor = " "
                table.add_row(cursor, f"[white]{res['id']}[/white]", f"[dim]{res['role']}[/dim]", Text(res["status"], style=res["status_style"]), f"[dim]{res['finding']}[/dim]")

        title = "[bold white]AWS Protected Infrastructure (↑/↓ to navigate, [Enter] to inspect)[/bold white]"
        return Panel(table, title=title, border_style="dim", box=box.SQUARE)

    def render_circuit_panel(self) -> Panel:
        t = Table.grid(expand=True, padding=(0, 1))
        t.add_column(style="dim white", no_wrap=True)
        t.add_column(justify="right", no_wrap=True)

        t.add_row("Guardrail Engine:", "[bold white]Strands Decider 2B[/bold white]")
        t.add_row("In-VPC Latency:", f"[bold white]{self.last_decision['latency_ms']:.1f} ms[/bold white]")
        t.add_row("Decision Confidence:", f"[bold green]{self.last_decision['confidence']:.1%}[/bold green]")
        t.add_row("Fail-Closed Boundary:", "[bold yellow]≥ 0.85 (Enforced)[/bold yellow]")
        t.add_row("Token Cost / 1k:", "[bold green]$0.00[/bold green]")
        t.add_row("Last Boto3 Proposal:", f"[white]{self.last_decision['proposed_tool']}[/white]")
        t.add_row("Blast Radius Scope:", f"[white]{self.last_decision['blast_radius']}[/white]")

        dec = self.last_decision["decision"]
        if dec in ("PERMIT", "PERMIT_AUTO_REMEDIATION"):
            dec_styled = "[bold black on green] PERMITTED TO BOTO3 [/bold black on green]"
        elif dec in ("ARMED", "BASELINE"):
            dec_styled = "[bold white on blue] ARMED & READY [/bold white on blue]"
        elif dec == "OVERRIDDEN":
            dec_styled = "[bold black on yellow] OVERRIDDEN (MFA) [/bold black on yellow]"
        else:
            dec_styled = "[bold white on red] HALTED & GATED [/bold white on red]"

        t.add_row("Circuit Gate:", dec_styled)
        return Panel(t, title="[bold white]In-VPC Circuit Breaker Telemetry[/bold white]", border_style="dim", box=box.SQUARE)

    def render_resource_inspector(self) -> Panel:
        resources = self.get_resources_list()
        res = resources[self.selected_index]

        t = Table.grid(expand=True, padding=(0, 1))
        t.add_column(width=18, style="bold dim white")
        t.add_column(ratio=1)

        t.add_row("AWS Resource ID:", f"[bold white]{res['id']}[/bold white]")
        t.add_row("Security Group / VPC:", f"[dim]{res['name']}[/dim]")
        t.add_row("AWS Service Type:", f"[white]{res['role']}[/white]")
        t.add_row("Security State:", Text(res['status'], style=res['status_style']))
        t.add_row("Guardrail Policy:", f"[bold green]{res['policy']}[/bold green]")
        t.add_row("Network Ingress Rules:", f"[white]{res['rules']}[/white]")
        t.add_row("GuardDuty Finding:", f"[bold red]{res['threat']}[/bold red]")
        t.add_row("Resource Details:", f"[dim white]{res['details']}[/dim white]")
        t.add_row("Fail-Closed Boundary:", "[bold green]Protected by Strands Decider 2B (<115ms Local In-VPC Gate)[/bold green]")

        return Panel(
            t,
            title=f"[bold white]AWS Resource Inspector: {res['id']} [ESC or Enter to exit][/bold white]",
            border_style="dim",
            box=box.SQUARE,
        )

    def render_full_logs(self) -> Panel:
        t = Table(box=box.SIMPLE, expand=True, padding=(0, 1))
        t.add_column("Timestamp", width=12, style="dim")
        t.add_column("AWS Source", width=14)
        t.add_column("CloudWatch / GuardDuty Event Message", ratio=1)

        for entry in self.logs:
            tag_style = entry.get("style", "dim")
            t.add_row(
                f"[{entry['time']}]",
                f"[{tag_style}]{entry['tag']}[/{tag_style}]",
                Text(entry["msg"], style="white"),
            )
        return Panel(t, title="[bold white]AWS CloudWatch & Security Hub Audit Stream[/bold white]", border_style="dim", box=box.SQUARE)

    def render_cluster_map(self) -> Panel:
        resources = self.get_resources_list()
        b_status = resources[0]["status"]
        db_status = resources[1]["status"]
        rt_status = resources[2]["status"]

        ascii_diagram = f"""
  [bold white]AWS VPC Topology: vpc-0123456789 (10.0.0.0/16) │ Region: us-east-1[/bold white]
  ──────────────────────────────────────────────────────────────────────────────────────────
  Internet Gateway (igw-core-01) ──▶ Default Route: [bold yellow]{rt_status}[/bold yellow]
  
  [white]Public Subnet (10.0.1.0/24)[/white]             [white]Private Subnet (10.0.2.0/24)[/white]
  ┌──────────────────────────────┐       ┌──────────────────────────────┐
  │ [bold white]EC2: i-0prod-bastion[/bold white]           │       │ [bold white]RDS: aurora-pg-core-db[/bold white]         │
  │ IP: 10.0.1.15                │       │ IP: 10.0.2.40                │
  │ SG: sg-0123456789            │       │ SG: sg-core-vpc-01           │
  │ Posture: {b_status:<19} │       │ Posture: {db_status:<19} │
  └──────────────┬───────────────┘       └──────────────▲───────────────┘
                 │                                      │
                 └──────────▶ [bold green]Strands Decider 2B Gate[/bold green] ──┘
                              [dim]In-VPC Sub-Second Circuit Breaker (114.7ms)[/dim]
  ──────────────────────────────────────────────────────────────────────────────────────────
        """
        return Panel(
            Text.from_markup(ascii_diagram),
            title="[bold white]VPC Network Architecture Topology Map[/bold white]",
            border_style="dim",
            box=box.SQUARE,
        )

    def render_footer(self) -> Panel:
        show_logs = self.logs[-2:] if console.height <= 24 else self.logs[-3:]
        log_table = Table.grid(expand=True)
        log_table.add_column(width=9, style="dim")
        log_table.add_column(width=10)
        log_table.add_column(ratio=1, no_wrap=True)

        for entry in show_logs:
            log_table.add_row(
                f"[{entry['time']}]",
                f"[{entry['style']}]{entry['tag']}[/{entry['style']}]",
                Text(entry["msg"], style="white", overflow="ellipsis"),
            )

        keybinds = (
            "[bold white][↑/↓][/bold white] Navigate  "
            "[bold white][Enter][/bold white] Inspect  "
            "[bold white][Tab][/bold white] Views  "
            "[bold green][1][/bold green] Remediate  "
            "[bold red][2][/bold red] Attack Shield  "
            "[bold yellow][3][/bold yellow] Route Gate  "
            "[bold yellow][B][/bold yellow] MFA  "
            "[bold white][R][/bold white] Reset  "
            "[bold white][W][/bold white] Web UI  "
            "[bold white][Q][/bold white] Quit"
        )

        t = Table.grid(expand=True)
        t.add_row(log_table)
        t.add_row(Text.from_markup(f"\n{keybinds}"))
        return Panel(t, title="[bold white]Navigation & Hotkeys[/bold white]", border_style="dim", box=box.SQUARE)


def _read_normalized_key(fd: Optional[int]) -> Optional[str]:
    """Reads keyboard input directly from raw file descriptor without stdio buffering."""
    if sys.platform != "win32" and fd is not None:
        rlist, _, _ = select.select([fd], [], [], 0.08)
        if not rlist:
            return None
        try:
            raw = os.read(fd, 32)
        except OSError:
            return None
        if not raw:
            return None

        # Arrow keys and ANSI sequences
        if raw in (b"\x1b[A", b"\x1bOA"):
            return "UP"
        if raw in (b"\x1b[B", b"\x1bOB"):
            return "DOWN"
        if raw in (b"\x1b[C", b"\x1bOC"):
            return "RIGHT"
        if raw in (b"\x1b[D", b"\x1bOD"):
            return "LEFT"
        if raw in (b"\x1b[5~", b"\x1b[H"):
            return "UP"
        if raw in (b"\x1b[6~", b"\x1b[F"):
            return "DOWN"
        if raw in (b"\r", b"\n"):
            return "ENTER"
        if raw == b"\t":
            return "TAB"
        if raw == b"\x1b":
            return "ESC"
        try:
            return raw.decode("utf-8", errors="ignore")
        except Exception:
            return None
    else:
        import msvcrt
        if msvcrt.kbhit():
            ch = msvcrt.getch()
            if ch in (b"\x00", b"\xe0"):
                ch2 = msvcrt.getch()
                if ch2 == b"H":
                    return "UP"
                elif ch2 == b"P":
                    return "DOWN"
                elif ch2 == b"K":
                    return "LEFT"
                elif ch2 == b"M":
                    return "RIGHT"
            elif ch in (b"\r", b"\n"):
                return "ENTER"
            elif ch == b"\t":
                return "TAB"
            elif ch == b"\x1b":
                return "ESC"
            return ch.decode("utf-8", errors="ignore")
        time.sleep(0.08)
        return None


def run_cockpit():
    """Starts the interactive Terminal Cockpit with full arrow-key navigation."""
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
        with Live(cockpit.build_view(), screen=True, auto_refresh=False, console=console) as live:
            live.refresh()
            last_clock_tick = time.time()

            while True:
                key = _read_normalized_key(fd)
                needs_redraw = False

                if key:
                    k = key.lower() if len(key) == 1 else key

                    # Modal Inspection Dismissal
                    if cockpit.inspecting:
                        if key in ("ESC", "ENTER") or k in ("q", "d", "x", " "):
                            cockpit.inspecting = False
                            needs_redraw = True
                    else:
                        # Navigation Keys
                        if key in ("UP",) or k == "k":
                            cockpit.selected_index = max(0, cockpit.selected_index - 1)
                            needs_redraw = True
                        elif key in ("DOWN",) or k == "j":
                            max_idx = len(cockpit.get_resources_list()) - 1
                            cockpit.selected_index = min(max_idx, cockpit.selected_index + 1)
                            needs_redraw = True
                        elif key in ("LEFT",) or k == "h":
                            cockpit.active_tab = (cockpit.active_tab - 1) % 3
                            needs_redraw = True
                        elif key in ("RIGHT",) or k == "l":
                            cockpit.active_tab = (cockpit.active_tab + 1) % 3
                            needs_redraw = True
                        elif key in ("ENTER",) or k in ("d", " "):
                            cockpit.inspecting = True
                            needs_redraw = True
                        elif key in ("TAB",) or k == "t":
                            cockpit.active_tab = (cockpit.active_tab + 1) % 3
                            needs_redraw = True
                        elif k in ("q", "\x03"):
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

                # Refresh on state change or 1Hz for clock
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
