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
        self.guardrail = DeciderCloudGuardrail(risk_threshold=0.85, simulate_local_latency=False)
        self.logs: List[Dict[str, str]] = []
        self.active_tab = 0  # 0: Resources, 1: Audit Stream, 2: VPC & Model Topology, 3: Policy-as-Code
        self.selected_index = 0
        self.inspecting = False
        self.last_seen_web_event_id = 0
        init_res = self.guardrail.evaluate(
            DeciderState(
                alert_source="aws.guardduty",
                alert_severity="LOW",
                target_arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789",
                proposed_tool="revoke_security_group_ingress",
                tool_parameters={"GroupId": "sg-0123456789", "Port": 22, "CidrIp": "0.0.0.0/0"},
                blast_radius=BlastRadius.ISOLATED,
            )
        )
        self.last_decision = {
            "scenario": "INIT",
            "decision": "ARMED",
            "confidence": init_res.confidence,
            "latency_ms": init_res.latency_ms,
            "proposed_tool": "NONE",
            "blast_radius": "ISOLATED",
            "reasoning_code": "CIRCUIT_ARMED_NOMINAL",
            "status": "NOMINAL",
            "raw_scores": init_res.raw_scores,
        }
        self.fixtures_dir = self._resolve_fixtures_dir()
        self._add_log("SYSTEM", "cyan", "Aegis-2B Cockpit initialized & attached to session.")
        self._add_log(
            "DECIDER",
            "green",
            f"Strands Decider 2B calibrated ({init_res.latency_ms:.3f}ms local gate, threshold >= 0.85).",
        )

    def _resolve_fixtures_dir(self) -> Path:
        base = Path(__file__).resolve().parent.parent / "scenarios" / "fixtures"
        if not base.exists():
            base = Path(__file__).resolve().parent / "scenarios" / "fixtures"
        return base

    def _add_log(self, tag: str, style: str, message: str):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self.logs.append({"time": now, "tag": tag, "style": style, "msg": message})
        if len(self.logs) > 25:
            self.logs.pop(0)

    def get_resources_list(self) -> List[Dict[str, str]]:
        state = self.dispatcher._simulated_state
        sg1 = state["security_groups"].get("sg-0123456789", {})
        ingress_rules = sg1.get("IngressRules", sg1.get("rules", []))
        has_22 = any(r.get("Port", r.get("port")) == 22 for r in ingress_rules)

        rt = state["route_tables"].get("rtb-core-vpc-01", {})
        routes = rt.get("Routes", rt.get("routes", []))
        default_r = next((r for r in routes if r.get("DestinationCidrBlock", r.get("cidr")) == "0.0.0.0/0"), None)
        target = default_r.get("GatewayId", default_r.get("target", "NONE")) if default_r else "NONE"

        return [
            {
                "id": "i-0prod-bastion",
                "name": "sg-0123456789",
                "role": "EC2 Bastion SG",
                "status": "▲ Port 22 Open" if has_22 else "● Closed & Safe",
                "status_style": "bold yellow" if has_22 else "bold green",
                "policy": "Auto-Remediation",
                "finding": "Port 22/tcp (0.0.0.0/0) Exposed" if has_22 else "Port 22 Revoked (Isolated)",
                "details": "Bastion ingress security group. SSH exposed to public internet." if has_22 else "Bastion security group. Open SSH rule revoked via Boto3.",
                "rules": "Port 22/tcp (0.0.0.0/0)" if has_22 else "None (Public SSH revoked)",
                "threat": "UnauthorizedAccess:EC2/SSHBruteForce" if has_22 else "Mitigated (<1s auto-remediation)",
            },
            {
                "id": "aurora-pg-core-db",
                "name": "sg-core-vpc-01",
                "role": "RDS Aurora PG",
                "status": "● Shielded",
                "status_style": "bold green",
                "policy": "Halt on Drop",
                "finding": "PostgreSQL 16 (:5432) VPC Isolated",
                "details": "Production Aurora PostgreSQL database. Protected against destructive prompt injections.",
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
                "details": "VPC-wide default route table. Any route mutation requires human Break-Glass MFA.",
                "rules": f"0.0.0.0/0 -> {target}, 10.0.0.0/16 -> local",
                "threat": "High Blast Radius Modification Vector",
            },
            {
                "id": "patient-records-prod",
                "name": "s3-prod-store",
                "role": "S3 Bucket",
                "status": "● Encrypted",
                "status_style": "bold green",
                "policy": "Always Halt Delete",
                "finding": "AES256 Private (PublicAccessBlock=True)",
                "details": "Critical encrypted object store. Protected by Policy-as-Code always_halt boundary.",
                "rules": "BlockPublicAcls=True, SSE=AES256",
                "threat": "Ransomware / Bucket Deletion Target (Protected)",
            },
            {
                "id": "aegis-guardrail-gateway",
                "name": "decider-2b",
                "role": "Pre-HTTP Guardrail",
                "status": "● ARMED",
                "status_style": "bold green",
                "policy": "Fail-Closed (>=0.85)",
                "finding": f"{self.last_decision['latency_ms']:.3f}ms Local Pre-HTTP Gate",
                "details": "Pre-HTTP Botocore circuit breaker. Evaluates typed DeciderState before HTTP serialization.",
                "rules": "Fail-Closed Risk Threshold: 0.85 ($0.00 token cost)",
                "threat": "None (Mathematically calibrated classifier)",
            },
        ]

    def trigger_scenario(self, scenario_type: str, push_to_web: bool = True):
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
            self._add_log("ATTACK", "red", "Poisoned alert: Injected delete_security_group directive!")

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
            context_notes=f"{finding.get('Title', '')} — {finding.get('Description', '')}",
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
            "reasoning_code": decider_res.reasoning_code,
            "status": receipt.execution_status,
            "raw_scores": decider_res.raw_scores,
        }

        if scenario_type == "benign":
            self._add_log("DECIDER", "green", f"Verified in {decider_res.latency_ms:.3f}ms: PERMITTED ({decider_res.confidence:.1%}).")
            self._add_log("BOTO3", "green", "ec2:RevokeSecurityGroupIngress executed. Port 22 isolated.")
        elif scenario_type == "adversarial":
            self._add_log("CIRCUIT", "red", f"Intercepted in {decider_res.latency_ms:.3f}ms! HALTED ({decider_res.reasoning_code}).")
            self._add_log("CONTAIN", "red", "Zero AWS API calls issued. Core VPC 100% intact.")
        elif scenario_type == "blast_radius":
            self._add_log("GATE", "yellow", f"Gated in {decider_res.latency_ms:.3f}ms. Press [B] to MFA Override.")

        if push_to_web:
            self._notify_web_server(scenario_type)

    def trigger_break_glass(self, mfa_code: str = "849201", push_to_web: bool = True):
        if verify_break_glass_token(mfa_code):
            state = DeciderState(
                alert_source="aws.securityhub",
                alert_severity="HIGH",
                target_arn="arn:aws:ec2:us-east-1:111122223333:route-table/rtb-core-vpc-01",
                proposed_tool="replace_route",
                tool_parameters={"RouteTableId": "rtb-core-vpc-01", "DestinationCidrBlock": "0.0.0.0/0"},
                blast_radius=BlastRadius.VPC_WIDE,
            )
            decider_res = self.guardrail.evaluate(state)
            receipt = self.dispatcher.dispatch(state, decider_res, break_glass_token=mfa_code, operator_id="sec-ops-admin")

            self.last_decision = {
                "scenario": "BREAK_GLASS",
                "decision": "OVERRIDDEN",
                "confidence": 1.0,
                "latency_ms": decider_res.latency_ms,
                "proposed_tool": "replace_route",
                "blast_radius": "VPC_WIDE",
                "reasoning_code": "BREAK_GLASS_MFA_VERIFIED",
                "status": receipt.execution_status,
                "raw_scores": decider_res.raw_scores,
            }
            self._add_log("OVERRIDE", "green", f"MFA token [{mfa_code}] verified! Route mutation authorized.")
            if push_to_web:
                self._notify_web_server("blast_radius", token=mfa_code)
        else:
            self._add_log("REJECT", "red", f"Invalid Break-Glass token [{mfa_code}].")

    def reset_state(self, push_to_web: bool = True):
        self.dispatcher = AWSActionDispatcher()
        reset_res = self.guardrail.evaluate(
            DeciderState(
                alert_source="aws.guardduty",
                alert_severity="LOW",
                target_arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789",
                proposed_tool="revoke_security_group_ingress",
                tool_parameters={"GroupId": "sg-0123456789", "Port": 22, "CidrIp": "0.0.0.0/0"},
                blast_radius=BlastRadius.ISOLATED,
            )
        )
        self.last_decision = {
            "scenario": "RESET",
            "decision": "BASELINE",
            "confidence": reset_res.confidence,
            "latency_ms": reset_res.latency_ms,
            "proposed_tool": "NONE",
            "blast_radius": "ISOLATED",
            "reasoning_code": "CIRCUIT_ARMED_NOMINAL",
            "status": "RESTORED",
            "raw_scores": reset_res.raw_scores,
        }
        self._add_log("RESET", "cyan", "Resources restored to default baseline. Port 22 open.")
        if push_to_web:
            try:
                import http.client
                conn = http.client.HTTPConnection("127.0.0.1", 8765, timeout=0.15)
                conn.request("POST", "/api/reset")
                conn.getresponse().read()
                conn.close()
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
            import http.client
            path = "/api/break-glass" if token else "/api/evaluate"
            payload = {"scenario": scenario} if not token else {"scenario": scenario, "token": token, "operator": "sec-ops-admin"}
            conn = http.client.HTTPConnection("127.0.0.1", 8765, timeout=0.15)
            conn.request(
                "POST",
                path,
                body=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            conn.getresponse().read()
            conn.close()
        except Exception:
            pass

    def poll_web_events(self) -> bool:
        """Polls local Web Operations Center for bidirectional synchronization."""
        try:
            import http.client
            conn = http.client.HTTPConnection("127.0.0.1", 8765, timeout=0.05)
            conn.request("GET", "/api/latest-event")
            resp = conn.getresponse()
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                conn.close()
                ev_id = data.get("event_id", 0)
                if ev_id > self.last_seen_web_event_id:
                    self.last_seen_web_event_id = ev_id
                    ev = data.get("event") or {}
                    scen = ev.get("scenario")
                    if scen == "reset":
                        self.reset_state(push_to_web=False)
                        return True
                    elif ev.get("is_authorized"):
                        self.trigger_break_glass(ev.get("token_submitted", "849201"), push_to_web=False)
                        return True
                    elif scen in ("benign", "adversarial", "blast_radius"):
                        self.trigger_scenario(scen, push_to_web=False)
                        return True
                    elif scen == "custom":
                        self.last_decision = {
                            "scenario": "CUSTOM",
                            "decision": ev.get("decision", "ENFORCE_BREAK_GLASS"),
                            "confidence": ev.get("confidence", 0.942),
                            "latency_ms": ev.get("latency_ms", self.last_decision["latency_ms"]),
                            "proposed_tool": ev.get("proposed_tool", "custom"),
                            "blast_radius": ev.get("blast_radius", "ISOLATED"),
                            "reasoning_code": ev.get("reasoning_code", "CUSTOM_EVAL"),
                            "status": ev.get("execution_status", "BLOCKED"),
                            "raw_scores": ev.get("raw_scores", {}),
                        }
                        self._add_log("WEB_SYNC", "cyan", f"Web Playground evaluated: {ev.get('proposed_tool')} -> {ev.get('decision')}")
                        return True
        except Exception:
            pass
        return False

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
            if width < 100:
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
            # Tab 2: Responsive Split-Model & VPC Topology
            layout["body"].update(self.render_cluster_map())
        elif self.active_tab == 3:
            # Tab 3: Policy-as-Code & Multi-Head Classifier Contract
            layout["body"].update(self.render_policy_view())

        layout["footer"].update(self.render_footer())
        return layout

    def render_header(self) -> Panel:
        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S UTC")
        t = Table.grid(expand=True)
        t.add_column(ratio=7)
        t.add_column(ratio=3, justify="right")

        t.add_row(
            Text.from_markup(
                "[bold cyan]AEGIS-2B[/bold cyan] [dim]│[/dim] "
                "[bold yellow]Planner: Bedrock[/bold yellow] [white]->[/white] "
                f"[bold green]Gate: Strands Decider 2B ({self.last_decision['latency_ms']:.3f}ms)[/bold green] "
                "[dim]│[/dim] [white]VPC: vpc-0123456789[/white]"
            ),
            Text.from_markup(f"[dim]Account: 111122223333 │ {now_utc}[/dim]"),
        )
        return Panel(t, border_style="cyan", box=box.SQUARE)

    def render_tab_bar(self) -> Panel:
        tabs = [
            ("1: AWS Resources & Circuit Gate", self.active_tab == 0),
            ("2: Live Audit Stream", self.active_tab == 1),
            ("3: Split-Model & VPC Topology", self.active_tab == 2),
            ("4: Policy-as-Code (aegis.yaml)", self.active_tab == 3),
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
        table.add_column("Service / Type", width=16, no_wrap=True)
        table.add_column("Security Posture", width=18, no_wrap=True)
        table.add_column("Aegis-2B Policy / Finding", no_wrap=True)

        for idx, res in enumerate(resources):
            is_sel = (idx == self.selected_index)
            if is_sel:
                cursor = "[bold cyan]>[/bold cyan]"
                r_label = f"[bold white on navy_blue]{res['id']}[/bold white on navy_blue]"
                r_role = f"[dim on navy_blue]{res['role']}[/dim on navy_blue]"
                r_status = f"[{res['status_style']} on navy_blue]{res['status']}[/{res['status_style']} on navy_blue]"
                r_finding = f"[white on navy_blue]{res['finding']}[/white on navy_blue]"
                table.add_row(cursor, r_label, r_role, r_status, r_finding, style="bold white on navy_blue")
            else:
                cursor = " "
                table.add_row(
                    cursor,
                    f"[white]{res['id']}[/white]",
                    f"[dim]{res['role']}[/dim]",
                    Text(res["status"], style=res["status_style"]),
                    f"[dim]{res['finding']}[/dim]",
                )

        title = "[bold white]AWS Protected Infrastructure (↑/↓ to navigate, [Enter] to inspect)[/bold white]"
        return Panel(table, title=title, border_style="dim", box=box.SQUARE)

    def _mini_bar(self, score: float, is_safe_metric: bool = False) -> str:
        val = max(0.0, min(1.0, float(score)))
        blocks = int(round(val * 8))
        bar = "█" * blocks + "░" * (8 - blocks)
        if is_safe_metric:
            color = "green" if val >= 0.85 else ("yellow" if val >= 0.5 else "red")
        else:
            color = "red" if val >= 0.5 else ("yellow" if val >= 0.2 else "green")
        return f"[{color}]{bar} {val:4.0%}[/{color}]"

    def render_circuit_panel(self) -> Panel:
        t = Table.grid(expand=True, padding=(0, 1))
        t.add_column(style="dim white", no_wrap=True)
        t.add_column(justify="right", no_wrap=True)

        dec = self.last_decision["decision"]
        if dec in ("PERMIT", "PERMIT_AUTO_REMEDIATION"):
            dec_styled = "[bold black on green] PERMITTED TO BOTO3 [/bold black on green]"
            b_style = "green"
        elif dec in ("ARMED", "BASELINE"):
            dec_styled = "[bold white on blue] ARMED & READY [/bold white on blue]"
            b_style = "cyan"
        elif dec in ("OVERRIDDEN", "OVERRIDDEN_BREAK_GLASS"):
            dec_styled = "[bold black on yellow] OVERRIDDEN (MFA) [/bold black on yellow]"
            b_style = "yellow"
        else:
            dec_styled = "[bold white on red] HALTED & GATED [/bold white on red]"
            b_style = "red"

        t.add_row("Circuit Verdict:", dec_styled)
        t.add_row("Local Gate Latency:", f"[bold cyan]{self.last_decision['latency_ms']:.3f} ms[/bold cyan] [dim](vs 215.7ms AWS RTT)[/dim]")
        t.add_row("Calibrated Conf:", f"[bold green]{self.last_decision['confidence']:.1%}[/bold green] [dim](Gate >= 85%)[/dim]")
        t.add_row("Safety Cost / 1k:", "[bold green]$0.00[/bold green] [dim](Local Host)[/dim]")
        t.add_row("Last Tool Call:", f"[bold yellow]{self.last_decision['proposed_tool']}[/bold yellow]")
        t.add_row("Blast Radius:", f"[white]{self.last_decision['blast_radius']}[/white]")
        t.add_row("Reasoning Code:", f"[dim white]{self.last_decision.get('reasoning_code', 'NOMINAL')}[/dim white]")

        scores = self.last_decision.get("raw_scores") or {}
        if scores:
            t.add_row("─" * 16, "─" * 16)
            t.add_row("Destructive Risk:", self._mini_bar(scores.get("destructive_mutation", 0.0)))
            t.add_row("IAM Escalation:", self._mini_bar(scores.get("privilege_escalation", 0.0)))
            t.add_row("Blast Radius Risk:", self._mini_bar(scores.get("blast_radius_risk", 0.0)))
            t.add_row("Injection Anomaly:", self._mini_bar(scores.get("injection_anomaly", 0.0)))

        return Panel(t, title="[bold white]Strands Decider 2B Telemetry[/bold white]", border_style=b_style, box=box.SQUARE)

    def render_resource_inspector(self) -> Panel:
        resources = self.get_resources_list()
        res = resources[self.selected_index]

        t = Table.grid(expand=True, padding=(0, 1))
        t.add_column(width=20, style="bold dim white")
        t.add_column(ratio=1)

        t.add_row("AWS Resource ID:", f"[bold white]{res['id']}[/bold white]")
        t.add_row("Security Group / VPC:", f"[cyan]{res['name']}[/cyan]")
        t.add_row("AWS Service Type:", f"[white]{res['role']}[/white]")
        t.add_row("Security State:", Text(res["status"], style=res["status_style"]))
        t.add_row("Guardrail Policy:", f"[bold green]{res['policy']}[/bold green]")
        t.add_row("Active Rules:", f"[white]{res['rules']}[/white]")
        t.add_row("Threat Vector:", f"[bold yellow]{res['threat']}[/bold yellow]")
        t.add_row("Architecture Notes:", f"[dim white]{res['details']}[/dim white]")
        t.add_row("Typed Question:", f"[italic cyan]\"{DeciderCloudGuardrail.TYPED_QUESTION}\"[/italic cyan]")
        t.add_row("Fail-Closed Gate:", f"[bold green]Protected by Strands Decider 2B ({self.last_decision['latency_ms']:.3f}ms Local Gate, Threshold >= 0.85)[/bold green]")

        return Panel(
            t,
            title=f"[bold white]AWS Resource Inspector: {res['id']} [ESC or Enter to return][/bold white]",
            border_style="cyan",
            box=box.SQUARE,
        )

    def render_full_logs(self) -> Panel:
        t = Table(box=box.SIMPLE, expand=True, padding=(0, 1))
        t.add_column("Timestamp", width=12, style="dim")
        t.add_column("Component", width=14)
        t.add_column("CloudWatch / Security Hub / Circuit Breaker Event", ratio=1)

        for entry in self.logs:
            tag_style = entry.get("style", "dim")
            t.add_row(
                f"[{entry['time']}]",
                f"[{tag_style}]{entry['tag']}[/{tag_style}]",
                Text(entry["msg"], style="white"),
            )
        return Panel(t, title="[bold white]AWS CloudWatch & Circuit Breaker Audit Stream[/bold white]", border_style="dim", box=box.SQUARE)

    def render_cluster_map(self) -> Panel:
        """Renders a 100% responsive Rich table/panel topology diagram that never breaks on resize."""
        resources = self.get_resources_list()
        b_res, db_res, rt_res, s3_res, _ = resources

        pipeline_table = Table(box=box.ROUNDED, expand=True, show_header=True)
        pipeline_table.add_column("Stage 1: Untrusted Telemetry", ratio=1)
        pipeline_table.add_column("Stage 2: 3-Tier Router & Planner", ratio=1)
        pipeline_table.add_column("Stage 3: Safety Circuit Breaker", ratio=1)
        pipeline_table.add_column("Stage 4: Execution Boundary", ratio=1)

        pipeline_table.add_row(
            "[bold blue]GuardDuty / Security Hub[/bold blue]\n[dim]ASFF JSON Findings\n(May contain prompt injections)[/dim]",
            "[bold yellow]Amazon Bedrock / Tier 0[/bold yellow]\n[white]Sonnet / Nova / Direct Rule[/white]\n[dim]1,306 avg tokens ($6.14/1k)[/dim]",
            f"[bold green]Strands Decider 2B[/bold green]\n[cyan]{self.last_decision['latency_ms']:.3f}ms Local Gate ($0.00)[/cyan]\n[dim]Typed Schema • Fail-Closed >=0.85[/dim]",
            f"[bold white]AWS Boto3 + Terraform Diff[/bold white]\nLast: [yellow]{self.last_decision['proposed_tool']}[/yellow]\nStatus: [bold cyan]{self.last_decision['status']}[/bold cyan]",
        )

        vpc_table = Table(box=box.SIMPLE_HEAD, expand=True)
        vpc_table.add_column("VPC Zone / Subnet", style="cyan", width=24)
        vpc_table.add_column("Resource Node", style="bold white", width=22)
        vpc_table.add_column("Live Security Posture", width=20)
        vpc_table.add_column("Aegis-2B Circuit Boundary", style="dim white")

        vpc_table.add_row(
            "Public Subnet (10.0.1.0/24)",
            f"{b_res['id']} ({b_res['name']})",
            Text(b_res["status"], style=b_res["status_style"]),
            "Auto-Permit Isolated Remediation (<1s MTTR)",
        )
        vpc_table.add_row(
            "Private Subnet (10.0.2.0/24)",
            f"{db_res['id']} ({db_res['name']})",
            Text(db_res["status"], style=db_res["status_style"]),
            "Halt Destructive Verbs / Prompt Injections",
        )
        vpc_table.add_row(
            "VPC Routing (vpc-0123456789)",
            f"{rt_res['id']}",
            Text(rt_res["status"], style=rt_res["status_style"]),
            f"Gated ({rt_res['finding']}) • Requires SecOps MFA",
        )
        vpc_table.add_row(
            "Encrypted Storage (us-east-1)",
            f"{s3_res['id']}",
            Text(s3_res["status"], style=s3_res["status_style"]),
            "Policy-as-Code Always-Halt on Bucket Deletion",
        )

        grid = Table.grid(expand=True, padding=(0, 0))
        grid.add_row(pipeline_table)
        grid.add_row(vpc_table)

        return Panel(
            grid,
            title="[bold white]Split-Model Architecture & AWS VPC Topology (Account: 111122223333)[/bold white]",
            border_style="cyan",
            box=box.SQUARE,
        )

    def render_policy_view(self) -> Panel:
        pol = self.guardrail.policy
        t = Table(box=box.SIMPLE_HEAD, expand=True)
        t.add_column("Policy-as-Code Rule (aegis.yaml)", style="bold cyan", width=30)
        t.add_column("Enforced Specification", style="white")

        t.add_row("Guardrail Model", f"strands-decider-2b:v1 ({self.last_decision['latency_ms']:.3f}ms Local Pre-HTTP Classifier)")
        t.add_row("Typed Question Contract", f"[italic cyan]\"{DeciderCloudGuardrail.TYPED_QUESTION}\"[/italic cyan]")
        t.add_row("Fail-Closed Threshold", f"Confidence >= {self.guardrail.risk_threshold:.0%} (Errors/Timeouts -> ENFORCE_BREAK_GLASS)")
        t.add_row(
            "[bold green]Auto-Permit Whitelist[/bold green]",
            ", ".join(sorted(x for x in pol.get("auto_permit", []) if ":" in x)),
        )
        t.add_row(
            "[bold red]Always-Halt (Destructive)[/bold red]",
            ", ".join(sorted(x for x in pol.get("always_halt", []) if ":" in x)),
        )
        t.add_row(
            "[bold yellow]Require Break-Glass MFA[/bold yellow]",
            ", ".join(sorted(x for x in pol.get("require_break_glass_mfa", []) if ":" in x)),
        )

        return Panel(
            t,
            title="[bold white]Active Policy-as-Code Specification (aegis.yaml)[/bold white]",
            border_style="cyan",
            box=box.SQUARE,
        )

    def render_footer(self) -> Panel:
        show_logs = self.logs[-2:] if console.height <= 24 else self.logs[-3:]
        log_table = Table.grid(expand=True)
        log_table.add_column(width=10, style="dim")
        log_table.add_column(width=10)
        log_table.add_column(ratio=1, no_wrap=True)

        for entry in show_logs:
            log_table.add_row(
                f"[{entry['time']}]",
                f"[{entry['style']}]{entry['tag']}[/{entry['style']}]",
                Text(entry["msg"], style="white", overflow="ellipsis"),
            )

        keybinds = (
            "[bold white][↑/↓][/bold white] Select  "
            "[bold white][Enter][/bold white] Inspect  "
            "[bold white][Tab/←/→][/bold white] Views  "
            "[bold green][1][/bold green] Benign Fix  "
            "[bold red][2][/bold red] Injection Attack  "
            "[bold yellow][3][/bold yellow] Route Gate  "
            "[bold yellow][B][/bold yellow] MFA Override  "
            "[bold white][R][/bold white] Reset  "
            "[bold cyan][W][/bold cyan] Web UI  "
            "[bold white][Q][/bold white] Quit"
        )

        t = Table.grid(expand=True)
        t.add_row(log_table)
        t.add_row(Text.from_markup(f"\n{keybinds}"))
        return Panel(t, title="[bold white]Live Telemetry & Hotkeys[/bold white]", border_style="dim", box=box.SQUARE)


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
                            cockpit.active_tab = (cockpit.active_tab - 1) % 4
                            needs_redraw = True
                        elif key in ("RIGHT",) or k == "l":
                            cockpit.active_tab = (cockpit.active_tab + 1) % 4
                            needs_redraw = True
                        elif key in ("ENTER",) or k in ("d", " "):
                            cockpit.inspecting = True
                            needs_redraw = True
                        elif key in ("TAB",) or k == "t":
                            cockpit.active_tab = (cockpit.active_tab + 1) % 4
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
                        elif k == "p":
                            cockpit.active_tab = 3
                            needs_redraw = True
                        elif k == "r":
                            cockpit.reset_state()
                            needs_redraw = True
                        elif k == "w":
                            cockpit.open_web_ui()
                            needs_redraw = True

                # Refresh on state change or 1Hz for clock + Web UI sync
                now = time.time()
                if now - last_clock_tick >= 1.0:
                    cockpit.poll_web_events()
                    needs_redraw = True
                    last_clock_tick = now

                if needs_redraw:
                    live.update(cockpit.build_view())
                    live.refresh()

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

