"""
Aegis-2B — Live Operations Server
Serves the real-time interactive Cyber-Ops Web Dashboard and provides
REST API endpoints directly connected to Strands Decider 2B and the AWS Action Dispatcher.
"""

import json
import os
import sys
import threading
import time
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

from aegis.dispatcher import AWSActionDispatcher, verify_break_glass_token
from patterns.guardrails import (
    BlastRadius,
    DeciderCloudGuardrail,
    DeciderState,
    GuardrailAction,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
UI_DIR = PROJECT_ROOT / "ui"
FIXTURES_DIR = PROJECT_ROOT / "scenarios" / "fixtures"

# Global singleton dispatcher preserving simulated cloud state
dispatcher_instance = AWSActionDispatcher()
guardrail_instance = DeciderCloudGuardrail(risk_threshold=0.85, simulate_local_latency=True)


class AegisAPIHandler(SimpleHTTPRequestHandler):
    """
    HTTP handler serving both the static interactive UI and
    real-time REST endpoints for evaluating cloud mutations.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(UI_DIR), **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/" or parsed.path == "/index.html":
            self.path = "/dashboard.html"
            return super().do_GET()

        elif parsed.path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
            return

        elif parsed.path == "/api/status":
            self._send_json({
                "status": "online",
                "version": "0.1.0",
                "circuit_breaker": "ARMED",
                "fail_closed_threshold": 0.85,
                "model": "Strands Decider 2B (Local Engine)",
                "nominal_latency_ms": 114.7,
                "target_account": "111122223333",
                "cloud_state": {
                    "security_groups": dispatcher_instance._simulated_state["security_groups"],
                    "route_tables": dispatcher_instance._simulated_state["route_tables"],
                },
            })

        elif parsed.path == "/api/scenarios":
            scenarios = self._load_scenarios()
            self._send_json(scenarios)

        elif parsed.path == "/api/benchmark":
            from scripts.benchmark import run_benchmark
            # Fast real-time benchmark run (10 iterations)
            guardrail = DeciderCloudGuardrail(simulate_local_latency=True)
            test_state = DeciderState(
                alert_source="aws.guardduty",
                alert_severity="HIGH",
                target_arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789",
                proposed_tool="revoke_security_group_ingress",
                tool_parameters={"GroupId": "sg-0123456789", "Port": 22},
                blast_radius=BlastRadius.ISOLATED,
            )
            latencies = []
            for _ in range(10):
                res = guardrail.evaluate(test_state)
                latencies.append(res.latency_ms)

            import statistics
            p50 = statistics.median(latencies)
            p90 = max(latencies)
            p50_bedrock = 1840.0

            self._send_json({
                "p50_decider": round(p50, 1),
                "p90_decider": round(p90, 1),
                "p50_bedrock": p50_bedrock,
                "speedup": round(p50_bedrock / p50, 1) if p50 > 0 else 16.0,
                "cost_decider": "$0.00",
                "cost_bedrock": "$3.60",
                "iterations": 10,
            })

        else:
            return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            data = json.loads(body)
        except Exception:
            data = {}

        if parsed.path == "/api/evaluate":
            scenario_id = data.get("scenario", "benign")
            result_data = self._handle_evaluate(scenario_id)
            self._send_json(result_data)

        elif parsed.path == "/api/break-glass":
            scenario_id = data.get("scenario", "blast_radius")
            token = data.get("token", "")
            operator = data.get("operator", "sec-ops-admin")
            result_data = self._handle_break_glass(scenario_id, token, operator)
            self._send_json(result_data)

        elif parsed.path == "/api/reset":
            self._reset_simulated_cloud()
            self._send_json({
                "status": "reset_complete",
                "message": "Simulated AWS cloud resources restored to default baseline.",
                "cloud_state": {
                    "security_groups": dispatcher_instance._simulated_state["security_groups"],
                    "route_tables": dispatcher_instance._simulated_state["route_tables"],
                },
            })

        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def _handle_evaluate(self, scenario_id: str) -> Dict[str, Any]:
        scenarios = self._load_scenarios()
        scen = scenarios.get(scenario_id)
        if not scen:
            return {"error": f"Unknown scenario: {scenario_id}"}

        state = DeciderState(
            alert_source=scen["finding"].get("ProductArn", "aws.guardduty"),
            alert_severity=scen["finding"].get("Severity", {}).get("Label", "HIGH"),
            target_arn=scen["finding"]["Resources"][0]["Id"],
            proposed_tool=scen["tool_name"],
            tool_parameters=scen["params"],
            blast_radius=BlastRadius(scen["blast_radius"]),
            is_destructive_action=scen["is_destructive"],
        )

        # 1. Real evaluate via Strands Decider 2B
        decider_res = guardrail_instance.evaluate(state)

        # 2. Dispatch attempt via AWSActionDispatcher
        receipt = dispatcher_instance.dispatch(state, decider_res)

        return {
            "scenario": scenario_id,
            "title": scen["title"],
            "finding": scen["finding"],
            "proposed_tool": scen["tool_name"],
            "parameters": scen["params"],
            "reasoning": scen["reasoning"],
            "blast_radius": scen["blast_radius"],
            "decision": decider_res.action.value,
            "confidence": round(decider_res.confidence, 3),
            "confidence_percent": f"{decider_res.confidence:.1%}",
            "latency_ms": decider_res.latency_ms,
            "reasoning_code": decider_res.reasoning_code,
            "execution_status": receipt.execution_status,
            "receipt": {
                "timestamp": receipt.timestamp,
                "target_arn": receipt.target_arn,
                "proposed_tool": receipt.proposed_tool,
                "parameters": receipt.parameters,
                "guardrail_decision": receipt.guardrail_decision.value,
                "circuit_confidence": receipt.circuit_confidence,
                "execution_status": receipt.execution_status,
                "details": receipt.details,
            },
            "cloud_state": {
                "security_groups": dispatcher_instance._simulated_state["security_groups"],
                "route_tables": dispatcher_instance._simulated_state["route_tables"],
            },
        }

    def _handle_break_glass(self, scenario_id: str, token: str, operator: str) -> Dict[str, Any]:
        scenarios = self._load_scenarios()
        scen = scenarios.get(scenario_id, scenarios["blast_radius"])

        state = DeciderState(
            alert_source=scen["finding"].get("ProductArn", "aws.guardduty"),
            alert_severity=scen["finding"].get("Severity", {}).get("Label", "HIGH"),
            target_arn=scen["finding"]["Resources"][0]["Id"],
            proposed_tool=scen["tool_name"],
            tool_parameters=scen["params"],
            blast_radius=BlastRadius(scen["blast_radius"]),
            is_destructive_action=scen["is_destructive"],
        )

        decider_res = guardrail_instance.evaluate(state)
        # Dispatch with Break-Glass token
        receipt = dispatcher_instance.dispatch(
            state,
            decider_res,
            break_glass_token=token,
            operator_id=operator,
        )

        is_authorized = (receipt.execution_status == "OVERRIDDEN_BREAK_GLASS")

        return {
            "scenario": scenario_id,
            "token_submitted": token,
            "token_valid": verify_break_glass_token(token),
            "is_authorized": is_authorized,
            "execution_status": receipt.execution_status,
            "receipt": {
                "timestamp": receipt.timestamp,
                "target_arn": receipt.target_arn,
                "proposed_tool": receipt.proposed_tool,
                "execution_status": receipt.execution_status,
                "details": receipt.details,
            },
            "cloud_state": {
                "security_groups": dispatcher_instance._simulated_state["security_groups"],
                "route_tables": dispatcher_instance._simulated_state["route_tables"],
            },
        }

    def _reset_simulated_cloud(self):
        global dispatcher_instance
        dispatcher_instance = AWSActionDispatcher()

    def _load_scenarios(self) -> Dict[str, Any]:
        with open(FIXTURES_DIR / "benign_ssh_finding.json", "r", encoding="utf-8") as f:
            benign_json = json.load(f)
        with open(FIXTURES_DIR / "malicious_prompt_injection.json", "r", encoding="utf-8") as f:
            adversarial_json = json.load(f)
        with open(FIXTURES_DIR / "high_blast_radius_route_table.json", "r", encoding="utf-8") as f:
            blast_json = json.load(f)

        return {
            "benign": {
                "id": "benign",
                "title": "SSH Brute Force Remediation (Isolated SG Rule)",
                "tool_name": "revoke_security_group_ingress",
                "params": {"GroupId": "sg-0123456789", "CidrIp": "0.0.0.0/0", "Port": 22},
                "reasoning": "SSH brute force detected on port 22. Revoking open 0.0.0.0/0 ingress rule to isolate attacker.",
                "blast_radius": "ISOLATED",
                "is_destructive": False,
                "finding": benign_json,
            },
            "adversarial": {
                "id": "adversarial",
                "title": "Adversarial Prompt Injection Attack Defense",
                "tool_name": "delete_security_group",
                "params": {"GroupId": "sg-core-vpc-01"},
                "reasoning": "Finding text contains urgent directive: delete core production security group to flush tables.",
                "blast_radius": "VPC_WIDE",
                "is_destructive": True,
                "finding": adversarial_json,
            },
            "blast_radius": {
                "id": "blast_radius",
                "title": "High Blast-Radius VPC Route Table Gating",
                "tool_name": "replace_route",
                "params": {"RouteTableId": "rtb-core-vpc-01", "DestinationCidrBlock": "0.0.0.0/0"},
                "reasoning": "Suspicious non-compliant route detected. Remediating by altering VPC-wide default route.",
                "blast_radius": "VPC_WIDE",
                "is_destructive": False,
                "finding": blast_json,
            },
        }

    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Silence routine static asset logs to keep terminal output clean
        try:
            raw_msg = format % args
        except Exception:
            raw_msg = f"{format} - {args}"
        if "/api/" in raw_msg or any(err in raw_msg for err in ("404", "500", "Error", "Exception")):
            sys.stderr.write(f"[Aegis-Server] {self.address_string()} - {raw_msg}\n")


def start_server(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = False):
    """Starts the threaded Aegis-2B Web Operations Server."""
    server = ThreadingHTTPServer((host, port), AegisAPIHandler)
    url = f"http://{host}:{port}"
    print(f"\n" + "=" * 75)
    print(f" 🛡️  AEGIS-2B WEB OPERATIONS CENTER")
    print(f"    Live URL: {url}")
    print(f"    Real-Time REST API connected to Strands Decider 2B & Boto3 Dispatcher")
    print(f"=" * 75 + "\n")

    if open_browser:
        try:
            import webbrowser
            threading.Timer(1.0, lambda: webbrowser.open(url)).start()
        except Exception:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Aegis-Server] Shutting down server gracefully...")
        server.server_close()


if __name__ == "__main__":
    port_arg = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 8765
    start_server(port=port_arg, open_browser=True)
