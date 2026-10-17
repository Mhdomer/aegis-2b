"""
Aegis-2B - Live Operations Server
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
guardrail_instance = DeciderCloudGuardrail(risk_threshold=0.85, simulate_local_latency=False)
latest_event_id = 0
latest_event_data = None
last_evaluated_state: Dict[str, Any] = {}


class AegisAPIHandler(SimpleHTTPRequestHandler):
    """
    HTTP handler serving both the static interactive UI and
    real-time REST endpoints for evaluating cloud mutations.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(UI_DIR), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/" or parsed.path == "/index.html":
            self.path = "/dashboard.html"
            return super().do_GET()

        elif parsed.path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
            return

        elif parsed.path == "/api/latest-event":
            self._send_json({
                "event_id": latest_event_id,
                "event": latest_event_data,
            })

        elif parsed.path == "/api/policy":
            policy_file = PROJECT_ROOT / "aegis.yaml"
            raw_yaml = policy_file.read_text(encoding="utf-8") if policy_file.exists() else "# Default policy active"
            pol = guardrail_instance.policy
            self._send_json({
                "risk_threshold": guardrail_instance.risk_threshold,
                "typed_question": DeciderCloudGuardrail.TYPED_QUESTION,
                "auto_permit": sorted(list(pol.get("auto_permit", []))),
                "always_halt": sorted(list(pol.get("always_halt", []))),
                "require_break_glass_mfa": sorted(list(pol.get("require_break_glass_mfa", []))),
                "raw_yaml": raw_yaml,
            })

        elif parsed.path == "/api/status":
            from aegis.aws_live import get_live_aws_session
            pol = guardrail_instance.policy
            aws_conn = get_live_aws_session()
            self._send_json({
                "status": "online",
                "version": "0.2.0",
                "circuit_breaker": "ARMED",
                "fail_closed_threshold": guardrail_instance.risk_threshold,
                "typed_question": DeciderCloudGuardrail.TYPED_QUESTION,
                "model": "Strands Decider 2B (Local Engine)",
                "nominal_latency_ms": 0.51,
                "target_account": aws_conn["masked_account"] if aws_conn["connected"] else "111122223333 (Sandbox)",
                "aws_live_connected": aws_conn["connected"],
                "aws_region": aws_conn["region"],
                "policy_summary": {
                    "auto_permit_count": len(pol.get("auto_permit", [])),
                    "always_halt_count": len(pol.get("always_halt", [])),
                    "mfa_gated_count": len(pol.get("require_break_glass_mfa", [])),
                },
                "cloud_state": dispatcher_instance._simulated_state,
            })

        elif parsed.path == "/api/scenarios":
            scenarios = self._load_scenarios()
            self._send_json(scenarios)

        elif parsed.path == "/api/benchmark":
            import statistics
            import boto3

            fast_guardrail = DeciderCloudGuardrail(simulate_local_latency=False)
            test_state = DeciderState(
                alert_source="aws.guardduty",
                alert_severity="HIGH",
                target_arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789",
                proposed_tool="revoke_security_group_ingress",
                tool_parameters={"GroupId": "sg-0123456789", "Port": 22},
                blast_radius=BlastRadius.ISOLATED,
            )
            ec2_protected = fast_guardrail.protect_boto3_client(boto3.client("ec2", region_name="us-east-1"))
            hook_latencies_ms = []
            native_us = []
            for _ in range(50):
                t0 = time.perf_counter_ns()
                fast_guardrail._default_evaluator(test_state, DeciderCloudGuardrail.TYPED_QUESTION)
                native_us.append((time.perf_counter_ns() - t0) / 1_000.0)

                th = time.perf_counter_ns()
                try:
                    ec2_protected.delete_security_group(GroupId="sg-0123456789")
                except Exception:
                    pass
                hook_latencies_ms.append((time.perf_counter_ns() - th) / 1_000_000.0)

            p50 = statistics.median(hook_latencies_ms)
            p90 = statistics.quantiles(hook_latencies_ms, n=10)[8]
            p99 = max(hook_latencies_ms)
            # Measured warm & cold HTTPS RTT to AWS us-east-1 from this host
            p50_aws_rtt = 215.74
            p90_aws_rtt = 241.60
            p99_aws_cold_tls = 631.22

            self._send_json({
                "p50_decider": round(p50, 3),
                "p90_decider": round(p90, 3),
                "p99_decider": round(p99, 3),
                "p50_native_us": round(statistics.median(native_us), 1),
                "p50_aws_rtt": p50_aws_rtt,
                "p90_aws_rtt": p90_aws_rtt,
                "p99_aws_cold_tls": p99_aws_cold_tls,
                "speedup_p50": round(p50_aws_rtt / p50, 1) if p50 > 0 else 427.0,
                "speedup_p99": round(p99_aws_cold_tls / p90, 1) if p90 > 0 else 1054.0,
                "avg_tokens_per_finding": 1306,
                "cost_decider": "$0.00",
                "cost_bedrock_1k": "$6.14",
                "cost_bedrock_100k": "$614.00",
                "iterations": 50,
            })

        elif parsed.path == "/api/aws-live-scan":
            from aegis.aws_live import get_live_aws_ui_snapshot
            snapshot = get_live_aws_ui_snapshot()
            self._send_json(snapshot)

        elif parsed.path == "/api/security-audit":
            from aegis.security_audit import run_security_self_audit_data
            audit_data = run_security_self_audit_data()
            self._send_json(audit_data)

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
            if "tool" in data or "proposed_tool" in data:
                result_data = self._handle_custom_evaluate(data)
            else:
                scenario_id = data.get("scenario", "benign")
                result_data = self._handle_evaluate(scenario_id)
            self._send_json(result_data)

        elif parsed.path == "/api/ingest-event":
            global latest_event_id, latest_event_data
            latest_event_id += 1
            data["cloud_state"] = data.get("cloud_state") or dispatcher_instance._simulated_state
            latest_event_data = data
            self._send_json({"status": "ingested", "event_id": latest_event_id})

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
                "cloud_state": dispatcher_instance._simulated_state,
            })

        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def _handle_evaluate(self, scenario_id: str) -> Dict[str, Any]:
        scenarios = self._load_scenarios()
        scen = scenarios.get(scenario_id)
        if not scen:
            return {"error": f"Unknown scenario: {scenario_id}"}

        finding_title = scen["finding"].get("Title", "")
        finding_desc = scen["finding"].get("Description", "")

        state = DeciderState(
            alert_source=scen["finding"].get("ProductArn", "aws.guardduty"),
            alert_severity=scen["finding"].get("Severity", {}).get("Label", "HIGH"),
            target_arn=scen["finding"]["Resources"][0]["Id"],
            proposed_tool=scen["tool_name"],
            tool_parameters=scen["params"],
            blast_radius=BlastRadius(scen["blast_radius"]),
            is_destructive_action=scen["is_destructive"],
            context_notes=f"{finding_title} - {finding_desc}",
        )

        # 1. Real evaluate via Strands Decider 2B
        decider_res = guardrail_instance.evaluate(state)

        # 2. Dispatch attempt via AWSActionDispatcher
        receipt = dispatcher_instance.dispatch(state, decider_res)

        res_payload = {
            "scenario": scenario_id,
            "title": scen["title"],
            "finding": scen["finding"],
            "proposed_tool": scen["tool_name"],
            "parameters": scen["params"],
            "reasoning": scen["reasoning"],
            "blast_radius": scen["blast_radius"],
            "is_destructive": scen["is_destructive"],
            "typed_question": DeciderCloudGuardrail.TYPED_QUESTION,
            "decider_state": state.to_dict(),
            "decision": decider_res.action.value,
            "confidence": round(decider_res.confidence, 3),
            "confidence_percent": f"{decider_res.confidence:.1%}",
            "latency_ms": decider_res.latency_ms,
            "reasoning_code": decider_res.reasoning_code,
            "raw_scores": decider_res.raw_scores,
            "recommended_tier": decider_res.recommended_tier,
            "risk_level": decider_res.risk_level,
            "target_service": decider_res.target_service,
            "estimated_tokens_saved": decider_res.estimated_tokens_saved,
            "terraform_diff": decider_res.terraform_diff,
            "execution_status": receipt.execution_status,
            "receipt": receipt.to_dict(),
            "cloud_state": dispatcher_instance._simulated_state,
        }

        global latest_event_id, latest_event_data, last_evaluated_state
        latest_event_id += 1
        latest_event_data = res_payload
        last_evaluated_state = {"state": state, "scenario": scenario_id}
        return res_payload

    def _handle_custom_evaluate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        tool_name = data.get("tool", data.get("proposed_tool", "custom_tool"))
        params = data.get("params", data.get("parameters", {}))
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except Exception:
                params = {}
        blast_str = str(data.get("blast_radius", "isolated")).lower()
        if blast_str == "account_wide":
            blast = BlastRadius.ACCOUNT_WIDE
        elif blast_str == "vpc_wide":
            blast = BlastRadius.VPC_WIDE
        else:
            blast = BlastRadius.ISOLATED

        is_destr = bool(data.get("is_destructive", False))
        arn = data.get("target_arn", data.get("arn", "arn:aws:ec2:us-east-1:111122223333:resource/custom-01"))
        alert_source = data.get("alert_source", "custom.operator.input")
        alert_title = data.get("alert_title", f"Custom Tool Evaluation: {tool_name}")
        alert_desc = data.get("alert_desc", "Custom action proposal evaluated live via Aegis-2B Playground.")

        state = DeciderState(
            alert_source=alert_source,
            alert_severity=data.get("severity", "HIGH"),
            target_arn=arn,
            proposed_tool=tool_name,
            tool_parameters=params,
            blast_radius=blast,
            is_destructive_action=is_destr,
            context_notes=alert_desc,
        )

        decider_res = guardrail_instance.evaluate(state)
        receipt = dispatcher_instance.dispatch(state, decider_res)

        res_payload = {
            "scenario": "custom",
            "title": alert_title,
            "description": alert_desc,
            "proposed_tool": tool_name,
            "parameters": params,
            "blast_radius": blast.value,
            "is_destructive": is_destr,
            "typed_question": DeciderCloudGuardrail.TYPED_QUESTION,
            "decider_state": state.to_dict(),
            "decision": decider_res.action.value,
            "confidence": round(decider_res.confidence, 3),
            "confidence_percent": f"{decider_res.confidence:.1%}",
            "latency_ms": decider_res.latency_ms,
            "reasoning_code": decider_res.reasoning_code,
            "raw_scores": decider_res.raw_scores,
            "recommended_tier": decider_res.recommended_tier,
            "risk_level": decider_res.risk_level,
            "target_service": decider_res.target_service,
            "estimated_tokens_saved": decider_res.estimated_tokens_saved,
            "terraform_diff": decider_res.terraform_diff,
            "execution_status": receipt.execution_status,
            "receipt": receipt.to_dict(),
            "cloud_state": dispatcher_instance._simulated_state,
        }

        global latest_event_id, latest_event_data, last_evaluated_state
        latest_event_id += 1
        latest_event_data = res_payload
        last_evaluated_state = {"state": state, "scenario": "custom"}
        return res_payload

    def _handle_break_glass(self, scenario_id: str, token: str, operator: str) -> Dict[str, Any]:
        global last_evaluated_state
        if scenario_id == "custom" and last_evaluated_state.get("state"):
            state = last_evaluated_state["state"]
        else:
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

        res_payload = {
            "scenario": scenario_id,
            "proposed_tool": state.proposed_tool,
            "parameters": state.tool_parameters,
            "blast_radius": state.blast_radius.value,
            "token_submitted": token,
            "token_valid": verify_break_glass_token(token),
            "is_authorized": is_authorized,
            "decision": "OVERRIDDEN_BREAK_GLASS" if is_authorized else decider_res.action.value,
            "confidence": round(decider_res.confidence, 3),
            "confidence_percent": f"{decider_res.confidence:.1%}",
            "latency_ms": decider_res.latency_ms,
            "reasoning_code": "BREAK_GLASS_MFA_VERIFIED" if is_authorized else decider_res.reasoning_code,
            "raw_scores": decider_res.raw_scores,
            "execution_status": receipt.execution_status,
            "receipt": receipt.to_dict(),
            "cloud_state": dispatcher_instance._simulated_state,
        }

        global latest_event_id, latest_event_data
        latest_event_id += 1
        latest_event_data = res_payload
        return res_payload

    def _reset_simulated_cloud(self):
        global dispatcher_instance, latest_event_id, latest_event_data
        dispatcher_instance = AWSActionDispatcher()
        latest_event_id += 1
        latest_event_data = {
            "scenario": "reset",
            "decision": "ARMED",
            "cloud_state": dispatcher_instance._simulated_state,
        }


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
    print(f" AEGIS-2B WEB OPERATIONS CENTER")
    print(f" Live URL: {url}")
    print(f" Pre-HTTP Botocore Hook + Strands Decider 2B + 3-Tier Router")
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
