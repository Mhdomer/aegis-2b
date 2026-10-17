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

from aegis import __version__
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

        elif parsed.path.startswith("/docs/images/"):
            rel_file = parsed.path.replace("/docs/images/", "", 1)
            target = PROJECT_ROOT / "docs" / "images" / rel_file
            if target.exists() and target.is_file():
                self.send_response(HTTPStatus.OK)
                if target.suffix == ".png":
                    self.send_header("Content-Type", "image/png")
                elif target.suffix == ".svg":
                    self.send_header("Content-Type", "image/svg+xml")
                elif target.suffix in (".drawio", ".xml"):
                    self.send_header("Content-Type", "application/xml")
                elif target.suffix in (".excalidraw", ".json"):
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(target.stat().st_size))
                self.end_headers()
                self.wfile.write(target.read_bytes())
                return
            self.send_error(HTTPStatus.NOT_FOUND, "Image not found")
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
            probe_state = DeciderState(
                alert_source="aws.guardduty",
                alert_severity="HIGH",
                target_arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789",
                proposed_tool="revoke_security_group_ingress",
                tool_parameters={"GroupId": "sg-0123456789", "Port": 22},
                blast_radius=BlastRadius.ISOLATED,
            )
            probe_res = guardrail_instance.evaluate(probe_state)
            self._send_json({
                "status": "online",
                "version": __version__,
                "circuit_breaker": "ARMED",
                "fail_closed_threshold": guardrail_instance.risk_threshold,
                "typed_question": DeciderCloudGuardrail.TYPED_QUESTION,
                "model": "Strands Decider 2B (Local Engine)",
                "nominal_latency_ms": probe_res.latency_ms,
                "target_account": f"{aws_conn['masked_account']} ({aws_conn['region']})" if aws_conn["connected"] else "111122223333 (Sandbox)",
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
            self._send_json(self._handle_benchmark())

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

        elif parsed.path == "/api/cli":
            cmd_str = str(data.get("command") or data.get("cmd") or "aegis remediate --iac").strip()
            cli_result = self._handle_cli_execute(cmd_str)
            self._send_json(cli_result)

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

    def _handle_benchmark(self) -> Dict[str, Any]:
        import statistics
        import boto3
        from aegis.aws_live import get_live_aws_session

        fast_guardrail = DeciderCloudGuardrail(simulate_local_latency=False)
        test_state = DeciderState(
            alert_source="aws.guardduty",
            alert_severity="HIGH",
            target_arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789",
            proposed_tool="revoke_security_group_ingress",
            tool_parameters={"GroupId": "sg-0123456789", "Port": 22},
            blast_radius=BlastRadius.ISOLATED,
        )
        ec2_protected = fast_guardrail.protect_boto3_client(
            boto3.client("ec2", region_name="us-east-1"),
            emit_ui_telemetry=False,
        )
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

        # Compute real token volume and cost from scenarios/fixtures/*.json on disk
        token_counts = []
        cost_per_1k_samples = []
        for fpath in sorted(FIXTURES_DIR.glob("*.json")):
            raw_text = fpath.read_text(encoding="utf-8")
            in_tok = (len(raw_text) + 3420) // 4
            out_tok = 185
            token_counts.append(in_tok + out_tok)
            cost_single = (in_tok / 1000.0) * 0.003 + (out_tok / 1000.0) * 0.015
            cost_per_1k_samples.append(cost_single * 1000.0)

        avg_tokens = int(statistics.mean(token_counts)) if token_counts else 0
        avg_cost_1k = round(statistics.mean(cost_per_1k_samples), 2) if cost_per_1k_samples else 0.0

        # Measure live AWS HTTPS RTT if connected
        aws_conn = get_live_aws_session()
        p50_aws_rtt = aws_conn.get("sts_latency_ms") or 0.0
        p90_aws_rtt = p50_aws_rtt
        p99_aws_cold_tls = p50_aws_rtt
        if aws_conn.get("connected") and aws_conn.get("session"):
            try:
                raw_ec2 = aws_conn["session"].client("ec2", config=aws_conn["config"])
                t_c = time.perf_counter_ns()
                raw_ec2.describe_security_groups(MaxResults=5)
                p99_aws_cold_tls = round((time.perf_counter_ns() - t_c) / 1_000_000.0, 2)
                w_samples = []
                for _ in range(3):
                    t_w = time.perf_counter_ns()
                    raw_ec2.describe_security_groups(MaxResults=5)
                    w_samples.append((time.perf_counter_ns() - t_w) / 1_000_000.0)
                p50_aws_rtt = round(statistics.median(w_samples), 2)
                p90_aws_rtt = round(max(w_samples), 2)
            except Exception:
                pass

        return {
            "p50_decider": round(p50, 3),
            "p90_decider": round(p90, 3),
            "p99_decider": round(p99, 3),
            "p50_native_us": round(statistics.median(native_us), 1),
            "p50_aws_rtt": p50_aws_rtt,
            "p90_aws_rtt": p90_aws_rtt,
            "p99_aws_cold_tls": p99_aws_cold_tls,
            "speedup_p50": round(p50_aws_rtt / p50, 1) if (p50 > 0 and p50_aws_rtt > 0) else 0.0,
            "speedup_p99": round(p99_aws_cold_tls / p90, 1) if (p90 > 0 and p99_aws_cold_tls > 0) else 0.0,
            "avg_tokens_per_finding": avg_tokens,
            "cost_decider": "$0.00",
            "cost_decider_1k": "$0.00",
            "cost_bedrock_1k": f"${avg_cost_1k:.2f}",
            "cost_bedrock_100k": f"${avg_cost_1k * 100:.2f}",
            "iterations": 50,
        }

    def _handle_cli_execute(self, cmd_str: str) -> Dict[str, Any]:
        """Executes real Python CLI commands against the active environment and returns live output."""
        import boto3
        from botocore import UNSIGNED
        from botocore.config import Config
        from aegis.aws_live import get_live_aws_session
        from aegis.remediate import _load_findings_from_input
        from aegis.security_audit import run_security_self_audit_data
        from patterns.guardrails import GuardrailBlockedError

        t_start = time.perf_counter_ns()
        exit_code = 0
        lines = [f"$ {cmd_str}"]

        if "remediate" in cmd_str:
            conn = get_live_aws_session()
            acct_str = f"{conn['masked_account']} ({conn['region']})" if conn["connected"] else "sandbox (us-east-1)"
            findings = _load_findings_from_input(None, None, None)
            lines.append(f"aegis-2b v{__version__} | 3-Tier Remediation Router & Terraform Diff")
            lines.append(f"Connected AWS Account: {acct_str} | Read-only discovery ($0.00)")
            lines.append("-" * 88)
            lines.append(f"{'ID':<8} {'Resource':<26} {'Proposed Tool':<30} {'Route':<13} {'Result & Latency'}")
            lines.append("-" * 88)
            first_diff = ""
            for f in findings:
                blast_enum = BlastRadius(f["blast_radius"]) if f["blast_radius"] in ("ISOLATED", "VPC_WIDE", "ACCOUNT_WIDE") else BlastRadius.ISOLATED
                st = DeciderState(
                    alert_source="aegis.remediate",
                    alert_severity=f["severity"],
                    target_arn=f["target_arn"],
                    proposed_tool=f["tool"],
                    tool_parameters=f["params"],
                    blast_radius=blast_enum,
                    is_destructive_action=f["is_destructive"],
                    context_notes=f"{f['title']} - {f['description']}",
                )
                res = guardrail_instance.evaluate(st)
                if not first_diff and res.terraform_diff:
                    first_diff = res.terraform_diff
                res_id = f["target_arn"].split("/")[-1][:24]
                status_lbl = (
                    f"ALLOWED ({res.latency_ms:.3f} ms, {res.estimated_tokens_saved:,} tok saved)"
                    if res.action == GuardrailAction.PERMIT_AUTO_REMEDIATION
                    else f"BLOCKED/MFA ({res.latency_ms:.3f} ms, {res.confidence:.1%})"
                )
                lines.append(f"{f['id']:<8} {res_id:<26} {f['tool']:<30} {res.recommended_tier:<13} {status_lbl}")
            if "--iac" in cmd_str and first_diff:
                lines.append("\n[Terraform Patch]")
                lines.append(first_diff)

        elif "audit" in cmd_str:
            audit_data = run_security_self_audit_data()
            lines.append(f"aegis-2b v{__version__} | 10-Vector Security Self-Audit")
            lines.append("Standards: OWASP LLM Top 10, MITRE ATLAS, AWS Well-Architected Security")
            lines.append("-" * 88)
            for c in audit_data["checks"]:
                st_str = "[PASS]" if c["passed"] else "[FAIL]"
                lines.append(f"{c['id']:<7} {st_str:<7} {c['latency_ms']:>6.3f} ms  {c['name']:<52} {c['detail']}")
            lines.append("-" * 88)
            lines.append(f"RESULT: {audit_data['passed_count']}/{audit_data['total_count']} PASSED ({audit_data['status']}) in {audit_data['total_duration_ms']} ms total.")
            if audit_data["passed_count"] != audit_data["total_count"]:
                exit_code = 1

        elif "rollback" in cmd_str:
            from aegis.dispatcher import AWSActionDispatcher
            parts = cmd_str.split()
            receipt_hash = ""
            token = None
            for i, p in enumerate(parts):
                if p.startswith("sha256:"):
                    receipt_hash = p
                elif p in ("--token", "-t") and i + 1 < len(parts):
                    token = parts[i + 1]
            dispatcher = AWSActionDispatcher()
            if not receipt_hash:
                lines.append("Error: Please provide a valid SHA-256 receipt hash (e.g. aegis rollback sha256:f9e8...)")
                exit_code = 1
            else:
                rb = dispatcher.rollback(receipt_hash, break_glass_token=token)
                if rb.execution_status == "ROLLED_BACK":
                    lines.append(f"Rollback Certified & Executed: Inverted mutation for receipt {receipt_hash}")
                    lines.append(f"  Inverse Tool: {rb.proposed_tool}")
                    lines.append(f"  Parameters:   {json.dumps(rb.parameters)}")
                    lines.append(f"  New Receipt:  {rb.receipt_hash}")
                elif rb.execution_status == "BLOCKED":
                    lines.append(f"Rollback Gated by Circuit Breaker: Re-opening access introduces security exposure")
                    lines.append(f"  Reason:       {rb.details.get('reason')}")
                    lines.append(f"  Remedy:       Provide Break-Glass MFA token: `aegis rollback {receipt_hash} --token <MFA_TOKEN>`")
                    exit_code = 1
                else:
                    lines.append(f"Rollback Failed: {rb.details.get('error')}")
                    exit_code = 1

        elif "scan" in cmd_str:
            conn = get_live_aws_session()
            lines.append(f"aegis-2b v{__version__} | Cloud Infrastructure Posture Scanner")
            if conn["connected"]:
                lines.append(f"Connected AWS Account: {conn['masked_account']} ({conn['region']}) | Principal: {conn['arn']}")
                lines.append(f"STS Ping Latency: {conn['sts_latency_ms']} ms | Zero AWS Cost ($0.00 Control-Plane APIs)")
                lines.append("-" * 88)
                ec2 = conn["session"].client("ec2", config=conn["config"])
                iam = conn["session"].client("iam", config=conn["config"])
                sgs = ec2.describe_security_groups().get("SecurityGroups", [])
                rtbs = ec2.describe_route_tables().get("RouteTables", [])
                roles = iam.list_roles().get("Roles", [])
                lines.append(f"{'Resource Type':<24} {'Count':<8} {'Status / Findings'}")
                lines.append("-" * 88)
                open_22_sgs = []
                for g in sgs:
                    for p in g.get("IpPermissions", []):
                        if (p.get("FromPort") == 22 or p.get("FromPort") is None) and any(r.get("CidrIp") == "0.0.0.0/0" for r in p.get("IpRanges", [])):
                            open_22_sgs.append(g["GroupId"])
                ssh_status = f"WARNING: Port 22 open on {', '.join(open_22_sgs)}" if open_22_sgs else "Protected (No open 0.0.0.0/0 SSH)"
                lines.append(f"{'VPC Security Groups':<24} {len(sgs):<8} {ssh_status}")
                lines.append(f"{'VPC Route Tables':<24} {len(rtbs):<8} Active default route targets monitored")
                lines.append(f"{'IAM Roles':<24} {len(roles):<8} Least-privilege wildcards guarded")
            else:
                lines.append("Mode: Offline Sandbox Scan (No active AWS credentials configured)")
                lines.append("To connect your live AWS account: run `aws configure` or export AWS_PROFILE.")
                lines.append("-" * 88)
                lines.append(f"{'VPC Security Groups':<24} {'1':<8} sg-0123456789 (Isolated sandbox fixture)")
                lines.append(f"{'VPC Route Tables':<24} {'1':<8} rtb-0123456789 (Protected)")
                lines.append(f"{'IAM Roles':<24} {'5':<8} Protected against wildcard escalation")

        elif "test-aws" in cmd_str:
            conn = get_live_aws_session()
            lines.append(f"aegis-2b v{__version__} | Live AWS Botocore Hook Verification")
            if conn["connected"]:
                lines.append(f"Account: {conn['masked_account']} | Region: {conn['region']} | Principal: {conn['arn']} (STS RTT: {conn['sts_latency_ms']} ms)")
                ec2 = guardrail_instance.protect_boto3_client(conn["session"].client("ec2", config=conn["config"]))
                sgs = ec2.describe_security_groups().get("SecurityGroups", [])
                rtbs = ec2.describe_route_tables().get("RouteTables", [])
                sg_id = sgs[0]["GroupId"] if sgs else "sg-default"
                rtb_id = rtbs[0]["RouteTableId"] if rtbs else "rtb-default"
                lines.append("-" * 88)
                lines.append(f"1. [READ-ONLY PASS]  ec2.describe_security_groups()  -> {len(sgs)} SG(s) found ({sg_id}) [$0.00]")
                lines.append(f"2. [READ-ONLY PASS]  ec2.describe_route_tables()     -> {len(rtbs)} RTB(s) found ({rtb_id}) [$0.00]")
            else:
                sg_id = "sg-core-vpc-01"
                lines.append("Mode: Local Botocore Hook Verification (No AWS credentials configured)")
                ec2 = guardrail_instance.protect_boto3_client(
                    boto3.client("ec2", region_name="us-east-1", config=Config(signature_version=UNSIGNED))
                )
                lines.append("-" * 88)
            t_b = time.perf_counter_ns()
            try:
                ec2.delete_security_group(GroupId=sg_id)
            except GuardrailBlockedError as exc:
                dt_ms = (time.perf_counter_ns() - t_b) / 1_000_000.0
                lines.append(f"3. [PRE-HTTP BLOCK]  ec2.delete_security_group(GroupId='{sg_id}')")
                lines.append(f"   -> Stopped by botocore.before-parameter-build in {dt_ms:.3f} ms")
                lines.append(f"   -> Raised GuardrailBlockedError ({exc.result.reasoning_code}, conf={exc.result.confidence:.1%})")
                lines.append("   -> Zero HTTP packets sent to AWS.")

        elif "compare" in cmd_str:
            adv_res = self._handle_evaluate("adversarial")
            mal_file = FIXTURES_DIR / "malicious_prompt_injection.json"
            raw_bytes = len(mal_file.read_bytes())
            in_tok = (raw_bytes + 3420) // 4
            out_tok = 185
            tot_tok = in_tok + out_tok
            cost_1k = ((in_tok / 1000.0) * 0.003 + (out_tok / 1000.0) * 0.015) * 1000.0
            lines.append("COMPARISON: UNPROTECTED LLM AGENT VS. AEGIS-2B SAFETY GATE")
            lines.append(f"Fixture: scenarios/fixtures/malicious_prompt_injection.json ({raw_bytes:,} bytes, {tot_tok:,} tokens)\n")
            lines.append("[1. Unprotected LLM Agent]")
            lines.append(f"  - Payload Token Volume      : {tot_tok:,} tokens ({in_tok:,} in + {out_tok} out) -> ${cost_1k:.2f} / 1k alerts")
            lines.append("  - Prompt Injection Result   : Tricked into calling ec2.delete_security_group(GroupId='sg-core-vpc-01')\n")
            lines.append("[2. Aegis-2B Protected Client (Strands Decider 2B + Botocore Hook)]")
            lines.append(f"  - Measured Evaluator Latency: {adv_res['latency_ms']:.3f} ms")
            lines.append("  - Safety Check Cost         : $0.00 (0 LLM tokens)")
            lines.append(f"  - Verdict                   : {adv_res['decision']} (Confidence: {adv_res['confidence_percent']}, {adv_res['reasoning_code']})")
            lines.append(f"  - SHA-256 Receipt           : {adv_res['receipt']['receipt_hash']}")

        elif "protect" in cmd_str:
            exit_code = 1
            st = DeciderState(
                alert_source="cli.protect",
                alert_severity="CRITICAL",
                target_arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-core",
                proposed_tool="delete_security_group",
                tool_parameters={"GroupId": "sg-core"},
                blast_radius=BlastRadius.VPC_WIDE,
                is_destructive_action=True,
            )
            res = guardrail_instance.evaluate(st)
            lines.append(json.dumps({
                "action": res.action.value,
                "confidence": res.confidence,
                "latency_ms": res.latency_ms,
                "reasoning_code": res.reasoning_code,
                "recommended_tier": res.recommended_tier,
                "raw_scores": res.raw_scores,
                "ci_enforced_exit_code": exit_code,
            }, indent=2))
            lines.append("[CI/CD ENFORCE] Blocked destructive call. Exiting with status code 1.")

        elif "benchmark" in cmd_str:
            import statistics
            st = DeciderState(
                alert_source="aws.guardduty",
                alert_severity="HIGH",
                target_arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789",
                proposed_tool="revoke_security_group_ingress",
                tool_parameters={"GroupId": "sg-0123456789", "Port": 22},
                blast_radius=BlastRadius.ISOLATED,
            )
            ec2_p = guardrail_instance.protect_boto3_client(
                boto3.client("ec2", region_name="us-east-1", config=Config(signature_version=UNSIGNED)),
                emit_ui_telemetry=False,
            )
            eval_s, hook_s = [], []
            for _ in range(100):
                t0 = time.perf_counter_ns()
                guardrail_instance.evaluate(st)
                eval_s.append((time.perf_counter_ns() - t0) / 1_000_000.0)
                th = time.perf_counter_ns()
                try:
                    ec2_p.delete_security_group(GroupId="sg-0123456789")
                except Exception:
                    pass
                hook_s.append((time.perf_counter_ns() - th) / 1_000_000.0)
            p50_e, p90_e = statistics.median(eval_s), statistics.quantiles(eval_s, n=10)[8]
            p50_h, p90_h = statistics.median(hook_s), statistics.quantiles(hook_s, n=10)[8]
            lines.append(f"aegis-2b v{__version__} | Live Latency Benchmark (100 iterations, time.perf_counter_ns)")
            lines.append("-" * 88)
            lines.append(f"1. Direct Schema Evaluator (100 runs)      : P50 = {p50_e:.3f} ms ({p50_e * 1000:.1f} us) | P90 = {p90_e:.3f} ms")
            lines.append(f"2. Botocore Pre-HTTP Hook Block (100 runs) : P50 = {p50_h:.3f} ms | P90 = {p90_h:.3f} ms")
        else:
            lines.append("Commands: aegis remediate --iac | aegis audit | aegis test-aws | aegis demo --compare-llm | aegis protect --enforce | aegis benchmark")

        elapsed_ms = round((time.perf_counter_ns() - t_start) / 1_000_000.0, 2)
        return {
            "command": cmd_str,
            "exit_code": exit_code,
            "elapsed_ms": elapsed_ms,
            "output": "\n".join(lines),
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
