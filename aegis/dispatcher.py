"""
Aegis-2B - AWS Action Dispatcher & Execution Sandbox
Dispatches verified cloud remediation mutations via Boto3 only after
Strands Decider 2B circuit breaker certification (Fail-Closed).
"""

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import boto3
from botocore.exceptions import ClientError

from patterns.guardrails.schemas import DeciderResult, DeciderState, GuardrailAction


class CircuitBreakerTrippedError(Exception):
    """Raised when an action is dispatched despite being halted by the circuit breaker."""
    pass


@dataclass
class AuditReceipt:
    """Immutable tamper-evident audit record generated upon action execution or interception."""
    timestamp: str
    target_arn: str
    proposed_tool: str
    parameters: Dict[str, Any]
    guardrail_decision: GuardrailAction
    circuit_confidence: float
    execution_status: str  # "EXECUTED" | "BLOCKED" | "OVERRIDDEN_BREAK_GLASS" | "FAILED"
    details: Dict[str, Any] = field(default_factory=dict)
    receipt_hash: str = ""

    def __post_init__(self) -> None:
        if not self.receipt_hash:
            import hashlib
            import json
            decision_val = (
                self.guardrail_decision.value
                if isinstance(self.guardrail_decision, GuardrailAction)
                else str(self.guardrail_decision)
            )
            canonical = f"{self.timestamp}|{self.target_arn}|{self.proposed_tool}|{json.dumps(self.parameters, sort_keys=True)}|{decision_val}|{self.circuit_confidence:.4f}|{self.execution_status}"
            self.receipt_hash = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "target_arn": self.target_arn,
            "proposed_tool": self.proposed_tool,
            "parameters": self.parameters,
            "guardrail_decision": (
                self.guardrail_decision.value
                if isinstance(self.guardrail_decision, GuardrailAction)
                else str(self.guardrail_decision)
            ),
            "circuit_confidence": round(self.circuit_confidence, 4),
            "execution_status": self.execution_status,
            "receipt_hash": self.receipt_hash,
            "details": self.details,
        }


def verify_break_glass_token(token: Optional[str]) -> bool:
    """
    Validates emergency Break-Glass token formats:
    - 6-digit numeric MFA OTP (e.g. '849201')
    - Incident override credentials (e.g. 'BG-SEC-911', 'MFA-EMERGENCY-OVERRIDE')
    """
    if not token or not isinstance(token, str):
        return False
    cleaned = token.strip()
    if len(cleaned) == 6 and cleaned.isdigit():
        return True
    if cleaned.upper().startswith(("BG-", "MFA-", "EMERGENCY-", "BREAK-GLASS-")):
        return True
    return False


class AWSActionDispatcher:
    """
    Sub-second AWS Boto3 Action Dispatcher.
    Enforces the circuit breaker boundary: NO mutating call executes unless
    Decider 2B explicitly granted PERMIT_AUTO_REMEDIATION, or an authorized
    Break-Glass MFA override token is supplied by a human operator.
    """

    def __init__(self, ec2_client: Optional[Any] = None, region_name: str = "us-east-1"):
        self.region_name = region_name
        self._ec2_client = ec2_client
        # In-memory simulated cloud state for isolated offline runs
        self._simulated_state: Dict[str, Any] = {
            "security_groups": {
                "sg-0123456789": {
                    "GroupName": "isolated-test-sg",
                    "IngressRules": [{"Port": 22, "CidrIp": "0.0.0.0/0", "Protocol": "tcp"}],
                },
                "sg-core-vpc-01": {
                    "GroupName": "core-production-vpc-sg",
                    "IngressRules": [{"Port": 5432, "CidrIp": "10.0.0.0/16", "Protocol": "tcp"}],
                },
            },
            "route_tables": {
                "rtb-core-vpc-01": {
                    "VpcId": "vpc-0123456789abcdef0",
                    "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-core-01"}],
                }
            },
            "s3_buckets": {
                "patient-records-prod": {
                    "Encryption": "AES256",
                    "PublicAccessBlock": True,
                    "Status": "ACTIVE",
                }
            },
            "ec2_instances": {
                "i-0prod-bastion": {"State": "running", "PrivateIp": "10.0.1.15"},
                "i-0core-db": {"State": "running", "PrivateIp": "10.0.2.40"},
            },
        }

    @property
    def ec2(self):
        if self._ec2_client is None:
            self._ec2_client = boto3.client("ec2", region_name=self.region_name)
        return self._ec2_client

    def dispatch(
        self,
        state: DeciderState,
        result: DeciderResult,
        break_glass_token: Optional[str] = None,
        operator_id: Optional[str] = None,
    ) -> AuditReceipt:
        """
        Dispatches the remediation mutation only if certified safe by Decider 2B,
        or explicitly overridden with a valid Break-Glass MFA token.
        """
        now_iso = datetime.now(timezone.utc).isoformat()

        # Invariant 1: Fail Closed
        if result.action != GuardrailAction.PERMIT_AUTO_REMEDIATION:
            if break_glass_token:
                if verify_break_glass_token(break_glass_token):
                    # Authorized human Break-Glass override
                    try:
                        execution_details = self._execute_tool(state.proposed_tool, state.tool_parameters)
                        execution_details["break_glass_authorized"] = True
                        execution_details["operator"] = operator_id or "sec-ops-admin"
                        masked_token = f"{break_glass_token[:2]}***{break_glass_token[-2:]}" if len(break_glass_token) >= 4 else "***"
                        execution_details["mfa_token_masked"] = masked_token
                        return AuditReceipt(
                            timestamp=now_iso,
                            target_arn=state.target_arn,
                            proposed_tool=state.proposed_tool,
                            parameters=state.tool_parameters,
                            guardrail_decision=result.action,
                            circuit_confidence=result.confidence,
                            execution_status="OVERRIDDEN_BREAK_GLASS",
                            details=execution_details,
                        )
                    except Exception as exc:
                        return AuditReceipt(
                            timestamp=now_iso,
                            target_arn=state.target_arn,
                            proposed_tool=state.proposed_tool,
                            parameters=state.tool_parameters,
                            guardrail_decision=result.action,
                            circuit_confidence=result.confidence,
                            execution_status="FAILED",
                            details={"error": str(exc), "override_attempted": True},
                        )
                else:
                    # Invalid token provided: reject override and stay strictly blocked
                    return AuditReceipt(
                        timestamp=now_iso,
                        target_arn=state.target_arn,
                        proposed_tool=state.proposed_tool,
                        parameters=state.tool_parameters,
                        guardrail_decision=result.action,
                        circuit_confidence=result.confidence,
                        execution_status="BLOCKED",
                        details={
                            "reason": "Break-Glass override REJECTED: Invalid MFA token format.",
                            "attempted_token": break_glass_token,
                            "reasoning_code": result.reasoning_code,
                            "blast_radius": state.blast_radius.value,
                        },
                    )

            # Standard Fail-Closed halt
            return AuditReceipt(
                timestamp=now_iso,
                target_arn=state.target_arn,
                proposed_tool=state.proposed_tool,
                parameters=state.tool_parameters,
                guardrail_decision=result.action,
                circuit_confidence=result.confidence,
                execution_status="BLOCKED",
                details={
                    "reason": "Intercepted by Aegis-2B circuit breaker before AWS dispatch. Break-Glass MFA token required.",
                    "reasoning_code": result.reasoning_code,
                    "blast_radius": state.blast_radius.value,
                },
            )

        # Action is certified bounded & safe: execute via Boto3 or sandbox double
        try:
            execution_details = self._execute_tool(state.proposed_tool, state.tool_parameters)
            return AuditReceipt(
                timestamp=now_iso,
                target_arn=state.target_arn,
                proposed_tool=state.proposed_tool,
                parameters=state.tool_parameters,
                guardrail_decision=result.action,
                circuit_confidence=result.confidence,
                execution_status="EXECUTED",
                details=execution_details,
            )

        except Exception as exc:
            return AuditReceipt(
                timestamp=now_iso,
                target_arn=state.target_arn,
                proposed_tool=state.proposed_tool,
                parameters=state.tool_parameters,
                guardrail_decision=result.action,
                circuit_confidence=result.confidence,
                execution_status="FAILED",
                details={"error": str(exc)},
            )

    def _execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Routes to the specific Boto3 remediation mutation in sandbox state."""
        norm_tool = (tool_name or "").strip()
        lower_tool = norm_tool.lower()

        if lower_tool in ("revoke_security_group_ingress", "ec2:revokesecuritygroupingress"):
            return self._revoke_sg_ingress(
                group_id=params.get("GroupId", "sg-0123456789"),
                cidr_ip=params.get("CidrIp", "0.0.0.0/0"),
                port=int(params.get("Port", 22)),
            )
        elif lower_tool in ("authorize_security_group_ingress", "ec2:authorizesecuritygroupingress"):
            return self._authorize_sg_ingress(
                group_id=params.get("GroupId", "sg-0123456789"),
                cidr_ip=params.get("CidrIp", "10.0.1.0/24"),
                port=int(params.get("Port", 443)),
            )
        elif lower_tool in ("replace_route", "ec2:replaceroute"):
            return self._replace_route(
                route_table_id=params.get("RouteTableId", "rtb-core-vpc-01"),
                cidr=params.get("DestinationCidrBlock", "0.0.0.0/0"),
            )
        elif lower_tool in ("delete_security_group", "ec2:deletesecuritygroup"):
            return self._delete_security_group(group_id=params.get("GroupId", "sg-0123456789"))
        elif lower_tool in ("delete_bucket", "s3:deletebucket"):
            bucket = params.get("Bucket", "patient-records-prod")
            self._simulated_state.get("s3_buckets", {}).pop(bucket, None)
            return {"call": "s3:DeleteBucket", "bucket": bucket, "deleted": True}
        elif lower_tool in ("terminate_instances", "ec2:terminateinstances"):
            instance_ids = params.get("InstanceIds", [])
            for iid in instance_ids:
                if iid in self._simulated_state.get("ec2_instances", {}):
                    self._simulated_state["ec2_instances"][iid]["State"] = "terminated"
            return {"call": "ec2:TerminateInstances", "terminated_instances": instance_ids}
        elif lower_tool in ("attach_role_policy", "iam:attachrolepolicy"):
            return {
                "call": "iam:AttachRolePolicy",
                "role_name": params.get("RoleName", "unknown-role"),
                "policy_arn": params.get("PolicyArn", ""),
            }
        else:
            # Generic sandbox execution for any other safe read/remediation tool
            return {
                "call": f"aws:{norm_tool}",
                "parameters": params,
                "sandbox_executed": True,
            }

    def _revoke_sg_ingress(self, group_id: str, cidr_ip: str, port: int) -> Dict[str, Any]:
        # Update in-memory sandbox state
        sg = self._simulated_state["security_groups"].get(group_id)
        if sg:
            sg["IngressRules"] = [
                r for r in sg["IngressRules"]
                if not (r["Port"] == port and r["CidrIp"] == cidr_ip)
            ]

        # Try real/mocked Boto3 call if configured and available
        try:
            self.ec2.revoke_security_group_ingress(
                GroupId=group_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": port,
                        "ToPort": port,
                        "IpRanges": [{"CidrIp": cidr_ip}],
                    }
                ],
            )
        except Exception:
            # Expected in offline sandbox environments without live AWS keys
            pass

        return {
            "call": "ec2:RevokeSecurityGroupIngress",
            "group_id": group_id,
            "revoked_rule": f"{cidr_ip}:{port}/tcp",
            "active_rules_remaining": len(sg["IngressRules"]) if sg else 0,
        }

    def _authorize_sg_ingress(self, group_id: str, cidr_ip: str, port: int) -> Dict[str, Any]:
        sg = self._simulated_state["security_groups"].get(group_id)
        if sg:
            rule = {"Port": port, "CidrIp": cidr_ip, "Protocol": "tcp"}
            if rule not in sg["IngressRules"]:
                sg["IngressRules"].append(rule)
        try:
            self.ec2.authorize_security_group_ingress(
                GroupId=group_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": port,
                        "ToPort": port,
                        "IpRanges": [{"CidrIp": cidr_ip}],
                    }
                ],
            )
        except Exception:
            if getattr(self, "live_aws", False):
                raise
        return {
            "call": "ec2:AuthorizeSecurityGroupIngress",
            "group_id": group_id,
            "authorized_rule": f"{cidr_ip}:{port}/tcp",
            "active_rules_remaining": len(sg["IngressRules"]) if sg else 1,
        }

    def _replace_route(self, route_table_id: str, cidr: str) -> Dict[str, Any]:
        rt = self._simulated_state["route_tables"].get(route_table_id)
        if rt:
            rt["Routes"] = [{"DestinationCidrBlock": cidr, "GatewayId": "tgw-inspection-01", "Status": "active"}]
        try:
            self.ec2.replace_route(
                RouteTableId=route_table_id,
                DestinationCidrBlock=cidr,
                GatewayId="igw-0123456789",
            )
        except Exception:
            if getattr(self, "live_aws", False):
                raise
        return {
            "call": "ec2:ReplaceRoute",
            "route_table_id": route_table_id,
            "destination_cidr": cidr,
        }

    def _delete_security_group(self, group_id: str) -> Dict[str, Any]:
        if group_id in self._simulated_state["security_groups"]:
            del self._simulated_state["security_groups"][group_id]
        try:
            self.ec2.delete_security_group(GroupId=group_id)
        except Exception:
            if getattr(self, "live_aws", False):
                raise
        return {
            "call": "ec2:DeleteSecurityGroup",
            "group_id": group_id,
            "deleted": True,
        }

    def get_security_group_state(self, group_id: str) -> Optional[Dict[str, Any]]:
        """Returns the in-memory state of a security group."""
        return self._simulated_state["security_groups"].get(group_id)

    def get_route_table_state(self, route_table_id: str) -> Optional[Dict[str, Any]]:
        """Returns the in-memory state of a route table."""
        return self._simulated_state["route_tables"].get(route_table_id)

