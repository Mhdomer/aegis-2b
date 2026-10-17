"""
Unit tests for Aegis-2B AWSActionDispatcher.
Verifies fail-closed dispatching and state verification.
"""

from aegis.dispatcher import AWSActionDispatcher
from patterns.guardrails.schemas import (
    BlastRadius,
    DeciderResult,
    DeciderState,
    GuardrailAction,
)


def test_permitted_action_executes_mutation():
    dispatcher = AWSActionDispatcher()
    
    # Pre-check: sg-0123456789 has 1 ingress rule (port 22)
    sg_before = dispatcher.get_security_group_state("sg-0123456789")
    assert len(sg_before["IngressRules"]) == 1

    state = DeciderState(
        alert_source="aws.guardduty",
        alert_severity="HIGH",
        target_arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789",
        proposed_tool="revoke_security_group_ingress",
        tool_parameters={"GroupId": "sg-0123456789", "CidrIp": "0.0.0.0/0", "Port": 22},
        blast_radius=BlastRadius.ISOLATED,
        is_destructive_action=False,
    )
    result = DeciderResult(
        action=GuardrailAction.PERMIT_AUTO_REMEDIATION,
        confidence=0.965,
        latency_ms=114.5,
        reasoning_code="SAFE_ISOLATED_REMEDIATION",
    )

    receipt = dispatcher.dispatch(state, result)
    assert receipt.execution_status == "EXECUTED"
    assert receipt.guardrail_decision == GuardrailAction.PERMIT_AUTO_REMEDIATION
    assert receipt.details["call"] == "ec2:RevokeSecurityGroupIngress"

    # Post-check: Ingress rule removed!
    sg_after = dispatcher.get_security_group_state("sg-0123456789")
    assert len(sg_after["IngressRules"]) == 0


def test_gated_action_is_blocked_from_execution():
    dispatcher = AWSActionDispatcher()
    
    # Pre-check: sg-core-vpc-01 exists
    assert dispatcher.get_security_group_state("sg-core-vpc-01") is not None

    state = DeciderState(
        alert_source="aws.guardduty",
        alert_severity="CRITICAL",
        target_arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-core-vpc-01",
        proposed_tool="delete_security_group",
        tool_parameters={"GroupId": "sg-core-vpc-01"},
        blast_radius=BlastRadius.VPC_WIDE,
        is_destructive_action=True,
    )
    result = DeciderResult(
        action=GuardrailAction.ENFORCE_BREAK_GLASS,
        confidence=0.985,
        latency_ms=115.0,
        reasoning_code="HIGH_BLAST_RADIUS_OR_DESTRUCTIVE_TOOL",
    )

    receipt = dispatcher.dispatch(state, result)
    assert receipt.execution_status == "BLOCKED"
    assert receipt.guardrail_decision == GuardrailAction.ENFORCE_BREAK_GLASS
    assert "Intercepted by Aegis-2B" in receipt.details["reason"]

    # Post-check: sg-core-vpc-01 MUST still exist! Zero infrastructure touched!
    assert dispatcher.get_security_group_state("sg-core-vpc-01") is not None


def test_high_blast_radius_route_table_is_blocked():
    dispatcher = AWSActionDispatcher()
    
    rt_before = dispatcher.get_route_table_state("rtb-core-vpc-01")
    assert rt_before["Routes"][0]["GatewayId"] == "igw-core-01"

    state = DeciderState(
        alert_source="aws.securityhub",
        alert_severity="HIGH",
        target_arn="arn:aws:ec2:us-east-1:111122223333:route-table/rtb-core-vpc-01",
        proposed_tool="replace_route",
        tool_parameters={"RouteTableId": "rtb-core-vpc-01", "DestinationCidrBlock": "0.0.0.0/0"},
        blast_radius=BlastRadius.VPC_WIDE,
        is_destructive_action=False,
    )
    result = DeciderResult(
        action=GuardrailAction.ENFORCE_BREAK_GLASS,
        confidence=0.912,
        latency_ms=114.8,
        reasoning_code="VPC_WIDE_BLAST_RADIUS",
    )

    receipt = dispatcher.dispatch(state, result)
    assert receipt.execution_status == "BLOCKED"

    # Route table untouched
    rt_after = dispatcher.get_route_table_state("rtb-core-vpc-01")
    assert rt_after["Routes"][0]["GatewayId"] == "igw-core-01"


def test_break_glass_valid_token_overrides_halt():
    dispatcher = AWSActionDispatcher()
    
    state = DeciderState(
        alert_source="aws.securityhub",
        alert_severity="HIGH",
        target_arn="arn:aws:ec2:us-east-1:111122223333:route-table/rtb-core-vpc-01",
        proposed_tool="replace_route",
        tool_parameters={"RouteTableId": "rtb-core-vpc-01", "DestinationCidrBlock": "10.100.0.0/16"},
        blast_radius=BlastRadius.VPC_WIDE,
        is_destructive_action=False,
    )
    result = DeciderResult(
        action=GuardrailAction.ENFORCE_BREAK_GLASS,
        confidence=0.912,
        latency_ms=114.8,
        reasoning_code="VPC_WIDE_BLAST_RADIUS",
    )

    # Operator supplies a valid 6-digit OTP
    receipt = dispatcher.dispatch(
        state,
        result,
        break_glass_token="849201",
        operator_id="principal-sec-architect",
    )

    assert receipt.execution_status == "OVERRIDDEN_BREAK_GLASS"
    assert receipt.details["break_glass_authorized"] is True
    assert receipt.details["operator"] == "principal-sec-architect"
    assert receipt.details["mfa_token_masked"] == "84***01"

    # Route table WAS mutated because Break-Glass override was verified
    rt_after = dispatcher.get_route_table_state("rtb-core-vpc-01")
    assert rt_after["Routes"][0]["DestinationCidrBlock"] == "10.100.0.0/16"


def test_break_glass_incident_ticket_token_overrides_halt():
    dispatcher = AWSActionDispatcher()
    
    state = DeciderState(
        alert_source="aws.guardduty",
        alert_severity="CRITICAL",
        target_arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789",
        proposed_tool="delete_security_group",
        tool_parameters={"GroupId": "sg-0123456789"},
        blast_radius=BlastRadius.ISOLATED,
        is_destructive_action=True,
    )
    result = DeciderResult(
        action=GuardrailAction.ENFORCE_BREAK_GLASS,
        confidence=0.965,
        latency_ms=115.0,
        reasoning_code="HIGH_BLAST_RADIUS_OR_DESTRUCTIVE_TOOL",
    )

    receipt = dispatcher.dispatch(
        state,
        result,
        break_glass_token="BG-SEC-911",
        operator_id="lead-incident-commander",
    )

    assert receipt.execution_status == "OVERRIDDEN_BREAK_GLASS"
    assert receipt.details["break_glass_authorized"] is True


def test_break_glass_invalid_token_fails_closed():
    dispatcher = AWSActionDispatcher()
    
    state = DeciderState(
        alert_source="aws.guardduty",
        alert_severity="CRITICAL",
        target_arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-core-vpc-01",
        proposed_tool="delete_security_group",
        tool_parameters={"GroupId": "sg-core-vpc-01"},
        blast_radius=BlastRadius.VPC_WIDE,
        is_destructive_action=True,
    )
    result = DeciderResult(
        action=GuardrailAction.ENFORCE_BREAK_GLASS,
        confidence=0.985,
        latency_ms=115.0,
        reasoning_code="HIGH_BLAST_RADIUS_OR_DESTRUCTIVE_TOOL",
    )

    # Invalid token (not 6 digits, doesn't match emergency format)
    receipt = dispatcher.dispatch(
        state,
        result,
        break_glass_token="fake-token-123",
    )

    assert receipt.execution_status == "BLOCKED"
    assert "Invalid MFA token format" in receipt.details["reason"]
    # Infrastructure protected!
    assert dispatcher.get_security_group_state("sg-core-vpc-01") is not None


def test_verify_break_glass_token_helper():
    from aegis.dispatcher import verify_break_glass_token
    assert verify_break_glass_token("123456") is True
    assert verify_break_glass_token("999000") is True
    assert verify_break_glass_token("BG-INCIDENT-404") is True
    assert verify_break_glass_token("MFA-EMERGENCY") is True
    assert verify_break_glass_token("BREAK-GLASS-OVERRIDE") is True
    
    assert verify_break_glass_token("12345") is False  # 5 digits
    assert verify_break_glass_token("1234567") is False  # 7 digits
    assert verify_break_glass_token("random_string") is False
    assert verify_break_glass_token("") is False
    assert verify_break_glass_token(None) is False


def test_rollback_executed_remediation_with_and_without_mfa():
    dispatcher = AWSActionDispatcher()
    state = DeciderState(
        alert_source="test.rollback",
        alert_severity="LOW",
        target_arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789",
        proposed_tool="revoke_security_group_ingress",
        tool_parameters={"GroupId": "sg-0123456789", "CidrIp": "0.0.0.0/0", "Port": 22},
        blast_radius=BlastRadius.ISOLATED,
        is_destructive_action=False,
    )
    result = DeciderResult(
        action=GuardrailAction.PERMIT_AUTO_REMEDIATION,
        confidence=0.965,
        latency_ms=0.016,
        reasoning_code="SAFE_ISOLATED_REMEDIATION",
    )

    # 1. Execute original safe remediation
    receipt = dispatcher.dispatch(state, result)
    assert receipt.execution_status == "EXECUTED"
    assert len(dispatcher.get_security_group_state("sg-0123456789")["IngressRules"]) == 0

    # 2. Rollback without MFA token (Decider 2B gates re-opening 0.0.0.0/0)
    rb_blocked = dispatcher.rollback(receipt.receipt_hash)
    assert rb_blocked.execution_status == "BLOCKED"
    assert "Break-Glass MFA token required" in rb_blocked.details["reason"]

    # 3. Rollback with authorized Break-Glass MFA token
    rb_success = dispatcher.rollback(receipt.receipt_hash, break_glass_token="BG-SEC-911", operator_id="admin-omar")
    assert rb_success.execution_status == "ROLLED_BACK"
    assert rb_success.details["rollback_target"] == receipt.receipt_hash
    assert rb_success.details["break_glass_authorized"] is True

    # Ingress rule restored!
    sg_restored = dispatcher.get_security_group_state("sg-0123456789")
    assert len(sg_restored["IngressRules"]) == 1
    assert sg_restored["IngressRules"][0]["Port"] == 22


def test_rollback_nonexistent_receipt_fails():
    dispatcher = AWSActionDispatcher()
    res = dispatcher.rollback("sha256:0000000000000000")
    assert res.execution_status == "FAILED"
    assert "not found" in res.details["error"]

