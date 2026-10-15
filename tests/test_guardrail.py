"""
Unit tests for Aegis-2B Reusable Cloud Guardrail.
"""

from patterns.guardrails import (
    DeciderCloudGuardrail,
    DeciderState,
    GuardrailAction,
    BlastRadius,
)


def test_benign_action_permits_auto_remediation():
    guardrail = DeciderCloudGuardrail(risk_threshold=0.85)
    state = DeciderState(
        alert_source="aws.guardduty",
        alert_severity="HIGH",
        target_arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-test",
        proposed_tool="revoke_security_group_ingress",
        tool_parameters={"GroupId": "sg-test", "Port": 22},
        blast_radius=BlastRadius.ISOLATED,
        is_destructive_action=False,
    )

    result = guardrail.evaluate(state)
    assert result.action == GuardrailAction.PERMIT_AUTO_REMEDIATION
    assert result.confidence >= 0.85
    assert result.latency_ms < 150.0


def test_destructive_action_enforces_break_glass():
    guardrail = DeciderCloudGuardrail(risk_threshold=0.85)
    state = DeciderState(
        alert_source="aws.guardduty",
        alert_severity="CRITICAL",
        target_arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-core",
        proposed_tool="delete_security_group",
        tool_parameters={"GroupId": "sg-core"},
        blast_radius=BlastRadius.VPC_WIDE,
        is_destructive_action=True,
    )

    result = guardrail.evaluate(state)
    assert result.action == GuardrailAction.ENFORCE_BREAK_GLASS
    assert result.confidence >= 0.85


def test_evaluator_error_fails_closed():
    # An evaluator that throws an exception must fail closed to BREAK_GLASS
    def broken_evaluator(state, question):
        raise RuntimeError("Inference timeout")

    guardrail = DeciderCloudGuardrail(inference_engine=broken_evaluator)
    state = DeciderState(
        alert_source="aws.guardduty",
        alert_severity="LOW",
        target_arn="arn:aws:ec2:us-east-1:111122223333:instance/i-test",
        proposed_tool="describe_instances",
        tool_parameters={},
    )

    result = guardrail.evaluate(state)
    assert result.action == GuardrailAction.ENFORCE_BREAK_GLASS
    assert "FALLBACK_ON_ERROR" in result.reasoning_code


def test_vpc_wide_blast_radius_enforces_break_glass():
    guardrail = DeciderCloudGuardrail(risk_threshold=0.85)
    state = DeciderState(
        alert_source="aws.securityhub",
        alert_severity="HIGH",
        target_arn="arn:aws:ec2:us-east-1:111122223333:route-table/rtb-core",
        proposed_tool="replace_route",
        tool_parameters={"RouteTableId": "rtb-core", "DestinationCidrBlock": "0.0.0.0/0"},
        blast_radius=BlastRadius.VPC_WIDE,
        is_destructive_action=False,
    )

    result = guardrail.evaluate(state)
    assert result.action == GuardrailAction.ENFORCE_BREAK_GLASS
    assert result.confidence >= 0.85


def test_all_scenario_fixtures_valid_json():
    import json
    from pathlib import Path
    fixtures_dir = Path(__file__).parent.parent / "scenarios" / "fixtures"
    fixture_files = list(fixtures_dir.glob("*.json"))
    assert len(fixture_files) >= 3

    for fix_file in fixture_files:
        with open(fix_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert "Id" in data
            assert "Severity" in data
            assert data["AwsAccountId"] == "111122223333"  # Invariant 5: No real AWS account IDs


def test_low_confidence_fails_closed_to_break_glass():
    # If the model returns PERMIT but with confidence below risk_threshold, it must downgrade to BREAK_GLASS
    def low_confidence_engine(state, question):
        from patterns.guardrails.schemas import DeciderResult
        return DeciderResult(
            action=GuardrailAction.PERMIT_AUTO_REMEDIATION,
            confidence=0.65,  # Below 0.85 threshold!
            latency_ms=114.0,
            reasoning_code="AMBIGUOUS_ACTION",
        )

    guardrail = DeciderCloudGuardrail(risk_threshold=0.85, inference_engine=low_confidence_engine)
    state = DeciderState(
        alert_source="aws.guardduty",
        alert_severity="LOW",
        target_arn="arn:aws:ec2:us-east-1:111122223333:instance/i-test",
        proposed_tool="modify_instance_attribute",
        tool_parameters={},
    )

    result = guardrail.evaluate(state)
    assert result.action == GuardrailAction.ENFORCE_BREAK_GLASS
    assert "LOW_CONFIDENCE_GATED" in result.reasoning_code


