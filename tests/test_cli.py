"""
Unit tests for Aegis-2B CLI and Custom Evaluation APIs.
"""

import json
import pytest
from aegis.cli import run_protect_command
from aegis.server import AegisAPIHandler, dispatcher_instance


def test_protect_command_json_output(capsys):
    # Test --json flag on benign tool call
    run_protect_command(
        tool="revoke_security_group_ingress",
        arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789",
        params_str='{"GroupId":"sg-0123456789","Port":22}',
        blast_str="isolated",
        is_destructive=False,
        interactive=False,
        as_json=True,
        enforce=False,
    )
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["status"] == "PERMITTED"
    assert data["permitted"] is True
    assert data["tool"] == "revoke_security_group_ingress"
    assert data["latency_ms"] < 200.0


def test_protect_command_enforce_exits_on_destructive():
    # Destructive action with --enforce must exit with code 1
    with pytest.raises(SystemExit) as excinfo:
        run_protect_command(
            tool="delete_security_group",
            arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-core",
            params_str='{"GroupId":"sg-core"}',
            blast_str="vpc_wide",
            is_destructive=True,
            interactive=False,
            as_json=True,
            enforce=True,
        )
    assert excinfo.value.code == 1


def test_protect_command_enforce_exits_0_on_permitted():
    # Safe action with --enforce must exit with code 0
    with pytest.raises(SystemExit) as excinfo:
        run_protect_command(
            tool="revoke_security_group_ingress",
            arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-test",
            params_str='{"Port":22}',
            blast_str="isolated",
            is_destructive=False,
            interactive=False,
            as_json=True,
            enforce=True,
        )
    assert excinfo.value.code == 0


def test_server_custom_payload_evaluation():
    # Test _handle_custom_evaluate in server
    handler = object.__new__(AegisAPIHandler)
    payload = {
        "tool": "delete_security_group",
        "params": {"GroupId": "sg-core-vpc-01"},
        "is_destructive": True,
        "blast_radius": "vpc_wide",
        "alert_title": "Injection Test",
        "alert_desc": "Operator submitted destructive delete."
    }
    result = handler._handle_custom_evaluate(payload)
    assert result["scenario"] == "custom"
    assert result["decision"] == "ENFORCE_BREAK_GLASS"
    assert result["is_destructive"] is True
    assert "raw_scores" in result
    assert "receipt" in result

    # Test Break-Glass override on the custom gated action
    bg_res = handler._handle_break_glass("custom", "849201", "sec-ops-admin")
    assert bg_res["is_authorized"] is True
    assert bg_res["execution_status"] == "OVERRIDDEN_BREAK_GLASS"


def test_server_safe_private_ingress_preset_executes():
    handler = object.__new__(AegisAPIHandler)
    payload = {
        "tool": "authorize_security_group_ingress",
        "params": {"GroupId": "sg-0123456789", "Port": 443, "CidrIp": "10.0.1.0/24"},
        "is_destructive": False,
        "blast_radius": "isolated",
        "alert_desc": "Safe private HTTPS ingress",
    }
    result = handler._handle_custom_evaluate(payload)
    assert result["decision"] == "PERMIT_AUTO_REMEDIATION"
    assert result["execution_status"] == "EXECUTED"
    assert result["recommended_tier"] == "tier_0_rule"
    assert result["estimated_tokens_saved"] > 0
    assert "--- a/infra/security_groups.tf" in result["terraform_diff"]


def test_remediate_cli_json_output(capsys):
    from aegis.remediate import run_remediate_cli

    ok = run_remediate_cli(
        input_path="scenarios/fixtures/benign_ssh_finding.json",
        as_json=True,
    )
    assert ok is True
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["total_findings"] >= 1
    assert data["total_tokens_saved"] >= 1000
    first = data["items"][0]
    assert first["router_output"]["tier"] == "tier_0_rule"
    assert "--- a/infra/security_groups.tf" in first["terraform_diff"]


