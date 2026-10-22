
from app.scanner import scan_configuration

def test_scan_returns_posture_and_findings():
    result = scan_configuration({
        "s3_buckets": [{
            "name": "public-demo",
            "block_public_access": {},
            "public": True,
            "encryption_enabled": False,
            "versioning_enabled": False,
            "logging_enabled": False,
        }],
        "security_groups": [{"id": "sg-1", "ingress": [{"port": 22, "source": "0.0.0.0/0"}]}],
        "iam_policies": [{"name": "wide-policy", "statements": [{"action": "*", "resource": "*"}]}],
        "account_settings": {"cloudtrail_enabled": False, "security_monitoring_alarm_configured": False},
    })
    assert result["scan_mode"] == "simulated_configuration"
    assert 0 <= result["posture_score"] <= 100
    assert result["summary"]["total_findings"] >= 7
    assert any(f["rule_id"] == "EC2_SSH_PUBLIC" for f in result["findings"])
    assert all(f["remediation"] for f in result["findings"])

def test_safe_configuration_has_no_findings():
    result = scan_configuration({
        "s3_buckets": [{
            "name": "safe-demo",
            "block_public_access": {
                "block_public_acls": True,
                "ignore_public_acls": True,
                "block_public_policy": True,
                "restrict_public_buckets": True,
            },
            "public": False,
            "encryption_enabled": True,
            "versioning_enabled": True,
            "logging_enabled": True,
        }],
        "security_groups": [],
        "iam_policies": [],
        "account_settings": {"cloudtrail_enabled": True, "security_monitoring_alarm_configured": True},
    })
    assert result["summary"]["total_findings"] == 0
    assert result["posture_score"] == 100
    assert result["risk_level"] == "Low"
