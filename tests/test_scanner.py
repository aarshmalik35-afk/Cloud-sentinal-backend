from app.scanner import (
    check_s3_public_access,
    check_security_group_rules,
    scan_configuration,
)


def test_flags_disabled_s3_public_access_block():
    findings = check_s3_public_access({
        "name": "demo-risk",
        "block_public_access": False,
    })
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_does_not_flag_enabled_s3_public_access_block():
    assert check_s3_public_access({
        "name": "demo-safe",
        "block_public_access": True,
    }) == []


def test_flags_public_ssh_but_not_public_https():
    findings = check_security_group_rules({
        "name": "demo-sg",
        "inbound_rules": [
            {"protocol": "tcp", "port": 22, "cidrs": ["0.0.0.0/0"]},
            {"protocol": "tcp", "port": 443, "cidrs": ["0.0.0.0/0"]},
        ],
    })
    assert len(findings) == 1
    assert findings[0]["check"] == "Public SSH access"


def test_scan_sample_configuration_counts_findings():
    result = scan_configuration({
        "s3_buckets": [{"name": "demo", "block_public_access": False}],
        "security_groups": [],
        "iam_policies": [],
    })
    assert result["finding_count"] == 1
    assert result["severity_counts"]["HIGH"] == 1
