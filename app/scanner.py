from __future__ import annotations

from typing import Any


def check_s3_public_access(bucket: dict[str, Any]) -> list[dict[str, Any]]:
    """Flag missing/disabled public-access block in simplified demo input.

    This is a heuristic for the sample schema, not a complete assessment of
    whether an actual AWS bucket is publicly accessible.
    """
    if "name" not in bucket:
        raise ValueError("Each S3 bucket entry must contain 'name'.")

    if bucket.get("block_public_access") is False:
        return [{
            "resource": bucket["name"],
            "service": "S3",
            "check": "S3 public-access protection",
            "severity": "HIGH",
            "status": "FAIL",
            "evidence": "The sample configuration marks public-access blocking as disabled.",
            "recommendation": "Review bucket policy and access requirements; enable suitable S3 Block Public Access settings.",
        }]

    if "block_public_access" not in bucket:
        return [{
            "resource": bucket["name"],
            "service": "S3",
            "check": "S3 public-access protection",
            "severity": "MEDIUM",
            "status": "REVIEW",
            "evidence": "The sample configuration does not provide public-access-block status.",
            "recommendation": "Inspect all four S3 Block Public Access settings and the bucket/access-point policies.",
        }]

    return []


def check_security_group_rules(group: dict[str, Any]) -> list[dict[str, Any]]:
    """Flag risky example ingress rules in supplied configuration data."""
    if "name" not in group:
        raise ValueError("Each security group entry must contain 'name'.")

    findings: list[dict[str, Any]] = []
    for rule in group.get("inbound_rules", []):
        if not isinstance(rule, dict):
            raise ValueError("Each inbound rule must be an object.")

        port = rule.get("port")
        protocol = str(rule.get("protocol", "tcp")).lower()
        cidrs = rule.get("cidrs", [])

        if not isinstance(cidrs, list):
            raise ValueError("Rule 'cidrs' must be a list.")

        public_cidr = any(cidr in ("0.0.0.0/0", "::/0") for cidr in cidrs)
        if public_cidr and protocol in ("tcp", "6") and port in (22, 3389):
            service_name = "SSH" if port == 22 else "RDP"
            findings.append({
                "resource": group["name"],
                "service": "EC2",
                "check": f"Public {service_name} access",
                "severity": "HIGH",
                "status": "FAIL",
                "evidence": f"Inbound TCP port {port} permits traffic from a public CIDR.",
                "recommendation": f"Restrict {service_name} to approved source ranges or use a managed access solution.",
            })
    return findings


def check_iam_policies(policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flag simplified policy examples with wildcard action and resource.

    This intentionally handles a limited normalized schema, not every IAM policy
    grammar or effective-permission scenario.
    """
    findings: list[dict[str, Any]] = []
    for policy in policies:
        name = policy.get("name", "unnamed-policy")
        actions = policy.get("actions", [])
        resources = policy.get("resources", [])
        if not isinstance(actions, list) or not isinstance(resources, list):
            raise ValueError("IAM policy 'actions' and 'resources' must be lists.")

        if "*" in actions and "*" in resources:
            findings.append({
                "resource": name,
                "service": "IAM",
                "check": "Broad IAM permissions",
                "severity": "HIGH",
                "status": "REVIEW",
                "evidence": "The normalized demo policy uses wildcard actions and resources.",
                "recommendation": "Review effective permissions and replace broad grants with least-privilege actions and resources.",
            })
    return findings


def scan_configuration(configuration: dict[str, Any]) -> dict[str, Any]:
    """Scan a normalized, AWS-style configuration object."""
    if not isinstance(configuration, dict):
        raise ValueError("Top-level configuration must be an object.")

    s3_buckets = configuration.get("s3_buckets", [])
    security_groups = configuration.get("security_groups", [])
    iam_policies = configuration.get("iam_policies", [])

    for key, value in (
        ("s3_buckets", s3_buckets),
        ("security_groups", security_groups),
        ("iam_policies", iam_policies),
    ):
        if not isinstance(value, list):
            raise ValueError(f"'{key}' must be a list.")

    findings: list[dict[str, Any]] = []
    for bucket in s3_buckets:
        if not isinstance(bucket, dict):
            raise ValueError("Each S3 bucket entry must be an object.")
        findings.extend(check_s3_public_access(bucket))

    for group in security_groups:
        if not isinstance(group, dict):
            raise ValueError("Each security group entry must be an object.")
        findings.extend(check_security_group_rules(group))

    findings.extend(check_iam_policies(iam_policies))

    counts = {
        "HIGH": sum(item["severity"] == "HIGH" for item in findings),
        "MEDIUM": sum(item["severity"] == "MEDIUM" for item in findings),
        "LOW": sum(item["severity"] == "LOW" for item in findings),
    }
    return {
        "mode": "sample_configuration",
        "resources_scanned": len(s3_buckets) + len(security_groups) + len(iam_policies),
        "finding_count": len(findings),
        "severity_counts": counts,
        "findings": findings,
        "disclaimer": (
            "Results are based on supplied normalized demo data. "
            "This backend does not connect to AWS and does not prove exploitability."
        ),
    }
