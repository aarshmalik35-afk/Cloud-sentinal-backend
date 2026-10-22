
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import hashlib
import json

SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 7, "low": 3, "info": 0}

RULES = {
    "S3_PUBLIC_ACCESS": {
        "title": "S3 public access is not fully blocked",
        "severity": "critical",
        "category": "Storage",
        "why": "Publicly accessible buckets can expose sensitive files to anyone on the internet.",
        "remediation": "Enable all S3 Block Public Access settings at the account and bucket levels. Review bucket policies and ACLs, then verify that public access is intentional if any exception remains.",
    },
    "S3_ENCRYPTION_DISABLED": {
        "title": "S3 default encryption is disabled",
        "severity": "high",
        "category": "Storage",
        "why": "Objects may be stored without server-side encryption configured as the bucket default.",
        "remediation": "Enable default server-side encryption using SSE-S3 or SSE-KMS, and review existing objects separately because default encryption does not retroactively encrypt all historical objects.",
    },
    "S3_VERSIONING_DISABLED": {
        "title": "S3 bucket versioning is disabled",
        "severity": "medium",
        "category": "Resilience",
        "why": "Accidental overwrites or deletions may be harder to recover from without object versioning.",
        "remediation": "Enable versioning for buckets that need recovery protection and define lifecycle rules to manage storage costs.",
    },
    "S3_LOGGING_DISABLED": {
        "title": "S3 access logging is disabled",
        "severity": "medium",
        "category": "Logging",
        "why": "Without suitable access logging, investigating access patterns and incidents can be harder.",
        "remediation": "Enable an appropriate access-logging or audit-logging solution, restrict access to the log destination, and define retention requirements.",
    },
    "EC2_SSH_PUBLIC": {
        "title": "SSH is exposed to the internet",
        "severity": "high",
        "category": "Network",
        "why": "A security group allows SSH (TCP/22) from 0.0.0.0/0 or ::/0, increasing brute-force and exploitation risk.",
        "remediation": "Restrict SSH to trusted IP ranges or use a managed access path such as AWS Systems Manager Session Manager. Avoid broad internet exposure.",
    },
    "EC2_RDP_PUBLIC": {
        "title": "RDP is exposed to the internet",
        "severity": "critical",
        "category": "Network",
        "why": "Public RDP (TCP/3389) exposure is a common target for credential attacks and exploitation.",
        "remediation": "Remove 0.0.0.0/0 and ::/0 from RDP rules. Restrict access to trusted networks or use a managed remote-access solution.",
    },
    "IAM_WILDCARD_ACTION": {
        "title": "IAM policy grants wildcard actions",
        "severity": "high",
        "category": "Identity",
        "why": "An Action of '*' can grant broader permissions than a workload or user needs.",
        "remediation": "Replace wildcard actions with the smallest set of required actions and resources. Review the policy with IAM Access Analyzer or equivalent policy review tooling.",
    },
    "IAM_WILDCARD_RESOURCE": {
        "title": "IAM policy grants access to all resources",
        "severity": "medium",
        "category": "Identity",
        "why": "A Resource of '*' can expand the impact of a compromised identity.",
        "remediation": "Scope Resource values to specific ARNs wherever the service supports resource-level permissions. Document any required exceptions.",
    },
    "CLOUDTRAIL_DISABLED": {
        "title": "CloudTrail management event logging is disabled",
        "severity": "high",
        "category": "Logging",
        "why": "Insufficient audit logging can reduce visibility into account activity and slow incident investigation.",
        "remediation": "Enable a multi-region CloudTrail trail with management events, protect log files, and configure appropriate retention and alerting.",
    },
    "CLOUDWATCH_ALARM_MISSING": {
        "title": "No security monitoring alarm is configured",
        "severity": "medium",
        "category": "Monitoring",
        "why": "Missing alarms can delay detection of suspicious activity or configuration changes.",
        "remediation": "Configure relevant CloudWatch metrics, alarms, and notifications for your environment's risk profile.",
    },
}

def _is_world_open(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip() in {"0.0.0.0/0", "::/0", "*"}
    if isinstance(value, list):
        return any(_is_world_open(v) for v in value)
    return False

def _finding(rule_id: str, resource_id: str, resource_type: str, evidence: str) -> dict[str, Any]:
    rule = RULES[rule_id]
    return {
        "id": hashlib.sha1(f"{rule_id}:{resource_id}".encode()).hexdigest()[:12],
        "rule_id": rule_id,
        "title": rule["title"],
        "severity": rule["severity"],
        "category": rule["category"],
        "resource_id": str(resource_id),
        "resource_type": resource_type,
        "evidence": evidence,
        "why_it_matters": rule["why"],
        "remediation": rule["remediation"],
        "status": "open",
    }

def scan_configuration(configuration: dict[str, Any]) -> dict[str, Any]:
    """Scan simulated AWS-style configuration data. This does not connect to AWS."""
    findings: list[dict[str, Any]] = []

    for bucket in configuration.get("s3_buckets", []):
        name = bucket.get("name", "unknown-bucket")
        public_block = bucket.get("block_public_access", {})
        blocked = all(public_block.get(k, False) is True for k in (
            "block_public_acls", "ignore_public_acls",
            "block_public_policy", "restrict_public_buckets"
        ))
        if not blocked or bucket.get("public", False) is True:
            findings.append(_finding("S3_PUBLIC_ACCESS", name, "S3 bucket",
                f"block_public_access={json.dumps(public_block, sort_keys=True)}; public={bucket.get('public', False)}"))
        if not bucket.get("encryption_enabled", False):
            findings.append(_finding("S3_ENCRYPTION_DISABLED", name, "S3 bucket", "encryption_enabled=false"))
        if not bucket.get("versioning_enabled", False):
            findings.append(_finding("S3_VERSIONING_DISABLED", name, "S3 bucket", "versioning_enabled=false"))
        if not bucket.get("logging_enabled", False):
            findings.append(_finding("S3_LOGGING_DISABLED", name, "S3 bucket", "logging_enabled=false"))

    for group in configuration.get("security_groups", []):
        group_id = group.get("id", "unknown-security-group")
        for rule in group.get("ingress", []):
            port = rule.get("port")
            source = rule.get("source", "")
            if not _is_world_open(source):
                continue
            if port == 22:
                findings.append(_finding("EC2_SSH_PUBLIC", group_id, "Security group", f"TCP/22 allowed from {source}"))
            elif port == 3389:
                findings.append(_finding("EC2_RDP_PUBLIC", group_id, "Security group", f"TCP/3389 allowed from {source}"))

    for policy in configuration.get("iam_policies", []):
        policy_id = policy.get("name", "unknown-policy")
        for statement in policy.get("statements", []):
            actions = statement.get("action", [])
            resources = statement.get("resource", [])
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            if "*" in actions:
                findings.append(_finding("IAM_WILDCARD_ACTION", policy_id, "IAM policy", f"Action={actions}"))
            if "*" in resources:
                findings.append(_finding("IAM_WILDCARD_RESOURCE", policy_id, "IAM policy", f"Resource={resources}"))

    account = configuration.get("account_settings", {})
    if not account.get("cloudtrail_enabled", False):
        findings.append(_finding("CLOUDTRAIL_DISABLED", "account", "Account setting", "cloudtrail_enabled=false"))
    if not account.get("security_monitoring_alarm_configured", False):
        findings.append(_finding("CLOUDWATCH_ALARM_MISSING", "account", "Account setting", "security_monitoring_alarm_configured=false"))

    # Deduplicate identical rule/resource pairs.
    unique = {(f["rule_id"], f["resource_id"]): f for f in findings}
    findings = sorted(unique.values(), key=lambda f: (
        ["critical", "high", "medium", "low", "info"].index(f["severity"]), f["title"], f["resource_id"]
    ))

    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_WEIGHTS}
    # Transparent heuristic: each finding subtracts a fixed severity weight, capped at 100.
    deductions = sum(SEVERITY_WEIGHTS[f["severity"]] for f in findings)
    score = max(0, 100 - min(100, deductions))
    critical_count = counts["critical"]
    high_count = counts["high"]
    risk_level = "Critical" if critical_count else "High" if high_count else "Moderate" if counts["medium"] else "Low"

    return {
        "scan_id": hashlib.sha256(f"{datetime.now(timezone.utc).isoformat()}:{json.dumps(configuration, sort_keys=True)}".encode()).hexdigest()[:16],
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "scan_mode": "simulated_configuration",
        "scope": "Provided AWS-style configuration data; no live AWS connection",
        "posture_score": score,
        "risk_level": risk_level,
        "summary": {
            "total_findings": len(findings),
            "by_severity": counts,
            "resources_reviewed": sum(len(configuration.get(k, [])) for k in ("s3_buckets", "security_groups", "iam_policies")) + 1,
        },
        "scoring_method": {
            "description": "Heuristic score: starts at 100 and subtracts fixed points per finding, capped at 100 total deductions.",
            "deductions": SEVERITY_WEIGHTS,
        },
        "findings": findings,
    }
