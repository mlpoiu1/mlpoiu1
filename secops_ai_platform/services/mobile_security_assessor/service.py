from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 25,
    "medium": 15,
    "low": 5,
    "info": 0,
}


@dataclass(frozen=True)
class CheckResult:
    title: str
    severity: str
    category: str
    recommendation: str

    def as_dict(self) -> dict[str, str]:
        return {
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "recommendation": self.recommendation,
        }


def assess_android_app(manifest: dict[str, Any], code_scan: dict[str, Any]) -> dict[str, Any]:
    """
    Build an ethical mobile app security report from static signals.

    Inputs are expected from authorized testing on owned apps or apps with written permission.
    """
    findings: list[CheckResult] = []

    permissions = set(manifest.get("permissions", []))
    if "android.permission.READ_SMS" in permissions:
        findings.append(
            CheckResult(
                title="Sensitive SMS permission requested",
                severity="high",
                category="permissions",
                recommendation="Request SMS permissions only if mandatory and explain business need.",
            )
        )

    if manifest.get("debuggable", False):
        findings.append(
            CheckResult(
                title="App is debuggable in production build",
                severity="critical",
                category="build-configuration",
                recommendation="Disable debug mode for release builds.",
            )
        )

    exported_components = manifest.get("exported_components", [])
    if exported_components:
        findings.append(
            CheckResult(
                title="Exported components discovered",
                severity="medium",
                category="attack-surface",
                recommendation="Review and restrict exported activities/services/receivers.",
            )
        )

    hardcoded_secrets = code_scan.get("hardcoded_secrets", 0)
    if hardcoded_secrets > 0:
        findings.append(
            CheckResult(
                title="Hardcoded secrets found in source",
                severity="high",
                category="secrets-management",
                recommendation="Move secrets to secure vaults and rotate compromised credentials.",
            )
        )

    weak_crypto_apis = code_scan.get("weak_crypto_apis", 0)
    if weak_crypto_apis > 0:
        findings.append(
            CheckResult(
                title="Weak cryptographic API usage",
                severity="high",
                category="cryptography",
                recommendation="Use modern crypto APIs and approved algorithms like AES-GCM.",
            )
        )

    cleartext_allowed = manifest.get("cleartext_traffic_permitted", False)
    if cleartext_allowed:
        findings.append(
            CheckResult(
                title="Cleartext network traffic permitted",
                severity="medium",
                category="network-security",
                recommendation="Set network security config to block cleartext traffic.",
            )
        )

    finding_dicts = [item.as_dict() for item in findings]
    risk_score = min(sum(SEVERITY_WEIGHTS[item["severity"]] for item in finding_dicts), 100)
    top_severity = _highest_severity(finding_dicts)

    return {
        "project": manifest.get("application_id", "unknown"),
        "authorized_testing_only": True,
        "finding_count": len(finding_dicts),
        "risk_score": risk_score,
        "highest_severity": top_severity,
        "findings": finding_dicts,
    }


def _highest_severity(findings: list[dict[str, str]]) -> str:
    ordered = ["critical", "high", "medium", "low", "info"]
    severities = {item.get("severity", "info") for item in findings}
    for severity in ordered:
        if severity in severities:
            return severity
    return "info"
