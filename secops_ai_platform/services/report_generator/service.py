
def build_summary_report(findings: list[dict]) -> dict:
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    sorted_findings = sorted(findings, key=lambda item: severity_order.get(item.get("severity", "low"), 1), reverse=True)

    return {
        "total_findings": len(findings),
        "highest_severity": sorted_findings[0]["severity"] if sorted_findings else "none",
        "top_findings": sorted_findings[:5],
        "next_actions": [
            "Investigate critical and high findings immediately",
            "Apply hardening recommendations",
            "Re-run scans after remediation",
        ],
    }
