from secops_ai_platform.services.hardening_auditor.service import run_hardening_audit
from secops_ai_platform.services.log_analyzer.service import analyze_logs
from secops_ai_platform.services.phishing_detector.service import score_url
from secops_ai_platform.services.report_generator.service import build_summary_report


def test_log_analyzer_detects_suspicious_lines() -> None:
    result = analyze_logs(["User login failed", "Service started normally"])
    assert result["finding_count"] == 1


def test_hardening_audit_score() -> None:
    result = run_hardening_audit({"firewall_enabled": True, "ssh_root_login_disabled": True})
    assert result["score"] == 50


def test_phishing_score_flags_risky_url() -> None:
    result = score_url("http://192.168.1.9/secure-login-update")
    assert result["risk_score"] >= 60


def test_report_generator_orders_findings() -> None:
    result = build_summary_report([
        {"title": "A", "severity": "medium"},
        {"title": "B", "severity": "high"},
    ])
    assert result["highest_severity"] == "high"
