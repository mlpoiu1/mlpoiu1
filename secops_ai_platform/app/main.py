from fastapi import FastAPI

from secops_ai_platform.services.hardening_auditor.service import run_hardening_audit
from secops_ai_platform.services.log_analyzer.service import analyze_logs
from secops_ai_platform.services.mobile_security_assessor.service import assess_android_app
from secops_ai_platform.services.phishing_detector.service import score_url
from secops_ai_platform.services.report_generator.service import build_summary_report

app = FastAPI(title="SecOps AI Platform", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze/logs")
def analyze(payload: dict) -> dict:
    entries = payload.get("entries", [])
    return analyze_logs(entries)


@app.post("/audit/hardening")
def audit(payload: dict) -> dict:
    config = payload.get("config", {})
    return run_hardening_audit(config)


@app.post("/detect/phishing")
def detect(payload: dict) -> dict:
    url = payload.get("url", "")
    return score_url(url)


@app.post("/report/summary")
def report(payload: dict) -> dict:
    findings = payload.get("findings", [])
    return build_summary_report(findings)


@app.post("/assess/mobile")
def assess_mobile(payload: dict) -> dict:
    manifest = payload.get("manifest", {})
    code_scan = payload.get("code_scan", {})
    return assess_android_app(manifest, code_scan)
