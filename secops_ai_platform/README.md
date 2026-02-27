# SecOps AI Platform (MVP)

A modular starter project that combines:
- AI-assisted log analysis
- Network/system hardening audit
- Phishing URL detection
- Mobile app security assessment (Android static checks)
- Automated security summary report generation

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r secops_ai_platform/requirements.txt
uvicorn secops_ai_platform.app.main:app --reload
```

## API endpoints

- `GET /health`
- `POST /analyze/logs`
- `POST /audit/hardening`
- `POST /detect/phishing`
- `POST /report/summary`
- `POST /assess/mobile`

## Test

```bash
pytest -q
```


## Mobile security endpoint payload

`POST /assess/mobile` accepts:

```json
{
  "manifest": {
    "application_id": "com.example.app",
    "permissions": ["android.permission.READ_SMS"],
    "debuggable": false,
    "exported_components": ["MainActivity"],
    "cleartext_traffic_permitted": false
  },
  "code_scan": {
    "hardcoded_secrets": 1,
    "weak_crypto_apis": 0
  }
}
```

The response includes `risk_score`, `highest_severity`, and remediation-focused findings for authorized assessments.
