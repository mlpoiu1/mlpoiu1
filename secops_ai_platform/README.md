# SecOps AI Platform (MVP)

A modular starter project that combines:
- AI-assisted log analysis
- Network/system hardening audit
- Phishing URL detection
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

## Test

```bash
pytest -q
```
