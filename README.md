## Hi there 👋

### 🚀 New Project Started: SecOps AI Platform

I have started building a modular cybersecurity project that combines:

- Log Analysis (AI + Rule-based)
- Hardening Audit for system/network controls
- Phishing URL Detection
- Automated Security Report Generation

Project source is in:

- `secops_ai_platform/README.md`
- `secops_ai_platform/app/main.py`
- `secops_ai_platform/services/`

### Quick run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r secops_ai_platform/requirements.txt
uvicorn secops_ai_platform.app.main:app --reload
```

### Run tests

```bash
pytest -q
```
