import re

SUSPICIOUS_PATTERNS = [
    r"\\d{1,3}(?:\\.\\d{1,3}){3}",
    r"login",
    r"verify",
    r"secure",
    r"update",
    r"@",
]


def score_url(url: str) -> dict:
    lowered = url.lower()
    matches = sum(bool(re.search(pattern, lowered)) for pattern in SUSPICIOUS_PATTERNS)
    score = min(matches * 20, 100)

    return {
        "url": url,
        "risk_score": score,
        "label": "phishing-suspected" if score >= 60 else "low-risk",
    }
