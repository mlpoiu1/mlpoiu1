SUSPICIOUS_KEYWORDS = ["failed", "unauthorized", "denied", "bruteforce", "malware"]


def analyze_logs(entries: list[str]) -> dict:
    findings = []
    for line in entries:
        lowered = line.lower()
        hits = [word for word in SUSPICIOUS_KEYWORDS if word in lowered]
        if hits:
            findings.append({"entry": line, "signals": hits, "severity": "high" if len(hits) > 1 else "medium"})

    return {
        "total_entries": len(entries),
        "finding_count": len(findings),
        "findings": findings,
    }
