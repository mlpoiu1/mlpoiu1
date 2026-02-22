
def run_hardening_audit(config: dict) -> dict:
    checks = {
        "ssh_root_login_disabled": config.get("ssh_root_login_disabled", False),
        "firewall_enabled": config.get("firewall_enabled", False),
        "auto_updates_enabled": config.get("auto_updates_enabled", False),
        "strong_password_policy": config.get("strong_password_policy", False),
    }
    failed = [name for name, passed in checks.items() if not passed]
    score = int(((len(checks) - len(failed)) / len(checks)) * 100)

    return {
        "score": score,
        "passed": [name for name, passed in checks.items() if passed],
        "failed": failed,
    }
