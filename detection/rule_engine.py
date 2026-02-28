import json
import os

_config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json")


def _load_config():
    try:
        with open(_config_path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def analyze(data):
    config = _load_config()
    thresholds = config.get("thresholds", {})
    cpu_threshold = thresholds.get("cpu_percent", 90)
    memory_threshold = thresholds.get("memory_percent", 95)
    failed_login_limit = thresholds.get("failed_login_limit", 5)

    threats = []

    system = data.get("system", {})
    if system.get("cpu", 0) > cpu_threshold:
        threats.append({"type": "HIGH_CPU", "severity": "HIGH"})

    if system.get("memory", 0) > memory_threshold:
        threats.append({"type": "HIGH_MEMORY", "severity": "HIGH"})

    processes = data.get("processes", [])
    for proc in processes:
        threats.append({
            "type": "MALICIOUS_PROCESS",
            "severity": "CRITICAL",
            "pid": proc.get("pid")
        })

    network = data.get("network", [])
    for conn in network:
        threats.append({
            "type": "SUSPICIOUS_IP",
            "severity": "MEDIUM",
            "ip": conn.get("ip")
        })

    failed_logins = data.get("failed_logins", 0)
    if failed_logins > failed_login_limit:
        threats.append({"type": "BRUTE_FORCE", "severity": "CRITICAL"})

    return threats
