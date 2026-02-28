import json
import os
import psutil

_config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json")

CRITICAL_PIDS = {0, 4}


def _load_config():
    try:
        with open(_config_path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def get_suspicious_processes():
    config = _load_config()
    blacklist = config.get("process_blacklist", ["xmrig", "miner", "hacktool"])

    suspicious = []

    for proc in psutil.process_iter(["pid", "name", "cpu_percent"]):
        try:
            pid = proc.info["pid"]
            name = (proc.info["name"] or "").lower()
            cpu = proc.info["cpu_percent"] or 0

            if pid in CRITICAL_PIDS:
                continue

            if any(bad in name for bad in blacklist):
                suspicious.append(proc.info)
            elif cpu > 80:
                suspicious.append(proc.info)

        except Exception:
            continue

    return suspicious
