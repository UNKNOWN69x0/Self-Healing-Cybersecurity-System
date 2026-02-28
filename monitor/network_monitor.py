import json
import os
import psutil

_config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json")

_DEFAULT_SAFE_IPS = ["127.0.0.1", "::1"]
_DEFAULT_TRUSTED_PREFIXES = (
    "13.", "15.", "20.", "40.", "52.",     # Microsoft / Azure
    "142.250.", "142.251.",               # Google
    "104.16.", "104.17.", "104.18.",      # Cloudflare
)


def _load_config():
    try:
        with open(_config_path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def is_private_ip(ip):
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("172.")
    )


def is_trusted_ip(ip, trusted_prefixes):
    return ip.startswith(tuple(trusted_prefixes))


def get_suspicious_connections():
    config = _load_config()
    safe_ips = set(config.get("safe_ips", _DEFAULT_SAFE_IPS))
    trusted_prefixes = config.get("trusted_ip_prefixes", _DEFAULT_TRUSTED_PREFIXES)

    suspicious = []

    for conn in psutil.net_connections(kind="inet"):
        if not conn.raddr:
            continue

        ip = conn.raddr.ip

        if ip in safe_ips:
            continue

        if is_private_ip(ip):
            continue

        if is_trusted_ip(ip, trusted_prefixes):
            continue

        suspicious.append({
            "ip": ip,
            "pid": conn.pid
        })

    return suspicious
