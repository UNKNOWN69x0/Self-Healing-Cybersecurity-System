import json
import os
import subprocess

_config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json")

_BYTES_PER_MB = 1_000_000


def _load_config():
    try:
        with open(_config_path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _check_firewall_disabled():
    """Return True if any Windows Firewall profile is reported as OFF."""
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            capture_output=True, text=True, timeout=5
        )
        return "OFF" in result.stdout.upper()
    except Exception:
        return False


def analyze(data):
    config = _load_config()
    thresholds = config.get("thresholds", {})
    cpu_threshold = thresholds.get("cpu_percent", 90)
    memory_threshold = thresholds.get("memory_percent", 95)
    failed_login_limit = thresholds.get("failed_login_limit", 5)
    bandwidth_alert_mbps = thresholds.get("bandwidth_alert_mbps", 10)
    port_scan_threshold = thresholds.get("port_scan_threshold", 5)
    suspicious_ports = set(config.get("suspicious_ports", [4444, 5555, 6666, 1337, 31337, 8443, 9001]))

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

    # Track connections per IP to detect port scans
    ip_ports = {}
    for conn in network:
        ip = conn.get("ip")
        port = conn.get("port")
        if ip:
            threats.append({
                "type": "SUSPICIOUS_IP",
                "severity": "MEDIUM",
                "ip": ip
            })
            if port is not None:
                ip_ports.setdefault(ip, set()).add(port)
                if port in suspicious_ports:
                    threats.append({
                        "type": "SUSPICIOUS_PORT",
                        "severity": "HIGH",
                        "ip": ip,
                        "port": port,
                        "detail": f"Connection on known malicious port {port} from {ip}",
                    })

    for ip, ports in ip_ports.items():
        if len(ports) >= port_scan_threshold:
            threats.append({
                "type": "PORT_SCAN",
                "severity": "HIGH",
                "ip": ip,
                "port_count": len(ports),
                "detail": f"Port scan detected from {ip} across {len(ports)} ports",
            })

    failed_logins = data.get("failed_logins", 0)
    if failed_logins > failed_login_limit:
        threats.append({"type": "BRUTE_FORCE", "severity": "CRITICAL"})

    # Data exfiltration: outbound bandwidth > threshold (MB/s)
    traffic = data.get("traffic", {})
    bytes_sent = traffic.get("bytes_sent_per_sec", 0)
    if bytes_sent > bandwidth_alert_mbps * _BYTES_PER_MB:
        threats.append({
            "type": "DATA_EXFILTRATION",
            "severity": "CRITICAL",
            "bytes_sent_per_sec": bytes_sent,
            "detail": f"Outbound bandwidth {bytes_sent / _BYTES_PER_MB:.1f} MB/s exceeds threshold",
        })

    # Firewall disabled check
    if _check_firewall_disabled():
        threats.append({
            "type": "FIREWALL_DISABLED",
            "severity": "CRITICAL",
            "detail": "Windows Firewall is disabled on one or more profiles",
        })

    return threats
