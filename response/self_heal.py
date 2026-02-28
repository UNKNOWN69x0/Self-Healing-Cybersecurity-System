import subprocess
from utils.logger import log_event

CRITICAL_PIDS = {0, 4}
SAFE_IPS = {"127.0.0.1", "::1"}

# Memory of already blocked IPs (runtime)
BLOCKED_IPS = set()


def heal(threat):
    t = threat.get("type")

    # -------- Process handling --------
    if t == "MALICIOUS_PROCESS":
        pid = threat.get("pid")

        if pid in CRITICAL_PIDS or pid is None:
            return

        subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
        log_event(f"Terminated process PID {pid}")

    # -------- Network handling --------
    elif t == "SUSPICIOUS_IP":
        ip = threat.get("ip")

        if ip is None or ip in SAFE_IPS:
            return

        # Prevent repeated blocking
        if ip in BLOCKED_IPS:
            return

        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=SHCS_Block_{ip}",
                "dir=in", "action=block", f"remoteip={ip}",
            ],
            capture_output=True,
        )

        BLOCKED_IPS.add(ip)
        log_event(f"Blocked IP {ip}")

    # -------- CPU handling --------
    elif t == "HIGH_CPU":
        log_event("WARNING: High CPU usage detected")

    # -------- Memory handling --------
    elif t == "HIGH_MEMORY":
        log_event("WARNING: High memory usage detected")

    # -------- Brute force handling --------
    elif t == "BRUTE_FORCE":
        log_event("CRITICAL: Brute force attack detected")
