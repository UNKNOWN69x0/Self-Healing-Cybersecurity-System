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

    # -------- ML anomaly handling --------
    elif t == "ML_ANOMALY":
        detail = threat.get("detail", "")
        log_event(f"WARNING: ML anomaly detected — {detail}")

    # -------- Port scan handling --------
    elif t == "PORT_SCAN":
        ip = threat.get("ip")
        if ip and ip not in SAFE_IPS and ip not in BLOCKED_IPS:
            os.system(
                f'netsh advfirewall firewall add rule name="SHCS_Block_{ip}" '
                f'dir=in action=block remoteip={ip}'
            )
            BLOCKED_IPS.add(ip)
            log_event(f"Blocked port-scanning IP {ip}")

    # -------- Data exfiltration handling --------
    elif t == "DATA_EXFILTRATION":
        detail = threat.get("detail", "")
        log_event(f"CRITICAL: Data exfiltration detected — {detail}")

    # -------- Suspicious port handling --------
    elif t == "SUSPICIOUS_PORT":
        ip = threat.get("ip")
        port = threat.get("port")
        if ip and ip not in SAFE_IPS and ip not in BLOCKED_IPS:
            os.system(
                f'netsh advfirewall firewall add rule name="SHCS_Block_{ip}" '
                f'dir=in action=block remoteip={ip}'
            )
            BLOCKED_IPS.add(ip)
        log_event(f"Blocked connection on suspicious port {port} from {ip}")

    # -------- DNS tamper handling --------
    elif t == "DNS_TAMPER":
        log_event("CRITICAL: DNS tampering detected — resetting DNS to 8.8.8.8 / 1.1.1.1")
        os.system('netsh interface ip set dns "Local Area Connection" static 8.8.8.8')
        os.system('netsh interface ip add dns "Local Area Connection" 1.1.1.1 index=2')

    # -------- Firewall disabled handling --------
    elif t == "FIREWALL_DISABLED":
        log_event("CRITICAL: Windows Firewall is disabled — re-enabling all profiles")
        os.system("netsh advfirewall set allprofiles state on")
