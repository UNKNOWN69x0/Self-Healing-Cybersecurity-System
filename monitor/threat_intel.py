# Known malicious / high-risk ports (common RAT, C2, and malware ports)
KNOWN_MALICIOUS_PORTS = {4444, 5555, 6666, 1337, 31337, 8443, 9001}

# Ports that should not have unexpected inbound connections
SUSPICIOUS_PORTS = {22, 23, 3389, 445, 135, 139}

# Known Tor exit node IP prefixes
TOR_EXIT_NODE_PREFIXES = {
    "185.220.101.",
    "185.220.100.",
    "45.33.32.",
    "199.249.230.",
    "199.249.228.",
    "176.10.104.",
    "185.130.44.",
}


def check_connection_threat(ip, port):
    """Return the threat level for a given remote IP and port.

    Returns:
        None   — no threat detected
        'LOW'  — mildly suspicious (unusual inbound port)
        'MEDIUM' — suspicious (Tor exit node)
        'HIGH'   — known malicious port
    """
    if ip is None:
        return None

    # Check for known malicious port first (highest priority)
    if port in KNOWN_MALICIOUS_PORTS:
        return "HIGH"

    # Check for Tor exit node
    for prefix in TOR_EXIT_NODE_PREFIXES:
        if ip.startswith(prefix):
            return "MEDIUM"

    # Check for unexpectedly exposed management/service ports
    if port in SUSPICIOUS_PORTS:
        return "LOW"

    return None
