import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from monitor.threat_intel import (
    KNOWN_MALICIOUS_PORTS,
    SUSPICIOUS_PORTS,
    TOR_EXIT_NODE_PREFIXES,
    check_connection_threat,
)


class TestKnownMaliciousPorts(unittest.TestCase):

    def test_known_malicious_ports_returns_high(self):
        for port in KNOWN_MALICIOUS_PORTS:
            with self.subTest(port=port):
                self.assertEqual(check_connection_threat("1.2.3.4", port), "HIGH")

    def test_suspicious_ports_returns_low(self):
        for port in SUSPICIOUS_PORTS:
            with self.subTest(port=port):
                result = check_connection_threat("1.2.3.4", port)
                # Suspicious ports should return LOW (unless also in malicious)
                if port not in KNOWN_MALICIOUS_PORTS:
                    self.assertEqual(result, "LOW")

    def test_benign_port_returns_none(self):
        self.assertIsNone(check_connection_threat("8.8.8.8", 443))
        self.assertIsNone(check_connection_threat("8.8.8.8", 80))
        self.assertIsNone(check_connection_threat("1.1.1.1", 53))

    def test_none_ip_returns_none(self):
        self.assertIsNone(check_connection_threat(None, 4444))


class TestTorExitNodes(unittest.TestCase):

    def test_tor_ip_prefix_returns_medium(self):
        for prefix in TOR_EXIT_NODE_PREFIXES:
            ip = prefix + "1"
            with self.subTest(ip=ip):
                result = check_connection_threat(ip, 443)
                # Tor on a benign port should be MEDIUM
                self.assertEqual(result, "MEDIUM")

    def test_malicious_port_overrides_tor(self):
        prefix = next(iter(TOR_EXIT_NODE_PREFIXES))
        ip = prefix + "1"
        result = check_connection_threat(ip, 4444)
        self.assertEqual(result, "HIGH")

    def test_regular_ip_not_flagged_as_tor(self):
        self.assertIsNone(check_connection_threat("8.8.8.8", 443))


class TestSpecificValues(unittest.TestCase):

    def test_port_4444_is_high(self):
        self.assertEqual(check_connection_threat("10.0.0.1", 4444), "HIGH")

    def test_port_1337_is_high(self):
        self.assertEqual(check_connection_threat("203.0.113.5", 1337), "HIGH")

    def test_port_22_is_low(self):
        self.assertEqual(check_connection_threat("203.0.113.5", 22), "LOW")

    def test_port_3389_is_low(self):
        self.assertEqual(check_connection_threat("203.0.113.5", 3389), "LOW")


if __name__ == "__main__":
    unittest.main()
