import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detection import rule_engine


class TestRuleEngine(unittest.TestCase):

    def _analyze(self, data):
        return rule_engine.analyze(data)

    def test_no_threats(self):
        data = {"system": {"cpu": 10, "memory": 50}, "processes": [], "network": [], "failed_logins": 0}
        threats = self._analyze(data)
        self.assertEqual(threats, [])

    def test_high_cpu(self):
        data = {"system": {"cpu": 95, "memory": 50}, "processes": [], "network": [], "failed_logins": 0}
        threats = self._analyze(data)
        types = [t["type"] for t in threats]
        self.assertIn("HIGH_CPU", types)
        cpu_threat = next(t for t in threats if t["type"] == "HIGH_CPU")
        self.assertEqual(cpu_threat["severity"], "HIGH")

    def test_high_memory(self):
        data = {"system": {"cpu": 10, "memory": 96}, "processes": [], "network": [], "failed_logins": 0}
        threats = self._analyze(data)
        types = [t["type"] for t in threats]
        self.assertIn("HIGH_MEMORY", types)
        mem_threat = next(t for t in threats if t["type"] == "HIGH_MEMORY")
        self.assertEqual(mem_threat["severity"], "HIGH")

    def test_suspicious_process(self):
        data = {
            "system": {"cpu": 10, "memory": 50},
            "processes": [{"pid": 1234, "name": "xmrig.exe", "cpu_percent": 0}],
            "network": [],
            "failed_logins": 0,
        }
        threats = self._analyze(data)
        types = [t["type"] for t in threats]
        self.assertIn("MALICIOUS_PROCESS", types)
        proc_threat = next(t for t in threats if t["type"] == "MALICIOUS_PROCESS")
        self.assertEqual(proc_threat["pid"], 1234)
        self.assertEqual(proc_threat["severity"], "CRITICAL")

    def test_suspicious_connection(self):
        data = {
            "system": {"cpu": 10, "memory": 50},
            "processes": [],
            "network": [{"ip": "1.2.3.4", "pid": 999}],
            "failed_logins": 0,
        }
        threats = self._analyze(data)
        types = [t["type"] for t in threats]
        self.assertIn("SUSPICIOUS_IP", types)
        ip_threat = next(t for t in threats if t["type"] == "SUSPICIOUS_IP")
        self.assertEqual(ip_threat["ip"], "1.2.3.4")
        self.assertEqual(ip_threat["severity"], "MEDIUM")

    def test_brute_force(self):
        data = {"system": {"cpu": 10, "memory": 50}, "processes": [], "network": [], "failed_logins": 6}
        threats = self._analyze(data)
        types = [t["type"] for t in threats]
        self.assertIn("BRUTE_FORCE", types)
        bf_threat = next(t for t in threats if t["type"] == "BRUTE_FORCE")
        self.assertEqual(bf_threat["severity"], "CRITICAL")

    def test_brute_force_not_triggered_below_limit(self):
        data = {"system": {"cpu": 10, "memory": 50}, "processes": [], "network": [], "failed_logins": 4}
        threats = self._analyze(data)
        types = [t["type"] for t in threats]
        self.assertNotIn("BRUTE_FORCE", types)


if __name__ == "__main__":
    unittest.main()
