import sys
import os
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from response import self_heal


class TestSelfHeal(unittest.TestCase):

    def setUp(self):
        # Reset shared state before each test
        self_heal.BLOCKED_IPS.clear()

    @patch("response.self_heal.os.system")
    @patch("response.self_heal.log_event")
    def test_heal_malicious_process(self, mock_log, mock_system):
        self_heal.heal({"type": "MALICIOUS_PROCESS", "pid": 9999})
        mock_system.assert_called_once_with("taskkill /PID 9999 /F")
        mock_log.assert_called()

    @patch("response.self_heal.os.system")
    @patch("response.self_heal.log_event")
    def test_heal_malicious_process_skips_critical_pid(self, mock_log, mock_system):
        self_heal.heal({"type": "MALICIOUS_PROCESS", "pid": 4})
        mock_system.assert_not_called()

    @patch("response.self_heal.os.system")
    @patch("response.self_heal.log_event")
    def test_heal_suspicious_ip(self, mock_log, mock_system):
        self_heal.heal({"type": "SUSPICIOUS_IP", "ip": "1.2.3.4"})
        mock_system.assert_called_once()
        call_args = mock_system.call_args[0][0]
        self.assertIn("1.2.3.4", call_args)
        mock_log.assert_called()

    @patch("response.self_heal.os.system")
    @patch("response.self_heal.log_event")
    def test_heal_suspicious_ip_skips_safe_ip(self, mock_log, mock_system):
        self_heal.heal({"type": "SUSPICIOUS_IP", "ip": "127.0.0.1"})
        mock_system.assert_not_called()

    @patch("response.self_heal.os.system")
    @patch("response.self_heal.log_event")
    def test_heal_suspicious_ip_no_duplicate_block(self, mock_log, mock_system):
        self_heal.heal({"type": "SUSPICIOUS_IP", "ip": "5.5.5.5"})
        self_heal.heal({"type": "SUSPICIOUS_IP", "ip": "5.5.5.5"})
        self.assertEqual(mock_system.call_count, 1)

    @patch("response.self_heal.log_event")
    def test_heal_high_cpu(self, mock_log):
        self_heal.heal({"type": "HIGH_CPU"})
        mock_log.assert_called()
        args = mock_log.call_args[0][0]
        self.assertIn("CPU", args.upper())

    @patch("response.self_heal.log_event")
    def test_heal_high_memory(self, mock_log):
        self_heal.heal({"type": "HIGH_MEMORY"})
        mock_log.assert_called()
        args = mock_log.call_args[0][0]
        self.assertIn("MEMORY", args.upper())

    @patch("response.self_heal.log_event")
    def test_heal_brute_force(self, mock_log):
        self_heal.heal({"type": "BRUTE_FORCE"})
        mock_log.assert_called()
        args = mock_log.call_args[0][0]
        self.assertIn("BRUTE", args.upper())

    @patch("response.self_heal.log_event")
    def test_heal_unknown_type_no_crash(self, mock_log):
        self_heal.heal({"type": "UNKNOWN_THREAT"})
        # Should not raise, log not necessarily called


if __name__ == "__main__":
    unittest.main()
