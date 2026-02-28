import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from monitor.traffic_monitor import TrafficMonitor


class _FakeCounters:
    def __init__(self, bs, br, ps, pr):
        self.bytes_sent = bs
        self.bytes_recv = br
        self.packets_sent = ps
        self.packets_recv = pr


class TestTrafficMonitor(unittest.TestCase):

    @patch("monitor.traffic_monitor.psutil.net_io_counters")
    @patch("monitor.traffic_monitor.psutil.net_connections", return_value=[1, 2, 3])
    @patch("monitor.traffic_monitor.time.time")
    def test_deltas_calculated_correctly(self, mock_time, mock_conns, mock_counters):
        # Initial state: t=0, counters at baseline
        mock_time.return_value = 0.0
        mock_counters.return_value = _FakeCounters(1000, 2000, 10, 20)

        monitor = TrafficMonitor()

        # After 1 second, 500 bytes sent, 1000 bytes received
        mock_time.return_value = 1.0
        mock_counters.return_value = _FakeCounters(1500, 3000, 15, 25)

        result = monitor.get_traffic_delta()

        self.assertAlmostEqual(result["bytes_sent_per_sec"], 500.0)
        self.assertAlmostEqual(result["bytes_recv_per_sec"], 1000.0)
        self.assertAlmostEqual(result["packets_sent_per_sec"], 5.0)
        self.assertAlmostEqual(result["packets_recv_per_sec"], 5.0)
        self.assertEqual(result["total_connections"], 3)

    @patch("monitor.traffic_monitor.psutil.net_io_counters")
    @patch("monitor.traffic_monitor.psutil.net_connections", return_value=[])
    @patch("monitor.traffic_monitor.time.time")
    def test_zero_elapsed_does_not_divide_by_zero(self, mock_time, mock_conns, mock_counters):
        mock_time.return_value = 5.0
        mock_counters.return_value = _FakeCounters(0, 0, 0, 0)
        monitor = TrafficMonitor()
        # Same timestamp — elapsed would be 0
        mock_counters.return_value = _FakeCounters(100, 200, 1, 2)
        result = monitor.get_traffic_delta()
        # Should not raise; values clamped to >= 0
        self.assertGreaterEqual(result["bytes_sent_per_sec"], 0)
        self.assertGreaterEqual(result["bytes_recv_per_sec"], 0)

    @patch("monitor.traffic_monitor.psutil.net_io_counters")
    @patch("monitor.traffic_monitor.psutil.net_connections", return_value=[])
    @patch("monitor.traffic_monitor.time.time")
    def test_deltas_clamped_to_zero_on_counter_wrap(self, mock_time, mock_conns, mock_counters):
        mock_time.return_value = 0.0
        mock_counters.return_value = _FakeCounters(1000, 1000, 10, 10)
        monitor = TrafficMonitor()

        # Simulate counter wrap-around (new < old)
        mock_time.return_value = 1.0
        mock_counters.return_value = _FakeCounters(500, 500, 5, 5)
        result = monitor.get_traffic_delta()
        self.assertGreaterEqual(result["bytes_sent_per_sec"], 0)
        self.assertGreaterEqual(result["bytes_recv_per_sec"], 0)

    @patch("monitor.traffic_monitor.psutil.net_io_counters")
    @patch("monitor.traffic_monitor.psutil.net_connections", side_effect=Exception("access denied"))
    @patch("monitor.traffic_monitor.time.time")
    def test_net_connections_exception_handled(self, mock_time, mock_conns, mock_counters):
        mock_time.return_value = 0.0
        mock_counters.return_value = _FakeCounters(0, 0, 0, 0)
        monitor = TrafficMonitor()
        mock_time.return_value = 1.0
        mock_counters.return_value = _FakeCounters(100, 200, 1, 2)
        result = monitor.get_traffic_delta()
        self.assertEqual(result["total_connections"], 0)


if __name__ == "__main__":
    unittest.main()
