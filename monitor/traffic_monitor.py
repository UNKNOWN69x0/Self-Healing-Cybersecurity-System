import time

import psutil


class TrafficMonitor:
    """Tracks network bandwidth deltas between successive calls."""

    def __init__(self):
        self._last = psutil.net_io_counters()
        self._last_time = time.time()

    def get_traffic_delta(self):
        """Return per-second network traffic metrics since the last call.

        Returns:
            dict with bytes_sent_per_sec, bytes_recv_per_sec,
            packets_sent_per_sec, packets_recv_per_sec, total_connections.
        """
        current = psutil.net_io_counters()
        now = time.time()
        elapsed = now - self._last_time
        if elapsed <= 0:
            elapsed = 1.0

        bytes_sent_per_sec = (current.bytes_sent - self._last.bytes_sent) / elapsed
        bytes_recv_per_sec = (current.bytes_recv - self._last.bytes_recv) / elapsed
        packets_sent_per_sec = (current.packets_sent - self._last.packets_sent) / elapsed
        packets_recv_per_sec = (current.packets_recv - self._last.packets_recv) / elapsed

        self._last = current
        self._last_time = now

        try:
            total_connections = len(psutil.net_connections())
        except Exception:
            total_connections = 0

        return {
            "bytes_sent_per_sec": max(0.0, bytes_sent_per_sec),
            "bytes_recv_per_sec": max(0.0, bytes_recv_per_sec),
            "packets_sent_per_sec": max(0.0, packets_sent_per_sec),
            "packets_recv_per_sec": max(0.0, packets_recv_per_sec),
            "total_connections": total_connections,
        }
