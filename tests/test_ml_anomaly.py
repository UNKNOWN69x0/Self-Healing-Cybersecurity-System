import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detection.ml_anomaly import AnomalyDetector

_ANOMALY = [99.9, 99.9, 500.0, 10.0, 100_000_000.0, 100_000_000.0, 200.0, 100.0]

_RNG = random.Random(42)


def _normal_sample():
    """Return a realistic varied normal feature vector with Gaussian noise."""
    return [
        _RNG.gauss(10.0, 3.0),      # cpu_percent
        _RNG.gauss(50.0, 5.0),      # memory_percent
        _RNG.gauss(20.0, 5.0),      # num_connections
        _RNG.uniform(0.0, 1.0),     # num_suspicious_processes
        _RNG.gauss(1024.0, 200.0),  # bytes_sent_delta
        _RNG.gauss(2048.0, 400.0),  # bytes_recv_delta
        _RNG.gauss(3.0, 1.0),       # num_unique_remote_ips
        _RNG.uniform(0.0, 2.0),     # failed_logins
    ]


def _make_detector(tmp_path):
    return AnomalyDetector(
        model_path=os.path.join(tmp_path, "model.pkl"),
        window_size=100,
        min_samples=20,
        retrain_interval=50,
        contamination=0.1,
    )


class TestAnomalyDetectorLearningMode(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.detector = _make_detector(self.tmp)

    def test_predict_returns_false_during_learning(self):
        for _ in range(10):
            self.detector.collect(_normal_sample())
        self.assertFalse(self.detector.predict(_ANOMALY))

    def test_status_mode_is_learning_initially(self):
        status = self.detector.get_status()
        self.assertEqual(status["mode"], "learning")
        self.assertEqual(status["samples"], 0)

    def test_status_shows_sample_count(self):
        for _ in range(5):
            self.detector.collect(_normal_sample())
        status = self.detector.get_status()
        self.assertEqual(status["samples"], 5)
        self.assertEqual(status["mode"], "learning")


class TestAnomalyDetectorActiveMode(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.detector = _make_detector(self.tmp)

    def _fill_baseline(self, n=25):
        for _ in range(n):
            self.detector.collect(_normal_sample())

    def test_status_mode_is_active_after_min_samples(self):
        self._fill_baseline()
        status = self.detector.get_status()
        self.assertEqual(status["mode"], "active")

    def test_normal_data_not_flagged(self):
        self._fill_baseline()
        # A realistic normal sample should not be flagged
        result = self.detector.predict([10.0, 50.0, 20.0, 0.0, 1024.0, 2048.0, 3.0, 0.0])
        self.assertFalse(result)

    def test_extreme_anomaly_flagged(self):
        # Train on varied normal data so the model can distinguish outliers
        self._fill_baseline(n=80)
        result = self.detector.predict(_ANOMALY)
        self.assertTrue(result)

    def test_rolling_window_respected(self):
        detector = AnomalyDetector(
            model_path=os.path.join(self.tmp, "win_model.pkl"),
            window_size=30,
            min_samples=20,
        )
        for _ in range(50):
            detector.collect(_normal_sample())
        self.assertLessEqual(len(detector.data_buffer), 30)


class TestAnomalyDetectorPersistence(unittest.TestCase):

    def test_model_save_and_load(self):
        tmp = tempfile.mkdtemp()
        model_path = os.path.join(tmp, "model.pkl")

        d1 = AnomalyDetector(model_path=model_path, min_samples=20)
        for _ in range(25):
            d1.collect(_normal_sample())
        self.assertIsNotNone(d1.model)
        self.assertTrue(os.path.exists(model_path))

        d2 = AnomalyDetector(model_path=model_path, min_samples=20)
        self.assertIsNotNone(d2.model)

    def test_missing_model_file_does_not_crash(self):
        tmp = tempfile.mkdtemp()
        d = AnomalyDetector(model_path=os.path.join(tmp, "nonexistent.pkl"))
        self.assertIsNone(d.model)


if __name__ == "__main__":
    unittest.main()
