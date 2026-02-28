import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    """ML-based anomaly detector using Isolation Forest on system/network features."""

    FEATURE_NAMES = [
        "cpu_percent",
        "memory_percent",
        "num_connections",
        "num_suspicious_processes",
        "bytes_sent_delta",
        "bytes_recv_delta",
        "num_unique_remote_ips",
        "failed_logins",
    ]

    def __init__(self, model_path="model/anomaly_model.pkl", window_size=100,
                 min_samples=20, retrain_interval=50, contamination=0.1):
        self.model_path = model_path
        self.window_size = window_size
        self.min_samples = min_samples
        self.retrain_interval = retrain_interval
        self.contamination = contamination
        self.data_buffer = []
        self.model = None
        self._cycles = 0
        self._load_model()

    def _load_model(self):
        """Try loading an existing persisted model from disk."""
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
        except Exception:
            self.model = None

    def _save_model(self):
        """Persist the current model to disk."""
        try:
            model_dir = os.path.dirname(self.model_path)
            if model_dir:
                os.makedirs(model_dir, exist_ok=True)
            joblib.dump(self.model, self.model_path)
        except Exception:
            pass

    def _train(self):
        """Fit a new Isolation Forest on the current data buffer."""
        X = np.array(self.data_buffer)
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
        )
        self.model.fit(X)
        self._save_model()

    def collect(self, features):
        """Add a feature vector to the rolling buffer; retrain when appropriate.

        Args:
            features: list of 8 floats matching FEATURE_NAMES order.
        """
        self.data_buffer.append(list(features))
        # Keep only the most recent window_size samples
        if len(self.data_buffer) > self.window_size:
            self.data_buffer.pop(0)

        self._cycles += 1

        # Train once we have enough samples, then retrain every retrain_interval
        n = len(self.data_buffer)
        if n >= self.min_samples:
            if self.model is None or self._cycles % self.retrain_interval == 0:
                self._train()

    def predict(self, features):
        """Return True if the feature vector is an anomaly, False otherwise.

        Returns False when still in learning mode (not enough data).
        """
        if self.model is None or len(self.data_buffer) < self.min_samples:
            return False
        X = np.array([list(features)])
        prediction = self.model.predict(X)
        # IsolationForest returns -1 for anomalies, 1 for inliers
        return int(prediction[0]) == -1

    def get_status(self):
        """Return a dict describing the current detector state."""
        n = len(self.data_buffer)
        if n < self.min_samples:
            return {
                "mode": "learning",
                "samples": n,
                "min_samples": self.min_samples,
            }
        return {
            "mode": "active",
            "samples": n,
            "cycles": self._cycles,
        }
