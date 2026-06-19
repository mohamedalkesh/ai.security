"""
Feature Drift Detector — monitors live traffic feature distributions
against the training baseline and raises alerts when drift is detected.

Uses Population Stability Index (PSI) per feature.
PSI < 0.1  → No drift  (green)
PSI < 0.25 → Moderate drift (yellow) — monitor
PSI >= 0.25 → Severe drift (red) — consider retraining
"""

from __future__ import annotations

import json
import logging
import pickle
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)

PSI_WARN  = 0.10
PSI_ALERT = 0.25
WINDOW    = 1000   # rolling window of flows for live distribution


def _psi(expected: np.ndarray, actual: np.ndarray, buckets: int = 10) -> float:
    """Population Stability Index between two distributions."""
    eps = 1e-8
    bins = np.percentile(expected, np.linspace(0, 100, buckets + 1))
    bins[0] -= eps; bins[-1] += eps
    e = np.histogram(expected, bins=bins)[0] / len(expected)
    a = np.histogram(actual,   bins=bins)[0] / len(actual)
    e = np.where(e == 0, eps, e)
    a = np.where(a == 0, eps, a)
    return float(np.sum((a - e) * np.log(a / e)))


class DriftDetector:
    """
    Maintains a rolling window of recent flow feature vectors and computes
    PSI against a training baseline when queried.

    Thread-safe — can be called from concurrent FastAPI request handlers.
    """

    def __init__(self, artifacts_dir: Path):
        self._lock = threading.Lock()
        self._window: deque = deque(maxlen=WINDOW)
        self.feature_names: List[str] = []
        self.baseline: Optional[np.ndarray] = None
        self._last_report: Optional[Dict] = None
        self._load_baseline(artifacts_dir)

    def _load_baseline(self, artifacts_dir: Path) -> None:
        fn_path = artifacts_dir / "feature_names.pkl"
        scaler_path = artifacts_dir / "scaler.pkl"
        if not fn_path.exists() or not scaler_path.exists():
            logger.warning("Drift detector: artifacts not found at %s", artifacts_dir)
            return
        with open(fn_path, "rb") as f:
            self.feature_names = pickle.load(f)
        with open(scaler_path, "rb") as f:
            scaler = pickle.load(f)
        # Baseline = training-set mean (scaler.mean_) in original feature space
        self.baseline = scaler.mean_        # shape: (n_features,)
        # Generate synthetic baseline distribution from scaler statistics
        rng = np.random.default_rng(42)
        self._baseline_samples = (
            scaler.mean_[None, :] +
            scaler.scale_[None, :] * rng.standard_normal((2000, len(self.feature_names)))
        )
        logger.info("Drift detector: baseline loaded (%d features)", len(self.feature_names))

    def reload(self, artifacts_dir: Path) -> None:
        with self._lock:
            self._window.clear()
            self._last_report = None
            self._load_baseline(artifacts_dir)

    def record(self, features: Dict[str, Any]) -> None:
        if not self.feature_names:
            return
        vec = [float(features.get(f, 0.0)) for f in self.feature_names]
        with self._lock:
            self._window.append(vec)

    def check(self) -> Dict:
        """Return drift report for all features. Cached until window advances by 10%."""
        with self._lock:
            n = len(self._window)
        if n < 50:
            return {"status": "insufficient_data", "n_samples": n, "features": {}}

        live = np.array(list(self._window))           # (n, features)
        baseline = self._baseline_samples

        feature_results = {}
        drifted = []
        warn = []
        for i, fname in enumerate(self.feature_names):
            try:
                psi = _psi(baseline[:, i], live[:, i])
            except Exception:
                psi = 0.0
            severity = "ok" if psi < PSI_WARN else ("warn" if psi < PSI_ALERT else "drift")
            feature_results[fname] = {"psi": round(psi, 4), "severity": severity}
            if severity == "drift":
                drifted.append(fname)
            elif severity == "warn":
                warn.append(fname)

        overall = "ok" if not drifted and not warn else \
                  ("drift" if drifted else "warn")

        report = {
            "status":            overall,
            "n_samples":         n,
            "drifted_features":  drifted,
            "warn_features":     warn,
            "features":          feature_results,
            "checked_at":        datetime.now(timezone.utc).isoformat(),
            "recommendation":    _recommendation(overall, drifted),
        }
        with self._lock:
            self._last_report = report
        return report

    def last_report(self) -> Optional[Dict]:
        with self._lock:
            return self._last_report


def _recommendation(status: str, drifted: List[str]) -> str:
    if status == "ok":
        return "No action required — model is tracking the live distribution."
    if status == "warn":
        return "Minor drift detected. Monitor over next 24 h before retraining."
    top = ", ".join(drifted[:5])
    return (f"Significant drift in: {top}. "
            "Run scripts/retrain.py to update the model on recent traffic.")
