"""Feature drift detection API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from app.services.ml_service import ml_service

router = APIRouter()


@router.get("/drift", tags=["model"])
def get_drift_report():
    """
    Returns the current feature drift report comparing live traffic
    distributions against the training baseline.

    PSI interpretation:
      < 0.10  → No significant drift (green)
      < 0.25  → Moderate drift     (yellow) — monitor
      >= 0.25 → Severe drift       (red)    — retrain
    """
    if not ml_service.loaded:
        raise HTTPException(status_code=503, detail="Model not loaded")
    if ml_service.drift is None:
        raise HTTPException(status_code=503, detail="Drift detector not initialised")
    return ml_service.drift.check()


@router.get("/drift/summary", tags=["model"])
def get_drift_summary():
    """Lightweight summary — status, sample count, and top drifted features only."""
    if not ml_service.loaded or ml_service.drift is None:
        return {"status": "unavailable", "n_samples": 0, "drifted_features": [], "warn_features": []}
    report = ml_service.drift.last_report()
    if report is None:
        report = ml_service.drift.check()
    return {
        "status":           report.get("status"),
        "n_samples":        report.get("n_samples"),
        "drifted_features": report.get("drifted_features", [])[:10],
        "warn_features":    report.get("warn_features", [])[:10],
        "recommendation":   report.get("recommendation"),
        "checked_at":       report.get("checked_at"),
    }
