"""Prediction endpoints."""

from __future__ import annotations

import logging
import shutil
import time
import uuid
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile
from starlette.concurrency import run_in_threadpool

from app.core.config import settings
from app.schemas.predict import (
    FlowFeatures,
    ModelInfo,
    PcapResult,
    PredictionResult,
)
from app.services.ml_service import ml_service

router = APIRouter(prefix="/api", tags=["predict"])
logger = logging.getLogger(__name__)


@router.get("/model/info", response_model=ModelInfo)
def model_info():
    """Return model metadata: classes, features, MITRE mapping."""
    try:
        return ml_service.info()
    except Exception as e:
        logger.exception("Model info failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/predict/flow", response_model=PredictionResult)
def predict_flow(payload: FlowFeatures):
    """Classify a single flow given its feature dict."""
    try:
        return ml_service.predict_flow(payload.features)
    except Exception as e:
        logger.exception("predict_flow failed")
        raise HTTPException(status_code=500, detail=str(e))


PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}
CSV_SUFFIXES = {".csv"}


@router.post("/predict/pcap", response_model=PcapResult)
async def predict_pcap(file: UploadFile = File(...)):
    """Upload a PCAP (default) or CSV file and classify the contained flows."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    suffix = Path(file.filename).suffix.lower()
    if suffix in PCAP_SUFFIXES:
        mode = "pcap"
    elif suffix in CSV_SUFFIXES:
        mode = "csv"
    else:
        allowed = ", ".join(sorted(list(PCAP_SUFFIXES | CSV_SUFFIXES)))
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported extension '{suffix}'. Allowed: {allowed}",
        )

    # Persist upload to disk (both pipelines need a file path)
    temp_name = f"{int(time.time())}_{uuid.uuid4().hex[:8]}{suffix}"
    temp_path = settings.upload_path / temp_name

    size_mb = 0.0
    try:
        with open(temp_path, "wb") as out:
            # Stream copy + size guard
            max_bytes = settings.max_upload_mb * 1024 * 1024
            written = 0
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File too large (> {settings.max_upload_mb} MB)",
                    )
                out.write(chunk)
            size_mb = written / (1024 * 1024)

        logger.info("Upload saved: %s (%.2f MB, mode=%s)", temp_path, size_mb, mode)
        # The prediction pipeline is CPU-bound and blocking. Run it in a worker
        # thread so it never blocks the event loop — keeps /health and other
        # requests responsive while a large PCAP is being analysed.
        if mode == "pcap":
            result = await run_in_threadpool(ml_service.predict_pcap, temp_path)
        else:
            result = await run_in_threadpool(ml_service.predict_csv, temp_path)
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("predict_pcap failed")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Always cleanup
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass
