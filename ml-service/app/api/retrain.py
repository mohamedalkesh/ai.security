"""
Retrain endpoint — logs incoming feedback batches from the backend and
returns a queued status. Real retraining of an XGBoost model needs the
original training set, so this endpoint records the trigger and exposes
queue stats; an operator (or a future batch job) can consume the log
and re-fit the model offline.

Why not partial_fit?
    XGBoost does not natively support online updates the way SGD-based
    models do. Honest behaviour > magical-but-broken behaviour.

Endpoints:
    POST /retrain        — record a retrain request (returns 202 Accepted)
    GET  /retrain/status — returns queue size, last request, last retrain
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/retrain", tags=["retrain"])

# Persist requests to a JSONL file under the storage dir so they survive restarts.
QUEUE_FILE: Path = settings.model_artifacts_path.parent / "storage" / "retrain_queue.jsonl"
QUEUE_FILE.parent.mkdir(parents=True, exist_ok=True)


class RetrainRequest(BaseModel):
    """Backend → ML retrain trigger payload."""
    trigger: str = Field(default="feedback", description="What triggered the retrain")
    feedback_count: int = Field(default=0, ge=0, description="Number of new labels since last run")
    since: Optional[str] = Field(default=None, description="ISO timestamp of last run")


class RetrainResponse(BaseModel):
    status: str
    queued_at: str
    queue_size: int
    feedback_count: int
    note: str


@router.post("", status_code=status.HTTP_202_ACCEPTED, response_model=RetrainResponse)
def queue_retrain(req: RetrainRequest) -> Dict[str, Any]:
    """Append the request to the queue file and ack."""
    now = datetime.now(timezone.utc).isoformat()
    record = {
        "queued_at":      now,
        "trigger":        req.trigger,
        "feedback_count": req.feedback_count,
        "since":          req.since,
    }
    try:
        with QUEUE_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError as e:
        logger.error("Failed to append retrain request: %s", e)

    queue_size = _count_queue()
    logger.info(
        "Retrain queued (trigger=%s, feedback=%d, queue size=%d)",
        req.trigger, req.feedback_count, queue_size,
    )
    return {
        "status":         "queued",
        "queued_at":      now,
        "queue_size":     queue_size,
        "feedback_count": req.feedback_count,
        "note":           "XGBoost re-fit requires offline batch processing — "
                          "request recorded in storage/retrain_queue.jsonl",
    }


@router.get("/status")
def retrain_status() -> Dict[str, Any]:
    """Inspect the retrain queue without modifying it."""
    last_request: Optional[Dict[str, Any]] = None
    queue_size = 0
    try:
        if QUEUE_FILE.exists():
            with QUEUE_FILE.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    queue_size += 1
                    try:
                        last_request = json.loads(line)
                    except json.JSONDecodeError:
                        continue
    except OSError as e:
        logger.warning("Could not read retrain queue: %s", e)

    return {
        "queue_size":   queue_size,
        "last_request": last_request,
        "queue_file":   str(QUEUE_FILE),
    }


def _count_queue() -> int:
    if not QUEUE_FILE.exists():
        return 0
    try:
        with QUEUE_FILE.open("r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())
    except OSError:
        return 0
