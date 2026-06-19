"""ML Service entry point."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.drift import router as drift_router
from app.api.monitor import router as monitor_router
from app.api.predict import router as predict_router
from app.api.retrain import router as retrain_router
from app.core.config import settings
from app.services.ml_service import ml_service


logging.basicConfig(
    level=logging.INFO if not settings.debug else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
# The multipart parser logs every uploaded chunk at DEBUG, which floods the
# log and adds overhead during large PCAP uploads. Keep it quiet.
logging.getLogger("multipart").setLevel(logging.WARNING)
logging.getLogger("python_multipart").setLevel(logging.WARNING)
logger = logging.getLogger("ml-service")


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Load the model once at startup, then auto-start live capture if configured."""
    logger.info("Starting %s ...", settings.app_name)
    try:
        ml_service.load()
        logger.info("Model warmed up successfully.")
    except Exception as e:
        logger.error("Model failed to load: %s", e)

    # Auto-start live capture if AUTOSTART_INTERFACE is set
    iface = settings.autostart_interface.strip()
    if iface:
        from app.services.live_monitor import live_monitor
        try:
            live_monitor.start(iface)
            logger.info("Live capture auto-started on interface: %s", iface)
        except Exception as e:
            logger.warning("Auto-start capture failed on '%s': %s", iface, e)
    yield
    logger.info("Shutting down ML Service.")


app = FastAPI(
    title=settings.app_name,
    description=(
        "Internal microservice that wraps the trained IDS XGBoost model.\n\n"
        "Used by the Java Spring Boot backend. Not meant to be exposed publicly."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["health"])
def health():
    return {
        "status": "ok",
        "service": settings.app_name,
        "model_loaded": ml_service.loaded,
    }


@app.post("/model/reload", tags=["model"])
def model_reload(body: dict = {}):
    """Hot-reload model artifacts after retraining. Called by scripts/retrain.py."""
    import os
    from pathlib import Path
    artifacts_dir = body.get("artifacts_dir")
    if artifacts_dir:
        os.environ["MODEL_ARTIFACTS_DIR"] = artifacts_dir
        ml_service.artifacts_dir = Path(artifacts_dir)
    try:
        ml_service._loaded = False
        ml_service.load()
        return {"status": "reloaded", "artifacts_dir": str(ml_service.artifacts_dir),
                "version": ml_service.version,
                "classes": list(ml_service.label_encoder.classes_)}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


app.include_router(predict_router)
app.include_router(monitor_router)
app.include_router(retrain_router)
app.include_router(drift_router)
