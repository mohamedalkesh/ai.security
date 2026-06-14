"""ML Service entry point."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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
    """Load the model once at startup so the first request is fast."""
    logger.info("Starting %s ...", settings.app_name)
    try:
        ml_service.load()
        logger.info("Model warmed up successfully.")
    except Exception as e:
        # Don't crash the server: /model/info will surface the error clearly
        logger.error("Model failed to load: %s", e)
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


app.include_router(predict_router)
app.include_router(monitor_router)
app.include_router(retrain_router)
