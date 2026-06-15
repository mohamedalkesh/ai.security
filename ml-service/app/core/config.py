"""Application configuration loaded from environment variables (.env)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


SERVICE_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=SERVICE_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        protected_namespaces=("settings_",),
    )

    # App
    app_name: str = "MADRS ML Service"
    host: str = "127.0.0.1"
    port: int = 8001
    debug: bool = True

    # CORS
    cors_origins: str = "http://localhost:8080"

    # Model paths
    model_artifacts_dir: str = "../AI/model_artifacts"
    ai_package_dir: str = "../AI"
    confidence_threshold: float = 0.6

    # Storage
    upload_dir: str = "./storage/uploads"
    max_upload_mb: int = 1024

    # Performance
    pcap_worker_threads: int = 0  # 0 = auto (use CPU count)
    # SHAP explainability is expensive (per-flow tree traversal). Only compute
    # it for the most relevant flows so large scans stay fast. Explanations are
    # generated for attack flows up to this many; benign flows and any excess
    # are skipped. Set to 0 to disable SHAP entirely.
    shap_max_flows: int = 0
    scan_flow_detail_limit: int = 200
    enable_payload_sampling: bool = False

    # ----- helpers -----
    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def _resolve(self, p: str) -> Path:
        path = Path(p)
        if not path.is_absolute():
            path = (SERVICE_ROOT / path).resolve()
        return path

    @property
    def model_artifacts_path(self) -> Path:
        return self._resolve(self.model_artifacts_dir)

    @property
    def ai_package_path(self) -> Path:
        return self._resolve(self.ai_package_dir)

    @property
    def upload_path(self) -> Path:
        p = self._resolve(self.upload_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
