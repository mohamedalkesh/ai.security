"""Pydantic models used by the prediction endpoints."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class FlowFeatures(BaseModel):
    """Generic feature dict. Keys must match feature_names from /model/info."""

    features: Dict[str, float] = Field(
        ...,
        description="Map of feature_name -> numeric value. "
                    "Missing features are filled with 0.",
        examples=[{"Flow Duration": 1234.0, "Total Fwd Packets": 12.0}],
    )


class PredictionResult(BaseModel):
    predicted: str
    confidence: float
    # v2 ensemble emits an extra anomaly flag from the IsolationForest head.
    # Optional so v1 responses still validate cleanly.
    anomaly: Optional[bool] = None
    probabilities: Dict[str, float]
    mitre_technique: str
    mitre_tactic: str
    severity: str
    description: str
    explanation: Optional[Dict[str, object]] = None


class FlowResult(PredictionResult):
    """Per-flow prediction result; metadata fields are optional."""

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[Any] = None
    dst_port: Optional[Any] = None
    protocol: Optional[Any] = None
    flow_id: Optional[Any] = None
    unique_sources: Optional[int] = None
    unique_destinations: Optional[int] = None
    top_sources: Optional[List[Dict[str, Any]]] = None
    top_destinations: Optional[List[Dict[str, Any]]] = None
    flow_duration: Optional[float] = Field(None, alias="Flow Duration")

    model_config = {"populate_by_name": True, "extra": "allow"}


class PcapResult(BaseModel):
    total_flows: int
    benign: int = 0
    attacks: int = 0
    avg_confidence: float = 0.0
    summary: Dict[str, int]
    metadata_quality: Optional[Dict[str, Any]] = None
    sampled: Optional[bool] = None
    original_rows: Optional[int] = None
    sampled_rows: Optional[int] = None
    flows: List[FlowResult]

    model_config = {"extra": "allow"}


class ModelInfo(BaseModel):
    # v2 adds version + anomaly_head; both default to None so v1 still works.
    version: Optional[str] = None
    model_type: str
    anomaly_head: Optional[str] = None
    classes: List[str]
    n_features: int
    feature_names: List[str]
    confidence_threshold: float
    artifacts_dir: str
    mitre_mapping: Dict[str, Dict[str, str]]

    model_config = {"protected_namespaces": ()}
