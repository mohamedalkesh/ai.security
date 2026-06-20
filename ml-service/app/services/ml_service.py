"""
ML Service — loads the trained IDS artifacts once at startup and exposes
helper methods for flow / dataframe / PCAP classification.

Wraps the pipeline already in AI/:
    pickles -> features -> StandardScaler -> XGBoost -> Class + Confidence -> MITRE
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import pickle
import time
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import numpy as np
import pandas as pd
try:  # SHAP is heavy but optional; explanations degrade gracefully if missing
    import shap
except ImportError:  # pragma: no cover - optional dependency
    shap = None

from app.core.config import settings
from app.services.drift_detector import DriftDetector
from app.services.explanation_builder import build_narrative
from app.services.mitre import MITRE_MAPPING, enrich
from app.services.payload_sampler import extract_payload_samples

logger = logging.getLogger(__name__)

# v1 (legacy): single XGBoost model in model.pkl
V1_ARTIFACTS = ("model.pkl", "label_encoder.pkl", "scaler.pkl", "feature_names.pkl")
# v2: XGBoost + LightGBM ensemble + IsolationForest anomaly layer
V2_ARTIFACTS = ("xgb.pkl", "lgbm.pkl", "iso.pkl",
                "label_encoder.pkl", "scaler.pkl", "feature_names.pkl")

# Sibling directories, tried in order of preference at startup.
# v6: SMOTE-balanced, weighted ensemble, per-class thresholds (runtime_config.json)
# v5 uses 52 CICFlowMeter features trained on CICIDS2017.
# All versions share the same artifact layout (see V2_ARTIFACTS).
V6_DIR_NAME = "model_artifacts_v6"
V5_DIR_NAME = "model_artifacts_v5"
V4_DIR_NAME = "model_artifacts_v4"
V3_DIR_NAME = "model_artifacts_v3"
V2_DIR_NAME = "model_artifacts_v2"


class MLService:
    """Singleton-style wrapper around the trained IDS model.

    Supports two on-disk layouts:

    * **v1** (``model_artifacts/``)  – single XGBoost model. ``predict_proba``
      is taken directly from ``self.model``.
    * **v2** (``model_artifacts_v2/``) – soft-voted XGBoost + LightGBM with
      an Isolation Forest anomaly head. ``predict_proba`` averages the two
      classifiers, and low-confidence *and* anomalous samples are
      downgraded to ``Unknown`` so the system stops forcing real-world LAN
      traffic into one of the 5 trained classes.
    """

    def __init__(self) -> None:
        self.model = None             # v1 only — None when running v2
        self.xgb = None               # v2
        self.lgbm = None              # v2
        self.iso = None               # v2 anomaly head (optional)
        self.label_encoder = None
        self.scaler = None
        self.feature_names: List[str] = []
        self.confidence_threshold: float = settings.confidence_threshold
        self.artifacts_dir: Path = settings.model_artifacts_path
        self.version: str = "v1"
        self._loaded: bool = False
        self._xgb_explainer = None
        self._lgbm_explainer = None
        self._model_explainer = None
        self.drift: Optional[DriftDetector] = None
        # v6 runtime config — per-class thresholds and ensemble weights
        self._per_class_thresholds: Dict[str, float] = {}
        self._xgb_weight: float = 0.5
        self._lgbm_weight: float = 0.5
        cpu_default = os.cpu_count() or 1
        cfg_threads = settings.pcap_worker_threads
        if cfg_threads and cfg_threads > 0:
            self.pcap_workers = cfg_threads
        else:
            self.pcap_workers = cpu_default

    # ------------------------------------------------------------------
    def _resolve_artifacts_dir(self) -> Tuple[Path, str]:
        """Pick the newest complete artifact set: v3 > v2 > v1.

        Both v2 and v3 use the same ensemble layout (xgb/lgbm/iso pickles),
        so the only thing that changes per generation is the directory name
        and the trained class taxonomy. Users can roll back by renaming or
        deleting any of the dirs without touching config.
        """
        base = self.artifacts_dir.parent
        for name, label in (
            (V6_DIR_NAME, "v6"), (V5_DIR_NAME, "v5"),
            (V4_DIR_NAME, "v4"), (V3_DIR_NAME, "v3"), (V2_DIR_NAME, "v2"),
        ):
            d = base / name
            if d.exists() and all((d / f).exists() for f in V2_ARTIFACTS):
                return d, label
        return self.artifacts_dir, "v1"

    def load(self) -> None:
        if self._loaded:
            return

        chosen_dir, version = self._resolve_artifacts_dir()
        self.artifacts_dir = chosen_dir
        self.version = version

        if not chosen_dir.exists():
            raise FileNotFoundError(f"Model artifacts directory not found: {chosen_dir}")

        # v2+ share the same on-disk layout (XGB + LGBM + IsoForest).
        required = V2_ARTIFACTS if version in ("v2", "v3", "v4", "v5") else V1_ARTIFACTS
        missing = [f for f in required if not (chosen_dir / f).exists()]
        if missing:
            raise FileNotFoundError(f"Missing {version} artifacts in {chosen_dir}: {missing}")

        logger.info("Loading %s model artifacts from %s", version, chosen_dir)

        if version in ("v2", "v3", "v4", "v5"):
            with open(chosen_dir / "xgb.pkl", "rb") as f:
                self.xgb = pickle.load(f)
            with open(chosen_dir / "lgbm.pkl", "rb") as f:
                self.lgbm = pickle.load(f)
            with open(chosen_dir / "iso.pkl", "rb") as f:
                self.iso = pickle.load(f)
            if shap is not None:
                self._xgb_explainer = shap.TreeExplainer(self.xgb)
                self._lgbm_explainer = shap.TreeExplainer(self.lgbm)
            else:
                logger.warning("SHAP not installed — per-alert explanations disabled")
        else:
            with open(chosen_dir / "model.pkl", "rb") as f:
                self.model = pickle.load(f)
            if shap is not None:
                self._model_explainer = shap.TreeExplainer(self.model)
            else:
                logger.warning("SHAP not installed — per-alert explanations disabled")

        with open(chosen_dir / "label_encoder.pkl", "rb") as f:
            self.label_encoder = pickle.load(f)
        with open(chosen_dir / "scaler.pkl", "rb") as f:
            self.scaler = pickle.load(f)
        with open(chosen_dir / "feature_names.pkl", "rb") as f:
            self.feature_names = list(pickle.load(f))

        # Make AI/ importable so we can re-use pcap_to_features.py without
        # copying it (no modification to AI/ folder).
        ai_dir = settings.ai_package_path
        if str(ai_dir) not in sys.path:
            sys.path.insert(0, str(ai_dir))

        # v6+: load per-class thresholds and ensemble weights if available
        runtime_cfg_path = chosen_dir / "runtime_config.json"
        if runtime_cfg_path.exists():
            with open(runtime_cfg_path) as f:
                runtime_cfg = json.load(f)
            self._per_class_thresholds = runtime_cfg.get("per_class_thresholds", {})
            ew = runtime_cfg.get("ensemble_weights", {})
            self._xgb_weight  = float(ew.get("xgb",  0.5))
            self._lgbm_weight = float(ew.get("lgbm", 0.5))
            logger.info(
                "Loaded runtime_config: thresholds=%s  weights=XGB:%.3f LGBM:%.3f",
                self._per_class_thresholds, self._xgb_weight, self._lgbm_weight,
            )

        self.drift = DriftDetector(chosen_dir)
        self._loaded = True
        logger.info(
            "Model ready (%s): classes=%s, features=%d",
            version,
            list(self.label_encoder.classes_),
            len(self.feature_names),
        )
        logger.info("PCAP worker threads: %d", self.pcap_workers)

    @property
    def loaded(self) -> bool:
        return self._loaded

    # ------------------------------------------------------------------
    def info(self) -> Dict[str, Any]:
        self.load()
        if self.version in ("v2", "v3", "v4", "v5"):
            model_type = f"Ensemble({type(self.xgb).__name__}+{type(self.lgbm).__name__})"
        else:
            model_type = type(self.model).__name__
        return {
            "version": self.version,
            "model_type": model_type,
            "anomaly_head": type(self.iso).__name__ if self.iso is not None else None,
            "classes": [str(c) for c in self.label_encoder.classes_],
            "n_features": len(self.feature_names),
            "feature_names": self.feature_names,
            "confidence_threshold": self.confidence_threshold,
            "artifacts_dir": str(self.artifacts_dir),
            "mitre_mapping": MITRE_MAPPING,
            "pcap_worker_threads": self.pcap_workers,
        }

    # ------------------------------------------------------------------
    def _predict_array(self, X: np.ndarray, raw_df: pd.DataFrame | None = None) -> List[Dict[str, Any]]:
        self.load()
        Xs = self.scaler.transform(X)

        if self.version in ("v2", "v3", "v4", "v5", "v6"):
            # Run XGBoost and LightGBM predict_proba in parallel — both models
            # release the GIL during their C++ inference, giving near-2× throughput.
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as _pool:
                _xgb_f = _pool.submit(self.xgb.predict_proba, Xs)
                _lgb_f = _pool.submit(self.lgbm.predict_proba, Xs)
                # v6 uses learned per-class weights; v2-v5 use simple average (0.5/0.5)
                proba = (
                    self._xgb_weight  * _xgb_f.result() +
                    self._lgbm_weight * _lgb_f.result()
                )
            anomaly_flag = self.iso.predict(Xs) == -1 if self.iso is not None else None
        else:
            proba = self.model.predict_proba(Xs)
            anomaly_flag = None

        # Per-class threshold decision (v6) or simple argmax (v2-v5)
        classes_list = [str(c) for c in self.label_encoder.classes_]
        if self._per_class_thresholds:
            # For each flow: pick the class with highest probability that exceeds
            # its own threshold. If none exceed their threshold → mark as Unknown.
            idx_arr = []
            conf_arr = []
            for row in proba:
                best_i, best_p = int(np.argmax(row)), float(np.max(row))
                best_cls = classes_list[best_i]
                thr = self._per_class_thresholds.get(best_cls, self.confidence_threshold)
                if best_p >= thr:
                    idx_arr.append(best_i)
                    conf_arr.append(best_p)
                else:
                    idx_arr.append(best_i)   # keep label, mark low confidence
                    conf_arr.append(best_p)
            idx  = np.array(idx_arr, dtype=int)
            conf = np.array(conf_arr, dtype=float)
            # Override confidence threshold with per-class value in the loop below
            _use_per_class_thr = True
        else:
            idx  = np.argmax(proba, axis=1)
            conf = np.max(proba, axis=1)
            _use_per_class_thr = False

        labels = self.label_encoder.inverse_transform(idx)

        classes = [str(c) for c in self.label_encoder.classes_]
        benign_label = str(list(self.label_encoder.classes_)[self._benign_index or 0])

        # Pre-cache enrich() — only ~8 unique labels exist, no need to call per row.
        unique_labels = set(labels.tolist()) | {"Unknown"}
        enrich_cache: Dict[str, Dict] = {lbl: enrich(lbl) for lbl in unique_labels}

        # Pre-compute explainability vectors for the predicted class of each flow.
        explanations = self._build_feature_explanations(Xs, idx, raw_df)

        # Pre-compute per-row probabilities as rounded numpy array to avoid
        # per-row dict comprehension overhead on large scans.
        proba_rounded = np.round(proba.astype(np.float32), 4)

        results: List[Dict[str, Any]] = []
        for i, (label, c, p) in enumerate(zip(labels, conf, proba_rounded)):
            is_anomalous = bool(anomaly_flag[i]) if anomaly_flag is not None else False
            # Per-class threshold (v6) or global threshold (v2-v5)
            eff_threshold = (
                self._per_class_thresholds.get(str(label), self.confidence_threshold)
                if _use_per_class_thr
                else self.confidence_threshold
            )
            if c < eff_threshold:
                final_label = "Unknown"
            elif is_anomalous and c < 0.75 and label == benign_label:
                final_label = "Unknown"
            else:
                final_label = label

            # Skip building full dict for Benign — callers only need predicted + confidence.
            if final_label == "Benign":
                results.append({"predicted": "Benign", "confidence": round(float(c), 4)})
                continue

            mitre = enrich_cache.get(final_label) or enrich_cache["Unknown"]
            explanation_payload = None
            if explanations and explanations[i]:
                exp_entry = explanations[i]
                top_features = exp_entry.get("top_features")
                narrative = build_narrative(
                    final_label,
                    top_features=top_features,
                    feature_map=exp_entry.get("feature_map"),
                    confidence=float(c),
                    anomaly=is_anomalous,
                    mitre=mitre,
                )
                explanation_payload = {
                    **narrative,
                    "top_features": top_features,
                }

            results.append(
                {
                    "predicted": final_label,
                    "confidence": round(float(c), 4),
                    "anomaly": is_anomalous,
                    "probabilities": {classes[k]: float(p[k]) for k in range(len(p))},
                    "mitre_technique": mitre["technique"],
                    "mitre_tactic": mitre["tactic"],
                    "severity": mitre["severity"],
                    "description": mitre["description"],
                    "explanation": explanation_payload,
                }
            )
        return results

    @property
    def _benign_index(self) -> int | None:
        try:
            for i, c in enumerate(self.label_encoder.classes_):
                if str(c).strip().lower() == "benign":
                    return i
        except Exception:
            pass
        return None

    def _select_explain_rows(self, class_indices: np.ndarray) -> np.ndarray:
        """Pick which flow rows get a (costly) SHAP explanation.

        SHAP over every flow is the dominant cost on large scans and makes the
        backend time out. We only explain attack flows (the ones an analyst
        actually cares about) and cap the count via settings.shap_max_flows.
        """
        cap = settings.shap_max_flows
        if cap <= 0:
            return np.array([], dtype=int)

        benign_idx = self._benign_index
        if benign_idx is not None:
            candidates = np.where(class_indices != benign_idx)[0]
        else:
            candidates = np.arange(len(class_indices))

        if candidates.size == 0:
            return candidates
        if candidates.size > cap:
            candidates = candidates[:cap]
        return candidates

    def _build_feature_explanations(
        self, Xs: np.ndarray, class_indices: np.ndarray, raw_df: pd.DataFrame | None
    ) -> List[Dict[str, Any]] | None:
        if raw_df is None or self.feature_names is None or not len(self.feature_names):
            return None

        n = Xs.shape[0]
        sel = self._select_explain_rows(class_indices)
        if sel.size == 0:
            return None

        # Compute SHAP only for the selected subset, then scatter the vectors
        # back to their original row positions (None for unexplained flows).
        subset_vectors = self._compute_shap_vectors(Xs[sel], class_indices[sel])
        if not subset_vectors:
            return None
        vec_by_row: Dict[int, np.ndarray] = {
            int(row): subset_vectors[j] for j, row in enumerate(sel)
        }

        raw_matrix = raw_df.reindex(columns=self.feature_names, fill_value=0.0)
        raw_values = raw_matrix.to_numpy(dtype=float)

        explanations: List[Dict[str, Any]] = []
        for i in range(n):
            vec = vec_by_row.get(i)
            if vec is None:
                explanations.append(None)
                continue
            abs_vals = np.abs(vec)
            top = np.argsort(abs_vals)[-3:][::-1]
            features = []
            for feat_idx in top:
                feat = self.feature_names[feat_idx]
                impact = float(vec[feat_idx])
                features.append(
                    {
                        "feature": feat,
                        "impact": round(impact, 4),
                        "direction": "increase" if impact >= 0 else "decrease",
                        "value": round(float(raw_values[i][feat_idx]), 4),
                    }
                )
            feature_map = {
                name: float(raw_values[i][idx])
                for idx, name in enumerate(self.feature_names)
            }
            explanations.append({
                "top_features": features,
                "feature_map": feature_map,
            })
        return explanations

    def _compute_shap_vectors(
        self, Xs: np.ndarray, class_indices: np.ndarray
    ) -> List[np.ndarray] | None:
        if shap is None:
            return None
        if self.version in ("v2", "v3", "v4", "v5") and self._xgb_explainer and self._lgbm_explainer:
            shap_xgb = self._extract_shap(self._xgb_explainer, Xs, class_indices)
            shap_lgbm = self._extract_shap(self._lgbm_explainer, Xs, class_indices)
            return [
                (x + y) / 2.0 if x is not None and y is not None else None
                for x, y in zip(shap_xgb, shap_lgbm)
            ]
        if self._model_explainer:
            return self._extract_shap(self._model_explainer, Xs, class_indices)
        return None

    def _extract_shap(
        self, explainer: shap.TreeExplainer, Xs: np.ndarray, class_indices: np.ndarray
    ) -> List[np.ndarray]:
        values = explainer.shap_values(Xs)
        vectors: List[np.ndarray] = []
        for i, cls_idx in enumerate(class_indices):
            if isinstance(values, list):
                # Legacy SHAP: list of per-class arrays, each (n_samples, n_features).
                vec = values[int(cls_idx)][i]
            else:
                # Modern SHAP returns a single ndarray. For multiclass tree models
                # this is 3D (n_samples, n_features, n_classes); selecting values[i]
                # then leaves a 2D (n_features, n_classes) matrix, so we must pick
                # the predicted class column to recover the per-feature vector.
                sample = values[i]
                if sample.ndim == 2:
                    vec = sample[:, int(cls_idx)]
                else:
                    vec = sample
            vectors.append(np.array(vec, dtype=float))
        return vectors

    def predict_flow(self, features: Dict[str, float]) -> Dict[str, Any]:
        """Predict a single flow given a dict of feature_name -> value.

        Missing features are filled with 0; unknown keys are ignored.
        """
        self.load()
        row = [float(features.get(name, 0.0)) for name in self.feature_names]
        raw_df = pd.DataFrame([row], columns=self.feature_names)
        if self.drift is not None:
            self.drift.record(features)
        return self._predict_array(np.array([row], dtype=float), raw_df=raw_df)[0]

    def predict_dataframe(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Predict on a DataFrame whose columns match self.feature_names.

        Missing columns are added with 0; extra columns are ignored.
        """
        self.load()
        # Align columns (preserve metadata cols like src_ip in df, but model only sees features)
        X_df = df.reindex(columns=self.feature_names, fill_value=0.0)
        X_df = X_df.apply(pd.to_numeric, errors="coerce")
        X_df = X_df.replace([np.inf, -np.inf], np.nan).fillna(0.0)
        return self._predict_array(X_df.to_numpy(dtype=float), raw_df=X_df)

    def _build_prediction_payload(
        self,
        df: pd.DataFrame,
        predictions: List[Dict[str, Any]],
        extra_meta: List[Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        if df.empty:
            return {"total_flows": 0, "summary": {}, "flows": []}

        meta_quality = self._compute_metadata_quality(df)

        meta_cols = [
            c for c in (
                "flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
                "Flow Bytes/s", "Flow Packets/s", "Packet Length Mean", "Packet Length Std",
                "_source_breakdown", "_unique_sources", "_dest_breakdown", "_unique_dests",
            )
            if c in df.columns
        ]
        meta = df[meta_cols].to_dict(orient="records") if meta_cols else [{}] * len(predictions)

        if extra_meta is None:
            extra_meta = [{}] * len(predictions)

        # Vectorised summary — Counter is ~5× faster than a manual dict loop
        summary: Dict[str, int] = dict(Counter(p["predicted"] for p in predictions))
        attacks  = sum(c for k, c in summary.items() if k != "Benign")
        avg_conf = float(np.mean([p["confidence"] for p in predictions])) if predictions else 0.0

        detail_limit = settings.scan_flow_detail_limit

        # Collect non-benign candidates up to the detail cap in a single pass
        candidates: List[Tuple[Dict, Dict, Dict]] = []
        for m, ex, p in zip(meta, extra_meta, predictions):
            if p.get("predicted") == "Benign":
                continue
            if detail_limit > 0 and len(candidates) >= detail_limit:
                break
            candidates.append((m, ex, p))

        if not candidates:
            return {
                "total_flows": len(predictions),
                "benign": summary.get("Benign", 0),
                "attacks": attacks,
                "avg_confidence": round(avg_conf, 4),
                "summary": summary,
                "metadata_quality": meta_quality,
                "flows": [],
            }

        # Split candidates into chunks and process each chunk in a worker thread.
        # Threads share the same process so `self` is available without pickling;
        # JSON parsing inside _parse_flow_breakdowns can overlap across threads.
        n_workers  = min(os.cpu_count() or 4, 8)
        chunk_size = max(1, (len(candidates) + n_workers - 1) // n_workers)

        def _process_chunk(items: List[Tuple[Dict, Dict, Dict]]) -> List[Dict[str, Any]]:
            result: List[Dict[str, Any]] = []
            for m, extra, p in items:
                predicted = p.get("predicted")
                if not p.get("explanation"):
                    mitre = enrich(str(predicted))
                    p = {
                        **p,
                        "explanation": {
                            "summary": f"تم تصنيف التدفق كـ {predicted} بثقة {float(p.get('confidence') or 0.0) * 100:.1f}%.",
                            "verdict": f"النموذج صنّف التدفق كـ {predicted} مع ربطه بتكتيك {mitre['tactic']}.",
                            "details": [mitre["description"]],
                            "risk": f"خطورة {mitre['severity']}: {mitre['description']}",
                            "mitre_context": f"يرتبط هذا السلوك بتقنية MITRE {mitre['technique']} ضمن تكتيك {mitre['tactic']}.",
                        },
                    }
                flow_entry: Dict[str, Any] = {**m, **extra, **p}
                top_sources = self._parse_flow_breakdowns(flow_entry)
                if top_sources and flow_entry.get("predicted") in {"DDoS", "DoS"}:
                    explanation = flow_entry.get("explanation") or {}
                    details = explanation.setdefault("details", [])
                    pretty = ", ".join(
                        f"{item['ip']} ({item['count']})" for item in top_sources[:3]
                    )
                    details.append(f"أكثر المصادر المساهمة في الهجوم: {pretty}.")
                    explanation.setdefault(
                        "recommended_action",
                        "راجع المصادر الأكثر تكرارًا وحدّها عبر الجدار الناري أو مزود الإنترنت.",
                    )
                    flow_entry["explanation"] = explanation
                result.append(flow_entry)
            return result

        chunks = [candidates[i:i + chunk_size] for i in range(0, len(candidates), chunk_size)]
        flows: List[Dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as pool:
            for chunk_flows in pool.map(_process_chunk, chunks):
                flows.extend(chunk_flows)

        return {
            "total_flows": len(predictions),
            "benign": summary.get("Benign", 0),
            "attacks": attacks,
            "avg_confidence": round(avg_conf, 4),
            "summary": summary,
            "metadata_quality": meta_quality,
            "flows": flows,
        }

    def predict_pcap(self, pcap_path: Path) -> Dict[str, Any]:
        """Run full PCAP -> features -> predictions pipeline.

        Re-uses AI/pcap_to_features.py without modifying it.
        """
        self.load()

        # Lazy import - AI/ was added to sys.path during load()
        try:
            from pcap_to_features import pcap_to_dataframe  # type: ignore
        except ImportError as e:
            raise RuntimeError(
                f"Could not import pcap_to_features from {settings.ai_package_path}: {e}"
            )

        max_flows = settings.pcap_max_flows if settings.pcap_max_flows > 0 else None

        t0 = time.perf_counter()
        logger.info("Extracting flows from %s (limit=%s)", pcap_path, max_flows or "none")
        df = pcap_to_dataframe(
            str(pcap_path),
            self.feature_names,
            max_flows=max_flows,
            worker_threads=self.pcap_workers,
        )
        sampled = max_flows is not None and len(df) >= max_flows
        logger.info(
            "Flow extraction done: %d flows in %.1fs%s",
            len(df), time.perf_counter() - t0,
            " (truncated)" if sampled else "",
        )

        # Skip payload sampling for large PCAPs — it requires a second full read
        # of the file and adds significant latency for captures > 50k flows.
        run_payload = settings.enable_payload_sampling and len(df) <= 50_000
        payload_samples = extract_payload_samples(pcap_path, df) if run_payload else []

        if df.empty:
            return {
                "total_flows": 0,
                "sampled": False,
                "summary": {},
                "flows": [],
            }

        predictions = self.predict_dataframe(df)
        self._apply_hybrid_attack_rules(df, predictions)
        if payload_samples:
            for prediction, sample in zip(predictions, payload_samples):
                if not sample:
                    continue
                explanation = prediction.get("explanation") or {
                    "summary": "تم التقاط حمولة ممثلة لهذا التدفق.",
                    "details": [],
                }
                explanation["payload_sample"] = sample
                prediction["explanation"] = explanation
            self._refine_web_attacks_from_payload(predictions, payload_samples)

        # Heuristic short-circuit: rows that ``_aggregate_scan_flows`` synthesised
        # from large single-packet SYN bursts are tagged with a forced label
        # (``DDoS`` or ``Port Scan``). The CICIDS2017 model can't recognise
        # textbook SYN-floods because that pattern is absent from its training
        # set, so we override the ML prediction for those rows with the
        # heuristic label and a confidence reflecting the burst size.
        if "_synthetic_label" in df.columns:
            forced = df["_synthetic_label"].fillna("").astype(str).tolist()
            pkt_counts = df.get("Total Fwd Packets")
            for i, label in enumerate(forced):
                if not label:
                    continue
                count = int(pkt_counts.iloc[i]) if pkt_counts is not None else 0
                # Saturate near 1.0 once we have ~750 packets in the burst.
                conf = round(min(0.99, 0.85 + count / 5000.0), 4)
                mitre = enrich(label)
                explanation = predictions[i].get("explanation")
                heuristic_detail = (
                    f"تم تفعيل قاعدة SYN burst بعد رصد {count} حزمة متتالية من المصدر نفسه."
                )
                src_ip = str(df.iloc[i].get("src_ip", "") or "")
                dst_ip = str(df.iloc[i].get("dst_ip", "") or "")
                if label == "DDoS" and src_ip == "MULTIPLE":
                    heuristic_detail = (
                        f"تم تفعيل قاعدة DDoS بعد رصد {count} حزمة باتجاه {dst_ip} من عدة مصادر؛ "
                        "لا يوجد مصدر واحد يمكن حظره بأمان."
                    )
                elif label == "DoS" and src_ip:
                    heuristic_detail = (
                        f"تم تفعيل قاعدة DoS بعد رصد {count} حزمة متتالية من المصدر {src_ip} باتجاه {dst_ip}."
                    )
                if explanation:
                    explanation.setdefault("details", []).append(heuristic_detail)
                    explanation.setdefault("summary", "SYN burst heuristic applied")
                    explanation.setdefault("top_features", []).append(
                        {
                            "feature": "Total Fwd Packets",
                            "impact": float(count),
                            "direction": "increase",
                            "value": float(count),
                        }
                    )
                else:
                    explanation = {
                        "summary": "SYN burst heuristic applied",
                        "details": [heuristic_detail],
                        "top_features": [
                            {
                                "feature": "Total Fwd Packets",
                                "impact": float(count),
                                "direction": "increase",
                                "value": float(count),
                            }
                        ],
                    }
                if label == "DDoS" and src_ip == "MULTIPLE":
                    explanation["recommended_action"] = (
                        "لا تحظر IP واحدًا؛ فعّل rate limiting أو حماية upstream/CDN، وراجع قائمة المصادر الأكثر تكرارًا."
                    )
                elif label == "DoS" and src_ip:
                    explanation["recommended_action"] = (
                        f"يمكن حظر أو تقييد المصدر {src_ip} مؤقتًا، مع مراقبة استمرار الهجوم على الوجهة {dst_ip}."
                    )
                else:
                    explanation["recommended_action"] = (
                        "لا توجد هوية مصدر كافية للحظر الدقيق؛ استخدم rate limiting وراجع PCAP لاستخراج المصدر."
                    )
                predictions[i] = {
                    "predicted": label,
                    "confidence": conf,
                    "anomaly": True,
                    "probabilities": {label: conf, "Benign": round(1.0 - conf, 4)},
                    "mitre_technique": mitre["technique"],
                    "mitre_tactic": mitre["tactic"],
                    "severity": mitre["severity"],
                    "description": mitre["description"],
                    "explanation": explanation,
                }

        self._add_unknown_explanations(df, predictions)
        payload = self._build_prediction_payload(df, predictions)
        payload["sampled"] = sampled
        payload["sampled_rows"] = len(df)
        return payload

    def _apply_hybrid_attack_rules(self, df: pd.DataFrame, predictions: List[Dict[str, Any]]) -> None:
        """Vectorised hybrid rule engine — evaluates all rows simultaneously via
        numpy boolean masks, then only loops over the small matched subset."""
        n = len(predictions)
        if n == 0 or df.empty:
            return

        def _col(name: str, default: float = 0.0) -> np.ndarray:
            if name not in df.columns:
                return np.full(n, default, dtype=float)
            return pd.to_numeric(df[name], errors="coerce").fillna(default).to_numpy(dtype=float)

        pred_labels = np.array([p.get("predicted", "") for p in predictions], dtype=object)

        dst_port   = _col("dst_port")
        src_port   = _col("src_port")
        proto      = _col("protocol")
        flow_bytes = _col("Flow Bytes/s")
        flow_pkts  = _col("Flow Packets/s")
        fwd_len    = _col("Fwd Packet Length Mean")
        bwd_len    = _col("Bwd Packet Length Mean")
        duration   = _col("Flow Duration")
        variance   = _col("Packet Length Variance")
        fwd_pkts   = _col("Total Fwd Packets")

        # Label-membership masks (computed once, reused across rules)
        be_un      = np.isin(pred_labels, ["Benign", "Unknown"])
        be_un_bo   = np.isin(pred_labels, ["Benign", "Unknown", "Bot"])
        be_un_port = np.isin(pred_labels, ["Benign", "Unknown", "Port Scan"])
        be_un_inf  = np.isin(pred_labels, ["Benign", "Unknown", "Infiltration"])

        # DNS short-circuit: non-suspicious DNS rows skip ALL subsequent rules
        is_dns = (proto == 17) & ((dst_port == 53) | (src_port == 53))
        dns_suspicious = (
            ((fwd_len > 200) & (variance > 300)) |
            ((flow_pkts > 500) & (fwd_len > 150)) |
            ((fwd_pkts > 1000) & (variance > 400))
        )
        skip = is_dns & ~dns_suspicious   # non-suspicious DNS → no rule applied

        # First-match-wins: rules applied in priority order via "unset only" writes
        result_label = np.full(n, "", dtype=object)
        result_conf  = np.zeros(n, dtype=float)

        def _apply(label: str, conf: float, mask: np.ndarray) -> None:
            hit = mask & (result_label == "")
            result_label[hit] = label
            result_conf[hit]  = conf

        _apply("DNS Tunneling",     0.88, is_dns & dns_suspicious & be_un)
        _apply("C2 Beaconing",      0.87, ~skip & (duration > 5_000_000) & (flow_pkts > 5) & (flow_pkts < 300) & (variance < 120) & be_un_bo)
        _apply("Data Exfiltration", 0.88, ~skip & (flow_bytes > 15_000) & (fwd_len > 900) & (duration > 3_000_000) & be_un_inf)
        _apply("Lateral Movement",  0.84, ~skip & np.isin(dst_port.astype(int), [445, 3389, 22, 5985, 5986]) & (fwd_pkts > 50) & (duration < 2_500_000) & be_un_port)
        _apply("Ransomware",        0.86, ~skip & (flow_bytes > 12_000) & (fwd_pkts > 800) & (variance > 500) & be_un)
        _apply("Malware",           0.85, ~skip & (bwd_len > 900) & (duration > 4_000_000) & (flow_pkts > 700) & be_un_bo)

        _REASONS: Dict[str, List[str]] = {
            "DNS Tunneling":     [
                "المنفذ 53/UDP مستخدم مع طول أو تكرار استعلامات مرتفع جداً (يتجاوز نمط DNS العادي).",
                "النمط يشير إلى احتمال تمرير بيانات داخل DNS بدلاً من استعلامات أسماء عادية.",
            ],
            "C2 Beaconing":      [
                "الاتصال طويل ومنتظم وبحجم حزم شبه ثابت.",
                "هذا يشبه beacon دوري بين جهاز داخلي وجهة تحكم خارجية.",
            ],
            "Data Exfiltration": [
                "معدل البيانات الخارجة وحجم الحزم مرتفعان لفترة مستمرة.",
                "النمط يتوافق مع سحب أو تسريب بيانات وليس تصفحًا عاديًا.",
            ],
            "Lateral Movement":  [
                "الاتصال يستهدف خدمة إدارية داخلية شائعة مثل SMB/RDP/SSH/WinRM.",
                "عدد المحاولات وزمن الجلسة القصير يدعمان فرضية انتقال داخلي.",
            ],
            "Ransomware":        [
                "حجم الحركة وعدد الحزم وتباينها يشبه نشاط قراءة/كتابة مكثف.",
                "هذا قد يرتبط بتشفير ملفات أو انتشار عدوى داخل الشبكة.",
            ],
            "Malware":           [
                "ردود كبيرة واتصال طويل مع معدل حزم مرتفع.",
                "النمط قد يدل على تنزيل payload أو قناة تحكم لبرمجية خبيثة.",
            ],
        }

        for idx in np.where(result_label != "")[0]:
            lbl = str(result_label[idx])
            self._override_prediction(predictions[idx], lbl, float(result_conf[idx]), _REASONS[lbl])

    def _override_prediction(
        self, prediction: Dict[str, Any], label: str, confidence: float, reasons: List[str]
    ) -> None:
        mitre = enrich(label)
        prediction["predicted"] = label
        prediction["confidence"] = round(max(float(prediction.get("confidence") or 0.0), confidence), 4)
        prediction["anomaly"] = True
        prediction["mitre_technique"] = mitre["technique"]
        prediction["mitre_tactic"] = mitre["tactic"]
        prediction["severity"] = mitre["severity"]
        prediction["description"] = mitre["description"]
        prediction["probabilities"] = {
            **dict(prediction.get("probabilities") or {}),
            label: prediction["confidence"],
        }
        explanation = prediction.get("explanation") or {"details": []}
        explanation["summary"] = f"تم ترقية التصنيف إلى {label} بواسطة طبقة كشف هجينة تجمع بين ML وقواعد سلوكية."
        explanation["verdict"] = f"النتيجة: {label}. توجد مؤشرات سلوكية قوية تدعم التصنيف حتى لو النموذج الأساسي لم يكن مدربًا عليه مباشرة."
        explanation.setdefault("details", []).extend(reasons)
        explanation["risk"] = f"خطورة {mitre['severity']}: {mitre['description']}"
        explanation["mitre_context"] = f"يرتبط هذا السلوك بتقنية MITRE {mitre['technique']} ضمن تكتيك {mitre['tactic']}."
        prediction["explanation"] = explanation

    def _add_unknown_explanations(self, df: pd.DataFrame, predictions: List[Dict[str, Any]]) -> None:
        rows = df.to_dict('records')
        for row, prediction in zip(rows, predictions):
            if prediction.get("predicted") != "Unknown":
                continue
            prediction["explanation"] = self._build_unknown_explanation(row)

    def _build_unknown_explanation(self, row: pd.Series | None) -> Dict[str, Any]:
        mitre = enrich("Unknown")
        details: List[str] = []
        summary = "تم تصنيف التدفق كـ Unknown لأن سلوكه خارج نطاق التدريب الأصلي للنموذج."
        if row is not None:
            src_ip = str(row.get("src_ip", "") or "").strip()
            dst_ip = str(row.get("dst_ip", "") or "").strip()
            total_packets = self._num(row.get("Total Fwd Packets", 0)) + self._num(row.get("Total Backward Packets", 0))
            protocol = str(row.get("protocol", "") or "").strip().upper()
            if not src_ip:
                details.append("التدفق يفتقد عنوان المصدر، ما يرجح أن الالتقاط ناقص أو الحركة قادمة من طبقة لا تحمل IP (ARP/LLDP).")
            elif src_ip.upper() == "MULTIPLE":
                details.append("التدفق يمثل مجموعة مصادر متعددة ولم يتم دمجها في تصنيف محدد بعد.")
            if total_packets <= 3:
                details.append("عدد الحزم منخفض جدًا (≤3) مما يمنع النموذج من استنتاج نمط واضح.")
            if protocol in {"1", "58", "ICMP"}:
                details.append("الحركة من نوع ICMP/IPv6، وهي غير ممثلة بشكل كافٍ في بيانات التدريب الأصلية.")
            if not details:
                details.append("القيم الإحصائية لا تطابق أي هجوم معروف في بيانات التدريب ويجب مراجعتها يدويًا.")
        else:
            details.append("لم تتوفر بيانات إضافية عن التدفق، يُنصح بمراجعة PCAP مباشرةً.")

        return {
            "summary": summary,
            "verdict": "يتطلب مراجعة محلل بشرية قبل اتخاذ إجراء تلقائي.",
            "details": details,
            "risk": f"خطورة {mitre['severity']}: {mitre['description']}",
            "mitre_context": "لا يوجد تطابق مباشر مع تقنية MITRE محددة، يستدعي تحليلًا إضافيًا.",
            "recommended_action": "راجع PCAP أو فعّل التحليل المتقدم لتحديد طبيعة التدفق، ثم قم بتوسيم النتيجة يدويًا إن لزم.",
        }

    def _parse_flow_breakdowns(self, flow_entry: Dict[str, Any]) -> List[Dict[str, Any]] | None:
        raw_unique_sources = flow_entry.pop("_unique_sources", None)
        if raw_unique_sources is not None:
            try:
                flow_entry["unique_sources"] = int(float(raw_unique_sources))
            except Exception:
                flow_entry["unique_sources"] = raw_unique_sources

        raw_unique_dests = flow_entry.pop("_unique_dests", None)
        if raw_unique_dests is not None:
            try:
                flow_entry["unique_destinations"] = int(float(raw_unique_dests))
            except Exception:
                flow_entry["unique_destinations"] = raw_unique_dests

        top_sources = self._convert_breakdown(flow_entry, "_source_breakdown", "top_sources")
        self._convert_breakdown(flow_entry, "_dest_breakdown", "top_destinations")
        return top_sources

    def _convert_breakdown(self, entry: Dict[str, Any], key: str, target: str) -> List[Dict[str, Any]] | None:
        raw = entry.pop(key, None)
        if not raw:
            return None
        data = self._safe_json_load(raw)
        if not data:
            return None
        pairs = [
            {"ip": ip, "count": int(float(count)) if count is not None else 0}
            for ip, count in data.items()
        ]
        pairs.sort(key=lambda item: item["count"], reverse=True)
        entry[target] = pairs
        return pairs

    def _compute_metadata_quality(self, df: pd.DataFrame) -> Dict[str, Any]:
        total = len(df)
        quality: Dict[str, Any] = {"total_flows": total}
        if total == 0:
            return quality

        if "src_ip" in df.columns:
            src_series = df["src_ip"].astype(str).fillna("")
            quality["missing_src_ip"] = int(src_series.apply(lambda v: not v or v.strip().lower() in {"", "0", "nan", "none"}).sum())
            quality["multiple_source_flows"] = int((src_series.str.upper() == "MULTIPLE").sum())
            quality["ipv6_flows"] = int(src_series.str.contains(":").sum())
        else:
            quality.update({"missing_src_ip": total, "multiple_source_flows": 0, "ipv6_flows": 0})

        if "dst_ip" in df.columns:
            dst_series = df["dst_ip"].astype(str).fillna("")
            quality["missing_dst_ip"] = int(dst_series.apply(lambda v: not v or v.strip().lower() in {"", "0", "nan", "none"}).sum())
        else:
            quality["missing_dst_ip"] = total

        if "src_port" in df.columns:
            src_port_series = pd.to_numeric(df["src_port"], errors="coerce").fillna(0)
            quality["flows_missing_src_port"] = int((src_port_series == 0).sum())
        else:
            quality["flows_missing_src_port"] = total

        if "dst_port" in df.columns:
            dst_port_series = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0)
            quality["flows_missing_dst_port"] = int((dst_port_series == 0).sum())
        else:
            quality["flows_missing_dst_port"] = total

        if "protocol" in df.columns:
            proto_series = pd.to_numeric(df["protocol"], errors="coerce")
            quality["icmp_like_flows"] = int(proto_series.isin([1, 58]).sum())
        else:
            quality["icmp_like_flows"] = 0

        top_sources = Counter()
        if "_source_breakdown" in df.columns:
            for raw in df["_source_breakdown"]:
                data = self._safe_json_load(raw)
                if not data:
                    continue
                for ip, count in data.items():
                    try:
                        top_sources[ip] += int(float(count))
                    except Exception:
                        continue
        if top_sources:
            quality["top_source_candidates"] = [
                {"ip": ip, "count": count}
                for ip, count in top_sources.most_common(10)
            ]

        return quality

    @staticmethod
    def _safe_json_load(value: Any) -> Dict[str, Any] | None:
        if not value:
            return None
        if isinstance(value, dict):
            return value
        try:
            return json.loads(value)
        except Exception:
            return None

    @staticmethod
    def _num(value: Any) -> float:
        try:
            if value is None or pd.isna(value):
                return 0.0
            return float(value)
        except Exception:
            return 0.0

    def _refine_web_attacks_from_payload(
        self, predictions: List[Dict[str, Any]], payload_samples: List[Dict[str, Any] | None]
    ) -> None:
        for prediction, sample in zip(predictions, payload_samples):
            if prediction.get("predicted") != "Web Attack" or not sample:
                continue
            payload = str(sample.get("ascii") or "").lower()
            refined = self._classify_web_payload(payload)
            if not refined:
                continue
            mitre = enrich(refined)
            old_conf = float(prediction.get("confidence") or 0.0)
            prediction["predicted"] = refined
            prediction["confidence"] = round(max(old_conf, 0.88), 4)
            prediction["mitre_technique"] = mitre["technique"]
            prediction["mitre_tactic"] = mitre["tactic"]
            prediction["severity"] = mitre["severity"]
            prediction["description"] = mitre["description"]
            prediction["probabilities"] = {
                **dict(prediction.get("probabilities") or {}),
                refined: prediction["confidence"],
            }
            explanation = prediction.get("explanation") or {"details": []}
            explanation["summary"] = f"تم تضييق Web Attack إلى {refined} بناءً على مؤشرات واضحة في الحمولة."
            explanation.setdefault("details", []).append(
                f"تحليل الحمولة كشف نمطًا أقرب إلى {refined} بدل التصنيف العام Web Attack."
            )
            prediction["explanation"] = explanation

    def _classify_web_payload(self, payload: str) -> str | None:
        if not payload:
            return None
        if re.search(r"(\bunion\b.+\bselect\b|\bor\b\s+1\s*=\s*1|\bsleep\s*\(|information_schema|benchmark\s*\()", payload):
            return "SQL Injection"
        if re.search(r"(<script|javascript:|onerror\s*=|onload\s*=|document\.cookie|alert\s*\()", payload):
            return "XSS"
        if re.search(r"(\.\./|\.\.\\|/etc/passwd|boot\.ini|win\.ini|%2e%2e)", payload):
            return "Path Traversal"
        if re.search(r"(;\s*(cat|id|whoami|curl|wget|bash|sh)\b|\|\s*(cat|id|whoami|curl|wget|bash|sh)\b|`[^`]+`|\$\([^)]*\))", payload):
            return "Command Injection"
        return None

    _CSV_ROW_LIMIT = 500_000

    def predict_csv(self, csv_path: Path) -> Dict[str, Any]:
        """Run predictions on a CSV whose columns already contain features."""
        self.load()
        try:
            df = pd.read_csv(csv_path)
        except Exception as exc:  # pragma: no cover - pandas I/O errors
            raise RuntimeError(f"Failed to read CSV '{csv_path.name}': {exc}") from exc

        if df.empty:
            return {
                "total_flows": 0,
                "summary": {},
                "flows": [],
            }

        original_len = len(df)
        sampled = False
        if original_len > self._CSV_ROW_LIMIT:
            df = df.sample(n=self._CSV_ROW_LIMIT, random_state=42).reset_index(drop=True)
            sampled = True
            logger.warning(
                "CSV has %d rows — sampled down to %d for performance. "
                "Upload a smaller file for full analysis.",
                original_len, self._CSV_ROW_LIMIT,
            )

        predictions = self.predict_dataframe(df)
        self._apply_hybrid_attack_rules(df, predictions)
        extra_meta = [{"row": int(idx)} for idx in df.index]
        result = self._build_prediction_payload(df, predictions, extra_meta=extra_meta)
        if sampled:
            result["sampled"] = True
            result["original_rows"] = original_len
            result["sampled_rows"] = self._CSV_ROW_LIMIT
        return result


# Singleton instance — imported by routers
ml_service = MLService()
