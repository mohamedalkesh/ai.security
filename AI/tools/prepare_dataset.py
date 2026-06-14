#!/usr/bin/env python3
"""Normalize heterogeneous PCAP corpora into the model's feature space.

Currently a scaffold: consumes a YAML manifest, expands PCAP globs, converts
flows via ``pcap_to_dataframe`` and writes unified CSV/Parquet chunks with
harmonised labels (using ``labeling_utils.LabelMap``).

Usage (dry run):
    python3 AI/tools/prepare_dataset.py --manifest AI/datasets/manifest.example.yaml --dry-run
"""

from __future__ import annotations

import argparse
import glob
import logging
import pickle
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from labeling_utils import LabelMap  # noqa: E402
from pcap_to_features import pcap_to_dataframe  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("dataset-prep")


# ---------------------------------------------------------------------------
def _resolve_path(base_dir: Path, raw_path: str | Path) -> Path:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = (base_dir / path)
    return path


def _resolve_glob(base_dir: Path, pattern: str) -> str:
    pattern_path = Path(pattern).expanduser()
    if pattern_path.is_absolute():
        return str(pattern_path)
    return str((base_dir / pattern_path))


@dataclass
class DatasetSpec:
    name: str
    pcap_glob: str
    label_map_key: str
    output: Path
    base_dir: Path
    description: str = ""
    default_label: Optional[str] = None
    label_strategy: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(
        cls,
        raw: Dict[str, Any],
        manifest_dir: Path,
        output_dir: Path,
        default_ext: str,
    ) -> "DatasetSpec":
        name = str(raw.get("name"))
        if not name:
            raise ValueError("Dataset entry missing 'name'")
        glob_pattern = raw.get("pcap_glob")
        if not glob_pattern:
            raise ValueError(f"Dataset '{name}' missing 'pcap_glob'")
        label_key = str(raw.get("label_map_key", name))
        desc = str(raw.get("description", ""))
        metadata = raw.get("metadata", {}) or {}
        label_strategy = raw.get("label_strategy", {}) or {}

        out_field = raw.get("output")
        if out_field:
            out_path = _resolve_path(output_dir, out_field)
        else:
            out_path = (output_dir / f"{name}{default_ext}")
        out_path = out_path.resolve()

        return cls(
            name=name,
            pcap_glob=_resolve_glob(manifest_dir, str(glob_pattern)),
            label_map_key=label_key,
            output=out_path,
            base_dir=manifest_dir,
            description=desc,
            default_label=raw.get("default_label"),
            label_strategy=label_strategy,
            metadata=metadata,
        )


# ---------------------------------------------------------------------------
class DatasetWriter:
    def __init__(self, path: Path, fmt: str, overwrite: bool) -> None:
        self.path = path
        self.fmt = fmt
        self.overwrite = overwrite
        self._header_written = False
        path.parent.mkdir(parents=True, exist_ok=True)
        if overwrite and path.exists():
            path.unlink()
        elif path.exists():
            self._header_written = True

    def write(self, df: pd.DataFrame) -> None:
        if df.empty:
            return
        if self.fmt == "csv":
            df.to_csv(
                self.path,
                mode="a" if self._header_written else "w",
                index=False,
                header=not self._header_written,
            )
            self._header_written = True
        elif self.fmt == "parquet":  # pragma: no cover - optional dependency
            try:
                import pyarrow  # pylint: disable=unused-import
            except ImportError as exc:
                raise RuntimeError("Install pyarrow to export Parquet") from exc
            df.to_parquet(self.path, engine="pyarrow", append=self._header_written)
            self._header_written = True
        else:
            raise ValueError(f"Unsupported format: {self.fmt}")


# ---------------------------------------------------------------------------
def load_feature_names(path: Path) -> List[str]:
    with open(path, "rb") as fh:
        names = pickle.load(fh)
    if not isinstance(names, list):  # pragma: no cover - sanity guard
        raise ValueError(f"Feature file {path} did not contain a list")
    return names


def expand_pcaps(pattern: str) -> List[Path]:
    return [Path(p).resolve() for p in glob.glob(pattern)]


class BaseLabeler:
    def __init__(self, dataset_key: str, label_map: LabelMap, fallback: Optional[str] = None) -> None:
        self.dataset_key = dataset_key
        self.label_map = label_map
        self.fallback = fallback or label_map.default_label

    def _map(self, raw_labels: Sequence[Any]) -> List[str]:
        mapped = self.label_map.normalise_many(raw_labels, dataset_keys=self.dataset_key)
        return [label if label else self.fallback for label in mapped]

    def assign(self, df: pd.DataFrame) -> Tuple[List[str], List[str]]:  # pragma: no cover - interface
        raise NotImplementedError


class StaticLabeler(BaseLabeler):
    def __init__(self, dataset_key: str, label_map: LabelMap, label: str) -> None:
        super().__init__(dataset_key, label_map, fallback=label)
        self.label = label

    def assign(self, df: pd.DataFrame) -> Tuple[List[str], List[str]]:
        raw = [self.label] * len(df)
        return self._map(raw), raw


class CSVLabeler(BaseLabeler):
    def __init__(
        self,
        dataset_key: str,
        label_map: LabelMap,
        cfg: Dict[str, Any],
        fallback: Optional[str],
        base_dir: Path,
    ) -> None:
        super().__init__(dataset_key, label_map, fallback=fallback)
        if "path" not in cfg or "column" not in cfg:
            raise ValueError("CSV label strategy requires 'path' and 'column'")
        match_on = cfg.get("match_on") or []
        if isinstance(match_on, str):
            match_on = [match_on]
        if not match_on:
            raise ValueError("CSV label strategy must define 'match_on' columns")
        self.match_on = [str(c).strip() for c in match_on]
        self.column = str(cfg["column"]).strip()
        csv_path = Path(cfg["path"]).expanduser()
        if not csv_path.is_absolute():
            csv_path = (base_dir / csv_path).resolve()
        usecols = list(dict.fromkeys(self.match_on + [self.column]))
        logger.info("Loading label CSV %s (cols=%s)", csv_path, usecols)
        self.label_df = pd.read_csv(csv_path, usecols=usecols)
        self.label_df.columns = [col.strip() for col in self.label_df.columns]
        self.label_df[self.column] = self.label_df[self.column].astype(str).str.strip()

    def assign(self, df: pd.DataFrame) -> Tuple[List[str], List[str]]:
        missing = [col for col in self.match_on if col not in df.columns]
        if missing:
            raise ValueError(f"Flow dataframe missing join columns: {missing}")
        key_df = df[self.match_on].copy()
        key_df["__row_id"] = range(len(df))
        merged = key_df.merge(self.label_df, how="left", on=self.match_on)
        merged = merged.sort_values("__row_id")
        raw = merged[self.column].fillna(self.fallback)
        return self._map(raw.tolist()), raw.tolist()


def build_labeler(spec: DatasetSpec, label_map: LabelMap) -> BaseLabeler:
    strategy = (spec.label_strategy.get("type") or "static").lower()
    if strategy == "csv":
        return CSVLabeler(spec.label_map_key, label_map, spec.label_strategy, spec.default_label, spec.base_dir)
    if spec.default_label:
        return StaticLabeler(spec.label_map_key, label_map, spec.default_label)
    return StaticLabeler(spec.label_map_key, label_map, label_map.default_label)


# ---------------------------------------------------------------------------
def process_dataset(
    spec: DatasetSpec,
    label_map: LabelMap,
    feature_names: List[str],
    fmt: str,
    max_flows: Optional[int],
    dry_run: bool,
    overwrite: bool,
) -> None:
    logger.info("=== Dataset: %s ===", spec.name)
    logger.info("Description: %s", spec.description or "(none)")
    pcaps = expand_pcaps(spec.pcap_glob)
    if not pcaps:
        logger.warning("No files matched %s", spec.pcap_glob)
        return
    if dry_run:
        logger.info("Dry run: %d PCAP(s) matched", len(pcaps))
        return

    if spec.output.exists() and not overwrite:
        logger.warning("Output %s already exists (skipping). Use --overwrite to rebuild.", spec.output)
        return

    writer = DatasetWriter(spec.output, fmt, overwrite)
    labeler = build_labeler(spec, label_map)
    total = 0
    for pcap_path in pcaps:
        logger.info("Processing %s", pcap_path)
        try:
            df = pcap_to_dataframe(str(pcap_path), feature_names, max_flows=max_flows)
        except Exception as exc:  # pragma: no cover - NFStream runtime errors
            logger.exception("Failed to parse %s: %s", pcap_path, exc)
            continue

        df["source_dataset"] = spec.name
        df["pcap_file"] = pcap_path.name
        for key, value in spec.metadata.items():
            df[f"meta_{key}"] = value

        labels, raw_labels = labeler.assign(df)
        df["label"] = labels
        df["raw_label"] = raw_labels
        writer.write(df)
        total += len(df)
        logger.info("Added %d flows (total=%d)", len(df), total)

    logger.info("Finished dataset %s → %s (%d flows)", spec.name, spec.output, total)


# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare mixed corpora for training")
    parser.add_argument("--manifest", required=True, help="Path to dataset manifest YAML")
    parser.add_argument("--feature-names", required=True, help="Pickle file listing expected features")
    parser.add_argument("--format", choices=("csv", "parquet"), default="csv")
    parser.add_argument("--max-flows", type=int, default=None, help="Cap flows per PCAP (debug)")
    parser.add_argument("--dry-run", action="store_true", help="Only validate manifest + list PCAPs")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing outputs")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    manifest_path = Path(args.manifest).expanduser().resolve()
    manifest_dir = manifest_path.parent

    import yaml  # local import to keep dependency optional until runtime

    manifest = yaml.safe_load(manifest_path.read_text()) or {}
    label_map_path = manifest.get("label_map")
    if not label_map_path:
        raise ValueError("Manifest missing 'label_map' path")
    label_map = LabelMap.from_file((manifest_dir / label_map_path).resolve())

    output_dir = manifest.get("output_dir")
    output_base = Path(output_dir).expanduser() if output_dir else manifest_dir
    if not output_base.is_absolute():
        output_base = (manifest_dir / output_base).resolve()

    datasets = manifest.get("datasets") or []
    if not datasets:
        raise ValueError("Manifest contains no datasets")

    feature_names = load_feature_names(Path(args.feature_names))

    specs = [
        DatasetSpec.from_dict(
            entry,
            manifest_dir,
            output_base,
            default_ext=(".parquet" if args.format == "parquet" else ".csv"),
        )
        for entry in datasets
    ]
    for spec in specs:
        process_dataset(
            spec,
            label_map,
            feature_names,
            fmt=args.format,
            max_flows=args.max_flows,
            dry_run=args.dry_run,
            overwrite=args.overwrite,
        )


if __name__ == "__main__":
    main()
