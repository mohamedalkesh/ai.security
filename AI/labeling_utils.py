#!/usr/bin/env python3
"""Shared helpers for normalising dataset labels across corpora."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None


def _ensure_yaml_available() -> None:
    if yaml is None:
        raise RuntimeError(
            "PyYAML is required for dataset manifest parsing. Install via 'pip install PyYAML'."
        )


def _flatten_aliases(raw_mapping: Mapping[str, Any]) -> Dict[str, str]:
    aliases: Dict[str, str] = {}
    for canonical, raw_aliases in raw_mapping.items():
        if canonical is None:
            continue
        canonical_clean = str(canonical).strip()
        if not canonical_clean:
            continue
        aliases[canonical_clean] = canonical_clean
        aliases[canonical_clean.lower()] = canonical_clean
        if not raw_aliases:
            continue
        if isinstance(raw_aliases, (str, bytes)):
            iter_aliases: Iterable[Any] = [raw_aliases]
        else:
            iter_aliases = raw_aliases  # type: ignore[assignment]
        for item in iter_aliases:
            if item is None:
                continue
            alias = str(item).strip()
            if not alias:
                continue
            aliases[alias] = canonical_clean
            aliases[alias.lower()] = canonical_clean
    return aliases


def _normalise_dataset_map(
    mapping: Optional[Mapping[str, str]],
    canonical_aliases: Mapping[str, str],
) -> Dict[str, str]:
    if not mapping:
        return {}
    normalised: Dict[str, str] = {}
    for raw_label, canonical in mapping.items():
        if raw_label is None:
            continue
        key = str(raw_label).strip()
        if not key:
            continue
        canonical_target = canonical_aliases.get(canonical, canonical)
        canonical_target = canonical_aliases.get(canonical_target.lower(), canonical_target)
        normalised[key] = canonical_target
        normalised[key.lower()] = canonical_target
    return normalised


@dataclass
class LabelMap:
    """Map dataset-specific labels to canonical operational classes."""

    canonical_aliases: Dict[str, str]
    dataset_maps: Dict[str, Dict[str, str]]
    default_label: str = "Unknown"

    @classmethod
    def from_file(cls, path: str | Path) -> "LabelMap":
        _ensure_yaml_available()
        file_path = Path(path).expanduser().resolve()
        if not file_path.exists():
            raise FileNotFoundError(f"Label map not found: {file_path}")
        loaded = yaml.safe_load(file_path.read_text()) or {}
        canonical_data = loaded.get("canonical") or {}
        dataset_data = loaded.get("datasets") or {}
        default_label = loaded.get("default_label", "Unknown")

        canonical_aliases = _flatten_aliases(canonical_data)
        dataset_maps = {
            name: _normalise_dataset_map(mapping, canonical_aliases)
            for name, mapping in dataset_data.items()
        }
        return cls(canonical_aliases=canonical_aliases, dataset_maps=dataset_maps, default_label=default_label)

    # ------------------------------------------------------------------
    def normalise(self, raw_label: Any, dataset_key: Optional[str] = None) -> str:
        if raw_label is None:
            return self.default_label
        label = str(raw_label).strip()
        if not label:
            return self.default_label

        dataset_lookup = self.dataset_maps.get(dataset_key or "", {})
        candidate = dataset_lookup.get(label)
        if candidate is None:
            candidate = dataset_lookup.get(label.lower())
        if candidate is None:
            candidate = self.canonical_aliases.get(label)
        if candidate is None:
            candidate = self.canonical_aliases.get(label.lower())
        if candidate is None:
            return label
        return self.canonical_aliases.get(candidate.lower(), candidate)

    # ------------------------------------------------------------------
    def normalise_many(
        self,
        labels: Sequence[Any],
        dataset_keys: Optional[Sequence[Optional[str]] | str] = None,
    ) -> List[str]:
        if isinstance(dataset_keys, str):
            dataset_iter: List[Optional[str]] = [dataset_keys] * len(labels)
        elif dataset_keys is None:
            dataset_iter = [None] * len(labels)
        else:
            if len(dataset_keys) != len(labels):
                raise ValueError("dataset_keys length must match labels length")
            dataset_iter = list(dataset_keys)
        return [self.normalise(label, ds) for label, ds in zip(labels, dataset_iter)]

    # ------------------------------------------------------------------
    def available_labels(self) -> List[str]:
        labels = {v for v in self.canonical_aliases.values()}
        labels.add(self.default_label)
        return sorted(labels)

    # ------------------------------------------------------------------
    def datasets(self) -> List[str]:
        return sorted(self.dataset_maps.keys())


__all__ = ["LabelMap"]
