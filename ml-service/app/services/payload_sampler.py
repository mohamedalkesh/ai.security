"""Extract representative payload snippets per flow for richer explanations."""

from __future__ import annotations

import logging
import math
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Optional, Tuple

import pandas as pd

try:  # scapy is optional but strongly recommended for payload previews
    from scapy.all import IP, IPv6, TCP, UDP, Raw, PcapReader  # type: ignore
except Exception:  # pragma: no cover - payload previews degrade gracefully
    IP = IPv6 = TCP = UDP = Raw = PcapReader = None  # type: ignore

logger = logging.getLogger(__name__)

FlowKey = Tuple[str, str, int, int, int]
PayloadSample = Dict[str, object]


@dataclass
class _FlowBucket:
    """Holds indices of flows sharing the same 5-tuple."""

    canonical: FlowKey
    indices: Deque[int] = field(default_factory=deque)
    aliases: List[FlowKey] = field(default_factory=list)


def extract_payload_samples(
    pcap_path: Path,
    df: pd.DataFrame,
    *,
    max_bytes: int = 96,
) -> List[Optional[PayloadSample]]:
    """Return a payload preview per DataFrame row (if available)."""

    if PcapReader is None:
        logger.debug("scapy unavailable; skipping payload sampling")
        return [None] * len(df)

    if df.empty:
        return []

    required = {"src_ip", "dst_ip", "protocol"}
    if not required.issubset(df.columns):
        logger.debug("Flow metadata missing (%s), payload previews disabled", required)
        return [None] * len(df)

    buckets, alias_map, pending = _build_flow_buckets(df.itertuples(index=False), max_len=len(df))
    samples: List[Optional[PayloadSample]] = [None] * len(df)
    if pending == 0:
        return samples

    try:
        reader = PcapReader(str(pcap_path))
    except Exception as exc:  # pragma: no cover - scapy I/O errors
        logger.warning("Failed to open PCAP for payload sampling: %s", exc)
        return samples

    try:
        for pkt in reader:
            meta = _packet_meta(pkt)
            if meta is None:
                continue

            bucket = buckets.get(meta["key"]) or alias_map.get(meta["key"])
            if bucket is None or not bucket.indices:
                continue

            payload = meta.get("payload")
            if payload is None:
                continue

            idx = bucket.indices.popleft()
            samples[idx] = _format_payload(payload, max_bytes=max_bytes, timestamp=meta.get("timestamp"))
            pending -= 1

            if not bucket.indices:
                buckets.pop(bucket.canonical, None)
                for alias in bucket.aliases:
                    alias_map.pop(alias, None)

            if pending <= 0:
                break
    finally:
        reader.close()

    return samples


def _build_flow_buckets(rows: Iterable[pd.Series], max_len: int) -> Tuple[Dict[FlowKey, _FlowBucket], Dict[FlowKey, _FlowBucket], int]:
    buckets: Dict[FlowKey, _FlowBucket] = {}
    alias_map: Dict[FlowKey, _FlowBucket] = {}
    pending = 0

    for idx, row in enumerate(rows):
        if idx >= max_len:
            break
        key = _row_to_key(row)
        if key is None:
            continue
        bucket = buckets.get(key)
        if bucket is None:
            bucket = _FlowBucket(canonical=key)
            buckets[key] = bucket
        bucket.indices.append(idx)
        pending += 1

        rev_key = (key[1], key[0], key[3], key[2], key[4])
        if rev_key != key:
            bucket.aliases.append(rev_key)
            alias_map[rev_key] = bucket

    return buckets, alias_map, pending


def _row_to_key(row: pd.Series) -> FlowKey | None:
    src_ip = _normalize_ip(getattr(row, "src_ip", None))
    dst_ip = _normalize_ip(getattr(row, "dst_ip", None))
    if not src_ip or not dst_ip:
        return None
    src_port = _normalize_port(getattr(row, "src_port", None))
    dst_port = _normalize_port(getattr(row, "dst_port", None))
    protocol = _normalize_port(getattr(row, "protocol", None))
    return (src_ip, dst_ip, src_port, dst_port, protocol)


def _normalize_ip(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return text


def _normalize_port(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    try:
        num = float(value)
    except (TypeError, ValueError):
        return 0
    if math.isnan(num):
        return 0
    return int(num)


def _packet_meta(pkt) -> Optional[Dict[str, object]]:  # pragma: no cover - scapy heavy
    layer_ip = None
    proto = 0
    if IP is not None and IP in pkt:
        layer_ip = pkt[IP]
        proto = int(layer_ip.proto)
    elif IPv6 is not None and IPv6 in pkt:
        layer_ip = pkt[IPv6]
        proto = int(layer_ip.nh)
    if layer_ip is None:
        return None

    src_ip = str(layer_ip.src)
    dst_ip = str(layer_ip.dst)
    src_port = dst_port = 0
    if TCP is not None and TCP in pkt:
        tcp = pkt[TCP]
        src_port, dst_port = int(tcp.sport), int(tcp.dport)
        l4_payload = bytes(bytes(tcp.payload))
    elif UDP is not None and UDP in pkt:
        udp = pkt[UDP]
        src_port, dst_port = int(udp.sport), int(udp.dport)
        l4_payload = bytes(bytes(udp.payload))
    else:
        l4_payload = bytes(bytes(layer_ip.payload)) if hasattr(layer_ip, "payload") else b""

    raw_payload = bytes(pkt[Raw]) if Raw is not None and Raw in pkt else l4_payload
    payload = raw_payload if raw_payload else None
    return {
        "key": (src_ip, dst_ip, src_port, dst_port, proto),
        "payload": payload,
        "timestamp": float(getattr(pkt, "time", 0.0)),
    }


def _format_payload(payload: bytes, *, max_bytes: int, timestamp: float | None) -> PayloadSample:
    payload = payload or b""
    trimmed = payload[:max_bytes]
    ascii_preview = _ascii_preview(trimmed)
    hex_preview = trimmed.hex()
    note = None
    if not trimmed:
        note = "لا توجد حمولة تطبيقية (حزم تحكم فقط)."
    elif len(payload) > max_bytes:
        note = f"تم عرض أول {max_bytes} بايت من أصل {len(payload)}."

    sample: PayloadSample = {
        "size_bytes": len(payload),
        "preview_bytes": len(trimmed),
        "hex": hex_preview,
        "ascii": ascii_preview,
        "timestamp": timestamp or 0.0,
    }
    if note:
        sample["note"] = note
    return sample


def _ascii_preview(data: bytes, width: int = 2) -> str:
    if not data:
        return ""
    chars = []
    for b in data:
        if 32 <= b <= 126:
            chars.append(chr(b))
        else:
            chars.append(".")
    grouped = ["".join(chars[i : i + 32]) for i in range(0, len(chars), 32)]
    return "\n".join(grouped)
