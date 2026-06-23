"""Live network monitor service.

Captures flows from a network interface using NFStream in a background thread,
batch-classifies them with the trained IDS model, and buffers non-Benign
detections so the backend can poll them and persist as Alerts.

Upgrades over the original single-flow implementation:
- Batch inference (up to ``BATCH_SIZE`` flows per ``BATCH_INTERVAL_MS``) — 10-50x
  faster than per-flow ``predict_flow`` calls, which is the difference between
  "can cope with a noisy LAN" and "drops packets when a scan starts".
- Tighter NFStream timeouts (``idle_timeout=5``, ``active_timeout=30``) — attacks
  are flagged within ~5s of the flow going quiet instead of ~15s.
- Rolling-window rate (last 10s) rather than cumulative average, so the UI
  number reacts in real time instead of slowly drifting.
- Per-second buckets for flows/attacks so the frontend can draw a smooth
  sparkline without resampling.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from collections import Counter, deque, defaultdict
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple, Union

import numpy as np

from app.services.ml_service import ml_service
from app.services.mitre import enrich

logger = logging.getLogger(__name__)

# Tunables ---------------------------------------------------------------
BATCH_SIZE = 128           # max flows per inference call (was 64)
BATCH_INTERVAL_MS = 100    # flush even if batch not full (was 150)
RATE_WINDOW_SEC = 10       # rolling window for flows/sec and attacks/sec
HISTORY_SEC = 60           # per-second buckets retained for sparkline

# Parallel classifier workers — scales with CPU count so multi-core machines
# can drain the queue faster than a single thread allows.
N_CLASSIFY_WORKERS: int = max(2, (os.cpu_count() or 4) // 2)

# Queue depth — 20K allows bursts of ~47s at 427 flows/s before any drops.
QUEUE_MAXSIZE: int = 20_000

# Auto-restart — capture thread restarts on non-permission errors.
CAPTURE_RESTART_MAX: int = 5
CAPTURE_RESTART_DELAY_SEC: int = 3

# ── Behavioral Baseline tunables ─────────────────────────────────────────────
# After BASELINE_WARMUP_SEC of monitoring, the system learns each source IP's
# normal flow rate (flows per minute).  An IP that suddenly exceeds
# BASELINE_SPIKE_FACTOR × its own baseline is flagged as anomalous, even if
# the ML model classified the individual flows as Benign.
BASELINE_WARMUP_SEC: int   = 300   # 5 min warm-up before baseline is active
BASELINE_WINDOW_SEC: int   = 600   # sliding window to compute baseline mean
BASELINE_SPIKE_FACTOR: float = 5.0 # × normal rate → anomaly flag
BASELINE_MIN_FLOWS: int    = 10    # minimum flows needed to build a baseline

# ── Precision tunables ───────────────────────────────────────────────────────
# Only report a detection when the model is at least this confident.
# Filters out low-confidence "Unknown" classifications (e.g. 56%).
MIN_CONFIDENCE: float = 0.80

# Repeat-validation: a source IP must produce at least this many flows with
# the SAME attack label within REPEAT_WINDOW_SEC before the system raises an
# alert.  Single-flow anomalies (one probe, one metadata lookup) are suppressed.
# Set to 1 to disable (report every detection immediately).
MIN_REPEAT: int = 2
REPEAT_WINDOW_SEC: int = 60

# Well-known server ports.  Flows where the SOURCE port is one of these and the
# DESTINATION port is ephemeral (≥1024) are server responses, not attacks.
SERVER_PORTS: frozenset = frozenset({
    20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 143,
    161, 389, 443, 465, 587, 636, 993, 995, 3306, 3389,
    5432, 6379, 8080, 8443, 8888,
})

# ── Safe-destination whitelist ───────────────────────────────────────────────
# Flows to/from these addresses are ALWAYS Benign — the CICIDS2017 training set
# never contained local-network protocols so the model false-positives on them.
SAFE_DST_EXACT: frozenset = frozenset({
    "255.255.255.255",   # IPv4 limited broadcast
    "224.0.0.1",         # all-hosts multicast
    "224.0.0.2",         # all-routers multicast
    "224.0.0.22",        # IGMP v3
    "224.0.0.251",       # mDNS
    "224.0.0.252",       # LLMNR
    "239.255.255.250",   # SSDP / UPnP
})


def _is_safe_flow(meta: Dict[str, Any]) -> bool:
    """Return True when a flow must be labelled Benign without ML inference."""
    dst = str(meta.get("dst_ip") or "").strip().lower()
    src = str(meta.get("src_ip") or "").strip().lower()

    # IPv6 multicast ff00::/8 (ff02::1, ff02::16, ff02::fb, …)
    if dst.startswith("ff"):
        return True

    # Exact-match whitelist
    if dst in SAFE_DST_EXACT:
        return True

    # IPv4 multicast 224.0.0.0 – 239.255.255.255
    try:
        if 224 <= int(dst.split(".")[0]) <= 239:
            return True
    except (ValueError, IndexError):
        pass

    # Link-local 169.254.0.0/16 — APIPA self-assigned IPs and cloud IMDS
    # (169.254.169.254 is the AWS/Azure/GCP instance metadata endpoint).
    # Traffic to/from these addresses is always local-network housekeeping.
    if dst.startswith("169.254.") or src.startswith("169.254."):
        return True

    return False


def _is_response_flow(meta: Dict[str, Any]) -> bool:
    """Return True when a flow looks like a server response, not an attack.

    Pattern: well-known server port (≤1024 or in SERVER_PORTS) as source,
    high ephemeral port (≥1024) as destination.  This is the TCP/UDP response
    direction — the model was trained on client→server flows and consistently
    mis-labels server→client return traffic as attacks.
    """
    try:
        src_port = int(meta.get("src_port") or 0)
        dst_port = int(meta.get("dst_port") or 0)
    except (TypeError, ValueError):
        return False

    if dst_port < 1024:          # destination is also a server port → not a response
        return False
    return src_port in SERVER_PORTS or src_port <= 1024


# ICMP heuristics mirror AI/pcap_to_features.py defaults so the live
# monitor surfaces ping floods / sweeps without needing model retraining.
ICMP_PROTOCOLS = (1, 58)
ICMP_FLOOD_PKTS = 15       # single-flow packet threshold — catches normal test pings
ICMP_PROBE_THRESHOLD = 3   # ICMP flows to one dst within window → flood signal
ICMP_SWEEP_HOSTS = 3       # distinct hosts a source must touch → sweep
ICMP_WINDOW_SEC = 15       # sliding window for probe accounting

# Notable application-protocol port map. Used to tag benign flows so
# the UI can show real network activity (e.g. "an email was sent") even
# when nothing malicious was detected.
NOTABLE_PORTS: Dict[int, Tuple[str, str, bool]] = {
    # port: (protocol_label, category, is_encrypted)
    25:   ("SMTP",      "email", False),
    465:  ("SMTPS",     "email", True),
    587:  ("SMTP-SUB",  "email", True),  # usually STARTTLS
    110:  ("POP3",      "email", False),
    995:  ("POP3S",     "email", True),
    143:  ("IMAP",      "email", False),
    993:  ("IMAPS",     "email", True),
    53:   ("DNS",       "dns",   False),
    80:   ("HTTP",      "web",   False),
    443:  ("HTTPS",     "web",   True),
    22:   ("SSH",       "admin", True),
    21:   ("FTP",       "file",  False),
}


def _classify_port(src_port: Optional[int], dst_port: Optional[int], protocol: Optional[int]) -> Optional[Dict[str, Any]]:
    """Return {label, category, encrypted, port} if either side hits a notable port."""
    for p in (dst_port, src_port):  # destination first (typical client→server)
        if p is None:
            continue
        info = NOTABLE_PORTS.get(int(p))
        if info:
            label, category, enc = info
            return {"label": label, "category": category, "encrypted": enc, "port": int(p)}
    try:
        proto_num = int(protocol) if protocol is not None else None
    except (TypeError, ValueError):
        proto_num = None
    if proto_num in ICMP_PROTOCOLS:
        return {"label": "ICMP", "category": "network", "encrypted": False, "port": None}
    return None


def _nflow_to_feature_dict(flow) -> Dict[str, float]:
    """Map an NFStream bidirectional flow object to CICIDS2017 feature dict."""

    def g(name, default=0):
        return getattr(flow, name, default) or 0

    def safe(n, d):
        return (n / d) if d else 0

    return {
        "Flow Duration": g("bidirectional_duration_ms") * 1000.0,
        "Total Fwd Packets": g("src2dst_packets"),
        "Total Backward Packets": g("dst2src_packets"),
        "Total Length of Fwd Packets": g("src2dst_bytes"),
        "Total Length of Bwd Packets": g("dst2src_bytes"),
        "Fwd Packet Length Max": g("src2dst_max_ps"),
        "Fwd Packet Length Min": g("src2dst_min_ps"),
        "Fwd Packet Length Mean": g("src2dst_mean_ps"),
        "Fwd Packet Length Std": g("src2dst_stddev_ps"),
        "Bwd Packet Length Max": g("dst2src_max_ps"),
        "Bwd Packet Length Min": g("dst2src_min_ps"),
        "Bwd Packet Length Mean": g("dst2src_mean_ps"),
        "Bwd Packet Length Std": g("dst2src_stddev_ps"),
        "Flow Bytes/s": safe(g("bidirectional_bytes"), g("bidirectional_duration_ms") / 1000.0),
        "Flow Packets/s": safe(g("bidirectional_packets"), g("bidirectional_duration_ms") / 1000.0),
        "Flow IAT Mean": g("bidirectional_mean_piat_ms") * 1000.0,
        "Flow IAT Std": g("bidirectional_stddev_piat_ms") * 1000.0,
        "Flow IAT Max": g("bidirectional_max_piat_ms") * 1000.0,
        "Flow IAT Min": g("bidirectional_min_piat_ms") * 1000.0,
        "Fwd IAT Total": g("src2dst_duration_ms") * 1000.0,
        "Fwd IAT Mean": g("src2dst_mean_piat_ms") * 1000.0,
        "Fwd IAT Std": g("src2dst_stddev_piat_ms") * 1000.0,
        "Fwd IAT Max": g("src2dst_max_piat_ms") * 1000.0,
        "Fwd IAT Min": g("src2dst_min_piat_ms") * 1000.0,
        "Bwd IAT Total": g("dst2src_duration_ms") * 1000.0,
        "Bwd IAT Mean": g("dst2src_mean_piat_ms") * 1000.0,
        "Bwd IAT Std": g("dst2src_stddev_piat_ms") * 1000.0,
        "Bwd IAT Max": g("dst2src_max_piat_ms") * 1000.0,
        "Bwd IAT Min": g("dst2src_min_piat_ms") * 1000.0,
        "Fwd PSH Flags": g("src2dst_psh_packets"),
        "Bwd PSH Flags": g("dst2src_psh_packets"),
        "Fwd URG Flags": g("src2dst_urg_packets"),
        "Bwd URG Flags": g("dst2src_urg_packets"),
        "Fwd Header Length": g("src2dst_packets") * 40,
        "Bwd Header Length": g("dst2src_packets") * 40,
        "Fwd Header Length.1": g("src2dst_packets") * 40,
        "Fwd Packets/s": safe(g("src2dst_packets"), g("src2dst_duration_ms") / 1000.0),
        "Bwd Packets/s": safe(g("dst2src_packets"), g("dst2src_duration_ms") / 1000.0),
        "Min Packet Length": g("bidirectional_min_ps"),
        "Max Packet Length": g("bidirectional_max_ps"),
        "Packet Length Mean": g("bidirectional_mean_ps"),
        "Packet Length Std": g("bidirectional_stddev_ps"),
        "Packet Length Variance": g("bidirectional_stddev_ps") ** 2,
        "FIN Flag Count": g("bidirectional_fin_packets"),
        "SYN Flag Count": g("bidirectional_syn_packets"),
        "RST Flag Count": g("bidirectional_rst_packets"),
        "PSH Flag Count": g("bidirectional_psh_packets"),
        "ACK Flag Count": g("bidirectional_ack_packets"),
        "URG Flag Count": g("bidirectional_urg_packets"),
        "CWE Flag Count": g("bidirectional_cwr_packets"),
        "ECE Flag Count": g("bidirectional_ece_packets"),
        "Down/Up Ratio": safe(g("dst2src_packets"), g("src2dst_packets")),
        "Average Packet Size": g("bidirectional_mean_ps"),
        "Avg Fwd Segment Size": g("src2dst_mean_ps"),
        "Avg Bwd Segment Size": g("dst2src_mean_ps"),
        "Fwd Avg Bytes/Bulk": 0,
        "Fwd Avg Packets/Bulk": 0,
        "Fwd Avg Bulk Rate": 0,
        "Bwd Avg Bytes/Bulk": 0,
        "Bwd Avg Packets/Bulk": 0,
        "Bwd Avg Bulk Rate": 0,
        "Subflow Fwd Packets": g("src2dst_packets"),
        "Subflow Fwd Bytes": g("src2dst_bytes"),
        "Subflow Bwd Packets": g("dst2src_packets"),
        "Subflow Bwd Bytes": g("dst2src_bytes"),
        "Init_Win_bytes_forward": 0,
        "Init_Win_bytes_backward": 0,
        "act_data_pkt_fwd": g("src2dst_packets"),
        "min_seg_size_forward": g("src2dst_min_ps"),
        "Active Mean": 0, "Active Std": 0, "Active Max": 0, "Active Min": 0,
        "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0,
    }


def _flow_meta(flow) -> Dict[str, Any]:
    def _s(attr):
        v = getattr(flow, attr, None)
        return v if v else None

    return {
        # ── Identity ──────────────────────────────────────────────────────
        "src_ip":   getattr(flow, "src_ip",   None),
        "dst_ip":   getattr(flow, "dst_ip",   None),
        "src_port": getattr(flow, "src_port", None),
        "dst_port": getattr(flow, "dst_port", None),
        "protocol": getattr(flow, "protocol", None),
        "ip_version": getattr(flow, "ip_version", None),
        "vlan_id":  getattr(flow, "vlan_id",  None) or None,
        # ── Volume ────────────────────────────────────────────────────────
        "packets":              getattr(flow, "bidirectional_packets", 0),
        "bytes":                getattr(flow, "bidirectional_bytes",   0),
        "bidirectional_packets": getattr(flow, "bidirectional_packets", 0),
        "bidirectional_bytes":   getattr(flow, "bidirectional_bytes",   0),
        "src2dst_packets":       getattr(flow, "src2dst_packets", 0),
        "dst2src_packets":       getattr(flow, "dst2src_packets", 0),
        "src2dst_bytes":         getattr(flow, "src2dst_bytes",   0),
        "dst2src_bytes":         getattr(flow, "dst2src_bytes",   0),
        # ── Timing ────────────────────────────────────────────────────────
        "flow_duration_ms": getattr(flow, "bidirectional_duration_ms", 0),
        "first_seen_ms":    getattr(flow, "bidirectional_first_seen_ms", None),
        "last_seen_ms":     getattr(flow, "bidirectional_last_seen_ms",  None),
        # ── Layer-2 (available when DPI is on) ────────────────────────────
        "src_mac": _s("src_mac"),
        "dst_mac": _s("dst_mac"),
        "src_oui": _s("src_oui"),
        "dst_oui": _s("dst_oui"),
        # ── Application layer (NFStream nDPI — n_dissections > 0) ─────────
        "app_name":       _s("application_name"),
        "app_category":   _s("application_category_name"),
        "app_confidence": getattr(flow, "application_confidence", None),
        "app_guessed":    getattr(flow, "application_is_guessed", None),
        "server_name":    _s("requested_server_name"),   # TLS SNI / HTTP Host
        "ja3_client":     _s("client_fingerprint"),       # JA3 hash
        "ja3_server":     _s("server_fingerprint"),       # JA3S hash
        "http_user_agent": _s("user_agent"),
        "http_content_type": _s("content_type"),
        # ── Process (system visibility mode) ──────────────────────────────
        "process_name": _s("system_process_name"),
        "process_pid":  getattr(flow, "system_process_pid", None) or None,
    }


_ICMP_TYPES: Dict[int, str] = {
    0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
    5: "Redirect", 8: "Echo Request", 9: "Router Advertisement",
    10: "Router Solicitation", 11: "Time Exceeded", 12: "Parameter Problem",
    13: "Timestamp", 14: "Timestamp Reply",
}


class PacketEnricher:
    """Parallel Scapy sniffer that captures L7 metadata per flow.

    Runs in a background daemon thread alongside NFStream.  NFStream gives us
    statistical flow features; Scapy gives us the *content* — DNS names, HTTP
    URLs, TLS SNI, ICMP type/code, ARP queries.  When NFStream finalises a flow
    we call ``lookup()`` to attach whatever Scapy captured for that 5-tuple.
    """

    _CACHE_TTL  = 120      # seconds before a cache entry expires
    _CACHE_MAX  = 60_000   # hard cap to prevent unbounded memory use

    def __init__(self) -> None:
        self._cache: Dict[tuple, Dict[str, Any]] = {}
        self._ts:    Dict[tuple, float] = {}
        self._lock   = threading.Lock()
        self._stop   = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._scapy_ok: bool = False

    # ------------------------------------------------------------------
    def start(self, iface: Union[str, List[str]]) -> None:
        self._ifaces = [iface] if isinstance(iface, str) else list(iface)
        self._stop.clear()
        label = "+".join(self._ifaces)
        self._thread = threading.Thread(
            target=self._sniff_loop, args=(self._ifaces,),
            name=f"pkt-enricher-{label}", daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------
    def lookup(self, src_ip: str, dst_ip: str,
               src_port: int, dst_port: int, proto: int) -> Dict[str, Any]:
        """Return any L7 metadata captured for this 5-tuple (or its reverse)."""
        fwd = (src_ip, dst_ip, src_port, dst_port, proto)
        rev = (dst_ip, src_ip, dst_port, src_port, proto)
        with self._lock:
            merged: Dict[str, Any] = {}
            merged.update(self._cache.get(rev, {}))
            merged.update(self._cache.get(fwd, {}))  # fwd wins on collision
            return merged

    # ------------------------------------------------------------------
    def _store(self, key: tuple, data: Dict[str, Any]) -> None:
        now = time.time()
        with self._lock:
            if len(self._cache) >= self._CACHE_MAX:
                # Evict the oldest entry to stay under the cap.
                oldest_key = min(self._ts, key=self._ts.__getitem__)
                self._cache.pop(oldest_key, None)
                self._ts.pop(oldest_key, None)
            existing = self._cache.setdefault(key, {})
            existing.update({k: v for k, v in data.items() if v is not None})
            self._ts[key] = now

    # ------------------------------------------------------------------
    def _sniff_loop(self, ifaces: Union[str, List[str]]) -> None:
        try:
            from scapy.all import sniff, conf as scapy_conf
            scapy_conf.verb = 0
            self._scapy_ok = True
        except ImportError:
            logger.warning("PacketEnricher: scapy not available — L7 enrichment disabled")
            return

        def _cb(pkt):
            if self._stop.is_set():
                return
            try:
                self._process(pkt)
            except Exception:
                pass

        # Single iface or list — Scapy accepts both.
        # Filter covers IPv4, IPv6, and ARP so no traffic type is missed.
        sniff_iface = ifaces if isinstance(ifaces, list) and len(ifaces) > 1 else (
            ifaces[0] if isinstance(ifaces, list) else ifaces
        )
        try:
            sniff(
                iface=sniff_iface,
                prn=_cb,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
                filter="ip or ip6 or arp",
            )
        except Exception as exc:
            logger.warning("PacketEnricher sniff error: %s", exc)

    # ------------------------------------------------------------------
    def _process(self, pkt) -> None:
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
        except ImportError:
            return

        data: Dict[str, Any] = {}

        # ── ARP (no IP layer) ─────────────────────────────────────────────
        try:
            from scapy.layers.l2 import ARP
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                arp_key = (str(arp.psrc), str(arp.pdst), 0, 0, 0)
                self._store(arp_key, {
                    "arp_op":     "who-has" if arp.op == 1 else "is-at",
                    "arp_src_mac": str(arp.hwsrc),
                    "arp_dst_ip":  str(arp.pdst),
                })
                return
        except Exception:
            pass

        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src_ip = str(ip.src)
        dst_ip = str(ip.dst)
        proto  = int(ip.proto)
        src_port = dst_port = 0

        try:
            if pkt.haslayer(TCP):
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
            elif pkt.haslayer(UDP):
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)
        except Exception:
            pass

        key = (src_ip, dst_ip, src_port, dst_port, proto)

        # ── DNS ───────────────────────────────────────────────────────────
        try:
            from scapy.layers.dns import DNS, DNSQR
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                if dns.qr == 0 and dns.qd:              # query
                    qname = dns.qd.qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="replace").rstrip(".")
                    data["dns_query"] = qname
                    data["dns_qtype"] = {
                        1: "A", 2: "NS", 5: "CNAME", 12: "PTR",
                        15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
                    }.get(dns.qd.qtype, str(dns.qd.qtype))
                elif dns.qr == 1 and dns.an:             # response
                    rips: List[str] = []
                    rr = dns.an
                    while rr and len(rips) < 5:
                        if hasattr(rr, "rdata"):
                            rips.append(str(rr.rdata))
                        rr = getattr(rr, "payload", None)
                        if rr and not hasattr(rr, "rdata"):
                            break
                    if rips:
                        data["dns_response_ips"] = rips
        except Exception:
            pass

        # ── HTTP (scapy's built-in HTTP layer) ────────────────────────────
        try:
            from scapy.layers.http import HTTPRequest, HTTPResponse
            if pkt.haslayer(HTTPRequest):
                req = pkt[HTTPRequest]
                def _dec(b):
                    return b.decode("utf-8", errors="replace") if isinstance(b, (bytes, bytearray)) else b
                data["http_method"] = _dec(getattr(req, "Method", None))
                data["http_url"]    = _dec(getattr(req, "Path",   None))
                data["http_host"]   = _dec(getattr(req, "Host",   None))
                ua = getattr(req, "User_Agent", None)
                if ua:
                    data["http_user_agent"] = _dec(ua)
            elif pkt.haslayer(HTTPResponse):
                sc = getattr(pkt[HTTPResponse], "Status_Code", None)
                if sc:
                    data["http_status"] = sc.decode("utf-8", errors="replace") if isinstance(sc, bytes) else str(sc)
        except Exception:
            pass

        # ── TLS SNI from raw ClientHello (covers HTTPS/QUIC/SMTPS…) ──────
        try:
            from scapy.packet import Raw
            if not data.get("server_name") and pkt.haslayer(Raw):
                sni = self._parse_tls_sni(bytes(pkt[Raw]))
                if sni:
                    data["tls_sni"] = sni
        except Exception:
            pass

        # ── ICMP type/code ────────────────────────────────────────────────
        try:
            if pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                data["icmp_type"] = _ICMP_TYPES.get(icmp.type, f"Type {icmp.type}")
                data["icmp_code"] = int(icmp.code)
        except Exception:
            pass

        if data:
            self._store(key, data)

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_tls_sni(raw: bytes) -> Optional[str]:
        """Extract SNI hostname from a TLS 1.x ClientHello record."""
        try:
            if len(raw) < 9 or raw[0] != 0x16 or raw[5] != 0x01:
                return None
            offset = 9  # past record header (5) + handshake type (1) + length (3)
            offset += 2  # ProtocolVersion
            offset += 32  # Random
            if offset >= len(raw):
                return None
            sid_len = raw[offset]; offset += 1 + sid_len
            if offset + 2 > len(raw):
                return None
            cs_len = int.from_bytes(raw[offset:offset + 2], "big"); offset += 2 + cs_len
            if offset + 1 > len(raw):
                return None
            cm_len = raw[offset]; offset += 1 + cm_len
            if offset + 2 > len(raw):
                return None
            ext_total = int.from_bytes(raw[offset:offset + 2], "big"); offset += 2
            end = offset + ext_total
            while offset + 4 <= end and offset + 4 <= len(raw):
                ext_type = int.from_bytes(raw[offset:offset + 2], "big")
                ext_len  = int.from_bytes(raw[offset + 2:offset + 4], "big")
                offset  += 4
                if ext_type == 0 and offset + 5 <= len(raw):  # server_name
                    name_len = int.from_bytes(raw[offset + 3:offset + 5], "big")
                    return raw[offset + 5: offset + 5 + name_len].decode("utf-8", errors="replace")
                offset += ext_len
        except Exception:
            pass
        return None


class ArpIsolator:
    """Network-wide host isolation via ARP cache poisoning.

    Sends forged ARP replies to both the target host and the default gateway,
    claiming to be each other.  All LAN traffic from/to the isolated IP is
    then rerouted through this machine.  Combined with the nftables FORWARD
    chain drop rules, the isolated host is effectively quarantined from the
    entire LAN — not just this machine.

    Requires: scapy (already used by PacketEnricher), raw-socket caps
    (``cap_net_raw`` on the python binary — granted by grant-capture-perms.sh).
    """

    ARP_INTERVAL = 2.0     # seconds between ARP poison bursts
    GW_PROBE_TIMEOUT = 3   # seconds to wait for gateway ARP reply
    MAC_PROBE_TIMEOUT = 2  # seconds to wait for target ARP reply

    def __init__(self) -> None:
        self._isolated: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._iface: Optional[str] = None
        self._local_mac: Optional[str] = None
        self._local_ip: Optional[str] = None
        self._gateway_ip: Optional[str] = None
        self._gateway_mac: Optional[str] = None
        self._scapy_ok: bool = False

    # ── Public API ───────────────────────────────────────────────────────────

    def start(self, iface: str) -> None:
        self._iface = iface
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._arp_loop, daemon=True, name="arp-isolator",
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def isolate(self, ip: str, reason: str = "") -> bool:
        """Add *ip* to the isolation set.  Returns True if newly added."""
        with self._lock:
            if ip in self._isolated:
                return False
            self._isolated[ip] = {
                "ip": ip,
                "reason": reason,
                "isolated_at": datetime.now(timezone.utc).isoformat(),
                "target_mac": None,
                "gateway_mac": None,
                "arp_ok": False,
            }
        logger.info("ArpIsolator: isolating %s (%s)", ip, reason or "no reason")
        return True

    def release(self, ip: str) -> bool:
        """Remove *ip* from isolation and send gratuitous ARP to restore caches."""
        with self._lock:
            info = self._isolated.pop(ip, None)
        if info is None:
            return False
        logger.info("ArpIsolator: releasing %s — restoring ARP caches", ip)
        try:
            self._restore_arp(ip, info)
        except Exception as e:
            logger.warning("ArpIsolator: ARP restore for %s failed: %s", ip, e)
        return True

    def list_isolated(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._isolated.values())

    # ── Internal loop ────────────────────────────────────────────────────────

    def _arp_loop(self) -> None:
        try:
            from scapy.all import get_if_hwaddr, get_if_addr  # noqa
            self._scapy_ok = True
        except ImportError:
            logger.warning("ArpIsolator: scapy not available — network-wide isolation disabled")
            return

        self._detect_network_info()

        while not self._stop.is_set():
            with self._lock:
                targets = list(self._isolated.items())

            for ip, info in targets:
                try:
                    self._spoof_arp(ip, info)
                except Exception as e:
                    logger.debug("ArpIsolator.spoof(%s): %s", ip, e)

            self._stop.wait(self.ARP_INTERVAL)

    def _detect_network_info(self) -> None:
        """Detect local MAC/IP and default gateway once at start."""
        try:
            from scapy.all import get_if_hwaddr, get_if_addr, srp, Ether
            from scapy.layers.inet import IP  # noqa
            try:
                from scapy.layers.l2 import ARP as ScapyARP
            except ImportError:
                from scapy.all import ARP as ScapyARP

            if not self._iface:
                return

            self._local_mac = get_if_hwaddr(self._iface)
            self._local_ip  = get_if_addr(self._iface)

            # Find the default gateway via `ip route`
            import subprocess
            out = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            for line in out.splitlines():
                if "default via" in line:
                    parts = line.split()
                    idx = parts.index("via")
                    self._gateway_ip = parts[idx + 1]
                    break

            # ARP-probe the gateway for its MAC
            if self._gateway_ip:
                ans, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") /
                    ScapyARP(pdst=self._gateway_ip),
                    iface=self._iface,
                    timeout=self.GW_PROBE_TIMEOUT,
                    verbose=False,
                )
                for _, rcv in ans:
                    self._gateway_mac = rcv[Ether].src
                    break

            logger.info(
                "ArpIsolator ready: iface=%s local=%s/%s gateway=%s gw_mac=%s",
                self._iface, self._local_ip, self._local_mac,
                self._gateway_ip, self._gateway_mac,
            )
        except Exception as e:
            logger.warning("ArpIsolator: network info detection failed: %s", e)

    def _resolve_target_mac(self, ip: str) -> Optional[str]:
        try:
            from scapy.all import srp, Ether
            try:
                from scapy.layers.l2 import ARP as ScapyARP
            except ImportError:
                from scapy.all import ARP as ScapyARP

            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ScapyARP(pdst=ip),
                iface=self._iface,
                timeout=self.MAC_PROBE_TIMEOUT,
                verbose=False,
            )
            for _, rcv in ans:
                return rcv[Ether].src
        except Exception:
            pass
        return None

    def _spoof_arp(self, ip: str, info: Dict[str, Any]) -> None:
        """Send one round of forged ARP replies for *ip*."""
        if not self._local_mac or not self._gateway_ip:
            return

        from scapy.all import sendp, Ether
        try:
            from scapy.layers.l2 import ARP as ScapyARP
        except ImportError:
            from scapy.all import ARP as ScapyARP

        # Lazy-resolve target MAC on first attempt
        if not info.get("target_mac"):
            mac = self._resolve_target_mac(ip)
            if mac:
                info["target_mac"] = mac
                with self._lock:
                    if ip in self._isolated:
                        self._isolated[ip]["target_mac"] = mac

        if not info.get("gateway_mac") and self._gateway_mac:
            info["gateway_mac"] = self._gateway_mac
            with self._lock:
                if ip in self._isolated:
                    self._isolated[ip]["gateway_mac"] = self._gateway_mac

        packets = []
        gw_mac  = info.get("gateway_mac") or self._gateway_mac

        # Tell GATEWAY: "IP X has our MAC" → LAN→X traffic comes to us
        if gw_mac:
            packets.append(
                Ether(dst=gw_mac) /
                ScapyARP(op=2,
                         pdst=self._gateway_ip, hwdst=gw_mac,
                         psrc=ip,                hwsrc=self._local_mac)
            )

        # Tell TARGET: "gateway has our MAC" → X→internet traffic comes to us
        if info.get("target_mac"):
            packets.append(
                Ether(dst=info["target_mac"]) /
                ScapyARP(op=2,
                         pdst=ip,               hwdst=info["target_mac"],
                         psrc=self._gateway_ip, hwsrc=self._local_mac)
            )

        if packets:
            sendp(packets, iface=self._iface, verbose=False)
            with self._lock:
                if ip in self._isolated:
                    self._isolated[ip]["arp_ok"] = True

    def _restore_arp(self, ip: str, info: Dict[str, Any]) -> None:
        """Send correct ARP replies to undo the poisoning for *ip*."""
        if not self._iface or not self._gateway_ip:
            return

        try:
            from scapy.all import sendp, Ether
            try:
                from scapy.layers.l2 import ARP as ScapyARP
            except ImportError:
                from scapy.all import ARP as ScapyARP

            target_mac = info.get("target_mac")
            gw_mac     = info.get("gateway_mac") or self._gateway_mac

            packets = []
            # Restore gateway's cache: "IP X has its real MAC"
            if gw_mac and target_mac:
                packets.append(
                    Ether(dst=gw_mac) /
                    ScapyARP(op=2,
                             pdst=self._gateway_ip, hwdst=gw_mac,
                             psrc=ip,                hwsrc=target_mac)
                )
            # Restore target's cache: "gateway has its real MAC"
            if target_mac and gw_mac:
                packets.append(
                    Ether(dst=target_mac) /
                    ScapyARP(op=2,
                             pdst=ip,               hwdst=target_mac,
                             psrc=self._gateway_ip, hwsrc=gw_mac)
                )

            if packets:
                # Send 3 times to reliably update ARP caches on both sides
                for _ in range(3):
                    sendp(packets, iface=self._iface, verbose=False)
                    time.sleep(0.1)
        except Exception as e:
            logger.debug("ArpIsolator._restore_arp(%s): %s", ip, e)


class LiveMonitor:
    """Singleton live-capture monitor with batched inference."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._capture_threads: List[threading.Thread] = []
        self._classify_threads: List[threading.Thread] = []
        self._stop_evt = threading.Event()
        self._streamers: List[Any] = []   # one NFStreamer per interface
        self._enricher = PacketEnricher()
        self._isolator = ArpIsolator()
        # Explicit running flag — flips False immediately on stop() so the UI
        # reflects "Stopped" even if capture threads are still blocked inside
        # libpcap waiting on a quiet/DOWN interface.
        self._running_flag: bool = False

        # Inter-thread queue from capture → classifier pool
        self._queue: "queue.Queue[Tuple[Dict[str, float], Dict[str, Any]]]" = queue.Queue(maxsize=QUEUE_MAXSIZE)

        self._ifaces: List[str] = []
        self._started_at: Optional[float] = None
        self._last_flow_at: Optional[float] = None
        self._error: Optional[str] = None

        self._total_flows: int = 0
        self._benign: int = 0
        self._attacks: int = 0
        self._dropped: int = 0        # queue overflow drops
        self._iface_flows: Counter = Counter()   # per-interface flow count
        self._iface_errors: Dict[str, str] = {}  # per-interface error messages

        # Non-Benign detections pending pickup by the backend
        self._pending: Deque[Dict[str, Any]] = deque(maxlen=2000)
        # Ring buffer for UI (attacks)
        self._recent: Deque[Dict[str, Any]] = deque(maxlen=50)

        # Recent notable benign flows tagged by app protocol — drives the
        # "Email & Application Activity" feed on the monitoring page.
        self._recent_email: Deque[Dict[str, Any]] = deque(maxlen=30)
        self._recent_app: Deque[Dict[str, Any]] = deque(maxlen=30)
        self._email_count: int = 0  # cumulative since session start

        # Per-second history: list of (epoch_sec_bucket, flows, attacks) — last HISTORY_SEC buckets
        self._history: Deque[Tuple[int, int, int]] = deque(maxlen=HISTORY_SEC)

        # Aggregations for the operations dashboard.
        # Keys are IP strings; values track flow + byte volume per peer.
        self._src_flows: Counter = Counter()    # flows per source IP
        self._src_bytes: Counter = Counter()    # bytes per source IP
        self._dst_flows: Counter = Counter()    # flows per destination IP
        self._dst_bytes: Counter = Counter()    # bytes per destination IP
        self._proto_flows: Counter = Counter()  # flows per app protocol label (HTTP, DNS, ...)
        self._proto_bytes: Counter = Counter()  # bytes per app protocol label
        self._total_bytes: int = 0              # cumulative bytes seen

        # Repeat-validation hits: (src_ip, attack_label) → deque of timestamps.
        self._attack_hits: Dict[Tuple[str, str], Deque[float]] = {}

        # Behavioral baseline: per-IP flow timestamps for anomaly detection.
        # After BASELINE_WARMUP_SEC the monitor flags IPs whose flow rate
        # spikes beyond BASELINE_SPIKE_FACTOR × their own rolling baseline.
        self._ip_flow_times: Dict[str, Deque[float]] = {}   # ip → deque of ts
        self._baseline_anomalies: Deque[Dict] = deque(maxlen=100)
        self._byte_history: Deque[Tuple[int, int]] = deque(maxlen=HISTORY_SEC)  # (bucket, bytes)

        # Rolling ICMP probe windows for heuristic flood / sweep detection.
        self._icmp_src_window: defaultdict[str, Deque[Tuple[float, Optional[str]]]] = defaultdict(deque)
        self._icmp_dst_window: defaultdict[str, Deque[float]] = defaultdict(deque)

    # ------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._running_flag

    # ------------------------------------------------------------------
    def start(self, iface: Union[str, List[str]]) -> Dict[str, Any]:
        ifaces = [iface] if isinstance(iface, str) else list(iface)

        # Reject DOWN interfaces up-front.
        try:
            import psutil
            stats = psutil.net_if_stats()
            live = []
            for i in ifaces:
                info = stats.get(i)
                if info is None:
                    raise ValueError(f"Interface '{i}' not found")
                if not info.isup:
                    raise ValueError(
                        f"Interface '{i}' is DOWN — pick an UP interface "
                        f"(e.g. one with an IP address) so packets can be captured."
                    )
                live.append(i)
            ifaces = live
        except ValueError:
            raise
        except Exception:
            pass

        with self._lock:
            if self.running:
                return self._status_locked()

            ml_service.load()
            self._running_flag = True
            self._ifaces = ifaces
            self._error = None
            self._started_at = time.time()
            self._last_flow_at = None
            self._total_flows = 0
            self._benign = 0
            self._attacks = 0
            self._dropped = 0
            self._iface_flows.clear()
            self._iface_errors.clear()
            self._pending.clear()
            self._recent.clear()
            self._recent_email.clear()
            self._recent_app.clear()
            self._email_count = 0
            self._history.clear()
            self._byte_history.clear()
            self._src_flows.clear()
            self._src_bytes.clear()
            self._dst_flows.clear()
            self._dst_bytes.clear()
            self._proto_flows.clear()
            self._proto_bytes.clear()
            self._attack_hits.clear()
            self._ip_flow_times.clear()
            self._baseline_anomalies.clear()
            self._total_bytes = 0
            self._stop_evt.clear()
            self._icmp_src_window.clear()
            self._icmp_dst_window.clear()
            self._streamers.clear()
            self._capture_threads.clear()
            self._classify_threads.clear()

            # Drain any stale items
            try:
                while True:
                    self._queue.get_nowait()
            except queue.Empty:
                pass

            self._enricher.stop()
            self._enricher.start(ifaces)
            self._isolator.stop()
            self._isolator.start(ifaces[0])   # ARP runs on first/primary interface

            # One capture thread per interface
            for i in ifaces:
                t = threading.Thread(
                    target=self._capture_worker, args=(i,),
                    name=f"live-capture-{i}", daemon=True,
                )
                self._capture_threads.append(t)
                t.start()

            # N parallel classifier workers sharing the single queue
            for n in range(N_CLASSIFY_WORKERS):
                t = threading.Thread(
                    target=self._classify_loop,
                    name=f"live-classify-{n}", daemon=True,
                )
                self._classify_threads.append(t)
                t.start()

            logger.info(
                "LiveMonitor started on %d interface(s): %s — %d classify workers",
                len(ifaces), ", ".join(ifaces), N_CLASSIFY_WORKERS,
            )
            return self._status_locked()

    # ------------------------------------------------------------------
    def stop(self) -> Dict[str, Any]:
        with self._lock:
            if not self.running:
                return self._status_locked()
            self._stop_evt.set()
            self._running_flag = False
            threads = list(self._capture_threads) + list(self._classify_threads)
            logger.info("LiveMonitor stop requested")
        self._enricher.stop()
        self._isolator.stop()
        # Best-effort: wait briefly for threads to drain.
        # Capture threads may stay alive inside libpcap until the next packet.
        for t in threads:
            t.join(timeout=2)
        return self.status()

    # ------------------------------------------------------------------
    def _capture_worker(self, iface: str) -> None:
        """Auto-restart wrapper around _capture_loop.

        Restarts up to CAPTURE_RESTART_MAX times on transient errors.
        Permission errors are not retried (they won't self-heal).
        """
        for attempt in range(CAPTURE_RESTART_MAX + 1):
            if self._stop_evt.is_set():
                break
            try:
                self._capture_loop(iface)
            except PermissionError as e:
                msg = f"Permission denied on {iface}: {e}"
                with self._lock:
                    self._iface_errors[iface] = msg
                    self._error = msg
                    # All done — permission won't fix itself
                    if not any(
                        t.is_alive() for t in self._capture_threads
                        if t is not threading.current_thread()
                    ):
                        self._running_flag = False
                logger.error(msg)
                break
            except Exception as e:
                if self._stop_evt.is_set():
                    break
                logger.warning(
                    "Capture on %s crashed (attempt %d/%d): %s",
                    iface, attempt + 1, CAPTURE_RESTART_MAX, e,
                )
                if attempt < CAPTURE_RESTART_MAX:
                    time.sleep(CAPTURE_RESTART_DELAY_SEC)
                else:
                    msg = f"Capture on {iface} failed after {CAPTURE_RESTART_MAX} retries: {e}"
                    with self._lock:
                        self._iface_errors[iface] = msg
                        self._error = msg
                    logger.error(msg)
            else:
                # Normal exit (stop_evt was set)
                break

        # All retries exhausted — flip running if no other capture is alive
        if not self._stop_evt.is_set():
            with self._lock:
                alive = [t for t in self._capture_threads if t.is_alive()
                         and t is not threading.current_thread()]
                if not alive:
                    self._running_flag = False

    # ------------------------------------------------------------------
    def _rolling_counts(self, window: int) -> Tuple[int, int]:
        """Sum of flows and attacks in the last ``window`` seconds."""
        now_bucket = int(time.time())
        min_bucket = now_bucket - window + 1
        flows = 0
        attacks = 0
        for b, f, a in self._history:
            if b >= min_bucket:
                flows += f
                attacks += a
        return flows, attacks

    def _status_locked(self) -> Dict[str, Any]:
        elapsed = (time.time() - self._started_at) if self._started_at else 0
        flows_w, attacks_w = self._rolling_counts(RATE_WINDOW_SEC)
        rate_window = min(RATE_WINDOW_SEC, elapsed) if elapsed > 0 else 0
        flows_per_sec = (flows_w / rate_window) if rate_window > 0 else 0.0
        attacks_per_sec = (attacks_w / rate_window) if rate_window > 0 else 0.0

        # Compact history array for the UI (last HISTORY_SEC seconds, 0-filled gaps).
        now_bucket = int(time.time())
        by_bucket = {b: (f, a) for b, f, a in self._history}
        series_flows: List[int] = []
        series_attacks: List[int] = []
        for i in range(HISTORY_SEC - 1, -1, -1):
            b = now_bucket - i
            f, a = by_bucket.get(b, (0, 0))
            series_flows.append(f)
            series_attacks.append(a)

        # Byte history + rolling bytes/sec
        bytes_by_bucket = {b: tot for b, tot in self._byte_history}
        series_bytes: List[int] = []
        bytes_w = 0
        min_bucket = now_bucket - RATE_WINDOW_SEC + 1
        for i in range(HISTORY_SEC - 1, -1, -1):
            b = now_bucket - i
            v = bytes_by_bucket.get(b, 0)
            series_bytes.append(v)
            if b >= min_bucket:
                bytes_w += v
        bytes_per_sec = (bytes_w / rate_window) if rate_window > 0 else 0.0

        # Top talkers (top 10 by flow count, with their byte total alongside).
        def _top(flow_cnt: Counter, byte_cnt: Counter, n: int = 10) -> List[Dict[str, Any]]:
            return [
                {"ip": ip, "flows": flows, "bytes": int(byte_cnt.get(ip, 0))}
                for ip, flows in flow_cnt.most_common(n)
            ]

        top_src = _top(self._src_flows, self._src_bytes)
        top_dst = _top(self._dst_flows, self._dst_bytes)

        # Protocol distribution (sorted by flow count desc).
        proto_dist = [
            {"label": p, "flows": f, "bytes": int(self._proto_bytes.get(p, 0))}
            for p, f in self._proto_flows.most_common()
        ]

        # Capture quality: percentage of flows that made it through without drops.
        # 100% when no drops; degrades as queue overflows under heavy traffic.
        observed = self._total_flows + self._dropped
        capture_quality = round(100.0 * self._total_flows / observed, 1) if observed > 0 else 100.0

        # Per-interface breakdown
        iface_stats = [
            {
                "name": i,
                "flows": int(self._iface_flows.get(i, 0)),
                "error": self._iface_errors.get(i),
            }
            for i in self._ifaces
        ]

        return {
            "running": self.running,
            # Single-interface compat field (first iface or None)
            "interface": self._ifaces[0] if self._ifaces else None,
            "interfaces": list(self._ifaces),
            "interface_stats": iface_stats,
            "classify_workers": N_CLASSIFY_WORKERS,
            "started_at": (
                datetime.fromtimestamp(self._started_at, tz=timezone.utc).isoformat()
                if self._started_at else None
            ),
            "uptime_sec": round(elapsed, 1),
            "total_flows": self._total_flows,
            "benign": self._benign,
            "attacks": self._attacks,
            "dropped": self._dropped,
            "capture_quality": capture_quality,   # 0–100 %
            "queue_depth": self._queue.qsize(),
            "queue_capacity": QUEUE_MAXSIZE,
            "flows_per_sec": round(flows_per_sec, 2),
            "attacks_per_sec": round(attacks_per_sec, 2),
            "bytes_per_sec": round(bytes_per_sec, 2),
            "total_bytes": int(self._total_bytes),
            "flows_last_10s": flows_w,
            "attacks_last_10s": attacks_w,
            "top_src_ips": top_src,
            "top_dst_ips": top_dst,
            "protocol_distribution": proto_dist,
            "history_bytes": series_bytes,
            "pending_detections": len(self._pending),
            "recent_detections": list(self._recent),
            "recent_email": list(self._recent_email),
            "recent_app": list(self._recent_app),
            "email_count": self._email_count,
            "history_flows": series_flows,
            "history_attacks": series_attacks,
            "error": self._error,
        }

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return self._status_locked()

    # ------------------------------------------------------------------
    def drain_detections(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Atomically pop up to ``limit`` buffered non-Benign detections."""
        out: List[Dict[str, Any]] = []
        with self._lock:
            while self._pending and len(out) < limit:
                out.append(self._pending.popleft())
        return out

    # ------------------------------------------------------------------
    def isolate_ip(self, ip: str, reason: str = "") -> bool:
        """Add *ip* to ARP isolation (network-wide quarantine)."""
        return self._isolator.isolate(ip, reason)

    def release_ip(self, ip: str) -> bool:
        """Remove *ip* from ARP isolation and restore ARP caches."""
        return self._isolator.release(ip)

    def list_isolated(self) -> List[Dict[str, Any]]:
        """Return the list of currently isolated IPs with their metadata."""
        return self._isolator.list_isolated()

    # ------------------------------------------------------------------
    def _check_behavioral_baseline(self, src_ip: str, now: float) -> Optional[Dict]:
        """Return an anomaly dict if this IP's flow rate spikes above its baseline.

        Works by maintaining a sliding window of per-IP flow timestamps.
        After BASELINE_WARMUP_SEC of monitoring, an IP that suddenly sends
        BASELINE_SPIKE_FACTOR × its own baseline rate triggers a synthetic
        'Behavioral Anomaly' detection — even when the ML model says Benign.
        """
        if not src_ip:
            return None
        started = self._started_at or now
        if (now - started) < BASELINE_WARMUP_SEC:
            return None   # still warming up

        times = self._ip_flow_times.setdefault(src_ip, deque())
        times.append(now)

        # Keep only the last BASELINE_WINDOW_SEC seconds
        cutoff = now - BASELINE_WINDOW_SEC
        while times and times[0] < cutoff:
            times.popleft()

        n = len(times)
        if n < BASELINE_MIN_FLOWS:
            return None   # not enough history to establish a baseline

        # Split window in half: baseline = first half, current = second half
        half = BASELINE_WINDOW_SEC / 2
        split = now - half
        baseline_flows = sum(1 for t in times if t < split)
        current_flows  = sum(1 for t in times if t >= split)

        if baseline_flows == 0:
            return None

        # Normalise to flows-per-minute for comparability
        baseline_rate = (baseline_flows / half) * 60
        current_rate  = (current_flows  / half) * 60

        if current_rate >= baseline_rate * BASELINE_SPIKE_FACTOR and current_rate > 20:
            confidence = min(0.95, 0.70 + 0.05 * (current_rate / baseline_rate - BASELINE_SPIKE_FACTOR))
            return {
                "predicted": "Behavioral Anomaly",
                "confidence": round(confidence, 4),
                "severity": "MEDIUM",
                "mitre_technique": "T1046",
                "mitre_tactic": "Discovery",
                "description": (
                    f"Flow rate spike: {current_rate:.0f} flows/min "
                    f"(baseline {baseline_rate:.0f} flows/min, ×{current_rate/baseline_rate:.1f})"
                ),
                "src_ip": src_ip,
            }
        return None

    # ------------------------------------------------------------------
    def _apply_icmp_heuristics(self, meta: Dict[str, Any]) -> Optional[Tuple[str, float]]:
        """Return (label, confidence) if an ICMP heuristic should override the model."""
        proto = meta.get("protocol")
        try:
            proto = int(proto)
        except (TypeError, ValueError):
            return None
        if proto not in ICMP_PROTOCOLS:
            return None

        packets = int(meta.get("bidirectional_packets") or meta.get("packets") or 0)
        if packets >= ICMP_FLOOD_PKTS:
            conf = min(0.99, 0.85 + packets / 500.0)
            return "ICMP Flood", conf

        # Track ALL ICMP flows (not just tiny probes) in sweep/flood windows.
        # Flows that reached the flood threshold above are already handled.

        now = time.time()
        label: Optional[str] = None
        conf = 0.9

        src_ip = meta.get("src_ip")
        dst_ip = meta.get("dst_ip")

        if src_ip:
            dq = self._icmp_src_window[src_ip]
            dq.append((now, dst_ip))
            while dq and now - dq[0][0] > ICMP_WINDOW_SEC:
                dq.popleft()
            unique_hosts = {host for _, host in dq if host}
            if len(unique_hosts) >= ICMP_SWEEP_HOSTS:
                label = "ICMP Sweep"
                conf = min(0.97, 0.85 + len(unique_hosts) / 10.0)
                dq.clear()

        if label is None and dst_ip:
            dq_dst = self._icmp_dst_window[dst_ip]
            dq_dst.append(now)
            while dq_dst and now - dq_dst[0] > ICMP_WINDOW_SEC:
                dq_dst.popleft()
            if len(dq_dst) >= ICMP_PROBE_THRESHOLD:
                label = "ICMP Flood"
                conf = min(0.96, 0.86 + len(dq_dst) * 0.02)
                dq_dst.clear()

        return (label, conf) if label else None

    # ==================================================================
    # Capture thread — produces (feature_dict, meta) into the queue
    # ==================================================================
    def _capture_loop(self, iface: str) -> None:
        """Inner capture loop for one interface.

        Raises PermissionError on permission failure so _capture_worker can
        distinguish it from transient errors that warrant a retry.
        """
        try:
            from nfstream import NFStreamer
        except ImportError as e:
            raise RuntimeError(f"nfstream not available: {e}") from e

        def _is_perm_error(msg: str) -> bool:
            m = msg.lower()
            return any(k in m for k in (
                "unable to activate source",
                "permission denied",
                "operation not permitted",
                "you don't have permission",
                "socket: operation not permitted",
                "no such device",
            ))

        def _perm_hint() -> str:
            return (
                "Capture requires raw-socket privileges. Run once on the host:\n"
                "  sudo bash scripts/grant-capture-perms.sh\n"
                "(this grants cap_net_raw + cap_net_admin to your python3 binary), "
                "then restart the ML service."
            )

        try:
            # promiscuous_mode=True  → see all frames on the segment (not just
            #   traffic addressed to this host).
            # snapshot_length=65535  → capture the full packet (no truncation).
            # accounting_mode=1      → byte counts at IP level (excludes L2 overhead,
            #   more accurate for network-layer IDS features).
            # n_meters=2             → two parallel NFStream flow meters, helps on
            #   busy interfaces with many concurrent flows.
            # n_dissections=20       → nDPI deep-packet inspection depth.
            streamer = NFStreamer(
                source=iface,
                statistical_analysis=True,
                n_dissections=20,
                accounting_mode=1,
                idle_timeout=2,
                active_timeout=30,
                promiscuous_mode=True,
                snapshot_length=65535,
                n_meters=2,
            )
        except Exception as e:
            msg = str(e)
            if _is_perm_error(msg):
                raise PermissionError(f"Cannot open '{iface}': {msg}\n{_perm_hint()}") from e
            raise RuntimeError(f"Failed to open interface '{iface}': {e}") from e

        with self._lock:
            self._streamers.append(streamer)

        try:
            for flow in streamer:
                if self._stop_evt.is_set():
                    break
                try:
                    feat = _nflow_to_feature_dict(flow)
                    meta = _flow_meta(flow)
                    meta["capture_interface"] = iface
                    enrichment = self._enricher.lookup(
                        str(meta.get("src_ip") or ""),
                        str(meta.get("dst_ip") or ""),
                        int(meta.get("src_port") or 0),
                        int(meta.get("dst_port") or 0),
                        int(meta.get("protocol") or 0),
                    )
                    for k, v in enrichment.items():
                        if k not in meta or meta[k] is None:
                            meta[k] = v
                    self._queue.put_nowait((feat, meta))
                    with self._lock:
                        self._iface_flows[iface] += 1
                except queue.Full:
                    with self._lock:
                        self._dropped += 1
                except Exception as e:
                    logger.exception("flow enqueue failed on %s: %s", iface, e)
        except PermissionError:
            raise
        except Exception as e:
            msg = str(e)
            if _is_perm_error(msg):
                raise PermissionError(f"Cannot capture on '{iface}': {msg}\n{_perm_hint()}") from e
            raise
        finally:
            with self._lock:
                try:
                    self._streamers.remove(streamer)
                except ValueError:
                    pass
            logger.info(
                "Capture loop exiting — iface=%s, iface_flows=%d, total_flows=%d, dropped=%d",
                iface, self._iface_flows.get(iface, 0), self._total_flows, self._dropped,
            )

    # ==================================================================
    # Classifier thread — batches flows and runs inference
    # ==================================================================
    def _classify_loop(self) -> None:
        batch_feats: List[Dict[str, float]] = []
        batch_meta: List[Dict[str, Any]] = []
        interval = BATCH_INTERVAL_MS / 1000.0
        next_flush = time.time() + interval

        while not (self._stop_evt.is_set() and self._queue.empty()):
            timeout = max(0.001, next_flush - time.time())
            try:
                feat, meta = self._queue.get(timeout=timeout)
                batch_feats.append(feat)
                batch_meta.append(meta)
            except queue.Empty:
                pass

            should_flush = (
                len(batch_feats) >= BATCH_SIZE
                or (batch_feats and time.time() >= next_flush)
            )
            if not should_flush:
                continue

            try:
                self._classify_batch(batch_feats, batch_meta)
            except Exception as e:
                logger.exception("batch inference failed: %s", e)
            batch_feats.clear()
            batch_meta.clear()
            next_flush = time.time() + interval

        # Final flush
        if batch_feats:
            try:
                self._classify_batch(batch_feats, batch_meta)
            except Exception as e:
                logger.exception("final batch inference failed: %s", e)

    def _classify_batch(
        self, feats: List[Dict[str, float]], metas: List[Dict[str, Any]]
    ) -> None:
        if not feats:
            return
        ml_service.load()
        # Build array in model's feature order.
        # Split batch into flows that need ML inference and flows that are
        # unconditionally Benign (multicast, broadcast, well-known local addrs).
        # Safe flows skip the model entirely — no wasted compute, no false positives.
        safe_mask = [_is_safe_flow(m) for m in metas]
        ml_feats  = [f for f, s in zip(feats, safe_mask) if not s]
        ml_metas  = [m for m, s in zip(metas, safe_mask) if not s]

        if ml_feats:
            names = ml_service.feature_names
            X = np.array(
                [[float(f.get(n, 0.0)) for n in names] for f in ml_feats],
                dtype=float,
            )
            ml_preds = ml_service._predict_array(X)  # type: ignore[attr-defined]
        else:
            ml_preds = []

        # Re-merge into a single flat sequence for the stats loop below.
        # Safe flows get a synthetic Benign prediction dict.
        _BENIGN_PRED = {"predicted": "Benign", "confidence": 1.0,
                        "severity": "INFORMATIONAL",
                        "mitre_technique": None, "mitre_tactic": None,
                        "description": None}
        ml_iter = iter(ml_preds)
        merged_preds = [_BENIGN_PRED if s else next(ml_iter) for s in safe_mask]

        now = time.time()
        now_bucket = int(now)
        added_flows = len(merged_preds)
        added_attacks = 0

        with self._lock:
            self._total_flows += added_flows
            self._last_flow_at = now
            added_bytes = 0
            for pred, meta in zip(merged_preds, metas):
                label = pred.get("predicted", "Benign")
                confidence = float(pred.get("confidence", 0.0))
                severity = pred.get("severity", "INFORMATIONAL")
                mitre_technique = pred.get("mitre_technique")
                mitre_tactic = pred.get("mitre_tactic")
                description = pred.get("description")

                flow_bytes = int(meta.get("bytes") or 0)
                added_bytes += flow_bytes

                # Track top-talker aggregations (independent of class).
                src = meta.get("src_ip")
                dst = meta.get("dst_ip")
                if src:
                    self._src_flows[src] += 1
                    self._src_bytes[src] += flow_bytes
                if dst:
                    self._dst_flows[dst] += 1
                    self._dst_bytes[dst] += flow_bytes

                # Tag every flow by app protocol (email/dns/web/ssh/...)
                # — independently of attack/benign — so the UI can show
                # network activity even when nothing is malicious.
                proto_info = _classify_port(meta.get("src_port"), meta.get("dst_port"), meta.get("protocol"))
                proto_label = proto_info["label"] if proto_info else "Other"
                self._proto_flows[proto_label] += 1
                self._proto_bytes[proto_label] += flow_bytes

                if proto_info is not None:
                    flow_event = {
                        "label": proto_info["label"],
                        "category": proto_info["category"],
                        "encrypted": proto_info["encrypted"],
                        "port": proto_info["port"],
                        "predicted": label,
                        "detected_at": datetime.now(timezone.utc).isoformat(),
                        **meta,
                    }
                    if proto_info["category"] == "email":
                        self._recent_email.append(flow_event)
                        self._email_count += 1
                    else:
                        self._recent_app.append(flow_event)

                override = self._apply_icmp_heuristics(meta)
                if override:
                    label, confidence = override
                    confidence = round(float(confidence), 4)
                    mitre = enrich(label)
                    severity = mitre["severity"]
                    mitre_technique = mitre["technique"]
                    mitre_tactic = mitre["tactic"]
                    description = mitre["description"]
                    # ICMP heuristics have their own accumulation windows —
                    # skip the generic MIN_REPEAT gate and alert immediately.
                    added_attacks += 1
                    self._attacks += 1
                    detection = {
                        "predicted": label,
                        "confidence": confidence,
                        "severity": severity,
                        "mitre_technique": mitre_technique,
                        "mitre_tactic": mitre_tactic,
                        "description": description,
                        "detected_at": datetime.now(timezone.utc).isoformat(),
                        **meta,
                    }
                    self._pending.append(detection)
                    self._recent.append(detection)
                    continue

                # Behavioral baseline — run on every flow (Benign or not).
                # If an IP's rate spikes abnormally, surface it even if the
                # ML model said Benign for this individual flow.
                src_for_baseline = str(meta.get("src_ip") or "")
                baseline_hit = self._check_behavioral_baseline(src_for_baseline, now)
                if baseline_hit and label == "Benign":
                    # Only one baseline alert per IP per 60 s to avoid flooding.
                    key = ("__baseline__", src_for_baseline)
                    bl_hits = self._attack_hits.setdefault(key, deque())
                    bl_hits.append(now)
                    while bl_hits and bl_hits[0] < now - 60:
                        bl_hits.popleft()
                    if len(bl_hits) == 1:   # first hit in this window → alert
                        self._benign += 1
                        added_attacks += 1
                        self._attacks += 1
                        detection = {**baseline_hit, **meta, "detected_at": datetime.now(timezone.utc).isoformat()}
                        self._pending.append(detection)
                        self._recent.append(detection)
                    else:
                        self._benign += 1
                    continue

                if label == "Benign":
                    self._benign += 1
                    continue

                # ── Precision filters (false-positive suppression) ─────────
                # Layer 1: response traffic — src is a well-known server port,
                # dst is ephemeral.  This is a server→client reply, not an attack.
                if _is_response_flow(meta):
                    self._benign += 1
                    continue

                # Layer 2: confidence gate — ignore low-confidence predictions.
                if confidence < MIN_CONFIDENCE:
                    self._benign += 1
                    continue

                # Layer 3: repeat validation — require MIN_REPEAT flows of the
                # same attack type from the same source IP within REPEAT_WINDOW_SEC.
                # A single anomalous flow is far more likely noise than a real attack.
                hit_key: Tuple[str, str] = (str(meta.get("src_ip") or ""), label)
                hits = self._attack_hits.setdefault(hit_key, deque())
                hits.append(now)
                cutoff = now - REPEAT_WINDOW_SEC
                while hits and hits[0] < cutoff:
                    hits.popleft()
                if len(hits) < MIN_REPEAT:
                    continue
                # ─────────────────────────────────────────────────────────────

                added_attacks += 1
                self._attacks += 1
                detection = {
                    "predicted": label,
                    "confidence": confidence,
                    "severity": severity,
                    "mitre_technique": mitre_technique,
                    "mitre_tactic": mitre_tactic,
                    "description": description,
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                    **meta,
                }
                self._pending.append(detection)
                self._recent.append(detection)

            self._total_bytes += added_bytes

            # Update per-second history (merge into existing bucket if needed)
            if self._history and self._history[-1][0] == now_bucket:
                b, f, a = self._history[-1]
                self._history[-1] = (b, f + added_flows, a + added_attacks)
            else:
                self._history.append((now_bucket, added_flows, added_attacks))

            # Per-second byte history (parallel structure to _history).
            if self._byte_history and self._byte_history[-1][0] == now_bucket:
                b, total = self._byte_history[-1]
                self._byte_history[-1] = (b, total + added_bytes)
            else:
                self._byte_history.append((now_bucket, added_bytes))


# Singleton instance
live_monitor = LiveMonitor()
