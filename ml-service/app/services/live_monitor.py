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
import queue
import threading
import time
from collections import Counter, deque, defaultdict
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple

import numpy as np

from app.services.ml_service import ml_service
from app.services.mitre import enrich

logger = logging.getLogger(__name__)

# Tunables ---------------------------------------------------------------
BATCH_SIZE = 64            # max flows per inference call
BATCH_INTERVAL_MS = 150    # flush even if batch not full
RATE_WINDOW_SEC = 10       # rolling window for flows/sec and attacks/sec
HISTORY_SEC = 60           # per-second buckets retained for sparkline

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
ICMP_FLOOD_PKTS = 50       # single-flow packet threshold (ping -f style)
ICMP_PROBE_THRESHOLD = 5   # single-packet ICMP probes to one dst → flood
ICMP_SWEEP_HOSTS = 5       # distinct hosts a source must touch → sweep
ICMP_WINDOW_SEC = 10       # sliding window for probe accounting

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
    return {
        "src_ip": getattr(flow, "src_ip", None),
        "dst_ip": getattr(flow, "dst_ip", None),
        "src_port": getattr(flow, "src_port", None),
        "dst_port": getattr(flow, "dst_port", None),
        "protocol": getattr(flow, "protocol", None),
        "packets": getattr(flow, "bidirectional_packets", 0),
        "bytes": getattr(flow, "bidirectional_bytes", 0),
        "bidirectional_packets": getattr(flow, "bidirectional_packets", 0),
        "bidirectional_bytes": getattr(flow, "bidirectional_bytes", 0),
        "src2dst_packets": getattr(flow, "src2dst_packets", 0),
        "dst2src_packets": getattr(flow, "dst2src_packets", 0),
    }


class LiveMonitor:
    """Singleton live-capture monitor with batched inference."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._capture_thread: Optional[threading.Thread] = None
        self._classify_thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._streamer = None
        # Explicit running flag — flips False immediately on stop() so the UI
        # reflects "Stopped" even if the capture thread is still blocked
        # inside libpcap waiting on a quiet/DOWN interface.
        self._running_flag: bool = False

        # Inter-thread queue from capture → classifier
        self._queue: "queue.Queue[Tuple[Dict[str, float], Dict[str, Any]]]" = queue.Queue(maxsize=5000)

        self._iface: Optional[str] = None
        self._started_at: Optional[float] = None
        self._last_flow_at: Optional[float] = None
        self._error: Optional[str] = None

        self._total_flows: int = 0
        self._benign: int = 0
        self._attacks: int = 0
        self._dropped: int = 0  # queue overflow

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
        # Used to require MIN_REPEAT detections of the same type from the same
        # source before surfacing an alert (suppresses one-shot anomalies).
        self._attack_hits: Dict[Tuple[str, str], Deque[float]] = {}
        self._byte_history: Deque[Tuple[int, int]] = deque(maxlen=HISTORY_SEC)  # (bucket, bytes)

        # Rolling ICMP probe windows for heuristic flood / sweep detection.
        self._icmp_src_window: defaultdict[str, Deque[Tuple[float, Optional[str]]]] = defaultdict(deque)
        self._icmp_dst_window: defaultdict[str, Deque[float]] = defaultdict(deque)

    # ------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._running_flag

    # ------------------------------------------------------------------
    def start(self, iface: str) -> Dict[str, Any]:
        # Reject DOWN interfaces up-front — capturing on them blocks libpcap
        # forever with zero packets and gives the user a misleading "running
        # but no traffic" state.
        try:
            import psutil  # local import: only needed at start
            stats = psutil.net_if_stats()
            info = stats.get(iface)
            if info is None:
                raise ValueError(f"Interface '{iface}' not found")
            if not info.isup:
                raise ValueError(
                    f"Interface '{iface}' is DOWN — pick an UP interface "
                    f"(e.g. one with an IP address) so packets can be captured."
                )
        except ValueError:
            raise
        except Exception:
            # psutil missing or transient error — skip the guard rather than block start
            pass

        with self._lock:
            if self.running:
                return self._status_locked()

            ml_service.load()  # ensure model ready before capture starts
            self._running_flag = True
            self._iface = iface
            self._error = None
            self._started_at = time.time()
            self._last_flow_at = None
            self._total_flows = 0
            self._benign = 0
            self._attacks = 0
            self._dropped = 0
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
            self._total_bytes = 0
            self._stop_evt.clear()
            self._icmp_src_window.clear()
            self._icmp_dst_window.clear()

            # Drain any stale items
            try:
                while True:
                    self._queue.get_nowait()
            except queue.Empty:
                pass

            self._capture_thread = threading.Thread(
                target=self._capture_loop, name=f"live-capture-{iface}", daemon=True
            )
            self._classify_thread = threading.Thread(
                target=self._classify_loop, name=f"live-classify-{iface}", daemon=True
            )
            self._capture_thread.start()
            self._classify_thread.start()
            logger.info("LiveMonitor started on interface %s", iface)
            return self._status_locked()

    # ------------------------------------------------------------------
    def stop(self) -> Dict[str, Any]:
        with self._lock:
            if not self.running:
                return self._status_locked()
            self._stop_evt.set()
            # Flip running off immediately so the UI updates without waiting
            # for the (possibly libpcap-blocked) capture thread to unwind.
            self._running_flag = False
            logger.info("LiveMonitor stop requested")
        # Best-effort: wait briefly for threads to finish current batch.
        # Capture thread may stay alive inside libpcap until the next packet
        # arrives — it's a daemon, so it will be reaped at process exit.
        for t in (self._classify_thread, self._capture_thread):
            if t is not None:
                t.join(timeout=2)
        return self.status()

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

        return {
            "running": self.running,
            "interface": self._iface,
            "started_at": (
                datetime.fromtimestamp(self._started_at, tz=timezone.utc).isoformat()
                if self._started_at else None
            ),
            "uptime_sec": round(elapsed, 1),
            "total_flows": self._total_flows,
            "benign": self._benign,
            "attacks": self._attacks,
            "dropped": self._dropped,
            "queue_depth": self._queue.qsize(),
            "flows_per_sec": round(flows_per_sec, 2),
            "attacks_per_sec": round(attacks_per_sec, 2),
            "bytes_per_sec": round(bytes_per_sec, 2),
            "total_bytes": int(self._total_bytes),
            "flows_last_10s": flows_w,
            "attacks_last_10s": attacks_w,
            "top_src_ips": top_src,             # [{ip, flows, bytes}, ...]
            "top_dst_ips": top_dst,
            "protocol_distribution": proto_dist, # [{label, flows, bytes}, ...]
            "history_bytes": series_bytes,       # 60 ints, oldest first
            "pending_detections": len(self._pending),
            "recent_detections": list(self._recent),
            "recent_email": list(self._recent_email),
            "recent_app": list(self._recent_app),
            "email_count": self._email_count,
            "history_flows": series_flows,      # 60 ints, oldest first
            "history_attacks": series_attacks,  # 60 ints, oldest first
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

        src_pkts = int(meta.get("src2dst_packets") or packets)
        dst_pkts = int(meta.get("dst2src_packets") or 0)
        is_probe = packets <= 4 and src_pkts <= 2 and dst_pkts <= 2
        if not is_probe:
            return None

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
    def _capture_loop(self) -> None:
        try:
            from nfstream import NFStreamer
        except ImportError as e:
            self._error = f"nfstream not available: {e}"
            logger.error(self._error)
            return

        try:
            # Tighter timeouts → flows are finalised and classified ~3x faster.
            self._streamer = NFStreamer(
                source=self._iface,
                statistical_analysis=True,
                n_dissections=0,
                accounting_mode=0,
                idle_timeout=5,
                active_timeout=30,
            )
        except Exception as e:
            self._error = f"Failed to open interface '{self._iface}': {e}"
            logger.error(self._error)
            return

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
            for flow in self._streamer:
                if self._stop_evt.is_set():
                    break
                try:
                    feat = _nflow_to_feature_dict(flow)
                    meta = _flow_meta(flow)
                    self._queue.put_nowait((feat, meta))
                except queue.Full:
                    # Classifier can't keep up — count the drop instead of blocking capture.
                    with self._lock:
                        self._dropped += 1
                except Exception as e:
                    logger.exception("flow enqueue failed: %s", e)
        except PermissionError as e:
            self._error = f"Permission denied on {self._iface}: {e}\n{_perm_hint()}"
            logger.error(self._error)
        except Exception as e:
            msg = str(e)
            if _is_perm_error(msg):
                self._error = (
                    f"Cannot capture on '{self._iface}': {msg}\n{_perm_hint()}"
                )
                logger.error(self._error)
            else:
                self._error = f"Capture loop error: {msg}"
                logger.exception("Capture loop error")
        finally:
            # Always clear the running flag so the UI doesn't get stuck on
            # "running" if the capture thread exited on its own (permissions,
            # iface vanished, libpcap error, ...).
            self._running_flag = False
            logger.info(
                "Capture loop exiting — iface=%s, flows=%d, attacks=%d, dropped=%d",
                self._iface, self._total_flows, self._attacks, self._dropped,
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
