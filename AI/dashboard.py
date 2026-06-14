"""
Simple SOC Dashboard for the IDS model (Streamlit).
Run: .venv/bin/streamlit run dashboard.py
"""

from __future__ import annotations

import os
import pickle
import time
from typing import Dict

import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

ARTIFACT_DIR = "./model_artifacts"
DEFAULT_DATASET = "./data/combine.csv"
CONFIDENCE_THRESHOLD = 0.6

LABEL_MAP: Dict[str, str] = {
    "benign": "Benign", "Benign": "Benign", "BENIGN": "Benign",
    "ftp-patator": "Brute Force", "FTP-Patator": "Brute Force",
    "ssh-patator": "Brute Force", "SSH-Patator": "Brute Force",
    "ddos": "DDoS", "DDoS": "DDoS",
    "dos hulk": "DDoS", "DoS Hulk": "DDoS",
    "dos goldeneye": "DDoS", "DoS GoldenEye": "DDoS",
    "dos slowloris": "DDoS", "DoS slowloris": "DDoS",
    "dos slowhttptest": "DDoS", "DoS Slowhttptest": "DDoS",
    "heartbleed": "DDoS", "Heartbleed": "DDoS",
    "portscan": "Port Scan", "PortScan": "Port Scan",
}

MITRE_MAPPING: Dict[str, Dict[str, str]] = {
    "Benign":      {"technique": "N/A",     "tactic": "N/A",                "severity": "Informational",
                    "description": "Normal network traffic."},
    "Brute Force": {"technique": "T1110",   "tactic": "Credential Access",  "severity": "High",
                    "description": "Repeated password/login guessing."},
    "Port Scan":   {"technique": "T1046",   "tactic": "Discovery",          "severity": "Medium",
                    "description": "Scanning network services and open ports."},
    "DDoS":        {"technique": "T1498",   "tactic": "Impact",             "severity": "High",
                    "description": "Service degradation via traffic flooding."},
    "Unknown":     {"technique": "Unknown", "tactic": "Unknown",            "severity": "Low",
                    "description": "Confidence below threshold, analyst review required."},
}

SEVERITY_COLOR = {
    "Informational": "#10b981",
    "Low": "#3b82f6",
    "Medium": "#f59e0b",
    "High": "#ef4444",
}


@st.cache_resource
def load_artifacts():
    paths = {
        "model": os.path.join(ARTIFACT_DIR, "model.pkl"),
        "label_encoder": os.path.join(ARTIFACT_DIR, "label_encoder.pkl"),
        "scaler": os.path.join(ARTIFACT_DIR, "scaler.pkl"),
        "feature_names": os.path.join(ARTIFACT_DIR, "feature_names.pkl"),
    }
    out = {}
    for k, p in paths.items():
        with open(p, "rb") as f:
            out[k] = pickle.load(f)
    return out["model"], out["label_encoder"], out["scaler"], out["feature_names"]


@st.cache_data(show_spinner=False)
def load_dataset(path: str, nrows: int | None = None) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False, nrows=nrows)
    df.columns = df.columns.str.strip()
    return df


@st.cache_data(show_spinner=False, max_entries=4)
def pcap_bytes_to_dataframe(pcap_bytes: bytes, suffix: str, feature_names: tuple, max_flows: int | None) -> pd.DataFrame:
    """Cache PCAP -> features conversion by file content hash."""
    import tempfile
    from pcap_to_features import pcap_to_dataframe as _convert

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(pcap_bytes)
        path = tmp.name
    try:
        return _convert(path, list(feature_names), max_flows=max_flows)
    finally:
        if os.path.exists(path):
            os.remove(path)


def normalize_label(raw) -> str:
    if raw is None:
        return ""
    return LABEL_MAP.get(str(raw).strip(), str(raw).strip())


def predict_batch(model, label_encoder, scaler, X: np.ndarray):
    Xs = scaler.transform(X)
    proba = model.predict_proba(Xs)
    idx = np.argmax(proba, axis=1)
    conf = np.max(proba, axis=1)
    classes = label_encoder.inverse_transform(idx)
    classes = np.where(conf < CONFIDENCE_THRESHOLD, "Unknown", classes)
    return classes, conf


def get_label_column(df: pd.DataFrame) -> str | None:
    for c in ["Label", "label", "LABEL", "Class", "class"]:
        if c in df.columns:
            return c
    return None


# ---------- UI ----------
st.set_page_config(page_title="IDS Dashboard", layout="wide", page_icon="🛡️")
st.markdown(
    "<h1 style='margin-bottom:0'>🛡️ AI-Based IDS Dashboard</h1>"
    "<p style='color:gray;margin-top:4px'>Network attack classification with MITRE ATT&CK mapping</p>",
    unsafe_allow_html=True,
)

if not os.path.exists(os.path.join(ARTIFACT_DIR, "model.pkl")):
    st.error("Model artifacts not found. Train first:\n\n`.venv/bin/python ids_pipeline.py --data-path ./data/combine.csv --sample-frac 0.1`")
    st.stop()

model, label_encoder, scaler, feature_names = load_artifacts()

with st.sidebar:
    st.header("⚙️ Controls")
    mode = st.radio("Input mode", ["CSV dataset", "PCAP file", "Live capture"], horizontal=True)
    if mode == "CSV dataset":
        dataset_path = st.text_input("Dataset path", value=DEFAULT_DATASET)
        n_samples = st.slider("Number of samples", 10, 1000, 200, step=10)
        seed = st.number_input("Random seed", value=42, step=1)
        pcap_files = None
        max_flows = None
        live_iface = None
        live_duration = None
    elif mode == "PCAP file":
        pcap_files = st.file_uploader(
            "Upload one or more PCAPs",
            type=["pcap", "pcapng"],
            accept_multiple_files=True,
        )
        quick_mode = st.checkbox("⚡ Quick analysis (first 10K flows per file)", value=True,
                                 help="Stops after 10K flows per file. Uncheck for full analysis.")
        max_flows = 10_000 if quick_mode else None
        dataset_path = None
        n_samples = None
        seed = None
        live_iface = None
        live_duration = None
    else:  # Live capture
        try:
            import psutil
            iface_choices = [i for i in psutil.net_if_stats() if psutil.net_if_stats()[i].isup and i != "lo"]
        except Exception:
            iface_choices = ["wlp0s20f3", "eth0"]
        live_iface = st.selectbox("Network interface", iface_choices)
        live_duration = st.slider("Capture duration (seconds)", 5, 120, 30, step=5)
        max_flows = st.number_input("Max flows", 100, 100000, 5000, step=500)
        st.warning("⚠️ Live capture requires CAP_NET_RAW. Run dashboard with `sudo` or grant capability to python.")
        pcap_files = None
        dataset_path = None
        n_samples = None
        seed = None
    run_btn = st.button("🚀 Run Analysis", type="primary", use_container_width=True)
    st.divider()
    st.caption(f"**Model:** {type(model).__name__}")
    st.caption(f"**Classes:** {', '.join(label_encoder.classes_)}")
    st.caption(f"**Features:** {len(feature_names)}")

if not run_btn:
    st.info("Set parameters from the sidebar and click **Run Analysis**.")
    st.stop()

label_col = None
sample = None

if mode == "Live capture":
    from nfstream import NFStreamer
    from pcap_to_features import _nfstream_to_cicids

    st.info(f"🎙️ Capturing from **{live_iface}** for **{live_duration}s** (or until {max_flows:,} flows)...")
    progress = st.progress(0.0, text="Starting capture...")
    status = st.empty()

    rows = []
    attr_names = None
    try:
        streamer = NFStreamer(
            source=live_iface,
            statistical_analysis=True,
            n_dissections=0,
            accounting_mode=0,
            idle_timeout=15,
            active_timeout=30,
        )
        t0 = time.time()
        for i, flow in enumerate(streamer):
            elapsed = time.time() - t0
            if elapsed >= live_duration or i >= max_flows:
                break
            if attr_names is None:
                attr_names = [k for k in dir(flow) if not k.startswith("_") and not callable(getattr(flow, k, None))]
            row = {}
            for k in attr_names:
                try:
                    row[k] = getattr(flow, k)
                except AttributeError:
                    row[k] = None
            rows.append(row)
            if i % 25 == 0:
                progress.progress(min(elapsed / live_duration, 1.0),
                                  text=f"Captured {i+1} flows | {elapsed:.1f}s elapsed")
                status.caption(f"Live: {i+1} flows so far")
    except PermissionError:
        st.error("❌ Permission denied. Run dashboard with `sudo` or grant CAP_NET_RAW to python.")
        st.stop()
    except Exception as exc:
        st.error(f"Capture failed: {exc}")
        st.stop()
    finally:
        progress.empty()
        status.empty()

    if not rows:
        st.warning("No flows captured. Generate some traffic and retry.")
        st.stop()

    nf_df = pd.DataFrame(rows)
    df = _nfstream_to_cicids(nf_df)
    for col in feature_names:
        if col not in df.columns:
            df[col] = 0

    st.success(f"✅ Captured **{len(df):,} flows** from `{live_iface}` in {time.time()-t0:.1f}s.")
    sample = df
    X = df[feature_names].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0)

elif mode == "PCAP file":
    if not pcap_files:
        st.error("Please upload at least one .pcap or .pcapng file from the sidebar.")
        st.stop()

    frames = []
    progress = st.progress(0.0, text="Extracting flows...")
    summary_lines = []
    for i, pf in enumerate(pcap_files, 1):
        progress.progress((i - 1) / len(pcap_files), text=f"Processing {pf.name} ({i}/{len(pcap_files)})...")
        pcap_bytes = pf.read()
        suffix = os.path.splitext(pf.name)[1] or ".pcap"
        try:
            sub = pcap_bytes_to_dataframe(pcap_bytes, suffix, tuple(feature_names), max_flows)
        except Exception as exc:
            st.error(f"❌ {pf.name}: {exc}")
            continue
        if sub.empty:
            st.warning(f"⚠️ No flows extracted from {pf.name}.")
            continue
        sub["__source_file__"] = pf.name
        frames.append(sub)
        summary_lines.append(f"- **{pf.name}** → {len(sub):,} flows")
    progress.progress(1.0, text="Done.")
    progress.empty()

    if not frames:
        st.error("No usable flows extracted from any uploaded PCAP.")
        st.stop()

    df = pd.concat(frames, ignore_index=True)
    st.success(f"Extracted **{len(df):,} flows total** from {len(frames)} file(s).")
    with st.expander("Per-file breakdown", expanded=False):
        st.markdown("\n".join(summary_lines))

    sample = df
    X = df[feature_names].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0)

else:
    if not os.path.exists(dataset_path):
        st.error(f"Dataset not found: {dataset_path}")
        st.stop()

    with st.spinner("Loading dataset..."):
        df = load_dataset(dataset_path, nrows=200_000)

    missing = [f for f in feature_names if f not in df.columns]
    if missing:
        st.error(f"Dataset is missing {len(missing)} required features. Example: {missing[:5]}")
        st.stop()

    label_col = get_label_column(df)
    sample = df.sample(n=min(n_samples, len(df)), random_state=int(seed)).reset_index(drop=True)

    X = sample[feature_names].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    valid_mask = ~X.isna().any(axis=1)
    X = X[valid_mask]
    sample = sample.loc[X.index]

with st.spinner("Running predictions..."):
    preds, confs = predict_batch(model, label_encoder, scaler, X.to_numpy(dtype=float))

result = pd.DataFrame({
    "Predicted": preds,
    "Confidence": np.round(confs, 4),
})
result["MITRE Technique"] = result["Predicted"].map(lambda p: MITRE_MAPPING.get(p, MITRE_MAPPING["Unknown"])["technique"])
result["MITRE Tactic"] = result["Predicted"].map(lambda p: MITRE_MAPPING.get(p, MITRE_MAPPING["Unknown"])["tactic"])
result["Severity"] = result["Predicted"].map(lambda p: MITRE_MAPPING.get(p, MITRE_MAPPING["Unknown"])["severity"])
result["Description"] = result["Predicted"].map(lambda p: MITRE_MAPPING.get(p, MITRE_MAPPING["Unknown"])["description"])
if label_col:
    result["True Label"] = sample[label_col].astype(str).map(normalize_label).values
    result["Match"] = np.where(result["True Label"] == result["Predicted"], "✅", "❌")

# Attach flow IPs/ports if available (PCAP mode)
for meta_col in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "__source_file__"):
    if meta_col in sample.columns:
        result[meta_col] = sample[meta_col].values
if "__source_file__" in result.columns:
    result = result.rename(columns={"__source_file__": "source_file"})

# ---------- Top metrics ----------
total = len(result)
attacks = int((result["Predicted"] != "Benign").sum())
benign = total - attacks
avg_conf = float(result["Confidence"].mean())
acc = float((result["Match"] == "✅").mean()) if "Match" in result.columns else None

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Samples", f"{total:,}")
c2.metric("Detected Attacks", f"{attacks:,}", delta=f"{attacks/total:.0%}")
c3.metric("Benign Traffic", f"{benign:,}", delta=f"{benign/total:.0%}")
c4.metric("Avg Confidence", f"{avg_conf:.2%}")
if acc is not None:
    st.success(f"🎯 Accuracy on this batch: **{acc:.2%}**")

st.divider()

# ---------- Charts ----------
left, right = st.columns(2)
with left:
    st.subheader("📊 Attack Type Distribution")
    counts = result["Predicted"].value_counts().reset_index()
    counts.columns = ["Attack Type", "Count"]
    fig = px.bar(counts, x="Attack Type", y="Count", color="Attack Type", text="Count")
    fig.update_layout(showlegend=False, height=380)
    st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("⚠️ Severity Breakdown")
    sev = result["Severity"].value_counts().reset_index()
    sev.columns = ["Severity", "Count"]
    fig = px.pie(sev, names="Severity", values="Count", color="Severity",
                 color_discrete_map=SEVERITY_COLOR, hole=0.4)
    fig.update_layout(height=380)
    st.plotly_chart(fig, use_container_width=True)

st.subheader("🎯 MITRE ATT&CK Tactics")
tac = result.groupby(["MITRE Tactic", "MITRE Technique"]).size().reset_index(name="Count")
fig = px.bar(tac, x="MITRE Tactic", y="Count", color="MITRE Technique", text="Count")
fig.update_layout(height=380)
st.plotly_chart(fig, use_container_width=True)

# ---------- Logs table ----------
st.subheader("📜 Detection Logs")
display_cols = ["Predicted", "Confidence", "Severity", "MITRE Technique", "MITRE Tactic", "Description"]
if "True Label" in result.columns:
    display_cols = ["Match", "True Label"] + display_cols
flow_cols = [c for c in ("source_file", "src_ip", "dst_ip", "dst_port", "protocol") if c in result.columns]
if flow_cols:
    display_cols = flow_cols + display_cols
MAX_DISPLAY = 2000
display_df = result[display_cols]
if len(display_df) > MAX_DISPLAY:
    st.caption(f"Showing first {MAX_DISPLAY:,} of {len(display_df):,} flows. Use the download button for full data.")
    display_df = display_df.head(MAX_DISPLAY)
st.dataframe(display_df, use_container_width=True, height=420)

csv = result.to_csv(index=False).encode("utf-8")
st.download_button("⬇️ Download Results (CSV)", data=csv, file_name="ids_predictions.csv", mime="text/csv")

# ---------- Session-level analysis (PCAP only) ----------
if "src_ip" in result.columns and "dst_ip" in result.columns:
    st.divider()
    st.header("🔬 Session-Level Threat Analysis")
    st.caption("Aggregated cross-flow detection (catches attacks the per-flow model misses).")

    PORTSCAN_PORTS = 50
    PORTSCAN_FLOWS = 100
    DDOS_FLOWS = 5000

    sources = result.groupby("src_ip").agg(
        total_flows=("dst_port", "size"),
        unique_dst_ports=("dst_port", "nunique"),
        unique_dst_ips=("dst_ip", "nunique"),
    ).reset_index()
    scanners = sources[
        (sources["unique_dst_ports"] >= PORTSCAN_PORTS) &
        (sources["total_flows"] >= PORTSCAN_FLOWS)
    ].sort_values("unique_dst_ports", ascending=False)

    targets = result.groupby("dst_ip").agg(
        total_flows=("src_ip", "size"),
        unique_src_ips=("src_ip", "nunique"),
    ).reset_index()
    targets = targets[targets["total_flows"] >= DDOS_FLOWS].sort_values("total_flows", ascending=False)

    s1, s2, s3 = st.columns(3)
    s1.metric("🎯 Port Scanners Detected", f"{len(scanners):,}")
    s2.metric("💥 DDoS / Flood Targets", f"{len(targets):,}")
    scanner_flow_ratio = (result["src_ip"].isin(scanners["src_ip"]).sum() / len(result)) if len(scanners) else 0
    s3.metric("Malicious Traffic Share", f"{scanner_flow_ratio:.1%}")

    sc_col, tg_col = st.columns(2)
    with sc_col:
        st.subheader("🎯 Top Port Scanners (T1046 / Discovery)")
        if scanners.empty:
            st.info("No port scanners detected.")
        else:
            st.dataframe(scanners.head(15), use_container_width=True, height=380)
    with tg_col:
        st.subheader("💥 DDoS Targets (T1498 / Impact)")
        if targets.empty:
            st.info("No DDoS targets detected.")
        else:
            st.dataframe(targets.head(15), use_container_width=True, height=380)

# ---------- AI-Suggested Response Actions ----------
st.divider()
st.header("🤖 AI-Suggested Response Actions")
st.caption("Auto-generated SOC playbook with ready-to-copy firewall commands.")

from response_recommender import build_action_plan, SEVERITY_RANK  # noqa: E402

# Build a unified detection frame: per-flow attacks + session-level scanners/DDoS
det_rows = []

# 1) Per-flow predicted attacks (if any)
attack_rows = result[result["Predicted"] != "Benign"].copy()
det_rows.append(attack_rows)

# 2) Session-level Port Scanners
if "src_ip" in result.columns:
    sources_full = result.groupby("src_ip").agg(
        total_flows=("dst_port", "size"),
        unique_dst_ports=("dst_port", "nunique"),
    ).reset_index()
    scanner_rows = sources_full[
        (sources_full["unique_dst_ports"] >= 50) & (sources_full["total_flows"] >= 100)
    ].copy()
    if not scanner_rows.empty:
        scanner_rows["Predicted"] = "Port Scan"
        scanner_rows["Severity"] = "Medium"
        scanner_rows = scanner_rows.rename(columns={"src_ip": "src_ip"})
        det_rows.append(scanner_rows[["src_ip", "Predicted", "Severity"]])

# 3) Session-level DDoS targets — synthesize attacker rows from top sources
if "src_ip" in result.columns and "dst_ip" in result.columns:
    targets_full = result.groupby("dst_ip").agg(total_flows=("src_ip", "size")).reset_index()
    flooded = targets_full[targets_full["total_flows"] >= 5000]
    if not flooded.empty:
        for tgt in flooded["dst_ip"]:
            top_attackers = (
                result[result["dst_ip"] == tgt]["src_ip"].value_counts().head(10).index.tolist()
            )
            ddos_df = pd.DataFrame({
                "src_ip": top_attackers,
                "Predicted": "DDoS",
                "Severity": "High",
                "dst_ip": tgt,
            })
            det_rows.append(ddos_df)

unified = pd.concat([d for d in det_rows if not d.empty], ignore_index=True) if det_rows else pd.DataFrame()

min_sev_choice = st.selectbox(
    "Minimum severity to include in response plan",
    ["Low", "Medium", "High"], index=1,
)
plan = build_action_plan(unified, min_severity=min_sev_choice, top_n_per_class=5) if not unified.empty else []

if not plan:
    st.success("✅ No high-severity actions required for this batch.")
else:
    st.warning(f"⚠️ Generated **{len(plan)}** prioritized response actions.")
    for i, item in enumerate(plan, 1):
        sev = item["priority"]
        sev_color = {"Critical": "🔴", "High": "🔴", "Medium": "🟠", "Low": "🟡"}.get(sev, "⚪")
        title = f"{sev_color} **#{i} — {item['attack_type']}**  ·  {item['tactic']}  ·  Priority: **{sev}**"
        if item.get("hits"):
            title += f"  ·  Hits: {item['hits']}"
        with st.expander(title, expanded=(i <= 3)):
            st.markdown("**🛡️ Recommended actions:**")
            for a in item["actions"]:
                st.markdown(f"- {a}")
            if item["commands"]:
                st.markdown("**⚙️ Ready-to-run commands:**")
                for label, cmds in item["commands"].items():
                    st.markdown(f"_{label}_")
                    tabs = st.tabs(list(cmds.keys()))
                    for tab, key in zip(tabs, cmds.keys()):
                        with tab:
                            st.code(cmds[key], language="bash")
