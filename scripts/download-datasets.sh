#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# MADRS — Dataset downloader for IDS pipeline v5 training.
#
# Downloads and prepares:
#   1. CICIDS2017    — original training set (University of New Brunswick)
#   2. NF-UQ-NIDS-2022 — modern 15-class dataset (Kaggle, ~2GB)
#   3. UNSW-NB15     — legacy but comprehensive (~900MB)
#   4. TON-IoT       — IoT + modern attacks including ransomware (~300MB)
#
# Usage:
#   bash scripts/download-datasets.sh [--all] [--cicids2017] [--nf-uq] [--unsw] [--toniot]
#
# Requirements:
#   apt install wget unzip p7zip-full
#   pip install kaggle   (for NF-UQ-NIDS — needs ~/.kaggle/kaggle.json)
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$ROOT/AI/data"
mkdir -p "$DATA"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERR]${NC}   $*"; }

# ── helpers ───────────────────────────────────────────────────────────────────
need_cmd() { command -v "$1" &>/dev/null || { error "Missing: $1"; exit 1; }; }
dl() { wget -q --show-progress --continue -O "$2" "$1"; }

# ── CICIDS2017 ────────────────────────────────────────────────────────────────
download_cicids2017() {
  info "=== CICIDS2017 (University of New Brunswick) ==="
  DIR="$DATA/cicids2017"; mkdir -p "$DIR"

  BASE="https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/GeneratedLabelledFlows.zip"
  info "Downloading GeneratedLabelledFlows.zip (~480MB) …"
  dl "$BASE" "$DIR/GeneratedLabelledFlows.zip"

  info "Extracting …"
  unzip -q -o "$DIR/GeneratedLabelledFlows.zip" -d "$DIR"
  rm "$DIR/GeneratedLabelledFlows.zip"

  info "Merging CSVs → $DATA/cicids2017.csv"
  python3 - << 'PY'
import pandas as pd, glob, os, sys
files = sorted(glob.glob(os.path.join(os.environ.get("DIR",""), "**/*.csv"), recursive=True))
print(f"  Found {len(files)} CSV files")
dfs = []
for f in files:
    try:
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()
        dfs.append(df)
        print(f"  {os.path.basename(f)}: {len(df)} rows")
    except Exception as e:
        print(f"  SKIP {f}: {e}")
out = pd.concat(dfs, ignore_index=True)
out.to_csv(os.path.join(os.environ.get("DATA",""), "cicids2017.csv"), index=False)
print(f"  Total: {len(out)} rows → cicids2017.csv")
PY
  info "✓ CICIDS2017 ready"
}

# ── NF-UQ-NIDS-2022 ───────────────────────────────────────────────────────────
download_nf_uq() {
  info "=== NF-UQ-NIDS-2022 (Kaggle — needs kaggle CLI) ==="
  need_cmd kaggle
  DIR="$DATA/nf-uq-nids"; mkdir -p "$DIR"

  info "Downloading via Kaggle API …"
  kaggle datasets download -d "dhoogla/nfuqnids2022" -p "$DIR" --unzip 2>/dev/null || \
  kaggle datasets download -d "hassan06/nfuqnids" -p "$DIR" --unzip 2>/dev/null || {
    warn "Kaggle download failed — download manually from:"
    warn "  https://www.kaggle.com/datasets/dhoogla/nfuqnids2022"
    warn "  Place the CSV as: $DATA/nf_uq_nids.csv"
    return 1
  }

  # rename to standard name
  CSV=$(find "$DIR" -name "*.csv" | head -1)
  if [ -n "$CSV" ]; then
    cp "$CSV" "$DATA/nf_uq_nids.csv"
    info "✓ NF-UQ-NIDS-2022 ready: $(wc -l < "$DATA/nf_uq_nids.csv") rows"
  fi
}

# ── UNSW-NB15 ─────────────────────────────────────────────────────────────────
download_unsw() {
  info "=== UNSW-NB15 ==="
  DIR="$DATA/unsw-nb15"; mkdir -p "$DIR"

  # UNSW-NB15 features CSV (public mirror)
  URLS=(
    "https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download?path=%2FUNSW-NB15%20-%20CSV%20Files&files=UNSW-NB15_1.csv"
    "https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download?path=%2FUNSW-NB15%20-%20CSV%20Files&files=UNSW-NB15_2.csv"
    "https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download?path=%2FUNSW-NB15%20-%20CSV%20Files&files=UNSW-NB15_3.csv"
    "https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download?path=%2FUNSW-NB15%20-%20CSV%20Files&files=UNSW-NB15_4.csv"
  )

  for i in "${!URLS[@]}"; do
    f="$DIR/UNSW-NB15_$((i+1)).csv"
    info "Downloading part $((i+1))/4 …"
    dl "${URLS[$i]}" "$f" || warn "Part $((i+1)) failed — try manual download"
  done

  info "Merging UNSW-NB15 → $DATA/unsw_nb15.csv"
  python3 - << 'PY'
import pandas as pd, glob, os
COLS_HDR = ["srcip","sport","dstip","dsport","proto","state","dur","sbytes","dbytes",
            "sttl","dttl","sloss","dloss","service","Sload","Dload","Spkts","Dpkts",
            "swin","dwin","stcpb","dtcpb","smeansz","dmeansz","trans_depth","res_bdy_len",
            "Sjit","Djit","Stime","Ltime","Sintpkt","Dintpkt","tcprtt","synack","ackdat",
            "is_sm_ips_ports","ct_state_ttl","ct_flw_http_mthd","is_ftp_login",
            "ct_ftp_cmd","ct_srv_src","ct_srv_dst","ct_dst_ltm","ct_src_ltm",
            "ct_src_dport_ltm","ct_dst_sport_ltm","ct_dst_src_ltm","attack_cat","Label"]
files = sorted(glob.glob(os.path.join(os.environ.get("DIR",""), "*.csv")))
dfs = []
for f in files:
    try:
        df = pd.read_csv(f, header=None, names=COLS_HDR, low_memory=False)
        dfs.append(df)
        print(f"  {os.path.basename(f)}: {len(df)} rows")
    except Exception as e:
        print(f"  SKIP {f}: {e}")
if dfs:
    out = pd.concat(dfs, ignore_index=True)
    # rename label column to standard
    out = out.rename(columns={"attack_cat": "Label"})
    out.to_csv(os.path.join(os.environ.get("DATA",""), "unsw_nb15.csv"), index=False)
    print(f"  Total: {len(out)} rows → unsw_nb15.csv")
PY
  info "✓ UNSW-NB15 ready"
}

# ── TON-IoT ───────────────────────────────────────────────────────────────────
download_toniot() {
  info "=== TON-IoT (UNSW — includes ransomware, XSS, SQLi) ==="
  warn "TON-IoT requires registration at:"
  warn "  https://research.unsw.edu.au/projects/toniot-datasets"
  warn "After download, place the Network_dataset.csv as: $DATA/toniot.csv"
  warn ""
  warn "Alternative: use Kaggle"
  warn "  kaggle datasets download -d 'dhoogla/toniot-datasets' -p $DATA/toniot/ --unzip"
}

# ── Combine all for training ──────────────────────────────────────────────────
combine_all() {
  info "=== Combining available datasets for v5 training ==="
  python3 - << 'PY'
import pandas as pd, os, sys

DATA = os.path.join(os.environ.get("DATA",""), "")
files = {
    "cicids2017": os.path.join(DATA, "cicids2017.csv"),
    "nf-uq-nids": os.path.join(DATA, "nf_uq_nids.csv"),
    "unsw-nb15":  os.path.join(DATA, "unsw_nb15.csv"),
    "toniot":     os.path.join(DATA, "toniot.csv"),
}
frames = []
for name, path in files.items():
    if os.path.exists(path):
        print(f"  Loading {name}: {path}")
        df = pd.read_csv(path, low_memory=False)
        df["_source"] = name
        frames.append(df)
    else:
        print(f"  SKIP (not found): {path}")

if not frames:
    print("No datasets found — nothing to combine")
    sys.exit(1)

out = pd.concat(frames, ignore_index=True, sort=False)
out_path = os.path.join(DATA, "combined_v5.csv")
out.to_csv(out_path, index=False)
print(f"\n✓ Combined: {len(out)} rows → {out_path}")
print("Class distribution:")
print(out.get("Label", out.get("label", pd.Series())).value_counts().to_string())
PY
}

# ── Main ──────────────────────────────────────────────────────────────────────
ALL=false; DO_CICIDS=false; DO_NF=false; DO_UNSW=false; DO_TONIOT=false; DO_COMBINE=false

[ $# -eq 0 ] && { echo "Usage: $0 [--all] [--cicids2017] [--nf-uq] [--unsw] [--toniot] [--combine]"; exit 0; }

for arg in "$@"; do
  case "$arg" in
    --all)        ALL=true ;;
    --cicids2017) DO_CICIDS=true ;;
    --nf-uq)      DO_NF=true ;;
    --unsw)       DO_UNSW=true ;;
    --toniot)     DO_TONIOT=true ;;
    --combine)    DO_COMBINE=true ;;
  esac
done

export DATA DIR

$ALL && { DO_CICIDS=true; DO_NF=true; DO_UNSW=true; DO_TONIOT=true; DO_COMBINE=true; }

$DO_CICIDS  && { DIR="$DATA/cicids2017";  download_cicids2017; }
$DO_NF      && { DIR="$DATA/nf-uq-nids"; download_nf_uq; }
$DO_UNSW    && { DIR="$DATA/unsw-nb15";   download_unsw; }
$DO_TONIOT  && download_toniot
$DO_COMBINE && combine_all

info ""
info "Next step — train v5 model:"
info "  python3 $ROOT/AI/ids_pipeline_v5.py \\"
info "      --data $DATA/combined_v5.csv \\"
info "      --dataset-names cicids2017 \\"
info "      --out $ROOT/AI/model_artifacts_v5"
