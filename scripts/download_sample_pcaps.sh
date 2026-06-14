#!/usr/bin/env bash
# Fetch a handful of publicly accessible PCAPs for quick testing.
# Usage: ./scripts/download_sample_pcaps.sh [destination_dir]

set -euo pipefail

DEST_DIR="${1:-$HOME/Desktop/datasets/samples}"
mkdir -p "$DEST_DIR"

fetch() {
  local url="$1"
  local filename="$2"
  local out="$DEST_DIR/$filename"
  if [ -f "$out" ]; then
    echo "[skip] $filename already present"
    return
  fi
  echo "[fetch] $filename"
  curl -L --fail --progress-bar "$url" -o "$out"
}

BASE="https://github.com/wireshark/wireshark/raw/master/test/captures"

fetch "$BASE/icmp.pcap" "icmp_sweep.pcap"
fetch "$BASE/http.cap" "http_web.pcap"
fetch "$BASE/ssh2.pcap" "ssh_bruteforce.pcap"
fetch "$BASE/smtp.pcap" "smtp_spam.pcap"
fetch "$BASE/dns.cap" "dns_queries.pcap"

echo "\nSaved files in $DEST_DIR:" 
ls -lh "$DEST_DIR"/*.pcap

echo "\nSHA256 checksums:" 
sha256sum "$DEST_DIR"/*.pcap
