#!/usr/bin/env python3
"""Quick benchmark helper for the MADRS stack.

Measures end-to-end latency for PCAP classification through the ML service and
through the Spring backend. Useful to compare before/after optimisations.

Usage (example):

    ./scripts/benchmark_scan.py \
        --pcap AI/data/extra/net-2009-11-23-16_54.pcap \
        --username testadmin --password testpass123

If --username/--password are omitted, backend measurements are skipped.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

try:
    import requests  # type: ignore
except ImportError as exc:  # pragma: no cover
    sys.stderr.write(
        "[benchmark] Python package 'requests' is required.\n"
        "Install it with: pip install requests\n"
    )
    raise SystemExit(1) from exc

DEFAULT_BACKEND = "http://127.0.0.1:8080"
DEFAULT_ML = "http://127.0.0.1:8001"
TIMEOUT = 60


def post_file(url: str, file_path: Path, headers: Optional[Dict[str, str]] = None) -> Tuple[float, requests.Response]:
    with file_path.open("rb") as fh:
        files = {"file": (file_path.name, fh, "application/octet-stream")}
        start = time.perf_counter()
        resp = requests.post(url, files=files, headers=headers, timeout=TIMEOUT)
        elapsed = time.perf_counter() - start
    return elapsed, resp


def login_for_token(backend: str, username: str, password: str) -> str:
    payload = {"username": username, "password": password}
    resp = requests.post(
        f"{backend.rstrip('/')}/api/auth/login",
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload),
        timeout=TIMEOUT,
    )
    if resp.status_code != 200:
        raise SystemExit(
            f"Login failed ({resp.status_code}): {resp.text.strip()}\n"
            "Ensure the credentials are valid or pass an API token manually."
        )
    data = resp.json()
    token = data.get("token")
    if not token:
        raise SystemExit("Login response did not include a token")
    return token


def run_benchmark(args: argparse.Namespace) -> None:
    pcap_path = Path(args.pcap)
    if not pcap_path.is_file():
        raise SystemExit(f"PCAP file not found: {pcap_path}")

    print("=== Benchmark Configuration ===")
    print(f"ML service : {args.ml_url}")
    print(f"Backend    : {args.backend_url if args.username else '(skipped)'}")
    print(f"PCAP file  : {pcap_path} ({pcap_path.stat().st_size / 1_048_576:.1f} MB)")
    print(f"Runs       : {args.runs}\n")

    ml_endpoint = f"{args.ml_url.rstrip('/')}/api/predict/pcap"
    backend_endpoint = f"{args.backend_url.rstrip('/')}/api/predict/pcap"

    # ---- Direct ML service ----
    ml_times = []
    for i in range(args.runs):
        elapsed, resp = post_file(ml_endpoint, pcap_path)
        if resp.status_code != 200:
            raise SystemExit(f"ML service returned {resp.status_code}: {resp.text[:200]}")
        ml_times.append(elapsed)
        print(f"[ML]  run {i+1}/{args.runs}: {elapsed:.2f} s")

    # ---- Backend (optional) ----
    backend_times = []
    token = None
    if args.username and args.password:
        token = login_for_token(args.backend_url, args.username, args.password)
        headers = {"Authorization": f"Bearer {token}"}
        for i in range(args.runs):
            elapsed, resp = post_file(backend_endpoint, pcap_path, headers=headers)
            if resp.status_code not in (200, 202):
                raise SystemExit(f"Backend returned {resp.status_code}: {resp.text[:200]}")
            backend_times.append(elapsed)
            print(f"[API] run {i+1}/{args.runs}: {elapsed:.2f} s")
    else:
        print("[API] skipped (no credentials provided)\n")

    def summarise(label: str, samples: list[float]) -> None:
        if not samples:
            return
        avg = sum(samples) / len(samples)
        best = min(samples)
        worst = max(samples)
        print(f"{label}: avg {avg:.2f} s · best {best:.2f} s · worst {worst:.2f} s")

    print("\n=== Summary ===")
    summarise("ML service", ml_times)
    summarise("Backend API", backend_times)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark PCAP classification latency")
    parser.add_argument("--pcap", required=True, help="Path to PCAP/CSV file to upload")
    parser.add_argument("--ml-url", default=DEFAULT_ML, help="ML service base URL")
    parser.add_argument("--backend-url", default=DEFAULT_BACKEND, help="Backend base URL")
    parser.add_argument("--username", help="Backend username for login")
    parser.add_argument("--password", help="Backend password for login")
    parser.add_argument("--runs", type=int, default=3, help="Number of repetitions per target")
    return parser.parse_args(argv)


if __name__ == "__main__":
    run_benchmark(parse_args())
