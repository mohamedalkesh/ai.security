# AI Model Expansion Plan

## Objectives
- Broaden the ensemble's coverage to the most common real-world intrusion techniques without relying on Live Monitor captures.
- Keep training runnable on the existing workstation (CPU + limited RAM) by using batch-friendly tree models.
- Preserve compatibility with the current 77-feature schema so the backend and ML service stay unchanged while we iterate.

## Target Attack Surface
1. **Volumetric floods**: TCP/UDP/ICMP, HTTP(S) GET/POST floods, DNS amplification.
2. **Credential/Brute-force**: SSH, RDP, FTP, SMTP, SMB.
3. **Scanning/Recon**: Port sweeps, ping sweeps, service fingerprinting (Nmap, Masscan).
4. **Botnet / Malware beacons**: Mirai-family, Gafgyt, IoT command & control, DGA traffic.
5. **Tunneling / Evasion**: VPN, Tor, DNS/ICMP tunneling, malicious TLS JA3 fingerprints.
6. **Lateral Movement & Exploits**: SMB, RDP, SQL injection, XSS, remote code exploits captured in curated corpora.

## Candidate Public Datasets
| Dataset | Format | Primary Coverage | Download Notes |
|---------|--------|------------------|----------------|
| **CICIDS2017** (already used) | PCAP + CSV | Broad enterprise attacks (DoS, PortScan, Botnet) | Hosted by Canadian Institute for Cybersecurity. Continue using as baseline.
| **UNSW-NB15** | PCAP + CSV | Exploits, DoS, Generic, Worms | https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/
| **Bot-IoT** | PCAP + flow CSV | IoT botnet behavior (DDoS, DoS, Recon, Theft) | https://research.unsw.edu.au/projects/bot-iot-dataset
| **TON_IoT / BoTNeTIoT-L01** | PCAP/NetFlow + logs | IoT/SCADA telemetry + botnet traffic | https://research.unsw.edu.au/projects/toniot-datasets
| **ISCX VPN/NonVPN** | PCAP | VPN tunneling, Tor, malicious HTTPS | https://www.unb.ca/cic/datasets/vpn.html
| **MAWI / CAIDA traces** | PCAP | Real backbone traffic for benign background | https://www.fukuda-lab.org/mawilab/ (requires request)
| **CTU-13 Botnet** | NetFlow | 13 distinct botnet scenarios | https://www.stratosphereips.org/datasets-ctu13
| **CSE-CIC-IDS2018** | PCAP + CSV | Modern mix of brute force, web attacks | https://www.unb.ca/cic/datasets/ids-2018.html
| **CIC-DoS2017** | PCAP + CSV | Single-purpose DoS floods (HOIC, LOIC) | https://www.unb.ca/cic/datasets/dos-2017.html

> ⚠️ Most hosts require manual agreement / email before download. Keep the raw archives in `/home/mohamed/Desktop/datasets/` once retrieved to avoid bloating the repo.

## Ingestion Strategy
1. **Raw Storage Layout**
   ```
   datasets/
     cicids2017/raw/*.pcap
     unsw-nb15/raw/*.pcap
     bot-iot/raw/*.pcap
     ...
   ```
2. **Normalization Script (`AI/tools/prepare_dataset.py`)**
   - Input: dataset manifest (YAML/JSON) describing PCAP paths + label mapping.
   - Output: unified Parquet/CSV with columns `{features..., label, source_dataset, capture_ts}`
   - Reuse `pcap_to_features.py` via a small wrapper to avoid code drift.
3. **Label Mapping**
   - Maintain `AI/datasets/label_map.yaml` that maps raw dataset labels to the 8 base classes plus new ICMP categories.
   - For datasets without fine-grained labels, fall back to heuristics (e.g., flows targeting port 22 with >N connections → `Brute Force`).
4. **Quality Gates**
   - Drop flows with missing IPs/ports.
   - Cap imbalance by undersampling benign or overweighting minority classes.
   - Persist summary stats per dataset (counts, bytes, unique hosts).

## Training Pipeline Updates
- New script `AI/train_global.py`:
  1. Reads unified dataset (configurable glob).
  2. Splits train/val/test via stratified sampling (e.g., 70/15/15) at **capture-day** granularity to avoid leakage.
  3. Trains ensemble (XGBoost, LightGBM, IsolationForest) with class weights and early stopping.
  4. Logs metrics per class (precision, recall, F1) to `reports/training/YYYY-MM-DD.json`.
  5. Saves artifacts under `AI/model_artifacts_global_v1/` (Booster dumps + metadata JSON + scaler if needed).
- Integrate optional CatBoost runner for experiments; keep toggled via CLI flag to control resource usage.

## Continuous Improvement Loop
1. **Monthly Dataset Refresh**: check for new public dumps or CTI PCAPs; update manifest.
2. **Benchmark Harness**: add `AI/tests/test_inference_accuracy.py` that loads the exported model and verifies baseline metrics > target thresholds.
3. **Deployment**: after training, update `ml-service/app/services/ml_service.py` to read the new artifact directory and expose version info in `/health`.
4. **Documentation**: Each training run appends a short changelog to this file noting datasets + metrics to maintain an audit trail.

## Immediate Next Steps
1. Add dataset manifest + ingestion script skeleton to repo.
2. Implement `train_global.py` scaffold reusing current feature space.
3. Once dataset archives are available, run the ingestion → training pipeline and compare metrics against v3.
