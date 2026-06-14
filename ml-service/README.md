# ML Service

Internal Python (FastAPI) microservice that wraps the trained IDS model.
**Not exposed publicly** — only the Java Spring Boot backend talks to it.

## Endpoints
- `GET  /health` — service + model status
- `GET  /api/model/info` — classes, features, MITRE mapping
- `POST /api/predict/flow` — JSON `{features: {…}}` → single prediction
- `POST /api/predict/pcap` — multipart `file` (.pcap) → flows + summary

Interactive docs: **http://localhost:8001/docs**

## Run
```bash
chmod +x run.sh
./run.sh
```

The script auto-detects `../AI/.venv` and re-uses it (so we don't reinstall
xgboost, sklearn, cicflowmeter, etc.). Falls back to a local `.venv`.

## Untouched files
This service **only reads** from the `AI/` folder:
- `AI/model_artifacts/*.pkl` (model weights)
- `AI/pcap_to_features.py` (imported, not modified)

No file in `AI/` is created, modified or deleted.
