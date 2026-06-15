FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpcap-dev gcc g++ libffi-dev libndpi-dev && \
    rm -rf /var/lib/apt/lists/*

ENV PYTHONOPTIMIZE=2
ENV MALLOC_TRIM_THRESHOLD_=100000

WORKDIR /app

COPY ml-service/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY ml-service/ ./ml-service/
COPY AI/model_artifacts_v4/ ./AI/model_artifacts_v4/
COPY AI/pcap_to_features.py ./AI/pcap_to_features.py

WORKDIR /app/ml-service

EXPOSE 8001

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8001}"]
