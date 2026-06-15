FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpcap-dev gcc g++ libffi-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY ml-service/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY ml-service/ ./ml-service/
COPY AI/model_artifacts_v4/ ./AI/model_artifacts_v4/

WORKDIR /app/ml-service

EXPOSE 8001

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8001}"]
