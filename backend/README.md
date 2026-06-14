# Java Spring Boot Backend

Main backend for the AI Security Platform. Talks to the Python `ml-service`
(running on `:8001`) for all model predictions.

## Run
```bash
cd backend
mvn spring-boot:run
```

Server will start on **http://localhost:8080**.

## Endpoints
- `GET  /api/health`         — backend + ML service status
- `GET  /api/model/info`     — proxied from ML service
- `POST /api/predict/flow`   — proxied from ML service
- `POST /api/predict/pcap`   — proxied (multipart) from ML service
- `GET  /actuator/health`    — Spring Boot health

## Requirements
- Java 21
- Maven 3.8+
- ML service running at `http://127.0.0.1:8001`
