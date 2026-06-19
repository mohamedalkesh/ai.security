#!/usr/bin/env bash
# Builds the backend JAR and copies it to a fixed path so systemd always finds it.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "→ Building backend JAR..."
cd "$ROOT/backend"
mvn package -DskipTests -q
cp target/backend-*.jar target/madrs-backend.jar
echo "✓ Built: $ROOT/backend/target/madrs-backend.jar"
