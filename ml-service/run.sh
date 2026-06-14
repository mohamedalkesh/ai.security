#!/usr/bin/env bash
# Run the ML service. Re-uses AI/.venv if present, else creates a local one.
set -e
cd "$(dirname "$0")"

if [ -d "../AI/.venv" ]; then
  echo "→ Using existing virtualenv: ../AI/.venv"
  PY="../AI/.venv/bin/python"
elif [ -d ".venv" ]; then
  echo "→ Using local virtualenv: .venv"
  PY=".venv/bin/python"
else
  echo "→ Creating local virtualenv .venv"
  python3 -m venv .venv
  PY=".venv/bin/python"
fi

# Install / update dependencies (uses `python -m pip` so it works even
# when the bundled `pip` shebang points to an old venv path)
echo "→ Installing requirements"
"$PY" -m pip install --quiet -r requirements.txt

# Run uvicorn
HOST=$(grep -E '^HOST=' .env 2>/dev/null | cut -d= -f2 || echo "127.0.0.1")
PORT=$(grep -E '^PORT=' .env 2>/dev/null | cut -d= -f2 || echo "8001")
echo "→ Starting on http://${HOST}:${PORT}  (docs: /docs)"
exec "$PY" -m uvicorn app.main:app --host "$HOST" --port "$PORT" --reload
