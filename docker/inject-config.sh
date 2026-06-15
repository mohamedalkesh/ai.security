#!/bin/sh
# Injects runtime API URL into the frontend before nginx starts.
# Set API_BASE_URL and WS_BASE_URL as environment variables in Railway dashboard.
cat > /usr/share/nginx/html/env-config.js << EOF
window.AISEC_API_BASE = "${API_BASE_URL:-}";
window.AISEC_WS_BASE  = "${WS_BASE_URL:-}";
EOF
