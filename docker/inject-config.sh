#!/bin/sh
# Inject API URL and substitute PORT in nginx config before nginx starts.
export PORT="${PORT:-80}"

cat > /usr/share/nginx/html/env-config.js << JSEOF
window.AISEC_API_BASE = "${API_BASE_URL}";
window.AISEC_WS_BASE  = "${WS_BASE_URL}";
JSEOF

envsubst '${PORT}' < /etc/nginx/conf.d/default.conf > /tmp/default.conf
cp /tmp/default.conf /etc/nginx/conf.d/default.conf
