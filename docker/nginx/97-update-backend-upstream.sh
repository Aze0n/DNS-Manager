#!/bin/sh
# backend-upstream aus env vars aktualisieren
set -e
HOST=${BACKEND_HOST:-backend}
PORT=${BACKEND_PORT:-8000}

# nginx.conf template ersetzen
sed -i "s/server backend:8000;/server $HOST:$PORT;/" /etc/nginx/nginx.conf