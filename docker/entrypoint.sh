#!/bin/sh
# backend start mit env-handling
set -e

# env/secrets laden
if [ -f /docker-entrypoint.d/90-handle-env.sh ]; then
  . /docker-entrypoint.d/90-handle-env.sh
fi

HOST=${UVICORN_HOST:-0.0.0.0}
PORT=${UVICORN_PORT:-8000}
exec python -m uvicorn app.main:app --host "$HOST" --port "$PORT"
