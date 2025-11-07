#!/bin/sh
# einfacher start (tls via nginx)
set -e
HOST=${UVICORN_HOST:-0.0.0.0}
PORT=${UVICORN_PORT:-8000}
exec python -m uvicorn app.main:app --host "$HOST" --port "$PORT"
