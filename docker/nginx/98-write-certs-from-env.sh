#!/bin/sh
# certs aus base64 env vars schreiben falls vorhanden
set -e
CERT_PATH="${CERT_DIR:-/certs}"
CERT_FILE="${CERT_FILE:-cert.pem}"
KEY_FILE="${KEY_FILE:-key.pem}"

mkdir -p "$CERT_PATH"
if [ -n "$CERT_PEM_B64" ] && [ -n "$KEY_PEM_B64" ]; then
  echo "$CERT_PEM_B64" | base64 -d > "$CERT_PATH/$CERT_FILE"
  echo "$KEY_PEM_B64" | base64 -d > "$CERT_PATH/$KEY_FILE"
  chmod 600 "$CERT_PATH/$KEY_FILE" || true
fi
