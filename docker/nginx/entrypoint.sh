#!/bin/sh
# self-signed cert generieren falls keins vorhanden und STRICT_TLS!=1
set -e
CERT_PATH="${CERT_DIR:-/certs}"
CF="$CERT_PATH/${CERT_FILE:-cert.pem}"
KF="$CERT_PATH/${KEY_FILE:-key.pem}"

mkdir -p "$CERT_PATH"
if [ ! -f "$CF" ] || [ ! -f "$KF" ]; then
  if [ "${STRICT_TLS}" = "1" ]; then
    echo "[strict tls] fehlende cert-dateien: $CF / $KF" >&2
    exit 1
  fi
  echo "self-signed cert generieren"
  openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -subj "/CN=localhost" \
    -keyout "$KF" -out "$CF" >/dev/null 2>&1 || {
      echo "cert generation fehlgeschlagen" >&2
      exit 1
    }
fi
