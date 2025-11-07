#!/bin/sh
# sichere .env/secrets behandlung für nginx container
set -e
SECRETS_DIR=${SECRETS_DIR:-/app/secrets}
mkdir -p "$SECRETS_DIR"

# SECRET_KEY priorität: env > docker secret > SECRET_KEY_FILE > generiert/persistent  
if [ -z "$SECRET_KEY" ]; then
  if [ -f /run/secrets/SECRET_KEY ]; then
    export SECRET_KEY="$(cat /run/secrets/SECRET_KEY)"
  elif [ -n "$SECRET_KEY_FILE" ] && [ -f "$SECRET_KEY_FILE" ]; then
    export SECRET_KEY="$(cat "$SECRET_KEY_FILE")"
  elif [ -f "$SECRETS_DIR/secret.key" ]; then
    export SECRET_KEY="$(cat "$SECRETS_DIR/secret.key")"
  else
    # 32 byte random key generieren und persistent speichern
    openssl rand -base64 32 > "$SECRETS_DIR/secret.key"
    chmod 600 "$SECRETS_DIR/secret.key" 2>/dev/null || true
    export SECRET_KEY="$(cat "$SECRETS_DIR/secret.key")"
  fi
fi

# MASTER_KEY priorität: env > docker secret > MASTER_KEY_FILE (nicht auto-generiert)
if [ -z "$MASTER_KEY" ]; then
  if [ -f /run/secrets/MASTER_KEY ]; then
    export MASTER_KEY="$(cat /run/secrets/MASTER_KEY)"
  elif [ -n "$MASTER_KEY_FILE" ] && [ -f "$MASTER_KEY_FILE" ]; then
    export MASTER_KEY="$(cat "$MASTER_KEY_FILE")"
  fi
fi

