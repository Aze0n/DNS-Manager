#!/bin/sh
# sichere .env/secrets behandlung backend
set -e
SECRETS_DIR=${SECRETS_DIR:-/app/secrets}
mkdir -p "$SECRETS_DIR"

# SECURE_MODE=1 -> keine auto-generation von MASTER_KEY (fehler falls fehlt)
SECURE_MODE_FLAG=${SECURE_MODE:-0}

# SECRET_KEY priorität: env > docker secret > SECRET_KEY_FILE > generiert/persistent
if [ -z "$SECRET_KEY" ]; then
  if [ -f /run/secrets/SECRET_KEY ]; then
    export SECRET_KEY="$(cat /run/secrets/SECRET_KEY)"
  elif [ -n "$SECRET_KEY_FILE" ] && [ -f "$SECRET_KEY_FILE" ]; then
    export SECRET_KEY="$(cat "$SECRET_KEY_FILE")"
  elif [ -f "$SECRETS_DIR/secret.key" ]; then
    export SECRET_KEY="$(cat "$SECRETS_DIR/secret.key")"
  else
    # fallback: random nur wenn secure_mode=0
    if [ "$SECURE_MODE_FLAG" = "1" ]; then
      echo "secure_mode aktiv: SECRET_KEY fehlt" >&2
      exit 1
    fi
    openssl rand -base64 32 > "$SECRETS_DIR/secret.key"
    chmod 600 "$SECRETS_DIR/secret.key" 2>/dev/null || true
    export SECRET_KEY="$(cat "$SECRETS_DIR/secret.key")"
  fi
fi

# MASTER_KEY priorität: env > docker secret > MASTER_KEY_FILE
if [ -z "$MASTER_KEY" ]; then
  if [ -f /run/secrets/MASTER_KEY ]; then
    export MASTER_KEY="$(cat /run/secrets/MASTER_KEY)"
  elif [ -n "$MASTER_KEY_FILE" ] && [ -f "$MASTER_KEY_FILE" ]; then
    export MASTER_KEY="$(cat "$MASTER_KEY_FILE")"
  elif [ "$SECURE_MODE_FLAG" = "0" ]; then
    # dev fallback optional persistent
    if [ -f "$SECRETS_DIR/master.key" ]; then
      export MASTER_KEY="$(cat "$SECRETS_DIR/master.key")"
    else
      openssl rand -base64 32 > "$SECRETS_DIR/master.key"
      chmod 600 "$SECRETS_DIR/master.key" 2>/dev/null || true
      export MASTER_KEY="$(cat "$SECRETS_DIR/master.key")"
    fi
  else
    echo "secure_mode aktiv: MASTER_KEY fehlt" >&2
  fi
fi