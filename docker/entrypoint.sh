#!/bin/sh
# Checks the configuration and prepares /data, then starts Apache.
# The server refuses to start without a valid token; there is no open mode.
set -eu

# Docker secrets: read the token from a file instead of the environment
if [ -n "${WURD_TOKEN_FILE:-}" ]; then
  if [ -n "${WURD_TOKEN:-}" ]; then
    echo "wurd: not starting. Set WURD_TOKEN or WURD_TOKEN_FILE, not both." >&2
    exit 1
  fi
  WURD_TOKEN="$(cat "$WURD_TOKEN_FILE")"
  export WURD_TOKEN
  unset WURD_TOKEN_FILE
fi

WURD_MAX_BODY_BYTES="$(php /app/bin/init.php)"
export WURD_MAX_BODY_BYTES

# Behind the TLS proxy, take the client's address from X-Forwarded-For, but only from the proxy itself
if [ -n "${WURD_TRUSTED_PROXIES:-}" ]; then
  set -- -DWURD_BEHIND_PROXY "$@"
fi

exec apache2-foreground "$@"
