#!/bin/sh
# Checks the configuration and prepares /data, then starts Apache.
set -eu

WURD_MAX_BODY_BYTES="$(php /app/bin/init.php)"
export WURD_MAX_BODY_BYTES

# Behind the TLS proxy, take the client's address from X-Forwarded-For, but only from the proxy itself
if [ -n "${WURD_TRUSTED_PROXIES:-}" ]; then
  set -- -DWURD_BEHIND_PROXY "$@"
fi

exec apache2-foreground "$@"
