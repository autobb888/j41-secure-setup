#!/bin/sh
# Bubblewrap entrypoint for jailbox MCP containers (degraded mode — no gVisor)
set -e

JAILBOX_BIND_FLAG="--ro-bind"
if [ "$JAILBOX_WRITABLE" = "true" ]; then
  JAILBOX_BIND_FLAG="--bind"
fi

exec bwrap \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /app /app \
  $JAILBOX_BIND_FLAG /jailbox /jailbox \
  --bind /tmp /tmp \
  --proc /proc \
  --dev /dev \
  --unshare-net \
  --unshare-pid \
  --die-with-parent \
  --new-session \
  -- node /app/mcp-server.js
