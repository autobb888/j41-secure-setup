#!/bin/sh
# Bubblewrap entrypoint for dispatcher agent containers (degraded mode — no gVisor)
set -e

exec bwrap \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /app /app \
  --bind /tmp /tmp \
  --proc /proc \
  --dev /dev \
  --unshare-net \
  --unshare-pid \
  --die-with-parent \
  --new-session \
  -- node /app/job-agent.js "$@"
