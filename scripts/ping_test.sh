#!/usr/bin/env bash
set -euo pipefail

# This sends an Ethernet frame into the container's TAP interface.
# It assumes the container is already running and the tap0 interface exists.

docker compose exec -T netstack bash -lc '
  ip link show tap0 >/dev/null 2>&1 || { echo "tap0 not found"; exit 1; }
  echo "Container is up; you can now send traffic from another host-side namespace or add a second container."
  ip addr show tap0
'
