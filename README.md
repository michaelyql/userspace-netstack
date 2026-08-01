# Userspace Network Stack

A proof-of-concept, tiny Linux userspace networking stack that can run inside Docker Desktop on macOS.

It contains:

- a TAP interface created inside the container
- Ethernet frame parsing
- ARP cache / ARP replies
- IPv4 parsing
- ICMP echo reply (ping responder)
- a clean place to add UDP/TCP later

It talks to a virtual NIC (TAP) instead of a physical NIC.

## Prerequisites

- Docker Desktop on macOS
- `docker compose` working in your shell

Docker Desktop includes Docker Engine, Docker CLI, and Docker Compose on Mac. `docker compose up` builds/recreates/starts the services in your compose file. 

## Quick start

```bash
chmod +x scripts/*.sh
./scripts/build.sh
./scripts/run.sh
```

In another terminal, send a ping into the container namespace:

```bash
./scripts/ping_test.sh
```

You should see the program print received Ethernet/ARP/ICMP frames.

## Manual commands

Build:

```bash
docker compose build
```

Run:

```bash
docker compose up
```

Stop:

```bash
docker compose down
```

## Notes

- This container needs access to `/dev/net/tun` and `NET_ADMIN` to create a TAP interface.
