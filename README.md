# Userspace Network Stack

A proof-of-concept, tiny Linux userspace networking stack that can run inside Docker Desktop on macOS.

It uses a TAP interface created inside the container to simulate a virtual NIC. It parses Ethernet frames, writes ARP (address resolution protocl) replies, parses IPv4 and generates ICMP echo replies. Adding a UDP/TCP stack can be done at later time.

## Prerequisites

- Docker Desktop on macOS
- `docker compose` working in your shell

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
