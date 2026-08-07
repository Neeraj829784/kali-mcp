# Deployment

kali-mcp is normally launched on demand by your AI client (see
[Configuration](configuration.md)). This page covers running it as a
long-lived service and managing its data.

## The data directory

Before deploying anywhere persistent, decide where runtime state lives. By
default it sits next to the code; setting `KALI_MCP_DATA_DIR` moves it all to one
folder:

```bash
export KALI_MCP_DATA_DIR=/var/lib/kali-mcp
```

Everything writable — `jobs.db`, `engagements.db`, `programs.db`, `vault.db`,
`vault.key`, `scope.txt`, `known_hosts`, `audit.log`, and `artifacts/` — then
lives there. The directory is created `0700` (owner-only). Back up this one
folder to preserve every engagement, credential, and the asset-inventory history.

## Systemd service

A unit file is included:

```bash
sudo cp kali-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now kali-mcp
journalctl -u kali-mcp -f
```

Edit `kali-mcp.service` to match your username, install path, and (recommended)
add an `Environment=KALI_MCP_DATA_DIR=...` line.

> Remember the transport rule from the [Security Model](security.md): the server
> only serves stdio. A systemd service is useful for keeping the process/data in
> a fixed place, not for exposing it over a network.

## Scheduling continuous recon

There is intentionally no built-in scheduler daemon. To run
[continuous recon](continuous-recon.md) on a timer, invoke `recon_sweep`
periodically from `cron` or a `systemd` timer. This keeps scheduling outside the
security-sensitive server process.

## A note on containers

kali-mcp runs great locally on Kali, which is the recommended setup: raw-socket
scans (`nmap -sS`, masscan) and root-only features "just work" with `sudo`, and
tools update via `apt`.

If you later want a container for portability, the `KALI_MCP_DATA_DIR` design
makes it straightforward — mount a single volume at that path and all state
persists. You'd base the image on `kalilinux/kali-rolling`, install the tools,
grant `NET_RAW`/`NET_ADMIN` for raw-socket scanning, and keep the stdio entry
point. This isn't shipped today, but the groundwork is in place.

## Next steps

- [Configuration](configuration.md) — environment variables and client setup
- [Security Model](security.md) — why stdio-only, and what to keep out of git
