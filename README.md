# TunnelPannel

[فارسی](README-fa.md) · [Real two-node report](docs/releases/v0.9.0-rc3/REAL_BENCHMARK.md)

The canonical panel at `/ranking` runs **82 real tunnel methods between two registered Linux servers**: deployment, actual traffic, latency/loss, measured throughput, service restart/recovery, ownership receipts and cleanup. The earlier 23 partial and 27 failed isolated lab methods were the remediation baseline; retained failed attempts and final real-node results are in the release report.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/DashSaman/TunnelPannel/codex/server-validation-20261013/install.sh | sudo env TUNNELPANNEL_VERSION=codex/server-validation-20261013 bash
```

This installs the reviewed candidate branch. For the exact delivered revision, use the pinned command in `install-one-line.txt`. Re-running preserves credentials and data. The installer creates the application account, installs dependencies, migrates the database, starts systemd and verifies HTTP health. It refuses to overwrite local source changes.

Real-node validation uses Ubuntu 24.04 amd64. Other environments need their own validation. The API binds to **127.0.0.1:8080**. From your computer:

```sh
ssh -L 8080:127.0.0.1:8080 root@YOUR_PANEL_SERVER
```

Open `http://127.0.0.1:8080/ranking`. First installation displays role tokens once; store them privately. Reinstallation preserves their hashes.

## Benchmark workflow

1. Connect with a role token. It stays in page memory and is cleared from the input after login.
2. As SUPER_ADMIN, register two nodes with SSH credentials and pinned SHA256 host-key fingerprints, then inspect each node. OPERATOR/SUPER_ADMIN can start/cancel tests; VIEWER can read results.
3. Select nodes, methods and profile. QUICK checks actual traffic. NORMAL uses 30 latency probes, a 10-second transfer and restart/recovery. DEEP uses 100 probes and 60-second transfers.
4. Results appear incrementally. History reopens active and completed runs. Failed setup, traffic or cleanup remains a failure; performance degradation retains measured metrics and reasons.
5. Cancellation attempts cleanup. Existing interfaces, services and unrelated firewall rules are preserved.

To update credentials, save the same node name and host with new credentials, then inspect it again. Identity stays unchanged and stale inventory is invalidated.

## Measurement scope

L3 uses bidirectional inner-address ICMP and TCP iperf3. Proxy/forward methods verify a remote nonce and SHA256-checked files. UDP validates echoed datagrams. Composites must fail when the actual carrier is stopped and recover after dependency restoration. Native HajSaman FULL also verifies policy routing and SNAT against an owned remote namespace.

CPU/RAM are whole-node measurements. HTTP timings include SSH execution overhead; compare like measurement bases. Two nearby servers establish behavior on these endpoints, not arbitrary NAT traversal, geographic latency, blocked networks or three-server multi-hop operation.

The canonical path is `apps/api`, `apps/web`, `core` and `orchestrator/pair_runtime.py`. Historical `deploy/`, the older single-executor SDK and legacy Docker dashboard remain for reference; their old feature claims and local smoke results are separate from this real-pair evidence.

## Maintenance

- Service: `systemctl status tunnelpannel-api`
- Health: `curl -fsS http://127.0.0.1:8080/health`
- Upgrade: run the pinned installer for the intended revision.
- Backup: `sudo bash /opt/tunnelpannel/scripts/backup.sh /path/to/backup.tar.gz`
- Restore: `sudo env RESTORE_TUNNELPANNEL=YES_I_UNDERSTAND bash /opt/tunnelpannel/scripts/restore.sh /path/to/backup.tar.gz`
- Uninstall: `sudo bash /opt/tunnelpannel/scripts/uninstall.sh`; configuration, data and unrelated network resources survive.

Keep `/etc/tunnelpannel/tunnelpannel.env` separately and privately with backups: the archive excludes installation secrets. Keep the installation secret paired with the database to decrypt node credentials. Supplied server passwords are excluded from source and reports.

[Task ledger](docs/development/TASK_LEDGER.md) · [Catalog](docs/development/CATALOG_INVENTORY.md) · [Historical baseline](docs/releases/v0.9.0-rc2/REAL_VALIDATION.md)
