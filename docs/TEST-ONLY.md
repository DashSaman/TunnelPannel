# Two-node test mode

[Installed results, runtime pin and screenshots](TEST-ONLY-VALIDATION.md).

[فارسی](TEST-ONLY-fa.md)

The owner selected private testing without a domain or payment processor. Keep the canonical API on loopback and use the existing SSH preview. Accounts, invitations and sandbox plans remain available; no purchase or charge occurs. The original two warm groups stay active with their entry credentials and membership preserved.

## Read the observation summary

In `/portal`, open **History and support** and select one hour, six hours, 24 hours or seven days. Each route shows the retained first-to-last sample span, sample count, UP/DEGRADED/DOWN/UNAVAILABLE counts, percentage of all retained samples where every member was UP, latest sample freshness, largest gap, and gaps exceeding twice the current monitoring interval. Disabled monitoring and stale/missing samples are explicit.

This report queries up to5,000 retained samples across the latest100 workspace routes, rather than the history table's latest200 rows. The seven-day retention and shared row ceiling can shorten a route's available window. A gap warning uses the current interval, which may differ from historical settings. The span excludes time before the first sample and after the last sample; an isolated sample has a zero span. A sample percentage is not continuous uptime or an SLA. Missing observation is distinct from measured DOWN.

Expand **Health-probe latency distribution** for per-method nearest-rank p50, p95 and maximum request latency. These are the gateway's nonce health checks, not ICMP ping, packet jitter or bulk throughput. The safe support download includes the default24-hour summary. `GET /api/operations/summary?window_s=86400` uses the current account's workspace; supported windows are60..604800 seconds. Viewer access is read-only. The response never includes node addresses, private configs, credentials or raw errors.

## Optional bounded connection-quality probe

Run on the source node using its installed checkout and a private, already-owned gateway `config.json`:

```sh
sudo /opt/tunnelpannel/.venv/bin/python /opt/tunnelpannel/scripts/mesh_quality_probe.py --config /PRIVATE/OWNED/GATEWAY/config.json --levels 1,8,32,64 --rounds 5 --interval 1 --output /PRIVATE/quality-ramp.json
```

For a roughly ten-minute lower-load observation, use `--levels 8 --rounds 60 --interval 10`. The exact duration includes work, waits and timeouts. Limits: up to8 levels,1..64 concurrent sessions,1..3600 rounds, at most50,000 requests,0..3600-second pauses and0.1..60-second request deadlines. The script reads the existing owned nonce target from the gateway configuration. It does not change route policies, pins, members, services or firewall rules. Run only one such workload per source at a time.

Each fresh authenticated SOCKS connection must return the exact configured nonce with HTTP200. The script holds validated sessions for150ms to overlap connections; that deliberate hold is excluded from measured latency. Wrong receipts, rejected connections and timeouts count as failures without automatic retries. PASS means all attempted receipts passed and the config file stayed identical; it does not assert all members were used or healthy. Inspect the separate fresh-health, worker continuity and per-member connection-counter fields. Counters include all gateway traffic and can reset when a worker restarts; they are not per-member byte utilization. The report includes host-wide sampled CPU and available RAM, not per-customer resource accounting.

The output omits credentials, target addresses, nonce bodies, raw exception messages and private file paths. Its request-latency percentiles include SOCKS setup and the health origin's serving capacity. Small health servers can queue simultaneous requests, so this is a short-request continuity/connection-sharing experiment, not a bandwidth benchmark or single-stream bonding test. Use the panel's NORMAL/DEEP transfer measurements for measured capacity. This probe does not reprove the public exit address or justify a speed guarantee.

## Scope and evidence

Choose a new report file outside the gateway runtime directory. Existing files and symlinks are refused; a report cannot overwrite the gateway configuration. The deliberate150ms overlap hold does not consume the network deadline.

The prior [installed commercial acceptance](COMMERCIAL-VALIDATION.md) remains the baseline:70 named checks,10 representative paired receipts and12 preserved warm members. The new observation and load evidence will record its exact runtime, timestamp, duration, counts and limitations separately. Two nearby test nodes cannot establish Iran-route behavior, destination/datacenter failure independence, seven-day availability, many-customer capacity or payment settlement.
