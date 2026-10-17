# Installed test-only validation — 2026-10-17

[فارسی](TEST-ONLY-VALIDATION-fa.md) · [Operator guide](TEST-ONLY.md)

Both authorized test installations run `c300a4a9b2036b9701c8dcebdcc9b3be06676f86`. Snapshot: `2026-10-17T13:14:56.996805+00:00`. The owner explicitly chose private testing without a domain or payment processor. Main remains unmerged; the verified pin works independently of merging PR2.

## Observation and installed behavior

Each original route has approximately **16.80 hours** between first and last retained samples; counts at this snapshot are **987 and 987**. All retained observations in this24-hour query are UP. This is a point-sample result, not continuous uptime or a seven-day SLA. No inter-sample gap exceeded twice the current60-second interval. The largest retained gaps include the API upgrade interval; see exact values and freshness in [the allowlisted snapshot](evidence/commercial/test-only-observation.json).

All four summary windows passed actual installed HTTP checks, including401 without authentication,422 for an invalid window, no-store, tenant-local route IDs and support-export privacy. The two entries, exact7+5 methods, balance modes and gateway PIDs stayed identical across upgrade and tests. All12 members were healthy after the localhost control. Existing per-method public-exit and failover proofs remain in the [prior acceptance](COMMERCIAL-VALIDATION.md); they were not relabelled as newly repeated drills.

## Bounded short-request load

The main workload produced **2,010/2,010 valid TCP nonce receipts**:525 ramp requests and480 lower-load requests per direction. The ramps used1/8/32/64 concurrent sessions, five rounds each. The lower-load phases used8 concurrent sessions,60 rounds and10-second pauses. These phases ran before upgrading the API, with the accepted `d757fa8` gateways. This release changes observation/reporting and the optional probe, with no tunnel or gateway code change. The final installed CLI additionally passed **4/4 receipts** with a140ms network deadline and refused overwriting both gateway configs and existing report files on both nodes.

| Route prefix | Phase | Receipts | Elapsed s | Last concurrency | Last-level p95 ms | Sampled host CPU max % | Minimum available RAM MiB |
|---|---|---:|---:|---:|---:|---:|---:|
| `35c3b766` | ramp | 525/525 | 33.183 | 64 | 1417.758 | 21.190 | 260.2 |
| `35c3b766` | soak | 480/480 | 610.038 | 8 | 48.907 | 21.053 | 247.3 |
| `7812cdf7` | ramp | 525/525 | 38.636 | 64 | 1977.341 | 19.298 | 192.5 |
| `7812cdf7` | soak | 480/480 | 626.963 | 8 | 1020.227 | 9.199 | 193.5 |

The ramp's counters increased on all7+5 members. During the lower-load phase, only4 of the7 members in one direction received new connections; all5 in the other direction did. Quality-weighted selection does not promise equal distribution. Counter deltas include other gateway traffic, and host resource snapshots include background processes.

High short-request tail latency was also reproduced against the same origins over **destination localhost with no tunnel**:8-way p95 approximately1.01/1.02s and64-way p95 approximately1.46/1.47s,720 additional valid control receipts. The installed Python health server's default accept backlog is5. This establishes a substantial test-origin limitation; it does not isolate every latency contribution. These health-origin results cannot be converted into bulk throughput, ICMP/packet jitter, per-member byte utilization or a customer speed guarantee. The deliberate150ms overlap hold is excluded from latency. See [all phase values and localhost controls](evidence/commercial/test-only-quality.json).

## Verification and recovery

Final runtime CI [portable39035240610](https://github.com/DashSaman/TunnelPannel/actions/runs/39035240610) and [security39035240599](https://github.com/DashSaman/TunnelPannel/actions/runs/39035240599) succeeded. Each Python3.11/3.12 job passed700 canonical,100 TunnelGuard and1 backend tests. Linux fresh/idempotent install, backup-mutate-restore, unrelated-resource-safe uninstall and shell checks passed. Fresh Windows canonical:678 PASS/22 platform skips. Required Ruff rules and portal JavaScript syntax passed. Known dependency deprecation warnings remain. [Exact job/count evidence](evidence/commercial/test-only-verification.json).

Live browser checks passed FA/EN, one-hour/24-hour switching, latency-detail expansion and390px mobile width375/content375 in both languages; temporary viewport override was reset. Private pre-upgrade and current handoff backups exist on each server; both current snapshot checksums verified. The new snapshots were not restored again: the previous physical two-node restore proof and fresh runtime CI restore test remain explicit. Independent installation keys stayed unchanged. [Install/backup proof](evidence/commercial/test-only-installed.json).

The initial private results aggregator used the wrong NodeRemote result key (`exit_code` instead of `code`); its failed aggregate was retained, and complete successful ramp artifacts were adopted without hiding or rerunning their data. New regression checks caught the150ms overlap consuming a short network deadline and a report path potentially overwriting a gateway config; both were corrected and verified before installing the final release. Windows test invocation initially lacked backend import-path/UTF-8 setup; the corrected full run above is the final result.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/DashSaman/TunnelPannel/c300a4a9b2036b9701c8dcebdcc9b3be06676f86/install.sh | sudo env TUNNELPANNEL_VERSION=c300a4a9b2036b9701c8dcebdcc9b3be06676f86 bash
```

![Live Persian observation summary](evidence/commercial/screenshots/observation-fa.png)

[English desktop](evidence/commercial/screenshots/observation-en.png) · [Persian mobile](evidence/commercial/screenshots/observation-mobile-fa.png) · [English mobile](evidence/commercial/screenshots/observation-mobile-en.png)
