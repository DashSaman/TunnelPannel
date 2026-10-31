# Installed TehNet expansion acceptance — 2026-10-19

Both execution nodes run `53a72f6ee2c3b675a331ddfaf6bc0052bc02eb71` / tree `c653c93946f66a49588cd5f6dc1c2d6d915cb70f`. The public static website runs `3a10ea0b1a0978c5f3cfc1e3f49daaa164078730` / tree `0e8ec8d99eaef724436ab440ab78e186d2f8e59f` at [TehNet](https://tehnet.ir/tunnels/). Its package was produced from the immutable Git archive; no application execution moved to the website host. Functional installer pin is the tested runtime revision above.

## Real paired results

One new NORMAL campaign completed **6/6** outcomes: 30 on-node HTTP latency samples each, verified payload, throughput, owned restart/recovery and released-resource evidence. Directions A/B identify the two authorized test nodes. L3 throughput is the lower received rate of the two iperf3 directions in each run; Backhaul uses timed SHA256-checked HTTP transfers. HTTP loss is application request failure rate, not inferred IP packet loss; all six had zero request failures in this finite run.

| Method | Direction | HTTP RTT ms | Jitter ms | Mbps | Verdict |
|---|---|---:|---:|---:|---|
| AMNEZIAWG | A_to_B | 3.560 | 1.165 | 1090.94 | PASS |
| BACKHAUL_TCP | A_to_B | 3.087 | 1.134 | 459.37 | PASS |
| IP4IN6 | A_to_B | 2.118 | 0.807 | 1529.12 | PASS |
| AMNEZIAWG | B_to_A | 3.684 | 1.045 | 1184.11 | PASS |
| BACKHAUL_TCP | B_to_A | 3.559 | 0.732 | 377.39 | PASS |
| IP4IN6 | B_to_A | 1.939 | 0.456 | 1596.62 | PASS |

AmneziaWG uses official source pin `b5928efb6ca19f0153958460c3d141f04abc5c2e`; both nodes verified binary SHA256 `f91c3ff319cd1cb5711108ab533a32bb5f7ef944d9cf1915834214872c82ecfc`. The roomier node built it within an own bounded cgroup and the same-architecture peer received verified engine bytes over pinned SSH. Backhaul uses the digest-pinned official0.7.2 release; host optimizations/sniffer/web UI remain disabled. Native4in6 used real IPv6 endpoints and IPv4 payload, independently of GRE/SIT.

## Real limits and cleanup

An isolated new three-member balance route passed a unique payload through each persistent member. Two concurrent downloads transferred **2,097,152 verified bytes in4.217953s =3.977573Mbps** under a4Mbps aggregate ceiling. A third concurrent connection was refused. The debit included114 upload/2,097,386 download bytes before policy change, total2,097,500. Restarting only this QA gateway preserved the counter. A public HTTPS policy edit retained usage and was observed by the worker before further traffic. The cap was set to2,163,036 bytes; the next response stopped after65,479 response bytes and the ledger reached the cap exactly (171 upload +2,162,865 download). Another QA-only gateway restart preserved the exhausted cap; a new connection was refused.

The QA route is STOPPED. All57 allocations across5 owned deployments, including its separate loopback payload origin, are released; origin/gateway files and services were removed. Durable accounting and historical receipts remain. No pre-existing route was rebuilt, pinned, reordered or restarted. Ten original members plus both original stable entry points passed fresh nonce receipts; original complete configurations, ordered entries, modes, pins, workers and installation/customer identities matched the then-current baseline. Twelve installed coexistence canaries on EACH node passed.

## Website, authentication and recovery

Public FA/EN and owner traffic-cap fields passed; mobile375/375 and desktop1265/1265 showed no horizontal overflow. Refresh preserves expanded route controls. Stopped/unavailable observations are labelled separately from old-worker capability. Owner and original customer HTTPS authentication, secure cookies, isolation and unpaid/owner-only guards passed. Only the dedicated static container changed:11 unrelated containers,50 links,5 selected service processes and nginx/WordPress configuration were preserved; no host nginx reload. Old releases remain available.

Fresh per-installation before/immediate-preinstall/after backups and separate env/keys were encrypted on EACH original node with separate root0600 keys and decrypt/SHA equality. Website config/restricted transport rescue was independently encrypted on the website host. No private backup export or live restore was performed. Main remains unmerged; existing PR2 carries the work; heartbeat remains PAUSED.

Runtime CI39292283736/39292283711 and website CI39297704672/39297704872 succeeded. Python3.11/3.12 portable jobs and Linux installer/lifecycle passed. The observed3.12 job reported799 root tests,100 TunnelGuard tests and1 backend smoke test PASS. The first attempted CI retained2 failures/795 passes, then corrected legacy executor separation and the POSIX test double before installation. Local unit baseline756PASS/33POSIX skips and focused follow-ups passed; frontend scripts parse and selected fatal Ruff rules pass.

Limits are cumulative **per route**, not pooled monthly billing. Historical workers are unchanged; enabling new enforcement on them requires the owner's explicit reconciliation. These finite nearby-node tests do not prove Iran quality, DPI resistance, SLA or bandwidth bonding of a single TCP session. [Guide](TUNNEL-EXPANSION.md) · [machine-readable evidence](evidence/commercial/tehnet-expansion-installed.json).

Final documentation checks passed37 focused catalog/manifest/receipt tests and7 release-asset tests,102 relative links and generated24-engine/94-profile/17-composition consistency. Incomplete direction, missing receipt, failed cleanup or failed payload cannot promote new verification labels. Historical method verdicts were preserved.

![Public TehNet control surface during the isolated acceptance route](screenshots/tehnet-route-usage-20261019.png)

The screenshot was taken during acceptance. The temporary QA route was subsequently stopped; historical entries remain visible in that workspace.
