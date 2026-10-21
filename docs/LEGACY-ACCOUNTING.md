# Migrate an existing gateway without rebuilding its tunnels

Installed and accepted on the two original groups; see [actual evidence](LEGACY-ACCOUNTING-VALIDATION.md).

The owner explicitly chooses **record usage without a ceiling until the administrator assigns one**. The customer pool has no artificial maximum or hidden end date. The existing credit protocol still uses bounded durable reservations and short renewable leases, so callback failure eventually refuses payload rather than silently losing accounting. Administrator first-cap edits retain recorded usage and held credit; a ceiling below their sum is refused. An explicit new period preserves previous history and requires all held credits safely closed.

The old gateways did not have persistent payload accounting. Their unknown prior traffic is not invented or billed retrospectively. Counting begins with the upgraded worker. If a route already has known durable per-route usage, it remains intact and its pre-cutover baseline is recorded separately from the new pooled period. Traffic is accepted relay payload, not ISP framing or guaranteed downstream delivery.

Only the selected gateway service is replaced, one source at a time. Stable address/port/login, upstream list and exact ordering/weights, balance/failover, pin, probe settings and existing policies are retained. Underlying tunnel services/interfaces are not rebuilt. Cutover requires matching encrypted/live configuration, exact supplied SHA/PID and two fresh healthy idle observations within45seconds. If the gateway does not become idle, no cutover occurs. Real nonce requests measure the observed success gap and failed samples; zero downtime or survival of old TCP sessions is not promised.

The system owner can now use the installed [administrator workflow](ADMIN-MIGRATION.md) without a manual SSH terminal. It performs fresh encrypted online controller snapshots before source dispatch. The root-only CLI remains available for privileged operators: take fresh canonical data/registry backups, source-usage snapshots and a separate installation environment on each original host first, install only a CI-verified immutable revision, then load the private environment on the **issuing execution controller** and use values from a fresh inspection:

```sh
/opt/tunnelpannel/.venv/bin/python /opt/tunnelpannel/scripts/migrate_route_accounting.py --workspace CUSTOMER_ID --route ROUTE_ID --expected-pid LIVE_PID --expected-config-sha256 LIVE_CONFIG_SHA256 --rescue-base /root/tp-accounting-migration
```

This is a privileged operator action. The owner API is restricted to the system SUPER_ADMIN; customers cannot request grandfathering. Existing live traffic retains its prior entitlement for these explicitly enrolled route credentials, while unpaid new work remains blocked and disabling the customer still refuses renewal. No plan/payment/account/password is modified.

A durable encrypted candidate and pending intent are saved before source dispatch. Ordinary policy/traffic/reconcile edits are fenced until controller/source agreement is finalized; incomplete coverage prevents first quota activation. If SSH response or final metadata commit is lost, inspect the private source receipt and resume with the same original configuration digest plus a fresh worker PID. An exact already-running candidate is adopted without another restart. A failed preflight/idle/rolled-back attempt remains recoverable with the same credential; source attempts and counters are retained. Never clear an uncertain intent or refund outstanding credit without proving the worker stopped. If an operator stops the route while recovery is pending, investigate and settle the candidate from the resident source ledger before re-enrolling it.

The website stays a static/proxy container. API, customer ledgers, backups, builds and test traffic stay on separate execution hosts. Encrypt fresh resident rescues independently with separate root0600 keys and verify decrypted hashes. No private export or live distributed restore is part of this migration.
