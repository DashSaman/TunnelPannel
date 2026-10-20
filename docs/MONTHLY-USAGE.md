# Shared customer traffic allowance

Installed on the two execution nodes and public static website; see [actual acceptance](MONTHLY-USAGE-VALIDATION.md). A customer workspace, including all its login accounts and route source servers, shares one administrator-managed allowance. This extends the existing per-route speed, byte and connection ceilings.

## Administrator workflow

Open **Portal → Users & sales administration → Shared monthly usage**. Select a customer and inspect reported usage, credit held by routes, allocatable balance, coverage and period history. Allocate a total ceiling in bytes/MiB/GiB/TiB and an explicit local-time end date. A fresh period defaults to30days; grants, extensions and new periods are manual. Saving an increased ceiling preserves usage. Concurrent edits require refresh rather than overwriting a newer revision.

**New period** preserves prior records and starts another allowance. All outstanding credit must be safely closed before this action. Changing a ceiling below used plus held credit is refused. No payment is collected and no existing payment receipt or purchased-plan snapshot is rewritten. Monthly allowance is managed independently by the owner, as requested.

All active routes must participate before a shared pool can be enabled. Existing unmetered workers cause a clear refusal; enabling the feature never restarts or reconciles them. The root-only [explicit existing-gateway migration](LEGACY-ACCOUNTING.md) now enrolls a live gateway without rebuilding its member tunnels; both original groups passed [installed acceptance](LEGACY-ACCOUNTING-VALIDATION.md). It starts an unlimited recording period until the administrator assigns a ceiling, retaining any known source baseline. Ordinary enable/reconcile does not silently migrate other historical workers. New routes automatically inherit an existing pool. The customer can inspect its own aggregate usage in **Plan and access**, but cannot edit allowance or another customer's records.

## Accounting and availability

Only combined upload/download payload accepted for relay by managed gateways is charged. SOCKS negotiation, internal direct-to-member health probes, benchmarks, ISP framing and traffic outside the managed gateways are excluded. Test requests through the stable SOCKS entry count as accepted payload. Accepted payload may later fail transport delivery; this is not an ISP invoice or acknowledged-wire counter. A root operator can bypass software on their own host; root tamper resistance is not promised.

The execution controller atomically reserves at most8MiB of credit per active route request. Reported usage plus held credit never exceeds the period ceiling. Source workers persist pending requests and atomically debit local route/credit counters before forwarding. Retries are idempotent. Reported usage can lag briefly while credit remains held; UI shows both figures rather than calling all reserved bytes consumed.

Idle workers fence and return unused credit after approximately3seconds, plus network/loop scheduling. Renewable leases last at most10seconds, reduced by request elapsed time and a one-second margin, and use a monotonic clock. A controller outage can use only already reserved valid credit; after lease expiry payload is refused. Expired/offline credit is never automatically refunded. Reconnecting/restarting reconciles durable state; stopping a route proves its owned worker is stopped before unused credit is returned. Corrupt/missing accounting remains a visible failure requiring investigation, not a reset. An offline node can therefore temporarily reduce available allowance. An expired period blocks further credit until an administrator extends it or safely starts another period.

## Execution-controller configuration

Set `TP_MONTHLY_QUOTA_URL=https://YOUR_PUBLIC_PANEL/PREFIX/quota/credits` in the **issuing execution controller's** private environment. The URL must reach that installation's API through a verified HTTPS endpoint; use the deployment's real prefix. Different independent controllers must use their own callback, not another installation's unrelated ledger. The website continues to serve static assets and proxy requests only; no database, gateway worker or accounting process is installed on the website host.

The callback uses a separate route-scoped credential issued over pinned SSH, never the customer's login/API key. Its hash binds route and workspace. TLS verification is mandatory; URL credentials, query strings, redirects and environment proxies are rejected. Requests are bounded/rate-limited. Credentials stay in private encrypted controller records and root0600 gateway configuration; public route responses contain neither the callback token nor secret reference.

The worker identifies itself as `TehNet-TunnelPannel-Gateway/1.0` and requests JSON. On the real public endpoint, default Python identification received HTTP403/code1010 on both source nodes; the genuine service identification received200. [Cloudflare documents browser-integrity filtering of missing/non-standard User-Agent headers](https://developers.cloudflare.com/waf/tools/browser-integrity-check/). No WAF/TLS settings were relaxed. Callback reachability starts as unknown and changes only after a real request; an idle loop cannot clear a failed contact.

The central tables live in the existing private `registry.db`, included in the canonical workspace snapshot. Preserve it together with every source's durable route-usage SQLite files and each installation's separate encryption environment. Backup/restore of a distributed allowance must fence participating workers first; restoring only the controller while workers retain newer credit can reissue spent allowance. No such live restore is part of acceptance.

## API surface

- Customer: `GET /api/billing/traffic`.
- Owner: `GET` / `PUT /api/billing/owner/workspaces/{workspace_id}/traffic` with `quota_bytes`, `ends_at`, `expected_revision`, optional `new_period`.
- Gateway only: `POST /quota/credits`, route credential in the Authorization header; caller cannot choose a workspace or another route.

Disabled/unpaid customers cannot reserve or renew usable credit, but can still settle/fence existing reservations. Historical billing, daily test admission and per-route limits retain their own semantics.
