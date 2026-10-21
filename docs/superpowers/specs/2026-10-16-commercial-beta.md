# Two-node commercial beta design

User authorization: implement all recommendations that can be built and honestly tested on the two supplied disposable servers. Continue inline without repeated approval. Preserve existing releases, data, keys, management connectivity and warm groups. No credentials belong in tracked files, screenshots or support exports.

## Product and acceptance

Deliver a closed paid-beta foundation for administrators bringing their own Linux servers: invite/account login, a guided route workflow, meaningful quality objectives and visible capability limits, subscription entitlements in an explicitly labelled sandbox, operational history/support exports, budgeted queued tests, safer node credential lifecycle, and an optional restricted telemetry agent. Keep the current TCP SOCKS product explicit. Existing UDP/IP benchmarking is not a promise of a full-IP VPN or UDP SOCKS relay. Existing API keys remain compatible.

Only 65.109.209.194 and 65.109.213.64 are authorized physical targets in this continuation. No Iran, extra destinations, real customers, actual money collection, public domain ownership or intercontinental results can be manufactured from this pair. Payments require a configured provider; signed sandbox events must never appear as collected money. A seven-day monitor can collect samples but a short acceptance run cannot be called a passed seven-day pilot. Single-stream bonding remains separate research; no speed guarantee.

## Identity and tenant boundaries

Keep account/invitation/session/TOTP/billing metadata in the existing private workspace registry database so native snapshots preserve it. Owner issues single-use expiring invitations for a workspace and role; there is no open owner registration. Passwords use salted scrypt, minimum12/max256 characters; plaintext never persists. Sessions are opaque random credentials stored only by hash, with absolute12h and idle30min expiry and server-side logout. Cookies are HttpOnly/SameSite=Strict, Secure for configured HTTPS origin; an explicit loopback-only development path permits private SSH previews. Cookie mutations require a session-bound CSRF token and matching origin; bearer API compatibility remains. Owner accounts can enable TOTP (30s/6digits, accepted once, bounded clock window), with encrypted seeds and single-use hashed recovery codes. Login/invite use bounded persistent throttling; changing credentials revokes other sessions. Disabled workspaces revoke sessions as well as keys. Scoped accounts never gain owner registry access.

## Plans, subscriptions and test budgets

Versioned starter/pro/team plan definitions provide node/group/member/test-unit caps, not invented prices. Price/provider configuration is explicit. A signed webhook adapter receives bounded JSON with timestamp, event ID, monotonic subscription revision and payload hash. Replay is idempotent; reuse of an ID with different content fails; stale revisions cannot roll back renewed access. Sandbox is default and visibly labelled. States: trial/active/past_due/expired/cancelled, with explicit paid-through and grace times. Default expiry blocks new expensive work but preserves read/export/stop operations. Existing running routes remain unless owner explicitly enables stop-on-expiry for that workspace; that policy uses scoped owned cleanup and never deletes customer databases. Legacy workspaces without subscriptions retain existing behavior.

Campaign estimates validate actual scoped/discovered nodes, selected directions/methods/profile, show candidate units and timed transfer/probe durations, distinguish a timeout ceiling from an ETA, and disclose unknown network volume/cold-build time. Admission reserves daily units atomically with the job in its own tenant DB, including concurrent requests. Retain full all-pairs mode; optional selected directions/starter scans reduce work. Durable bounded worker slots prevent unbounded expensive threads; queued jobs recover after process restart. No fake currency or exact byte estimate.

## Quality and operation

Objectives balanced/latency/throughput/stability change ranking of valid real receipts while preserving distinct-carrier preference, purpose filtering and custom order. Explain metrics, measurement age, encryption/capability and shared physical failure domains. Do not pad recommendations or give confidence percentages without observations.

An opt-in monitor stores bounded historical observations and change events per workspace, including unavailable/stale samples. Sampled availability is labelled sampled, not an SLA. No healthy observation is fabricated when SSH/worker is unavailable. In-app alerts and redacted downloadable support reports use an explicit field allowlist; no raw Job payload, runtime config, receipts, exceptions, keys, account email or SSH credentials. No external notifications are sent without a configured authorized destination. Owner dashboard exposes customer/invite/plan/usage controls; customers see only their own data.

## Server access and telemetry agent

Offer optional replacement of the bootstrap password with a unique encrypted per-node SSH key, verified against the pinned host key before discarding the old credential. Append/remove only exact owned authorized_keys entries, preserve foreign keys, verify ownership/symlinks, support rotation and revocation safely, and record sanitized audits. A root SSH key still grants root authority and must not be marketed as least privilege.

An optional unprivileged telemetry agent authenticates with revocable per-node certificates over mutual TLS and exposes only typed inventory/health sampling, no arbitrary command/shell API. Bind reports to workspace+node, bound payloads, reject replay/revoked/foreign identities. It does not replace privileged tunnel installation: the dedicated SSH credential remains for those operations. Test actual two-host TLS, revocation, replay, restart and cleanup. Supply private CA/domain ingress examples without pretending to provision a public trusted certificate or a payment account.

## Delivery

Use tests first for real behavior, preserve red/green evidence and meaningful failures, run full separate canonical/TunnelGuard/backend suites and lint, then real isolated beta-tenant API/UI/onboarding/budget/billing/agent/recovery checks on the pair. Preserve existing warm entries and unrelated resources. Upgrade/backup/restore acceptance includes new registry tables. Publish bilingual operating and commercial-beta docs, screenshots, sanitized evidence and a pinned installer through the existing repository workflow. Report any approval gate literally; never route around it. No unsupported production certification.
