# Commercial beta operator and customer guide

This is an invitation-only TCP SOCKS product. The commercial acceptance report records the exact installed revision, tests and elapsed observation time. A feature being present in this guide is not a claim that every geography, operating system or future customer network has been validated.

## Install and open

Use the repository's `install-one-line.txt` for the pinned release command. The installer preserves the installation secret and database on reruns and binds the canonical API to loopback. First-run owner API tokens are shown once. Keep them privately; the database stores hashes. Keep the installation encryption secret with your encrypted recovery backup.

For a private preview, forward a loopback panel port over SSH and open `/portal`. For public account sessions, configure `TP_PUBLIC_ORIGIN=https://your-panel.example` and terminate trusted HTTPS. The application must see the correct HTTPS scheme and Host; trust forwarding headers only from the actual reverse proxy. Account sessions on arbitrary public HTTP hosts are refused. No domain or payment provider is automatically provisioned.

## Owner bootstrap and invitations

Open **Owner bootstrap / API key** and enter the owner token. It remains in page memory. Create a customer workspace, then invite an email to that workspace. The **System owner** invitation creates an owner account; customer `SUPER_ADMIN` never gains owner-registry access. Roles are customer administrator, operator and viewer. Viewers cannot mutate network resources.

Share the private invitation link through your chosen channel; the panel does not send email. The token is single-use, email-bound and expires after one day by default. Its URL fragment is removed from the address bar when loaded. The recipient sets a password of at least12 characters, then signs in. Cookie sessions use HttpOnly, SameSite Strict and CSRF protection; Secure is required for configured public HTTPS. Absolute lifetime is12 hours, idle lifetime30 minutes. Existing bearer API keys remain supported.

Use **Create authenticator secret** and enter the displayed secret in an authenticator app, then confirm a six-digit code. Save the eight recovery codes before clearing the private output. Enabling MFA and changing a password revoke existing sessions. Recovery codes are single-use. Account password changes require the current password and MFA when enabled. Secrets are never put in browser localStorage.

## Plans and sandbox subscription lifecycle

Starter supports up to2 servers/5 members per direction/500 candidate units daily; Pro6/10/5000; Team12/10/25000. These are ceilings: the owner's workspace limits can be lower. Team's plan ceiling for concurrent tests is2, but the default workspace admission ceiling remains1 until the owner raises it. Active route limits are2/12/24 respectively.

Customers request a plan. The owner activates or renews sandbox access, chooses the duration and may cancel it. Duplicate events and stale revisions cannot undo a newer grant. No checkout, price, currency or payment processor is configured, and no payment is collected. An optional signed external-event bridge requires `TP_BILLING_MODE=bridge` and a separate strong `TP_BILLING_WEBHOOK_SECRET`; integrating an actual provider and checkout remains operator work. The sandbox is not a billing receipt.

At period end the configured grace period applies; after grace, new expensive work is blocked. Read, support export, credential refresh, monitoring settings, cancellation and owned stop remain usable. Existing routes remain running by default. **Stop this customer's owned routes after expiry** is an explicit owner opt-in. Cleanup rechecks the subscription revision before dispatch and reconciles only that workspace's recorded resources. Renewing never enables a separately suspended workspace. Databases and history are not deleted on cancellation.

## Add and secure servers

Enter a name, public IPv4/IPv6 address, SSH user/port and exactly one password or private key. Supply an out-of-band verified SHA256 host fingerprint when available. Otherwise onboarding records the first observed key, then verifies it during authentication and discovery. A changed key fails pinned connections. Customer SSH targets must be public addresses. Deployment currently requires root or passwordless sudo.

**Create / rotate managed key** installs a unique Ed25519 key with SSH forwarding/agent/PTY restrictions, verifies a fresh pinned SSH connection and required privileges, then switches the encrypted node reference and removes the previous password. Rotation removes only the exact previously owned public line. A root key still has root privileges. A durable operation record supports rollback or cleanup after interruption. Foreign authorized keys, services and tunnel resources are preserved.

**Verify and refresh access** accepts replacement credentials. For a managed node, replacement access is verified before the old managed key is revoked. Discover the node again after changing credentials. Endpoint/user/port changes on a managed node require revocation first through the API. A busy physical node returns409 rather than racing another mutation.

## Estimate, measure and recommend

Choose nodes, all directed pairs or specific directions, an objective and a test scope. The representative first pass contains5 templates; full catalog mode includes registered compositions; custom mode lets you choose. NORMAL measures latency, jitter, request loss, capacity and restart recovery. DEEP measures longer. These are finite experiments, not a seven-day availability guarantee. RTT is the documented on-node HTTP request or UDP echo measurement, not automatically ICMP ping.

The quote is `directions × methods`:2nodes ×108 methods =216 candidate units;10nodes =9720. The displayed sum of candidate timeouts is a ceiling for those stages, not an ETA. Queue wait and cold dependency builds are excluded, and bytes cannot be predicted honestly. Reservation and job creation share one transaction. Cancellation keeps today's reservation; UTC midnight resets the daily budget. Discovery, limits or budget changes invalidate an optional confirmed estimate.

The process-safe test pool defaults to2 workers (`TP_TEST_WORKERS`, clamped1..4). Excess jobs remain in the durable queue; no waiting thread is created per request. Mesh and standalone benchmark APIs share quotas and slots. Recovery dispatches queued work. Interrupted standalone work reconciles its recorded resources and becomes INTERRUPTED; a campaign reconciles an interrupted child before continuing.

Balanced, latency, throughput and stability objectives use explicit scoring weights. Qualification still requires real paired data, a receipt, restart recovery, cleanup and finite measured metrics. Distinct outer carriers are preferred before remaining rank. Five is the default, not a padding target: shortfall is visible. **Recommend protocol-encrypted templates only** filters suggestions conservatively. It does not turn a raw transport into an encrypted tunnel or prohibit explicit expert choices. Read the reason, encryption label and failure domain in the result.

## Activate, fail over and balance

Open **Review recommendations, activate and balance** to reach Mesh in the same session. Reorder or select more qualified methods within the workspace cap; save and activate each direction. Each destination has an independent authenticated SOCKS entry on the source node. Copy **Show outbound** only into the source-node proxy client; it contains private credentials.

Preference/failover uses healthy warm alternatives for new sessions. Balance shares new TCP connections using measured capacity, request loss, jitter and observed load. Existing TCP sessions reconnect after a tunnel fails. Reconciliation changes members while retaining the owned entry port and credentials, with client reconnection during rebuild. Multiple tunnels to one destination do not survive loss of that entire destination. Single-stream bonding/MPTCP and full UDP/IP VPN are separate capabilities, not guarantees of this interface.

## Operations, history and recovery

Monitoring is off until opted in. Set a60..3600-second sample interval. The panel stores up to7days,5000 samples and1000 transitions per workspace. UP/DEGRADED/DOWN require a current observed gateway state; unavailable/stale/failed observation is UNAVAILABLE. Transition records survive controller restart and do not duplicate every polling tick. External notification delivery is unconfigured.

**Download safe support export** contains allowlisted numeric measurements and state, excluding addresses, names, raw errors, full receipts, runtime configuration and secrets. Administrative audit shows scoped mutation patterns and hashed principals; it is local operational history, not a tamper-proof compliance log. Failed audit writes are logged generically. Never substitute a support export for an encrypted recovery backup.

Use the existing backup/restore scripts. Online snapshots include the registry (accounts, invitations, subscription state and telemetry authority) plus customer databases. Preserve each installation's own encryption identity. Do not copy one installation's encrypted database onto another installation with a different key. Test restoration with the private backup before depending on it.

## Optional restricted telemetry

The agent is push-only and unprivileged. It reads fixed Linux proc files for uptime, load and memory. It accepts no commands and does not deploy tunnels; SSH remains the privileged deployment channel. The separate mTLS hub derives identity from the client certificate, never from headers or a customer-supplied workspace ID. Certificates last30days, sequence numbers persist in the registry, and disabled/revoked/rotated identities cannot report.

Start the hub using the installed Python environment and a free operator-allocated port:

```sh
python -m agent.hub --listen 127.0.0.1 --port YOUR_FREE_PORT --server-name YOUR_VERIFIED_HOST --registry /var/lib/tunnelpannel/workspaces
```

The hub needs the installation's `TP_SECRET_KEY`; load it privately from the runtime environment. Provision a dedicated service and firewall policy for a publicly reachable mTLS listener. Set `TP_AGENT_HUB_URL` to the verified HTTPS origin before API enrollment. The client validates the authority and hostname. Download a node's private bundle, keep it mode600, and run from the verified checkout:

```sh
sudo bash scripts/agent-install.sh /private/node-bundle.json
```

The installer uses systemd DynamicUser, read-only system protection and LoadCredential. Check **Fresh report** and expiry in the node details. After rotation, install the new bundle and verify reporting before expiry. Revoking a certificate does not delete a node or its SSH access. Remove only the owned client using `sudo bash scripts/agent-install.sh --uninstall`; revoke its certificate separately. No third-party telemetry destination is contacted.

## Validation boundaries

See the commercial acceptance report and the earlier [mesh report](MESH-VALIDATION.md) for exact evidence. Two nearby test hosts cannot establish Iran access, multi-country failure domains, many-customer capacity, a seven-day SLA, payment settlement or a universal throughput improvement. Public commercial launch needs the corresponding real pilot and provider/domain configuration.

## Installed acceptance

[Two-server report, exact values, screenshots and boundaries](COMMERCIAL-VALIDATION.md). The pinned command is in `install-one-line.txt`.
