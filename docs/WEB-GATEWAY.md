# Website gateway and remote execution

The Tehran Network host serves the website entry only. The controller API,
SQLite/workspaces, account sessions, entitlement/usage checks, durable queue,
scoring, engine compilation and tunnel execution remain on separate servers.
No canonical API or job worker is installed by the website-gateway installer.

The gateway uses two isolated, unprivileged systemd units: a pinned SSH local
forward to the controller's loopback API and a separate nginx process on a
loopback HTTP port. It does not edit or reload the system nginx website, add
firewall rules, change routing, or create a network tunnel interface. Each unit
has a CPU quota of10%; memory limits are64MiB for SSH and96MiB for nginx. These
are enforced limits, not measured capacity promises. Both ports use the existing
canonical port manager and a fresh fail-closed listener/container/reservation
scan. Failed binding or an unrelated listener cannot count as healthy: both
socket owners and the forwarded API health must match.

Only this dedicated transport key is stored on the website host. Customer SSH
passwords and installation encryption keys stay in the remote controller's
encrypted workspace storage. nginx access logging and request/response disk
buffering are disabled. The forwarded API still enforces account/workspace
authorization; a web gateway is not an authorization bypass.

## Installation

Prerequisites: systemd Linux, python3, nginx and openssh-client already installed.
Create a dedicated forwarding-only SSH account on the controller and authorize
only the gateway's public key with `restrict,port-forwarding`,
`permitopen="127.0.0.1:API_PORT"` and a forced command that refuses sessions.
Do not use a controller root key. Independently verify and pin the controller's
SSH host key. The installer refuses foreign paths/accounts/units, validates the
private-key file and host pins, and preserves changed operator configuration.

The controller's sshd policy for this dedicated user must additionally set
`AllowTcpForwarding local`, `AllowStreamLocalForwarding no`, `PermitTunnel no`,
`PermitOpen 127.0.0.1:API_PORT`, `PasswordAuthentication no`, `PermitTTY no`,
`AllowAgentForwarding no`, `X11Forwarding no` and `ForceCommand /bin/false`.
Validate with `sshd -t` and inspect effective policy before reloading sshd.
`permitopen` alone does not disable remote forwarding.

The command below pins the CI-verified complete revision. For a later release, replace both commit identifiers together:

```sh
curl -fsSL https://raw.githubusercontent.com/DashSaman/TunnelPannel/d68556d17f8b4a8276bc4c2344139bffc9329042/scripts/install-web-gateway.sh | sudo env TP_GATEWAY_VERSION=d68556d17f8b4a8276bc4c2344139bffc9329042 TP_GATEWAY_CONTROLLER_HOST=192.0.2.10 TP_GATEWAY_SSH_USER=tp-web-gateway TP_GATEWAY_KEY_FILE=/root/gateway.key TP_GATEWAY_KNOWN_HOSTS_FILE=/root/gateway.known_hosts bash
```

Optional variables: `TP_GATEWAY_SSH_PORT`, `TP_GATEWAY_API_PORT`,
`TP_GATEWAY_HTTP_PORT`, `TP_GATEWAY_FORWARD_PORT`. Explicit occupied/reserved
ports refuse installation. A retry with the same identity/ports rechecks files
and listener ownership before restarting only the two gateway units. A failed
start leaves a PREPARED receipt and credentials privately for inspection; it is
not reported as successful. No customer data is copied to the gateway.

Read the selected ports/status from
`/etc/tunnelpannel-web-gateway/receipt.json`. For private testing use an SSH local
forward to its loopback HTTP port and open `/portal`. Future public website
integration must terminate HTTPS in the existing website proxy; no new domain,
public port or website cutover is performed by this installer.

## Commercial boundary

Accounts, workspace limits, daily candidate usage and sandbox subscription
entitlements are enforced by the remote controller. Sandbox entitlements never
represent collected money. Actual pay-per-use pricing, credit reservation,
settlement/refund semantics and payment-provider checkout are a separate
integration before charging customers. A proxy deployment alone does not
implement paid access or single sign-on with the website.

Keep the controller/node servers while they host workspaces or live tunnels.
Moving a website entry does not migrate those resources. Back up the controller
databases plus its separate install key; keep a separate private gateway-key
backup and verify the encrypted rescue. Do not restore backups over live tunnel
workspaces merely to configure the website entry.


Installed two-node and website acceptance: [English report](WATERWALL-GATEWAY-VALIDATION.md).
