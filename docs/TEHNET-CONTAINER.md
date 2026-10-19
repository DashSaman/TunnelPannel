# Website container on an existing HTTPS site

The public entry can run under `https://tehnet.ir/tunnels/` in a dedicated
nginx container. Only static UI and reverse proxying run there. The API,
accounts/customer databases, quota checks, jobs, builds and tunnels remain on
the remote controller/nodes. There is no Docker socket, controller database,
customer credential or SSH private-key mount in this container.

Package from a reviewed source checkout on an administration/build machine:

```sh
python scripts/container_web_gateway.py OUTPUT --prefix /tunnels --origin https://tehnet.ir --port FREE_LOOPBACK_PORT --upstream-port EXISTING_SSH_FORWARD_PORT --image nginx@sha256:VERIFIED_DIGEST
```

Choose the port with the canonical port manager against a fresh, complete host
inventory, including container publications, operator reservations and prior
allocations. Recheck immediately before startup; fail on a bind conflict.
The package refuses an existing output path and requires a digest-pinned image.
It namespaces page/asset links, discovers the API base from the auth script's
URL and extracts inline scripts to files for a `script-src 'self'` policy.
Invite and campaign links retain the application prefix. The existing root
deployment remains compatible.

The generated Compose service uses nginx as UID101, a read-only filesystem,
all capabilities dropped, no-new-privileges, a bounded temporary filesystem,
32 tasks, 96MiB memory and 0.20 CPU. Host networking is deliberate: it can reach
the existing loopback-only, restricted SSH forward without exposing that
forward to a Docker bridge. Its HTTP listener also binds only to loopback;
the host's existing HTTPS nginx publishes only `/tunnels/`. Host networking
shares the host network namespace; it is not network-namespace isolation.
The container has no SSH credentials and cannot create network interfaces.

Before publication, make private backups of the site configuration/menu and
database, controller database and its separate installation env/key. Record
current unrelated containers, services and all current route configuration
hashes/worker PIDs. Wait for every controller benchmark/deployment job to drain.
Never cancel customer work or restart warm tunnel workers for this change.

Set `TP_PUBLIC_ORIGIN=https://tehnet.ir` on the controller and explicitly trust
only `127.0.0.1` for Uvicorn forwarded headers. Restart only the controller API
after the work check; keep its source, keys and databases. The existing HTTPS
proxy must overwrite Host/protocol/client headers, not trust client-supplied
values. Its generated location preserves the prefix through the container;
the container strips it for the canonical API, preserves Origin and CSRF,
and scopes Secure/HttpOnly/SameSite cookies to `/tunnels/`. Cookie login through
an old localhost preview is intentionally no longer the canonical origin.

Copy the generated package to a new owned release directory, validate Compose
and `nginx -t` in the container, then start only its service. Add the generated
`host-location.conf` via a dedicated include to the existing site's TLS
server block, guarded by the current configuration hash. Run host `nginx -t`
before a graceful reload. Retain the exact before files for rollback; never
restore unrelated files changed by another operator. The existing private
SSH transport and private HTTP fallback can remain available for diagnostics.

Only after HTTPS, assets and cookie login succeed, append one idempotent
“مدیریت تونل” custom link to the current WordPress primary menu. Use WordPress
menu APIs and preserve the IDs, order, URLs and parents of existing entries.
The same primary menu supplies the desktop and mobile navigation. No WordPress
account, payment or SSO integration is implied.

Acceptance must cover actual public HTTPS, all four pages/assets, authenticated
node/history reads and workspace isolation, cookie flags/path, rejected foreign
Origin and missing CSRF, anonymous API denial, FA/EN/mobile navigation, and
preservation of existing site services and tunnel configs/PIDs. Store only
allowlisted evidence in Git; keep backups and credentials private. Public paid
checkout is a separate request; this deployment does not charge money.
