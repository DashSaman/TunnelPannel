# Installed TehNet owner console — 2026-10-19

The paid account portal is **https://tehnet.ir/tunnels/**, linked from the existing
site menu. Sign in with the assigned username/password. A system owner sees
**Users & sales administration** and its four tabs: **Users**, **Access & quotas**,
**Plans & prices**, **Manual payments**. Customer accounts see their own workspace.
Credentials are private, hashed on the controller, and absent from this repository.

[Owner guide](COMMERCIAL-OWNER.md) · [فارسی](COMMERCIAL-OWNER-VALIDATION-fa.md)

## Installed and verified

Both execution nodes now run `97b5af8ba33556aadc8ae580271d9692a1ccce2b` (tree `b1d52d1d6d775fc0dd2de4c99a76a120a4afba65`). The website static release remains `e85b4e660ddd0ae8652cce99e5db753216b7cdc7`; the follow-up contains no frontend change. Runtime portable/Linux lifecycle39279868625 and security39279868600 completed successfully before rollout.
The original commercial release portable/Linux lifecycle run [39274699149](https://github.com/DashSaman/TunnelPannel/actions/runs/39274699149)
and security run [39274699132](https://github.com/DashSaman/TunnelPannel/actions/runs/39274699132) succeeded.
The website hosts only static nginx/proxying; API, databases, account/payment
state, queues, builds, benchmarks and tunnel execution stay on separate nodes.

Actual public HTTPS QA passed username sign-in, owner/customer separation,
unpaid new-work402, tenant owner-API403, manual activation, duplicate receipt
idempotence, changed duplicate409, purchased quota snapshots, immediate customer
caps and session revocation after account edits. The receipt was explicitly
**QA ONLY / NO FUNDS**; no money moved. Only that newly created QA account,
workspace, plan and receipt were removed with a private server-side rescue.
Existing accounts/workspaces/catalog/receipts exactly matched the pre-QA API baseline.
No customer tunnel was created, removed or reconfigured by this account test.

Plans intentionally have no invented selling prices. Configure price, IRT/IRR,
duration and quotas first; then confirm an actual offline receipt to activate a
customer. No online checkout/provider or WordPress SSO is enabled. Old sandbox
credit does not grant paid access in manual mode. A system owner can validate
the installation without purchasing a plan.

![Installed owner plans, Persian](evidence/commercial/tehnet-owner-plans-fa.png)

Real browser FA/EN owner views and mobile375/375 content/viewport widths passed;
the temporary viewport override was reset.

## Physical transport evidence and completed guard follow-up

New campaign `64e7ccc80f7d4f519315c7baf87b8e5e` retained14 outcomes.
HTTP2-TLS, WS-TLS, REALITY and VLESS-REALITY each passed both directions:
**8 successful measured results with receipts**. Six HajSaman results were
blocked by the coexistence forwarding guard. Campaign PASS means successful
routes were available; it does **not** mean14/14 methods succeeded.

The host-local SIT/WG guard was overly broad: those two adapters do not need
global forwarding. Regression tests reproduced2 failures, then19 targeted tests
passed after the narrow fix. Revision `97b5af8ba33556aadc8ae580271d9692a1ccce2b`
is now installed on BOTH execution nodes after its queued CI completed successfully.
Fresh preinstall backups/env and the then-current group baseline were rechecked.
New campaign `257d3f9b7f9c43d198f99fdfde993bf7` passed SIT and WG in both
directions: **4/4 successful results with receipts**, each30 latency samples,
measured throughput, recovery and released16/22 owned resources respectively.
The initial6 guarded failures remain unchanged in their original campaign.
FULL still correctly refuses to change disabled global IPv4 forwarding.

Installed coexistence canaries passed12 checks on EACH node, including IPv4/IPv6
TCP/UDP listeners, existing tunnel/service detection, occupied/reserved ports,
missing-tool refusal, preserved API PID and owned-only cleanup. The former
unregistered empty QA database was rescued privately only after a drained API
restart and verification that no process held its file open. No registered
customer database was removed. Public owner/customer HTTPS sign-in and paid
admission guards were checked again after the backend upgrade.


The [upstream review](UPSTREAM-REVIEW-20261019.md) records T6, Gold and WaterWall-H
pins. Private T6 source was not copied. Gold packaging claims are not measured
speed gains. Existing accepted WaterWall tail-drain fixes remain; historical
failed receipts are not overwritten. Two same-datacenter nodes do not prove
Iran-route reliability, many-customer scale or single-stream bonding.

## Preservation, rollout incidents and recovery

Ten current members, complete ordered configs, modes, pins and live worker PIDs
1140595/873935 stayed intact. Keys, root access and customer identities were
preserved. The website container is UID101/read-only/cap-drop with96MiB/0.20CPU/
32pids; no API/DB/SSH key or Docker socket is mounted inside it.

Two own-container rollback attempts are retained: a20s health wait ended before
Docker's first30s check; corrected readiness requires healthy Docker and HTTP200
with a45s budget. Another attempt noticed a separate `tehnet-software` project
update. Its current healthy container and one veth replacement were recorded and
preserved;10 original unrelated containers stayed unchanged. Final comparison
preserved all11 then-current unrelated containers,50 links,5 service PIDs and
nginx files. No host nginx reload or WordPress/menu change was needed.

Fresh immediate-preinstall and final after archives, plus separate env/key material for each installation
were retained privately and encrypted **on each original server** with separate
root0600 keys. Decryption SHA256 equality passed. Website config and its restricted
transport identity have their own encrypted rescue. No sensitive server backup
was exported locally; originals remain. This is not a new offsite DR copy and
no restore was performed over live data.

New owned service units discard process stdout/stderr and use private umask.
Root can still inspect runtime files/binaries/memory; copying public source or
preventing root inspection cannot be guaranteed. Central access/payment audit
records remain for accounting. Existing/unrelated journals are not purged.

[Machine-readable evidence](evidence/commercial/tehnet-owner-installed.json).
Main remains unmerged; the existing PR2 carries publication work.
