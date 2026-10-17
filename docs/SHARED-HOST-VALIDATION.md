# Shared-host candidate checkpoint — 2026-10-17

**Live API upgrade is deferred at the owner's request until campaign
`757cdb8cd8ff45afa05a55aa4395a919` finishes.** Both test APIs still run
`c300a4a9b2036b9701c8dcebdcc9b3be06676f86` at this checkpoint. The new
coexistence feature is published and candidate-tested, not claimed installed.
The Tehran Network/MyTel host was inspected read-only; its site, containers,
reverse proxy, legacy panel and existing tunnels were not changed.

Available immutable revision including the Tehran Network introduction: `8f1e425c38c76f8b1acb570a2392c060f7c3a5c1`. Its complete CI succeeded after the functional98e2424 baseline. A thread heartbeat checks every10 minutes and resumes the deferred two-node rollout after the owner's campaign and other active work finish; it does not cancel them.

[Usage, capacity and limits](SHARED-HOST.md) · [Allowlisted evidence](evidence/commercial/coexistence-candidate.json).

| Check | Observed result |
|---|---|
| Functional commit with successful CI | `98e2424dc1bdeb085688350304dee6fe3a751243` |
| Portable CI | [39039902316](https://github.com/DashSaman/TunnelPannel/actions/runs/39039902316), SUCCESS |
| Security CI | [39039902280](https://github.com/DashSaman/TunnelPannel/actions/runs/39039902280), SUCCESS |
| Python3.11 and3.12, each | 718 canonical +100 TunnelGuard +1 backend PASS |
| Linux installation | Fresh, rerun, backup/mutate/restore, unrelated-safe uninstall, syntax and ShellCheck PASS |
| Windows | 696 PASS /22 platform skips |
| Isolated physical canaries | 12 named checks on EACH test node PASS |
| Existing warm groups at canary entry | 2 groups /10 healthy members; entries, methods, modes and worker PIDs preserved |
| Shared host inventory | 2 CPUs,3.73GiB RAM, about1.84GiB available;10 containers,23 services,31 tunnel-class links including kernel defaults |
| Real existing container publications | 3 bindings read, no container changes |
| UI | Actual saved shared-host report in isolated local candidate API; FA/EN, export and390px mobile PASS; document375/content375; viewport reset |
| Recovery | Both backup archives plus separate installation env/keys rescued locally; DPAPI encrypt/decrypt equality verified; same Windows account/machine required |

The entering10-member baseline reflects existing owner-visible state: the
historical7-member source route had already been stopped and a5-member
failover route created before this acceptance. The5-member reverse balance
group remained. No historical route was recreated or its credentials reset.

Initial candidate CI39038813751 had717 PASS/1 FAIL per Python version because
a POSIX reservation test's narrow fake remote did not recognize the new host
inspection command. The test now supplies its known empty socket snapshot
while retaining the real allocator and durable reservation logic. The original
failure is retained; the corrected test passed on a physical Linux test node,
then both complete CI matrices passed. Initial installer CI already passed.

Screenshots below are **local candidate previews with the actual saved report**,
not screenshots of a completed remote upgrade. The preview database contains
no SSH secret or copied jobs and exposes a viewer-only role. The service
introduction identifies this as a Tehran Network offering. SSO, WordPress
accounts, live checkout and website/reverse-proxy integration remain pending.

![Persian inventory preview](evidence/commercial/screenshots/preview-fa.png)

![Tehran Network service introduction](evidence/commercial/screenshots/tehnet-service-fa.png)

Further previews: [English](evidence/commercial/screenshots/preview-en.png),
[Persian mobile](evidence/commercial/screenshots/preview-mobile-fa.png),
[English mobile](evidence/commercial/screenshots/preview-mobile-en.png).

After the owner's campaign ends, capture the then-current active groups,
take fresh backups, install the verified immutable revision, rerun owned
canaries and fresh discovery, verify actual data-plane receipts and preserve
the then-current entries and workers. Refresh installed-version evidence and
recovery material afterward. Do not cancel the owner's campaign, delete test
servers, merge main or migrate the shared host as part of that deferred step.
