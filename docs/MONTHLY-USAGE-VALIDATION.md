# Installed shared allowance acceptance — 20 October 2026

The public panel at **https://tehnet.ir/tunnels/portal** and both authorized execution APIs run functional source `fb0d553c8c268d444ab6d03470e56f998e9d3707`, tree `2aa6e9137d5c863c0de64a39e15b078271d105c0`. Static bundle SHA256: `dce9c45ac55396caba1eed5ecef5036c9ac47183e2cdeaa29af73104fad03332`. The website serves static assets and proxies requests; all accounting, source ledgers, builds and test traffic run elsewhere.

## Administrator workflow

Sign in with the existing administrator account, then open **Users & sales administration → Shared monthly usage**. Choose a customer, inspect usage/held credit/coverage/history, set a total byte/MiB/GiB/TiB ceiling and end date, then save. Raising the ceiling preserves consumption. **New period** keeps prior history and requires all outstanding credits safely closed. A fresh form defaults to30days; allocation, extension and renewal are entirely manual. The customer sees its own pool under **Plan and access**. [Detailed guide and callback configuration](MONTHLY-USAGE.md).

## Actual two-node results

Two independently deployed opposite-source native4in6 routes shared one new temporary administrator-workspace pool. Each route retained its own32Mbps/1GiB/eight-connection limits. No customer account, subscription, plan or payment was created/changed.

| Check | Observed result |
|---|---|
| Small transfer from each source | 1,048,576 verified body bytes each; combined ledger2,097,512 bytes, held0 |
| Restart only the two QA gateways | Both persistent source counters and central total unchanged |
| Simultaneous large transfers | Exact ceiling33,554,555 bytes; source totals15,728,583 +17,825,972; held0; partial payload hashes verified |
| Administrator top-up | +1,048,593 bytes, previous usage retained; second source reached exact34,603,148 byte ceiling |
| Explicit expiry with65,536 unspent bytes | Both sources refused payload, usage remained34,603,148 |
| Manual new period | Exact2,097,165 byte ceiling; prior34,603,148 retained; lifetime source counters17,825,748 +18,874,565 equal both periods combined |
| Exhaustion recheck | Both sources returned0 payload, counters unchanged |
| Owned cleanup | Two STOPPED jobs, six ROLLED_BACK deployments,42 allocations released, zero live owned resources; source counters and stopped history retained |

Full resident registry rescue preceded removal of only our temporary allowance rows, restoring the owner's original no-pool state. Real customer histories were not reset. This was an accounting correctness test, not a throughput benchmark or proof that every source receives a fair bandwidth share.

The first physical attempt failed closed at0 usage because default Python requests received403/code1010 on both nodes. A bounded status request using the genuine product identification returned200. The client now sends `TehNet-TunnelPannel-Gateway/1.0` and JSON Accept; contact starts unknown and reflects actual requests. No WAF/TLS relaxation. [Official Cloudflare explanation](https://developers.cloudflare.com/waf/tools/browser-integrity-check/). Original failure evidence is retained privately.

## Preservation and publication

Fresh real nonce receipts passed through all10 original members and both stable entries. Complete gateway configurations, upstream order, modes, pins, entry credentials and original worker identities remained unchanged. Both nodes passed12 fresh installed coexistence canaries; only their named canary units/interfaces/reservations were removed. Account/password/MFA/workspace records and installation/RBAC/root-access identities matched the pre-upgrade baseline. The historical seven-member group was not recreated.

Public static rollout changed only the dedicated web container. It preserved11 unrelated containers,50 links, five selected service PIDs, nginx files and WordPress; no host-nginx reload. Readiness used the real Docker probe schedule (45second budget), required healthy plusHTTP200, and retained the old release. Public owner/existing-customer authentication, secure cookies and unpaid admission guard passed. Actual FA/EN monthly fields and usage card passed;375px client/scroll widths matched on mobile and1265px on desktop; viewport reset. Screenshots were visually inspected; the current browser tool refused local image-file export (`EPERM`), so no newly saved screenshot is asserted.

Fresh canonical registry/data backups plus online source-ledger snapshots were taken before, immediately before installation and after QA. Each installation's environment was kept separately. Both execution hosts and the website independently encrypted their resident rescues using separate root0600 keys; decrypted SHA256 matched, originals retained. No private backup/key export or live distributed restore occurred.

Functional CI [portable39414814113](https://github.com/DashSaman/TunnelPannel/actions/runs/39414814113) and [security39414814111](https://github.com/DashSaman/TunnelPannel/actions/runs/39414814111) succeeded before installation. Observed Python3.12 logs:818 root tests,100 TunnelGuard,1 backend; Linux fresh/idempotent install, backup/restore and safe uninstall passed. Earlier local776pass/33POSIXskips and33 targeted callback checks are distinct runs. Initial local missing-template failure and first physical callback failure remain historical. Final documentation CI is reported separately after publication; this functional pin remains immutable.

## Limits

All active routes must support accounting before the customer pool is enabled. Existing unmetered live groups are deliberately untouched and cause activation refusal; schedule an explicit migration if their owner wants metering. Accepted relay payload can include data later lost downstream; probes/benchmarks and traffic outside managed gateways are excluded. Short credit leases bound offline operation; offline credit is conservatively held until safe reconciliation. Root can bypass software on their own server. This two-node test establishes neither Iran connectivity nor long-term SLA. Manual commerce remains enabled; no gateway, SSO, server deletion or main merge. Heartbeat stays paused.

[Redacted machine-readable evidence](evidence/commercial/tehnet-monthly-installed.json) · [Persian report](MONTHLY-USAGE-VALIDATION-fa.md) · [Pinned installer](../install-one-line.txt).
