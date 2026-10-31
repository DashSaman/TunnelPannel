# Mesh public evidence

Functional source: `a115027e357f5ea5ce279445e40a678a06949c5b`. Physical scope is two nearby Ubuntu24.04 amd64 hosts. Read the [English](../../MESH-VALIDATION.md) / [Persian](../../MESH-VALIDATION-fa.md) report for chronology, failed attempts and limits. Files describe different runs; they are not all one atomic rerun at the final SHA.

| File | Purpose |
|---|---|
| [public-campaign-matrix.json](public-campaign-matrix.json) | 216 NORMAL outcomes, safe metrics, recommendations and receipt hashes |
| [kernel-followup-summary.json](kernel-followup-summary.json) | 18/18 affected kernel/composition reruns |
| [dotted-key-proof.json](dotted-key-proof.json) | Existing packed GRE key exclusion and owned cleanup |
| [balancing-latest.json](balancing-latest.json) | 12 comparison rounds and 128 verified 64MiB streams including failure/pin/concurrent checks |
| [five-member-failover-drill-latest.json](five-member-failover-drill-latest.json) | Earlier five-member switches through one stable entry |
| [custom-seven-reconcile.json](custom-seven-reconcile.json) | Actual UI seven-member rebuild with unchanged entry |
| [api-restart-with-warm-groups.json](api-restart-with-warm-groups.json) | Independent workers preserved |
| [canonical-migration-a.json](canonical-migration-a.json) | Same-host migration with original key and history |
| [final-installed-acceptance.json](final-installed-acceptance.json) | Both pinned installations, private backup verification and observed 7+5 health |
| [installed-lifecycle-final-b.json](installed-lifecycle-final-b.json) | Actual B upgrade/backup/restore/uninstall/reinstall |
| [owned-firewall-lifecycle.json](owned-firewall-lifecycle.json) | IPv4/IPv6 allow/stop/restart, effective rule preservation |
| [workspace-lifecycle.json](workspace-lifecycle.json) | Customer isolation, rotation, quota, snapshot and revocation |
| [wwh-strict-and-large.json](wwh-strict-and-large.json) | Eight wrong-CA checks and 24×64MiB downloads |
| [wwh-upload.json](wwh-upload.json) | 24×64MiB uploads and memory observations |
| [wwh-coldfresh-source-build.json](wwh-coldfresh-source-build.json) | Empty-source/build-cache compilation |
| [software-suites-current.json](software-suites-current.json) | Disposable-host suite exit codes |
| [ci-summary.json](ci-summary.json) | Immutable-source CI runs, job IDs and software test counts |

No SSH passwords, workspace plaintext keys, SOCKS passwords, installation keys, environment files or database snapshots are included. Receipt hashes refer to retained private ownership records; they do not substitute for independently repeating the experiment. Whole-node CPU/RAM, HTTP curl timing, ICMP/UDP and TCP measurements have distinct bases. Connection sharing does not imply single-stream bonding or a guaranteed speed increase.
