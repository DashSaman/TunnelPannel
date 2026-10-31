# Mesh evidence ledger

Functional source: a115027e357f5ea5ce279445e40a678a06949c5b. Baseline: e73aa88352a1c783aebfcf8f3d615ad33293d409. The owner authorized implementation, disposable-pair tests and publication. Read [the final report](../MESH-VALIDATION.md), [Persian manual](../PANEL-GUIDE-fa.md) and [sanitized evidence](../evidence/mesh/INDEX.md).

## Architecture and boundaries

Customer databases and hashed keys are separate. SSH and runtime secrets use the installation encryption key. Background jobs freeze workspace scope. Owner APIs create customers, rotate/disable keys and set quotas; disabling API access does not stop running routes. Physical-host leases serialize workspaces within one installation, not separate controllers.

The catalog has 108 identities: 91 profiles and 17 explicit compositions across 21 families, plus 6 aliases. Original 82 identities remain and 26 are added. All 33 accessible owner repositories were reviewed. t4 is PBX; t6 WG/SIT overlaps existing functionality. No private source, duplicate alias or research-only protocol is counted as an implemented adapter. See MESH-SOURCES.md and THIRD_PARTY_NOTICES.md.

Directed all-pairs campaigns retain outcomes/history/cancellation/restart cleanup and qualify recommendations using setup, real traffic, recovery, metrics and cleanup receipts. Default five prefers distinct outer carriers before remaining quality rank. Custom larger ordered selections are quota-bounded. Fewer qualified choices remain fewer.

Persistent groups have independent authenticated loopback TCP SOCKS entries, warm members, nonce health probes, hysteresis/hold-down, healthy manual pins and credential-preserving rebuild. Existing TCP sessions reconnect after failure. Full destination failure requires another destination. SOCKS is not a full-IP VPN. Quality-weighted least-active-connections sharing reserves during setup, releases on failure/cancel/close and excludes unhealthy members. It shares independent connections, not one TCP stream; speed improvement is not guaranteed.

Durable root-owned reservation books retain ports, inner prefixes, SSH interfaces and XFRM/VTI/GRE identifiers while members are stopped. Unsafe books fail closed. Cleanup removes books last. Shared keyless GRE/IP6GRE/IPIP/SIT carriers use host-flocked per-member refs, inner addresses, preferred-source routes and boot/ifindex/alias ownership; only the last owned reference deletes a carrier. L2 GRE has distinct reserved keys. Existing quoted dotted keys are decoded as packed 32-bit values. Prefix checks cover both families/all nondefault tables. Exact peer-scoped IPv4/IPv6 firewall cleanup preserves unrelated rules and management routes.

## Verified physical evidence

- Complete customer UI campaign 716cd920944b498f8761e95a1638a0ac: 216/216 NORMAL PASS (108 identities each direction); 98 persistent-TCP-qualified choices and 10 exclusions per direction. Complete matrix predates the final concurrency corrections. Follow-ups, not a claimed full rerun at every commit: XFRM/VTI 08de697d549f4be0af5152cb9d8dc945 6/6 PASS; affected kernel/composition campaign 723d39050d6f4fbfa2aba9c3387012b5 18/18 PASS at eb3f1bf0; real occupied dotted-key proof PASS with final allocator.
- Concurrent five-member groups at cf676eab: 12 comparison rounds plus concurrency/failure/pin checks; 128/128 SHA256-verified 64MiB streams (8GiB), actual destination public exits, gateway restart, stopped-member reservation retention, manual pins, unchanged management routes and proof cleanup. Failure exclusion took21.502s. Mean Mbps failover→balance: A→B1370.370→1405.211; B→A1401.621→1183.837. One direction improved, the other worsened. These small sequential samples do not establish a general speed gain.
- Real UI rebuild to seven forward members retained exact entry host/port/user/password; reverse five stayed healthy. Final pinned installation acceptance observed all7+5 healthy. The throughput comparison remains a5+5 result. Earlier five-member stable-entry switches21.424/20.821/20.927/20.928s remain separately recorded.
- WaterWall-H strict CA/hostname verification preserved. Source613bb32c93db40b09cb915070e5f7ff09ad3c81d, patchca1-h2drain3:8 wrong-CA checks,24 verified64MiB downloads +24 uploads; bounded H2 upload RSS about30MiB. Empty-source/build-cache compile567.976s PASS; earlier16.471s was incremental. Initial H2 EOF/OOM failures retained.
- VMessTCP/WS TLS,AnyTLS,ShadowTLS3+SS2022:8 directional passes. Corrected Naive certificate/client options and SIT-over-WG:4 targeted passes; other new compositions:20 passes. Initial failures retained.
- Owned IPv4/IPv6 allow→stop/block→restart/allow PASS; effective prior rules preserved;11 proof allocations released. Failed raw iptables-save comparison retained.
- Workspace lifecycle PASS: owner isolation, independent DBs, rotate/revoke, quotas before SSH, online backup/restore with decryptable secrets, tamper rejection and disabled-key rejection.
- Canonical same-host A migration retained A's key and history; never copied A's encrypted DB to B. Actual pinned a115 installation on both: A upgrade/idempotence/preserved history and workers/native backup with3 workspaces and2 verified real SSH nodes; B upgrade/idempotence/backup-mutate-restore/uninstall-reinstall preserving unrelated interface and A-managed engine units.
- Browser checks: clean onboarding/password clearing/history/progress/FA-EN,390×844 no horizontal overflow, mode/pin/reconcile and authenticated Topology add/search/reload/logout. Topology is explicitly planned, not installed multi-hop.

## Software evidence and regressions

a115027e:643 canonical +100 TunnelGuard +1 backend tests passed separately on both Python3.11 and3.12. Decoded job logs confirm counts. Portable/Linux-install run38914599544 and security run38914599641 succeeded; canonical Ruff/catalog/ShellCheck/Bash/fresh+idempotent install/health/backup-restore/safe uninstall passed. Latest disposable Ubuntu software run also returned all three suite exits0.

Meaningful regressions include unauthorized SOCKS method/auth/command early returns; legacy benchmark cancellation/ownership/admission boundaries; setup cancellation and balanced reservations; shared carrier rollback/foreign resources/boot/corruption; pair-wide XFRM/GRE/VTI identifiers; stable entry reservation before SSH member allocation; dotted ikey/okey/key exclusion; scoped Topology sessions and saved-path derivation. The actual credential-refresh field error was corrected to auth_method PASSWORD plus encrypted secret, and real SSH was verified before installed backup acceptance.

## Scope and follow-up work

Evidence is two nearby Ubuntu24.04 amd64 hosts. Iran/intercontinental/NAT/three-physical-node graphs and other distributions remain unverified. Three-node six-directed-route software coverage is separate from physical proof. No universal production certification is implied.

Owner APIs support later sales integration. Public signup/payment/webhooks/domain/TLS ingress and automatic subscription stop are not connected. Existing credentials and backup keys stay private. Restoring a registry restores historical key hashes; recheck access/rotation after restore. A desktop preview depends on its local SSH forward and is not a public persistent endpoint.

The reports link the exact installed runtime, staged physical receipts and immutable-source CI. Documentation-only commits can follow without changing runtime files. Future release gates must be checked against their actual commit and environment rather than inheriting these PASS labels.
