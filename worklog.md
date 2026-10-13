# MTF Multi-Tunnel Failover — Worklog

---
Task ID: 1
Agent: Super Z (main)
Task: Deploy multi-tunnel failover system (77 methods) on 45.141.148.59, panel at tun.softarg.ir:9443 (Docker, isolated port), agent progress file, bilingual README, push to GitHub

Work Log:
- SSH helper created: scripts/sshrun.py (paramiko, root@45.141.148.59)
- Server probed: Ubuntu 24.04, kernel 6.8, wireguard/ipip/sit/xfrm modules loaded, strongSwan 5.9.13, xl2tpd, nftables present
- Port 8443 occupied by anytls-server (user's SSL error explained) → panel moved to 9443
- New GitHub token stored: .ghtoken (DashSaman) — TunnelPannel private repo accessible
- Cloned TunnelPannel + HajSamanTunnel + Hedioum-Pool-Tunnel + paqet to /home/z/my-project/tp/
- EXACT 77 methods extracted via AST from plan_executor/executor.py *_METHODS sets → deploy/methods_registry.json (13 families: SSH6 GOST15 FRP6 RATHOLE5 CHISEL6 WSTUNNEL3 VPN5 XRAY7 SINGBOX5 WATERWALL3 PAQET2 COMPOSITE6 KERNEL8)
- Built engine: mtf/registry.py state.py core.py (probes+FSM+VIP 10.10.10.5 policy routing table 51000) api.py (FastAPI login/methods/apply/status/mode/manual/settings/receipts)
- Kernel harness: mtf_kernel.sh — real host↔netns(mtfpeer) tunnels: WG, GRE, GRETAP, SIT, IPIP, VXLAN, IP6GRE, IP6GRETAP, VTI(XFRM), L2TP, OpenVPN(TLS), IKEv2 profile, SSH×6, composites
- Userspace harness: mtf_userspace.py — loopback server+client pairs, data-through receipts: GOST×15, FRP×6, RATHOLE×5, CHISEL×6, WSTUNNEL×3, XRAY×7, SINGBOX×5, WATERWALL×3, PAQET×2
- Panel UI: dark neon glass RTL fa/en, Vazirmatn woff2 bundled, live polling 3s, checkbox→apply, auto/manual failover, debounce settings, receipts table
- Docker: mtf-panel:1.0 (ubuntu24.04 + net stack + venv), privileged, network_mode host, volumes /opt/multitunnel/*, TLS certs from pvnet-caddy wildcard
- Bootstrap: scripts/bootstrap.sh (stages → data/STATUS.json), binaries fetcher v2 with ELF verification
- Fixed: compose→docker run (no buildx), TemplateResponse new signature, xray config syntax, fonts

Stage Summary:
- PANEL LIVE: https://tun.softarg.ir:9443 (TLS ✓, external curl ✓)
- Admin password (bootstrap): REDACTED (was committed in cleartext — rotate it; see docs/development/CURRENT_STATE.md)
- 77-method test suite running in container (test_progress.json)
- Pending: 4 binaries (rathole/WaterWall/paqet/hedioum) retry w/ token, receipts review, failover drill, README, GitHub push


## 2026-10-13 disposable-node validation

Historical RC2 baseline (superseded by RC3): 32 PASS / 23 PARTIAL / 27 FAIL in the isolated legacy lab, six real kernel methods and the WG-to-GRE drill. See docs/releases/v0.9.0-rc2/REAL_VALIDATION.md.



## 2026-10-14 real panel benchmark verification

Latest two-node NORMAL results: 82 PASS, derived from the full matrix (76 PASS/6 FAILED) and explicit corrected-profile reruns. Fresh software suites: 533 canonical + 100 TunnelGuard + 1 backend PASS. Real canonical node registration, pinned SSH, encrypted credentials and panel jobs are wired. See docs/releases/v0.9.0-rc3/REAL_BENCHMARK.md. Latest five selected DEEP profiles PASS (initial 4 PASS/1 FAILED retained; unchanged sing-box rerun PASS). Public pinned install on both nodes and full node-B lifecycle PASS. Python 3.11/3.12, Linux installer, security and shell CI PASS at e6a2c419; final delivery commit verification follows. Zero live ownership allocations; historical orphan receipt preserved. Native Hedioum rapid short-connection churn remains a documented diagnostic limitation; sustained TUN speed uses bidirectional iperf3. Supplied credentials never belong in tracked files.

Final access acceptance: authenticated node listing; missing-token regression red then green; 534 canonical + 100 TunnelGuard + 1 backend fresh PASS, canonical lint/catalog/shell checks PASS.
