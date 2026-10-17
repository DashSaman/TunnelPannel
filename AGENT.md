# AGENT.md — Multi-Tunnel Failover System (mtf)

## Current test-only handoff — 2026-10-17

Only the two currently authorized disposable nodes65.109.209.194 and65.109.213.64 apply; historical hosts below are not continuation targets. Runtime c300a4a9b2036b9701c8dcebdcc9b3be06676f86 installed on both. No domain or payments requested. See [current validation](docs/TEST-ONLY-VALIDATION.md), [Persian report](docs/TEST-ONLY-VALIDATION-fa.md) and AGENTS.md top. Original7+5 balance members/entries/workers preserved.2010 paired main receipts+4 final installed receipts PASS;720 separate localhost-origin controls.987 samples per route/16.7979h, all retained UP, no continuous-SLA claim. Runtime CI700+100+1 each Python3.11/3.12; Windows678/22skips. Keep PR2 unmerged for owner review. Backups/checksums and credentials remain private.

> **فایل پیشرفت پروژه — این فایل را هر ایجنت/دستیار قبل از ادامه کار بخواند.**
> **Project progress file — every agent MUST read this before continuing work.**

- **Server:** 45.141.148.59 (root) — Ubuntu 24.04.1 LTS, kernel 6.8.0-52-generic
- **Domain:** tun.softarg.ir → 45.141.148.59 (verified)
- **Panel target:** https://tun.softarg.ir:2053 (via existing `pvnet-caddy` container, wildcard cert *.softarg.ir)
- **Install root:** /opt/multitunnel (bin, engine, panel, methods, receipts, tests, data, logs, venv)
- **VIP:** 10.10.10.5/32 (floats over active kernel tunnel via policy routing table 51000)
- **Stack:** FastAPI + SQLite + systemd + nftables; UI: dark neon, fa/en RTL, Vazirmatn
- **Failover:** Auto/Manual, probes = ping RTT + loss% + jitter, FSM UP/DEGRADED/DOWN,
  debounce = consecutive-failure hysteresis (3) + switch cooldown (30 s)

## آپشن‌های کاربر (User requirements — locked)
1. همه تانل‌ها باید واقعاً کار کنند و در پنل با «تیک‌زدن → ثبت» به‌صورت خودکار فعال شوند.
2. هر ۷۷ متد TunnelPannel + ۳ ریپوی جدید (paqet, Hedioum-Pool-Tunnel, HajSamanTunnel) باید تست و فعال شوند.
3. ۶ پروتکل کرنلی (WireGuard/OpenVPN/IKEv2-VTI/L2TP-IPsec/GRE/SIT) با VIP واقعی.
4. پنل حرفه‌ای رنگی گرافیکی (سبک ui-ux-pro-max) دوزبانه fa/en با RTL و Vazirmatn.
5. فایل AGENT.md (همین فایل) همیشه به‌روز.
6. README دوزبانه کامل با اسکرین‌شات و توضیح تک‌تک دکمه‌ها/آپشن‌ها.
7. نتیجه نهایی روی GitHub. ⚠️ بعد از اتمام: کاربر باید root password و GitHub token افشاشده را عوض کند.

## ✅ Completed (do not redo)
- [x] Analysis: TunnelPannel 77 methods (45 main + 2 KCP + 30 EXTRA), 3 new repos analyzed
- [x] Server probed: root OK, kernel modules OK (wireguard, ipip, sit, xfrm_interface, tunnel4/6, udp_tunnel)
- [x] Tools on server: strongSwan 5.9.13, xl2tpd, nftables 1.0.9, iptables, socat, jq, git, python3.12 + venv + pip
- [x] /opt/multitunnel base: venv (fastapi/uvicorn/httpx), bin: xray, sing-box, gost, chisel, hysteria, tuic, frps, frpc, wstunnel
- [x] Existing services respected: docker pvnaive :80/:443, caddy :2053, 3x-ui :2096, node :3000, postgres :5432/:5433, anytls-panel

## 🔄 In progress
- [ ] Missing binaries download on server: rathole, waterwall, paqet, hedioum (+ go.tgz already there)
- [ ] TunnelPannel repo re-locate (exact 77 method IDs) — workspace was reset, rebuilding registry
- [ ] Engine: registry.py, adapters.py (userspace loopback + kernel netns harness), probes.py, fsm.py, vip.py, failover.py, db.py
- [ ] Panel: FastAPI app + dark neon fa/en RTL UI + login + live status
- [ ] systemd: mtf-core.service, mtf-panel.service
- [ ] Caddy route tun.softarg.ir:2053 → 127.0.0.1:8500

## ⏳ Remaining
- [ ] Real tests ALL methods → /opt/multitunnel/receipts/*.json (kernel: host↔netns real tunnels; userspace: loopback data-through receipts)
- [ ] Failover live drill: break active tunnel → auto-switch VIP → cooldown/hysteresis verified
- [ ] Screenshots of panel (browser)
- [ ] README.fa-en.md with screenshots + every button/option explained
- [ ] Push to GitHub (repo: DashSaman — needs token; ⚠️ old token leaked in chat, user must issue new one)
- [ ] Security note to user: change root password (redacted — see docs/development/CURRENT_STATE.md §Security; rotate it) after delivery

## Notes / decisions
- Panel on 127.0.0.1:8500, TLS terminated by existing caddy (wildcard cert), no port conflicts.
- VIP failover is kernel-tunnel-native (WG/GRE/SIT/IPIP/VTI/L2TP). Userspace methods are
  health-monitored + auto-selected for SOCKS-level failover (honest limitation, documented in README).
- Kernel tests use a dedicated network namespace `mtfpeer` + veth pair (root available) —
  real kernel data path, real handshake, real ping through tunnel, all on one server.
- Receipts are JSON: {method, started, data_ok, rtt_ms, loss_pct, jitter_ms, verdict, evidence}.

## ✅ Round 2 (v2.1 — Ops Console rebuild)
- [x] ui-ux-pro-max-skill repo studied file-by-file (708 files); its 3-layer token
      method + chart rules + AA-contrast rules applied to a full UI rebuild
- [x] Unique "Ops Console" UI: SVG icon set (no emoji), 8 tabs, SVG chart engine
      (line/area, bars, donut, gauge) with direct labels, bilingual fa/en RTL/LTR
- [x] NEW tab «تانل‌های سرورها»: scan all servers for existing tunnels + catalog
      of 41 persistent profiles with tick-to-install between two sides + book + remove
- [x] NEW tab «پورت‌ها و تداخل»: per-side listener scan, IP-proto occupancy,
      48 reserved system ports, conflict-free auto port assignment (v4+v6)
- [x] NEW module portmgr.py (conflict scan + allocator) and metrics.py (/proc sampler)
- [x] Multi-distro install: apt/dnf/yum/zypper/pacman/apk + ufw/firewalld/iptables
- [x] Dual-stack: userspace binds ::, WireGuard/GRE/IPIP/VXLAN/VTI inner fd00::/126,
      v6-native SIT/IP6GRE/IP6GRETAP/VTI6 with global-v6 detection
- [x] E2E live: GOST_SOCKS5 pair installed 45↔91 with auto port 21000 (dual-stack
      listener verified, unit active) then fully removed per main-server rule
- [x] AGENTS.md (never-stop contract) + bilingual READMEs documenting every button
      + 7 live screenshots in docs/shots/


## 2026-10-13 disposable-node validation

Historical RC2 baseline (superseded by RC3): 32 PASS / 23 PARTIAL / 27 FAIL in the isolated legacy lab, six real kernel methods and the WG-to-GRE drill. See docs/releases/v0.9.0-rc2/REAL_VALIDATION.md.


## 2026-10-14 real panel benchmark verification

Latest two-node NORMAL results: 82 PASS, derived from the full matrix (76 PASS/6 FAILED) and explicit corrected-profile reruns. Fresh software suites: 533 canonical + 100 TunnelGuard + 1 backend PASS. Real canonical node registration, pinned SSH, encrypted credentials and panel jobs are wired. See docs/releases/v0.9.0-rc3/REAL_BENCHMARK.md. Latest five selected DEEP profiles PASS (initial 4 PASS/1 FAILED retained; unchanged sing-box rerun PASS). Public pinned install on both nodes and full node-B lifecycle PASS. Python 3.11/3.12, Linux installer, security and shell CI PASS at e6a2c419; final delivery commit verification follows. Zero live ownership allocations; historical orphan receipt preserved. Native Hedioum rapid short-connection churn remains a documented diagnostic limitation; sustained TUN speed uses bidirectional iperf3. Supplied credentials never belong in tracked files.
