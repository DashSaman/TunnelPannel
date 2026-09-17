# AGENT.md — Multi-Tunnel Failover System (mtf)

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
- [ ] Security note to user: change root password 123456@Saman after delivery

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
