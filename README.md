# MTF — Multi-Tunnel Failover System

> **English** | [فارسی](README-fa.md)

A production-grade multi-tunnel failover system: **82 tunnel methods**, an SSH server-probe engine, a tunnel recommendation engine, and a dark-neon bilingual (fa/en, RTL/LTR) web panel — all delivered as an isolated Docker container that never touches other services on the host.

**Live panel:** `https://tun.softarg.ir:9443`

---

## 📸 Screenshots — real probe of two live servers

| Login | Dashboard (82 methods) |
|---|---|
| ![login](docs/shots/01-login.png) | ![dashboard](docs/shots/02-dashboard.png) |

| SSH Probe — pairwise matrix (loss 0%, RTT 38ms, score 95) | Recommendations (ranked + why) |
|---|---|
| ![probe](docs/shots/04-probe-results.png) | ![reco](docs/shots/05-recommendations.png) |

| Probe form (2 real servers) | Filled before test run |
|---|---|
| ![probe-form](docs/shots/03-probe.png) | ![filled](docs/shots/03-probe-filled.png) |

---

## ✨ Features

### 🧩 82 Tunnel Methods (13 families)
Kernel-space and userspace tunnels, including the three flagship custom methods:

| Family | Notes |
|---|---|
| **HEDIOUM** (Pool/Tunnel) | custom Go binary — SOCKS pool + TUN mode |
| **HAJSAMAN** (SIT/WG/FULL) | custom scripted tunnels |
| **PAQET** (RAW/KCP/SOCKS5) | QUIC/KCP accelerated transport |
| GOST | 15 multi-protocol relay/socks/http/ss |
| FRP | 6 fast reverse proxy |
| RATHOLE | 5 Rust-based lightweight reverse proxy |
| CHISEL | 6 HTTP tunnel over TCP/UDP |
| WSTUNNEL | 3 WebSocket+QUIC tunnel |
| VPN | 5 OpenVPN / WireGuard / IKEv2 / L2TP |
| XRAY | 7 VLESS/VMess/Trojan/Reality |
| SING-BOX | 5 modern universal proxy |
| WATERWALL | 3 anti-DPI custom protocol |
| COMPOSITE | 6 chained multi-hop tunnels |
| KERNEL (SIT/GRE/IPIP/VXLAN/VTI…) | 8 real netns-backed kernel tunnels |

### 🔍 SSH Server Probe Engine
- Add any number of servers (name / IP / SSH port / user / password)
- Concurrent probing: SSH latency, kernel, OS, uptime, IPs
- Full **pairwise quality matrix** (ICMP with TCP fallback): loss %, RTT, jitter
- Credentials are used in-memory only — **never persisted**

### 🎯 Tunnel Recommendation Engine
For every server pair, scores all 82 methods and answers:
- *Which tunnels can connect this pair?*
- *Which one is best — and **why*** (fa + en explanation, tags, fit %)
- Rules: high score + UDP → WireGuard/GRE/IPIP · packet loss → Hedioum/WaterWall/paqet · jitter → paqet/wstunnel · blocked UDP → chisel/gost · the 3 flagship methods are always listed

### 🔁 Failover
- **Auto mode**: health-monitoring FSM with debounce, auto-switch to best tunnel
- **Manual mode**: one-click pick from the recommendation cards
- **VIP failover**: virtual IP `10.10.10.5` follows the active tunnel (policy routing, table 51000)

### 🌐 Panel UI
- Dark neon glass design, bilingual **fa/en with full RTL/LTR switching**
- Live 3s polling, tabs: Dashboard / Server Probe / Recommendations
- Username + password login, session cookies, TLS (wildcard cert)

---

## 🚀 Deployment

The system runs as **one isolated container** (`mtf-panel`) on a dedicated Docker network (`mtfnet`), publishing only port **9443**. Other services on the host are never touched.

```bash
# layout (bind mounts)
/opt/multitunnel/
├── engine/     # FastAPI engine: api.py, probe_engine.py, core.py, state.py, registry.py
├── panel/      # templates + static (i18n UI)
├── methods/    # harnesses: mtf_kernel.sh (netns), mtf_userspace.py
├── bin/        # hedioum, paqet, rathole, wstunnel, waterwall, tuic,
│               #   xray, sing-box, gost, chisel, frps/frpc, hysteria
├── certs/      # panel.pem / panel-key.pem (wildcard *.softarg.ir)
├── data/       # panel_secret.json, STATUS.json, probe_last.json, receipts
└── logs/
```

```bash
docker run -d --name mtf-panel \
  --network mtfnet --privileged \
  -p 9443:9443 \
  -v /opt/multitunnel/engine:/opt/multitunnel/engine \
  -v /opt/multitunnel/panel:/opt/multitunnel/panel \
  -v /opt/multitunnel/methods:/opt/multitunnel/methods \
  -v /opt/multitunnel/bin:/opt/multitunnel/bin \
  -v /opt/multitunnel/certs:/opt/multitunnel/certs \
  -v /opt/multitunnel/data:/opt/multitunnel/data \
  -v /opt/multitunnel/logs:/opt/multitunnel/logs \
  mtf-panel:2.0
```

> `--privileged` is required only for the kernel-tunnel families (netns / WireGuard / GRE…).

### Default login
```
URL:      https://tun.softarg.ir:9443
username: admin
password: (set in /opt/multitunnel/data/panel_secret.json)
```

---

## 🧪 How to use

1. **Login** → Dashboard shows live status of all 82 methods (checkbox = activate).
2. **Server Probe tab** → add server rows (name/IP/SSH port/user/password) → *Start Probe*.
   The matrix shows pairwise loss/RTT/jitter and a health score.
3. **Recommendations tab** → best pair first, then a card per server pair:
   ranked methods with fit %, medals 🥇🥈🥉, fa/en reasoning, and a one-click **pick**.
4. Switch **Auto/Manual** failover from the Dashboard; VIP `10.10.10.5` follows.

**Scoring:** `score = 100 − loss×1.8 − min(rtt/8, 35) − min(jitter×1.2, 20)`

---

## 🔐 Security notes
- Panel is behind TLS; change the admin password immediately after first login (`POST /api/credentials`).
- Probe credentials are never written to disk; only aggregates (`probe_last.json`) are stored.
- Run a firewall allowing only `9443/tcp` to the panel.

## 📄 License
Internal project — DashSaman. All rights reserved.
