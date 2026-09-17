# TunnelGuard 🛡️

**Multi-tunnel failover control plane** — یک پنل وب حرفه‌ای که چند تونل
(WireGuard / GRE / SIT 6in4 / OpenVPN / IKEv2-VTI / L2TPv3) را هم‌زمان نگه
می‌دارد، سلامت هر کدام را با پینگ/پکت‌لاست/جیتر می‌سنجد و در صورت خرابی
**خودکار یا با یک کلیک** بین‌شان سوییچ می‌کند — در حالی که آی‌پی مجازی ثابت
(مثلاً `10.10.10.5`) برای سرویس بالادستی هیچ‌وقت عوض نمی‌شود.

[فارسی](#فارسی) · [English](#english) · [محدودیت‌های واقعی](docs/LIMITATIONS.fa.md)

---

## فارسی

### چرخه‌ی کار
```
پروب هر تونل (ICMP + TCP-fallback، هر ۳ ثانیه)
        ↓
امتیاز وزنی ۰..۱۰۰ (پکت‌لاست ۴۰ / پینگ ۳۰ / جیتر ۲۰ / پایداری ۱۰)
        ↓
FSM فیل‌اُور  — آتو: N چک ناموفق ⇒ سوییچ با کول‌داون/هیسترزیس/ضدفلپ
               منوال: پین تک‌کلیکی؛ هیچ سوییچ خودکاری تا فعال‌سازی مجدد آتو
        ↓
مدیر روتینگ — VIP 10.10.10.5/32 روی lo · روت split/default · SNAT · MSS-clamp
               + سینک روت برگشتی روی مقصد از طریق SSH
        ↓
داشبورد (RTL فارسی/انگلیسی، تم تیره/روشن) — چارت زنده، لاگین JWT، WebSocket
```

### نصب (Ubuntu 22.04/24.04، بدون Docker — سرویس systemd مستقیم روی هاست)
```bash
# از روی پوشه پروژه (یا ریپو پس از push):
sudo INSTALL_DIR=/opt/tunnelguard TF_SOURCE=$(pwd) bash install.sh
```
نصب‌کننده wireguard-tools/openvpn/nftables را نصب و سرویس را بالا می‌آورد و
رمز ادمین اولیه را چاپ می‌کند. پنل: `http://127.0.0.1:8080`

### تست موتورها روی سرور واقعی (مهم‌ترین دستور)
```bash
sudo python3 scripts/selftest.py              # همه موتورها
sudo python3 scripts/selftest.py --engine wireguard
cat selftest-receipts/summary.md              # رسید PASS/FAIL هر موتور
```
هر موتور: precheck → ساخت تونل واقعی بین هاست و یک netns شبیه‌ساز مقصد →
ping از داخل تونل → شمارنده‌ها → teardown. خروجی JSON رسید قابل‌حفظ است.

### حالت شبیه‌سازی (بدون دستکاری شبکه)
```bash
TF_SIM_MODE=1 python -m tfd     # کل چرخه با موتور Sim — برای دمو/آموزش
```

### API
`/docs` (Swagger) · `POST /api/auth/login` · `GET /api/state` ·
`POST /api/mode {mode:"auto"|"manual", pinned_tunnel_id}` ·
`POST /api/failover/switch/{id}` · `GET/POST/PUT/DELETE /api/tunnels` ·
**`POST /api/tunnels/batch {tunnels:[…], activate:true}`** (ویزارد؛ ساخت + فعال‌سازی + پروب اول + رسید IP خروجی) ·
**`POST /api/tunnels/{id}/activate`** ·
`GET /api/metrics` · `GET/PUT /api/settings` · `WS /ws`

---

## English

**TunnelGuard** keeps multiple tunnels alive, scores each by
ping/loss/jitter, and fails over automatically (threshold + cooldown +
anti-flap) or with one manual click — while a pinned virtual IP
(`10.10.10.5/32`) plus nftables SNAT keeps the upstream identity constant.

```bash
sudo TF_SOURCE=$(pwd) bash install.sh          # systemd service, no Docker
sudo python3 scripts/selftest.py               # per-engine PASS/FAIL receipts
TF_SIM_MODE=1 python -m tfd                    # lab/sim mode
```

Engines: WireGuard (MTU 1420) · GRE (1476) · SIT 6in4 (1480) · OpenVPN
static-key (1440) · IKEv2/VTI (1436) · L2TPv3 (1410) · **Hedioum Pool Tunnel**
(userspace, SOCKS5 ingress + optional TUN — see below) · **HajSaman** (slot
reserved — repo private). MSS clamping is automatic; see
`docs/LIMITATIONS.fa.md` for honest limits (TCP sessions break on switch;
6to4 is deprecated, SIT replaces it; ICMP degradation and UDP500/4500
reachability are flagged by prechecks, not silently assumed).

### موتورها (v1.2)

| موتور | لایه | MTU | نوع |
|---|---|---|---|
| WireGuard | L3 | 1420 | kernel |
| GRE | L3 | 1476 | kernel |
| SIT 6in4 | L3-IPv6 | 1480 | kernel |
| OpenVPN | L3 | 1440 | kernel |
| IKEv2/VTI | L3 | 1436 | kernel |
| L2TPv3/IPsec | L3 | 1410 | kernel |
| Hedioum Pool Tunnel | userspace | — | SOCKS5 / TUN (اختیاری) |
| **HajSaman Tunnel** | L3 · WG داخل SIT (proto 41) | 1420 | kernel — CLI یا native |
| **Paqet** | userspace · KCP روی raw-TCP | 1350 | SOCKS5 |

### Hedioum Pool Tunnel engine (v1.1)
One TunnelGuard tunnel = one Hedioum **foreign node** on the Iran hub.
Paste the v2 **pairing token** from `hedioum-tunnel setup-foreign` (or fill
foreign IP/port + 32-hex key manually) — the wizard decodes it client-side,
auto-fills the form, and on submit the tunnel is created, the node is
**merged** into `/etc/hedioum/hedioum.json` (co-tenant nodes preserved),
the service is restarted, and a receipt is produced:

- through-tunnel probe: real SOCKS5 CONNECT round-trips (RTT/loss/jitter)
- exit-IP receipt: HTTP GET through the tunnel to 3 IP-echo providers

Notes (honest):
- SOCKS-only mode (`tun_enabled=false`): probes + per-app traffic work;
  the kernel cannot route the VIP through it, so the FSM never promotes it
  ACTIVE for failover (guarded, with a dashboard-visible event).
- TUN mode (`tun_enabled=true`): routable like any kernel engine.
- Verified end-to-end in this repo's lab: real foreign + hub processes,
  `api.ipify.org`/`google.com` HTTP 200 through the SSH-mimic pool —
  `python3 scripts/run_hedioum_e2e.py`.

### HajSamanTunnel engine (v1.2 — واقعی)
استک upstream: `Xray(fwmark) → WireGuard → SIT (proto 41) → Foreign → SNAT`.
دو حالت، با همان پروب‌های خود ابزار:

- **mode=cli** (پیش‌فرض وقتی ابزار نصب است): اسلات واقعی `hajsaman-tunnel`
  را start/stop می‌کند و کانفیگ `tunnels.d/<slot>.conf` را می‌خواند:
  پینگ همتای WG با source-IP داخل تونل + رسید exit-IP با
  `curl --interface <WG_IP>` (همان بررسی diagnostics خود ویزارد).
- **mode=native** (بدون ابزار): همین استک دونفره را مستقیم می‌سازد —
  SIT با ULA `fd00:05a1:<id>::/64`، wg-quick /30 داخل آن، ip-rule/table با
  fwmark، MTU 1480/1420، و در سمت خارج MASQUERADE. حالت سه‌سروره و
  auto-heal همچنان کار ابزار اصلی است.
- محدودیت صادقانه (خودشان هم می‌گویند): ISP همچنان پروتکل ۴۱، حجم و PPS
  را می‌بیند؛ بلاک‌شدن proto 41 در بالادست قابل تشخیص محلی نیست.

نصب ابزار اصلی برای حالت cli: `bootstrap.sh` ریپوی HajSamanTunnel.

### Paqet engine (v1.2)
تونل raw-packet: بسته‌های TCP دستی‌ساخته با pcap + حمل‌ونقل رمز KCP/smux —
از conntrack و قوانین stateful فایروال عبور می‌کند (ایده‌ی
`gfw_resist_tcp_proxy`). یک TunnelGuard tunnel = یک endpoint:

- **role=client** (ایران): SOCKS5 محلی + port-forward اختیاری؛ پروب واقعی
  = SOCKS5 CONNECT دور-رفت + رسید exit-IP (HTTP GET از داخل تونل).
- **role=server** (خارج): مانیتور liveness + رندر قوانین اجباری iptables
  (`NOTRACK` + دراپ RST کرنل — طبق README خود paqet) که روی up() خودکار
  اعمال می‌شود.
- precheck صادقانه: root/CAP_NET_RAW برای raw socket، MAC گیت‌وی،
  پورت غیراستاندارد، کلید KCP، هشدار block=none/null.
- نصب: `sudo bash scripts/install_paqet.sh` (ریلیز آماده، وگرنه ساخت از
  سورس با go + libpcap-dev).
- SOCKS5-only است: FSM هرگز آن را حامل VIP نمی‌کند (همان گارد هدیوم).

### Quick-add wizard (v1.1)
`⚡ Quick add` on the dashboard: pick several engines → one form per pick →
submit → every tunnel is created, prechecked, brought up, probed and
verified automatically, with a per-step ✔/✖ report (precheck / engine up /
status / first probe / exit-IP receipt).

**Stack:** FastAPI + SQLite (WAL) + JWT + WebSocket, vanilla-JS dashboard
(Chart.js vendored — no CDN dependency on the server), paramiko peer
route-sync. Tests: `python3 -m pytest tests/` (100 tests) + hedioum E2E
(`scripts/run_hedioum_e2e.py`) + per-engine receipts
(`scripts/selftest.py --engine ...`).
