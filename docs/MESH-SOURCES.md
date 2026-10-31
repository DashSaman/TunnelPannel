# Repository review / بررسی مخزن‌ها

Reviewed on 2026-10-15: root manifests and README of all 33 repositories accessible through the owner's connection, with targeted source inspection for actual tunnel candidates. Private source and private application details are excluded from this public inventory. The owner specifically confirmed t4: it is a PBX/Issabel application, with no new tunnel. t6's WireGuard-over-SIT concept is already represented by the HajSaman profiles; no private source was imported or counted twice.

در تاریخ بالا، فایل‌های معرفی هر ۳۳ مخزن در دسترس و سورس هدفمند نامزدهای تانل بررسی شدند. سورس خصوصی و جزئیات برنامه‌های خصوصی منتشر نشده‌اند. t4 با تأیید مالک بررسی شد و پنل تلفنی است؛ تانل جدید ندارد. ایدهٔ WireGuard روی SIT در t6 در پروفایل‌های HajSaman موجود است و دوباره شمرده نشده است.

## Public sources reviewed / منابع عمومی بررسی‌شده

| Repository | Disposition |
|---|---|
| [PVNetwork-Client](https://github.com/DashSaman/PVNetwork-Client) | Android client integration reference: sing-box/AnyTLS/VMess and OpenVPN. Not a server installer. |
| [PVN-amirrezagol](https://github.com/DashSaman/PVN-amirrezagol) | 93 research matrix entries; does not implement 93 tunnels. Open-source candidate gap list includes AnyTLS, VMess, ShadowTLS, NaiveProxy, OpenConnect, SSTP, SoftEther. Proprietary appliance compatibility excluded from generic Linux claims. |
| [OV-PvNetwork](https://github.com/DashSaman/OV-PvNetwork) | OpenVPN control panel; OpenVPN already covered. Optional AnyConnect/OpenConnect is a candidate. |
| [paqet-tunnel](https://github.com/DashSaman/paqet-tunnel) | Existing Paqet installer/profile overlap. |
| [paqet](https://github.com/DashSaman/paqet) | Already integrated Paqet engine. |
| [Hedioum-Pool-Tunnel](https://github.com/DashSaman/Hedioum-Pool-Tunnel) | TLS pool/native TUN present. SSH and STARTTLS SMTP/IMAP/Postgres/MySQL handshakes and mixed pool are candidates; TLS decoy names are not separate crypto protocols. |
| [-SEO](https://github.com/DashSaman/-SEO) | Application/research unrelated to Linux tunnel engines; no new deployable tunnel identified in reviewed manifest/README. |
| [PV-NativePanel](https://github.com/DashSaman/PV-NativePanel) | Public Go/Caddy NaiveProxy implementation; genuine new engine candidate. Multi-tenant product is not imported. |
| [TehNet](https://github.com/DashSaman/TehNet) | Application/research unrelated to Linux tunnel engines; no new deployable tunnel identified in reviewed manifest/README. |
| [PVNetwork-Reseller-Dashboard](https://github.com/DashSaman/PVNetwork-Reseller-Dashboard) | Reseller UI; no new tunnel engine. |
| [TunnelPannel](https://github.com/DashSaman/TunnelPannel) | Target baseline: 82 identities including six typed composites. |
| [GoldWaterTunnel](https://github.com/DashSaman/GoldWaterTunnel) | WG direct already covered; public MIT WaterWall Reality/VLESS is a genuine new candidate. |
| [Tolid-mohtava](https://github.com/DashSaman/Tolid-mohtava) | Application/research unrelated to Linux tunnel engines; no new deployable tunnel identified in reviewed manifest/README. |
| [MyTellPBX](https://github.com/DashSaman/MyTellPBX) | Application/research unrelated to Linux tunnel engines; no new deployable tunnel identified in reviewed manifest/README. |
| [akh-bot](https://github.com/DashSaman/akh-bot) | Application/research unrelated to Linux tunnel engines; no new deployable tunnel identified in reviewed manifest/README. |
| [WaterWall-H](https://github.com/DashSaman/WaterWall-H) | Public MPL-2.0 transport engine; pinned source build 613bb32c93db40b09cb915070e5f7ff09ad3c81d. Paired configs inspected. New transports need real validation. |
| [PV-GrowthOS](https://github.com/DashSaman/PV-GrowthOS) | Marketing platform mentions existing Xray/Hedioum infrastructure; no new wire protocol. |
| [OmniDrive](https://github.com/DashSaman/OmniDrive) | Application/research unrelated to Linux tunnel engines; no new deployable tunnel identified in reviewed manifest/README. |
| [2-id](https://github.com/DashSaman/2-id) | Application/research unrelated to Linux tunnel engines; no new deployable tunnel identified in reviewed manifest/README. |
| [Arz](https://github.com/DashSaman/Arz) | Application/research unrelated to Linux tunnel engines; no new deployable tunnel identified in reviewed manifest/README. |
| [melika](https://github.com/DashSaman/melika) | Application/research unrelated to Linux tunnel engines; no new deployable tunnel identified in reviewed manifest/README. |

## Delivered additions / موارد افزوده‌شده

- Six independently rendered Hedioum mimic pools: SSH, SMTP STARTTLS, IMAP STARTTLS, PostgreSQL STARTTLS, MySQL STARTTLS and a mixed TLS/SSH/SMTP pool.
- Four WaterWall-H profiles: WS/TLS, HTTP2/TLS, Reality and VLESS/Reality. Pinned public source, strict owned CA/hostname validation and reproducible bounded HTTP2 upload/download fixes; see the MPL notice.
- VMess TCP/TLS and WS/TLS, AnyTLS, ShadowTLS3 plus Shadowsocks AEAD2022, and Naive HTTPS through the installed sing-box engine.
- Eleven additional typed compositions: IPIP over WireGuard/SSH/GOST; GRETAP over WireGuard/SSH; SIT over WireGuard; VXLAN over WireGuard/SSH/GOST; WireGuard over GOST/SSH. Existing six compositions remain.

These are 26 new identities. TLS cover names, protocol aliases, private duplicate implementations and research matrix labels are not additional methods. The research list also names OpenConnect, SSTP and SoftEther; the reviewed manifests did not provide a validated paired adapter for this release. They remain research candidates, absent from the selectable catalog. Proprietary appliance protocols are excluded. Arbitrary nested permutations are not implemented: only the declared pairable overlay/carrier templates are offered, with real carrier-stop testing.

این افزوده‌ها ۲۶ شناسه‌اند. نام پوشش TLS، نام مستعار، نسخهٔ خصوصی تکراری و برچسب‌های جدول پژوهشی، روش جدید نیستند. نام‌های OpenConnect، SSTP و SoftEther در پژوهش‌ها دیده شدند، اما برای این انتشار آداپتور جفت‌شدهٔ تأییدشده ندارند و قابل انتخاب نیستند. ترکیب دلخواه و تودرتوی همهٔ نام‌ها ارائه نشده است؛ فقط قالب‌های مشخص قابل‌جفت‌سازی همراه آزمون توقف حامل عرضه می‌شوند.
