<div dir="rtl" align="right">

# TunnelPannel (TehranNetwork / NetAuto)

[English](README.md) · **فارسی**

TunnelPannel یک کنترل‌پلین Self-hosted برای اتوماسیون شبکه است که سرورهای لینوکسی را به‌عنوان Endpoint ثبت می‌کند، Inventory شبکه را می‌خواند، Precheck دوطرفه انجام می‌دهد، از داخل صفحه Tunnel Composer روش‌های تونل را انتخاب می‌کند و پلن را از طریق SSH به‌صورت مرحله‌ای اجرا می‌کند. همین عملیات از ربات تلگرام نیز قابل کنترل است.

موتور فعلی **۷۷ روش تونل/ترنسپورت** دارد؛ از GRE، WireGuard و VXLAN کرنل لینوکس تا خانواده‌های SSH، GOST، FRP، Rathole، Chisel، wstunnel، VLESS، sing-box، IPsec، OpenVPN، WaterWall و Paqet.

> این نرم‌افزار تنظیمات شبکه سرورهایی را که به‌عنوان Endpoint معرفی می‌کنید تغییر می‌دهد. فقط روی سرورهایی که مدیریتشان با خودتان است استفاده کنید و برای سرورهای ریموت همیشه مسیر بازیابی خارج از تونل داشته باشید.

## قابلیت‌های اصلی

- پنل وب برای مدیریت، Endpointها و Tunnel Composer.
- اتصال SSH برای Inventory، Precheck و اجرای ترتیبی پلن‌ها.
- اجرای چندمرحله‌ای، نمایش Progress و امکان Cancel.
- ۷۷ روش executable در `plan_executor`.
- PostgreSQL برای داده‌های دائمی و Redis برای Job/Eventها.
- رمزگذاری Credentialهای Endpoint در دیتابیس با Fernet مشتق‌شده از `APP_SECRET_KEY`.
- ثبت Fingerprint کلید SSH در اتصال اول و Pin کردن آن در اتصال‌های بعدی.
- مدیریت کاربر/Super Admin، Audit Log، Operations و Health Check.
- ربات تلگرام چندزبانه به‌صورت اختیاری.
- استقرار Docker Compose با Bind شدن وب فقط روی `127.0.0.1` به‌صورت پیش‌فرض.

## معماری

```text
Browser / Telegram
        |
        v
 netauto-web (Nginx, localhost:18080)
        |
        v
 netauto-api (FastAPI) ---- netauto-postgres
        |                         |
        +-------------------- netauto-redis
        |                         |
        +--> netauto-worker ------+
        +--> netauto-scheduler ---+
        +--> netauto-plan-executor
                     |
                     +---- SSH ----> Endpoint A
                     +---- SSH ----> Endpoint B / ...
```

سرویس‌های Compose شامل `postgres`، `redis`، `api`، `bot`، `worker`، `plan_executor`، `scheduler` و `web` هستند. به‌صورت پیش‌فرض فقط Web روی هاست پورت منتشر می‌کند و PostgreSQL/Redis/API داخلی داخل شبکه Docker می‌مانند.

## پیش‌نیاز

- Ubuntu 22.04/24.04 یا سیستم apt-based سازگار؛ Debian 12 حالت fallback موردنظر است.
- دسترسی root/sudo روی Control Server.
- اینترنت برای Imageهای Docker و پکیج‌های موردنیاز Endpointها.
- دسترسی SSH از Control Server به سرورهایی که قرار است مدیریت شوند.

## نصب تک‌خطی

ریپوی GitHub در حال حاضر **Private** است؛ بنابراین توکنی با دسترسی Read به Repository Contents لازم است. ابتدا Token را Export کن و بعد:

```bash
export GITHUB_TOKEN='YOUR_GITHUB_TOKEN'; curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" -H 'Accept: application/vnd.github.raw+json' 'https://api.github.com/repos/DashSaman/TunnelPannel/contents/install.sh?ref=main' | sudo -E bash
```

Installer به‌صورت پیش‌فرض پروژه را در `/opt/tunnelpannel` می‌گذارد، فقط اگر Docker وجود نداشته باشد آن را نصب می‌کند، Secretهای قوی برای برنامه/PostgreSQL/Redis می‌سازد، Compose را Validate می‌کند، Stack را Build/Start می‌کند و منتظر Health Check می‌ماند.

اگر بعداً Repository عمومی شد، دستور کوتاه‌تر زیر کافی است:

```bash
curl -fsSL https://raw.githubusercontent.com/DashSaman/TunnelPannel/main/install.sh | sudo bash
```

متغیرهای قابل Override هنگام نصب: `INSTALL_DIR`، `WEB_BIND_PORT`، `APP_BASE_URL`، `ADMIN_USERNAME`، `ADMIN_PASSWORD`، `BRANCH` و `REPO_SLUG`.

**محافظت در برابر تداخل:** اگر Installer کانتینرهای `netauto-*` موجود روی سرور ببیند، به‌طور پیش‌فرض متوقف می‌شود تا سرویس قبلی را خراب نکند. `ALLOW_EXISTING_NETAUTO=1` فقط وقتی استفاده شود که عمداً Stack موجود را مدیریت می‌کنی.

## نصب دستی

```bash
git clone https://github.com/DashSaman/TunnelPannel.git
cd TunnelPannel
sudo bash install.sh
```

## تنظیمات `.env`

فایل `.env` Runtime است و وارد Git نمی‌شود. متغیرهای مهم:

| متغیر | کاربرد |
|---|---|
| `APP_BASE_URL` | آدرس HTTPS خارجی پنل یا آدرس localhost در راه‌اندازی اولیه |
| `APP_SECRET_KEY` | Secret اصلی برای مشتق‌کردن کلید رمزگذاری Credentialها |
| `JWT_SECRET_KEY` | کلید امضای JWT |
| `WEB_BIND_PORT` | پورت محلی پنل؛ پیش‌فرض `18080` |
| `POSTGRES_PASSWORD` / `DATABASE_URL` | رمز و DSN دیتابیس |
| `REDIS_PASSWORD` / `REDIS_URL` | رمز و DSN ردیس |
| `BOOTSTRAP_ADMIN_USERNAME` / `BOOTSTRAP_ADMIN_PASSWORD` | اطلاعات Super Admin اولیه |
| `BOT_INTERNAL_API_KEY` | کلید داخلی ارتباط ربات و API |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_BOT_ENABLED` | تنظیمات اختیاری ربات تلگرام |
| `SMTP_*` / `EMAIL_ENABLED` | تنظیمات اختیاری ایمیل |

**مهم:** بعد از اینکه Credentialهای Endpoint داخل دیتابیس ذخیره شدند، `APP_SECRET_KEY` را بدون Migration عوض نکن. کلید Fernet از این مقدار مشتق می‌شود و تغییر آن باعث می‌شود Credentialهای قبلی دیگر قابل Decrypt نباشند.

Installer رمز تصادفی Admin اولیه را فقط یک بار در خروجی نشان می‌دهد؛ همان لحظه آن را ذخیره کن و بعد از ورود تغییرش بده.

## دسترسی وب و HTTPS

Compose به‌صورت پیش‌فرض پنل را فقط روی `127.0.0.1:18080` Bind می‌کند. برای دامنه، Reverse Proxy موجود روی هاست را به این پورت وصل کن و PostgreSQL/Redis/API داخلی را مستقیم روی اینترنت باز نکن.

نمونه Upstream در Nginx هاست:

```nginx
server {
    listen 443 ssl http2;
    server_name panel.example.com;

    location / {
        proxy_pass http://127.0.0.1:18080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

بعد از تنظیم دامنه، `APP_BASE_URL=https://panel.example.com` را در `.env` قرار بده و فقط همین Compose Project را Restart کن.

## روش‌های قابل اجرا (۷۷ روش)

مرجع اصلی `SUPPORTED` داخل `plan_executor/executor.py` است. مجموعه فعلی:

- **Native / Kernel / Overlay:** `GRE`, `GRETAP`, `IPIP`, `SIT_6IN4`, `IP6GRE`, `IP6GRETAP`, `VXLAN`, `VTI`, `VTI6`, `WIREGUARD`, `GRE_OVER_WIREGUARD`.
- **خانواده SSH:** `SSH_LOCAL_FORWARD`, `SSH_REMOTE_FORWARD`, `SSH_DYNAMIC_SOCKS`, `SSH_TUN_L3`, `SSH_TAP_L2`, `AUTOSSH_REVERSE`, `GRE_OVER_SSH`, `SIT_OVER_SSH`.
- **خانواده GOST:** `GOST_SOCKS5`, `GOST_SOCKS5_KCP`, `GOST_HTTP`, `GOST_HTTP2`, `GOST_WS`, `GOST_GRPC`, `GOST_QUIC`, `GOST_SSH`, `GOST_TUN`, `GOST_TAP`, `GOST_TCP_FORWARD`, `GOST_UDP_FORWARD`, `GOST_REMOTE_TCP`, `GOST_REMOTE_UDP`, `GOST_KCP_FORWARD`, `GRE_OVER_GOST`, `GRETAP_OVER_GOST`, `SIT_OVER_GOST`.
- **Chisel:** `CHISEL_TCP`, `CHISEL_UDP`, `CHISEL_SOCKS5`, `CHISEL_REVERSE_TCP`, `CHISEL_REVERSE_UDP`, `CHISEL_REVERSE_SOCKS5`.
- **Rathole:** `RATHOLE_TCP`, `RATHOLE_UDP`, `RATHOLE_TLS`, `RATHOLE_WEBSOCKET`, `RATHOLE_NOISE`.
- **FRP:** `FRP_TCP`, `FRP_UDP`, `FRP_KCP`, `FRP_QUIC`, `FRP_STCP`, `FRP_XTCP`.
- **wstunnel:** `WSTUNNEL_TCP`, `WSTUNNEL_UDP`, `WSTUNNEL_SOCKS5`.
- **VPN / IPsec:** `OPENVPN`, `IKEV2_IPSEC`, `L2TP_IPSEC`.
- **Modern Proxy / sing-box:** `VLESS_TCP`, `VLESS_WS`, `VLESS_GRPC`, `VLESS_REALITY`, `VLESS_VISION_REALITY`, `VLESS_XHTTP`, `VLESS_XHTTP_REALITY`, `TROJAN_TLS`, `SHADOWSOCKS`, `HYSTERIA2`, `TUIC`, `SINGBOX_TUN`.
- **WaterWall:** `WATERWALL_DIRECT`, `WATERWALL_TLS_MUX`, `WATERWALL_REVERSE`.
- **Paqet:** `PAQET_RAW_KCP`, `PAQET_SOCKS5`.

بعضی روش‌ها به قابلیت‌های Kernel/OS، پورت آزاد، دانلود پکیج، دامنه/TLS یا شرایط خاص Routing نیاز دارند. قبل از اجرا Precheck را انجام بده؛ وجود یک روش در Catalog به معنی مناسب‌بودن آن برای هر دو سرور نیست.

## مسیرهای مهم پنل

- `/` — ورودی اصلی
- `/admin` — پنل مدیریت
- `/app` — Workspace کاربر
- `/composer` — Tunnel Composer
- `/docs` — مستندات FastAPI
- `/api/v1/health` — Health endpoint

## عملیات و نگهداری

از داخل مسیر نصب:

```bash
bash scripts/healthcheck.sh
bash scripts/final_healthcheck.sh
```

بکاپ PostgreSQL و Config در پوشه محلی و Ignoreشده `backups/`:

```bash
bash scripts/backup.sh
```

Restore دیتابیس:

```bash
bash scripts/restore.sh backups/postgres-YYYYMMDD-HHMMSS.sql.gz
```

آپدیت بعد از Pull کردن Revision بررسی‌شده:

```bash
git pull --ff-only
bash scripts/update.sh
```

توقف و حذف Containerهای همین Stack با حفظ Volumeهای دائمی:

```bash
bash scripts/uninstall.sh
```

حذف دائمی Data عمداً اتوماتیک نشده است. دستور `docker compose down -v` دیتابیس، Redis و Volumeهای برنامه را نابود می‌کند و فقط بعد از بکاپ تأییدشده باید اجرا شود.

## نکات امنیتی

- `.env`، بکاپ‌ها، Dumpها، Private Keyها، Certificateها، دیتابیس و Logها وارد Git نمی‌شوند.
- Credentialهای SSH/sudo قبل از ذخیره در دیتابیس رمزگذاری می‌شوند.
- کلید SSH سرورها بعد از Discovery اول Fingerprint و Pin می‌شود.
- Web listener به‌طور پیش‌فرض فقط localhost است.
- Installer اگر `netauto-*` موجود ببیند بدون Override صریح ادامه نمی‌دهد.
- GitHub Token برای Clone خصوصی فقط به‌صورت Header موقت استفاده می‌شود و داخل URL مربوط به `origin` ذخیره نمی‌شود.

## ساختار Repository

```text
backend/         FastAPI، Auth، Models و Routeهای Endpoint/Composer/Admin
bot/             ربات تلگرام و ترجمه‌ها
plan_executor/   موتور ۷۷ روشی و Orchestration روی SSH
worker/          Jobهای Inventory/Precheck/Endpoint
scheduler/       Jobهای زمان‌بندی و Heartbeat
web/             UI پنل، Admin، App و Composer
proxy/           Nginx داخلی
scripts/         Install/Update/Backup/Restore/Health/Uninstall
tests/           Smoke/Release testهای Repository
```

پوشه `.netauto-master/` Artifactهای تاریخی مربوط به ساخت Engine Packهای نسخه اصلی را نگه می‌دارد. Backupهای Production و Runtime State عمداً در Git نیستند.

## توسعه و تست

بدون بالا آوردن سرویس‌ها:

```bash
python3 -m unittest tests.test_release_assets -v
bash -n install.sh
```

با `.env` تنظیم‌شده:

```bash
docker compose config
docker compose run --rm --no-deps api python -m unittest discover app/tests
```

برای Stack در حال اجرا، `bash scripts/final_healthcheck.sh` مسیرهای API/DB، هر ۷۷ روش Executor، Policy کلید SSH، Assetهای وب و Nginx را بررسی می‌کند.

## سازگاری با نصب قبلی

نسخه Production اولیه در `/opt/network-automation` بوده و Container/Volumeها Prefix `netauto-` دارند. Installer جدید به‌طور پیش‌فرض `/opt/tunnelpannel` را استفاده می‌کند ولی نام‌های داخلی را برای سازگاری نگه می‌دارد. دو نسخه با همین Container/Volume nameها را روی یک Docker Host هم‌زمان نصب نکن.

## Repository

`https://github.com/DashSaman/TunnelPannel`

</div>
