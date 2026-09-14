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

## روش‌های قابل اجرا (۷۷ روش)

مرجع اصلی `SUPPORTED` داخل `plan_executor/executor.py` است. مجموعه فعلی خانواده‌های Native/Linux، SSH، GOST، Chisel، Rathole، FRP، wstunnel، OpenVPN/IPsec، VLESS/sing-box، WaterWall و Paqet را پوشش می‌دهد. قبل از اجرا Precheck را انجام بده؛ وجود یک روش در Catalog به معنی مناسب‌بودن آن برای هر دو سرور نیست.

## مسیرهای مهم پنل

- `/` — ورودی اصلی
- `/admin` — پنل مدیریت
- `/app` — Workspace کاربر
- `/composer` — Tunnel Composer
- `/docs` — مستندات FastAPI
- `/api/v1/health` — Health endpoint

## عملیات و نگهداری

```bash
bash scripts/healthcheck.sh
bash scripts/final_healthcheck.sh
bash scripts/backup.sh
```

Backupهای Production و Runtime State عمداً در Git نیستند.

## توسعه و تست

```bash
python3 -m unittest tests.test_release_assets -v
bash -n install.sh
docker compose config
```

برای Stack در حال اجرا، `bash scripts/final_healthcheck.sh` مسیرهای API/DB، هر ۷۷ روش Executor، Policy کلید SSH، Assetهای وب و Nginx را بررسی می‌کند.

## انتقال کامل به سرور جدید

نصب Fresh و بازیابی واقعی State پروژه روی Ubuntu 24.04 در محیط ایزوله تست شده است. Count کاربران، Endpointها و Credentialهای رمزگذاری‌شده با Production تطبیق داده شد و Health Check نهایی پاس شد.

اطلاعات Runtime و داده‌های Production عمداً داخل Git نگهداری نمی‌شوند. برای انتقال کامل، سورس را از Repository نصب کن و State عملیاتی را از Backup امن همان نصب بازیابی کن. جزئیات فنی Disaster Recovery در `README.md` و ابزارهای پوشه `scripts/` مستند شده است.

## Repository

`https://github.com/DashSaman/TunnelPannel`

</div>
