# TehranNetwork / NetAuto Starter

این بسته، مرحله اول پروژه اتوماسیون شبکه است.

## سرویس‌های فعلی

- `netauto-api`: API با FastAPI
- `netauto-bot`: ربات تلگرام با aiogram
- `netauto-worker`: صف اجرای Jobها
- `netauto-scheduler`: زمان‌بندی و Heartbeat
- `netauto-postgres`: دیتابیس
- `netauto-redis`: صف و Cache
- `netauto-web`: ورودی وب داخلی روی پورت 18080

## نکته امنیتی

وب فقط روی `127.0.0.1:18080` باز می‌شود. برای دامنه
`tunnel.softarg.ir` باید Reverse Proxy اصلی سرور به این پورت متصل شود.

## نصب

```bash
cd /opt
mkdir -p network-automation
cd network-automation
# فایل‌ها را اینجا قرار بده
cp .env.example .env
nano .env
chmod +x scripts/*.sh
./scripts/install.sh
```

حداقل این مقادیر را در `.env` تغییر بده:

```env
APP_SECRET_KEY=
JWT_SECRET_KEY=
POSTGRES_PASSWORD=
DATABASE_URL=
REDIS_PASSWORD=
REDIS_URL=
BOOTSTRAP_ADMIN_USERNAME=
BOOTSTRAP_ADMIN_PASSWORD=
```

برای فعال‌کردن ربات:

```env
TELEGRAM_BOT_TOKEN=
TELEGRAM_BOT_ENABLED=true
```

برای Gmail SMTP:

```env
EMAIL_ENABLED=true
SMTP_USERNAME=example@gmail.com
SMTP_PASSWORD=GOOGLE_APP_PASSWORD
SMTP_FROM_EMAIL=example@gmail.com
```

## بررسی سلامت

```bash
./scripts/healthcheck.sh
```

یا:

```bash
curl http://127.0.0.1:18080/api/v1/health
```

## مسیرها

- `/admin`
- `/app`
- `/api/v1/health`
- `/docs`

## وضعیت مالی

در نسخه فعلی:

```env
BILLING_MODE=development
PAYMENTS_ENABLED=false
DEFAULT_CURRENCY=USDT
SECONDARY_CURRENCY=IRT
```

هیچ پرداخت واقعی در این مرحله انجام نمی‌شود.

---

## نسخه عملیاتی 1.0.0

قابلیت‌های تکمیل‌شده این نسخه:

- پنل Jobها و تاریخچه عملیات برای کاربر و مدیر
- تنظیمات عملیاتی، وضعیت سرویس‌ها و تفکیک XHTTP مستقیم از CDN
- مدیریت کاربران، نقش‌ها، فعال/غیرفعال‌سازی و ریست رمز توسط Super Admin
- Audit Log در پنل مدیریت
- حذف عادی امن Endpoint و حذف اجباری فقط برای Super Admin با واردکردن نام دقیق
- حذف Routeهای قدیمی و بدون احراز هویت ربات
- Rate limit ورود و Security Headerهای API
- ثبت و کنترل Fingerprint کلید SSH بعد از اتصال اولیه
- محافظت از آخرین Super Admin
- بررسی سلامت نهایی با `scripts/final_healthcheck.sh`

### XHTTP

`VLESS_XHTTP` و `VLESS_XHTTP_REALITY` در Catalog به‌صورت **Direct** مشخص شده‌اند و برای تست مستقیم بین دو Endpoint به دامنه یا CDN نیاز ندارند.

حالت `VLESS XHTTP TLS + CDN` در صفحه تنظیمات جدا نمایش داده می‌شود، اما تا زمانی که دامنه واقعی، TLS و اتصال Provider تعریف نشده باشد عمداً Executable نیست؛ سیستم آن را با تست مستقیم اشتباه نمی‌گیرد.

### بررسی نهایی

```bash
cd /opt/network-automation
bash scripts/final_healthcheck.sh
```
