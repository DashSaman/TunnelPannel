# AGENTS.md — Permanent Agent Rules / قوانین همیشگی ایجنت

## 2026-10-17 commercial beta handoff / تحویل بتای تجاری

Active source worktree: work/saas-source, codex/commercial-beta-20261016. Final functional runtime d757fa836db2ddf838bb1f6897fbb3e30cde3a9c installed and rechecked on BOTH authorized disposable nodes:65.109.209.194 and65.109.213.64. Never use historical hosts listed below for this continuation. Preserve independent installation keys and original7+5 warm groups. Credentials are private, never publish them.

Tasks1–7 implementation and physical acceptance:70 named commercial checks PASS;10/10 representative bidirectional receipts, restart/queue ownership cleanup, both-node key lifecycle/rollback, actual cross-server unprivileged mTLS/revocation, balance/failover, grace/expiry/scoped cleanup, both-node backup-mutate-restore and pinned reruns.12/12 original public exits and final live health PASS; entry ports/credentials compared with pre-upgrade archive unchanged. See docs/COMMERCIAL-VALIDATION.md and -fa.md, docs/evidence/commercial and docs/development/COMMERCIAL_LEDGER.md for exact revisions/boundaries.

Final runtime Linux CI38963184697 and security38963184676 SUCCESS; Python3.11/3.12 each692 canonical+100 TunnelGuard+1 backend PASS. Windows670/22skips,89/11skips,1 backend PASS. Actual390px FA/EN widths375/375 after long-fingerprint fix. Catalog91 profiles+17 compositions=108 identities; historical registry-import reports do not replace live paired receipts.

Runtime and final documentation/evidence use the existing PR2 feature branch codex/mesh-recommendations-20261015. Native blob/tree hashes and expected-head leases must be verified. Main remains e73aa88352a1c783aebfcf8f3d615ad33293d409; metadata/main approval gate must not be bypassed via CLI or direct main refs. install-one-line.txt pins the verified runtime independently of main merge. Final documentation-only publication may follow runtime.

Two handoff accounts exist (system owner and original-group customer); private credentials are outside Git and /root/tunnelpannel-commercial-access.txt on A. Predictable old demo API key revoked; exact QA foreign-key canaries removed; test worker pool restored to default2. Original-group monitor enabled at60s; snapshot858.1s/28samples/6transitions, NOT a seven-day SLA result. Agent certificate30days; rotate/install before expiry. Current private backup on EACH host:/root/tp-commercial-acceptance/handoff-current.tar.gz plus checksum. Keep each installation encryption key separately.

No actual payment, public HTTPS domain, Iran/multi-country hardware pilot, many-customer load or long-term SLA was supplied/verified. TCP SOCKS connection sharing is implemented; single-stream bonding and full UDP/IP VPN are outside this accepted beta. Do not infer they work from the number of templates. User authorized all feasible two-node work; complete the verified handoff, do not restart historical Task3/Task5 checkpoints below or invent new scope. One read-only assistant already used for this request; no duplicate advice. Remind owner to rotate chat-supplied SSH passwords after handoff without printing them.

> **این فایل قرارداد همیشگی هر ایجنت/دستیاری است که روی این مخزن کار می‌کند.
> قبل از هر کار بخوان، بعد از هر تسک به آن برگرد و تسک بعدی را بدون مکث شروع کن.**
>
> **This file is the standing contract for every agent working on this repo.
> Read it before starting, return to it after every task, and start the next
> task immediately — never wait for permission.**

---

## ۱. قانون طلایی: توقف ممنوع / The Golden Rule: Never Stop

- **منتظر تأیید یا اجازه نمان.** تا وقتی کار باقی مانده، تسک بعدی را بلافاصله شروع کن.
  / **Never wait for approval.** As long as work remains, start the next task immediately.
- بعد از اتمام هر تسک، همین فایل را به‌روز کن و **خودت را یادآوری کن: «تسک بعدی؟»**
  / After each task, update this file and ask yourself: "next task?"
- اگر به خطا خوردی، همان‌جا فیکس کن و ادامه بده؛ گزارش «نیمه‌تمام» ممنوع است.
  / If you hit an error, fix it in place and continue; half-finished reports are forbidden.
- کار فقط زمانی تمام است که: کد نوشته شده + روی سرور واقعی تست شده + مستندات دوزبانه
  کامل است + همه‌چیز روی گیت‌هاب پوش شده باشد.
  / Work is done only when: code written + tested on the real server + bilingual
  docs complete + everything pushed to GitHub.

## ۲. نقش سرورها / Server Roles (locked by owner)

| Server | Role / نقش |
|---|---|
| `91.107.138.246` | **اصلی:** فقط موتور، پنل و اسکریپت. روی آن تانل دائمی نساز. / **Main:** engine, panel and scripts only — no permanent tunnels. |
| `45.141.148.59` | **تست:** همه ساخت/تست/نصب تانل‌ها اینجا انجام شود. / **Test:** build/test/install tunnels here. |
| سرورهای تست جدید که کاربر می‌دهد | همان نقش تست. / Same test role. |

- اگر روی سرور اصلی «فقط برای تست» چیزی لازم شد: بدون تداخل با سرویس‌های دیگر،
  پورت آزاد (از مدیر پورت پنل) و بعد از تست **پاک‌سازی کامل**.
  / If the main server is strictly needed for a test: no conflicts (use the panel's
  port manager), and **full cleanup** afterwards.
- اختیار کامل و همیشگی از طرف کاربر صادر شده است (ری‌استارت سرویس‌های خود پروژه آزاد است).
  / Full standing authorization was granted by the owner (restarting project services is allowed).

## ۳. دسترسی‌ها / Access map

- SSH: `scripts/sshrun.py` (45.141.148.59) و `scripts/sshrun2.py` (91.107.138.246)
- GitHub token: فایل `.ghtoken` (each machine keeps its own)
- Panel: `https://tun.softarg.ir:9443` — container `mtf-panel` on 91.107.138.246, port 9443 only

## ۴. قوانین مهندسی / Engineering rules

1. **بدون کرش:** اسکریپت‌های طولانی را در فایل ذخیره کن، با `nohup` روی سرور اجرا کن
   و با پولینگ کوتاه دنبال کن (نشست‌ها ممکن است قطع شوند).
   / Persist long scripts to files, run them on the server with `nohup`, poll briefly.
2. **پورت‌ها:** هرگز پورت ثابت hard-code نکن؛ از `mtf/portmgr.py` (اسکن تداخل + تخصیص
   خودکار v4/v6) استفاده کن. / Never hard-code ports; use `mtf/portmgr.py`.
3. **چندتوزیعه:** کد نصب باید apt/dnf/yum/zypper/pacman/apk را پشتیبانی کند —
   محدود به اوبونتو نباشد. / Install code must support all main distro families.
4. **دو پشته:** کانفیگ‌ها باید روی IPv4 و IPv6 کار کنند (bind دو-پشته، آدرس‌های v6
   داخل تونل). / Configs must work on IPv4 AND IPv6 (dual-stack binds + inner v6 addrs).
5. **مستندسازی دوزبانه:** هر ویژگی/دکمه جدید → README.md + README-fa.md با اسکرین‌شات.
   / Every new feature/button → both READMEs with a screenshot.
6. **UI:** آیکون SVG (نه ایموجی)، کنتراست AA، RTL/LTR، بدون وابستگی CDN.
   / UI: SVG icons (no emoji), AA contrast, RTL/LTR, zero CDN dependencies.

## ۵. چک‌لیست پایان هر نشست / End-of-session checklist

- [ ] همه تسک‌ها انجام شد؟ / All tasks done?
- [ ] تست E2E روی پنل زنده انجام شد؟ / E2E tested against the live panel?
- [ ] AGENT.md و worklog به‌روز شد؟ / AGENT.md and worklog updated?
- [ ] Commit + push به `main`؟ / Committed and pushed to `main`?
- [ ] گزارش نهایی فارسی به کاربر داده شد؟ / Final Persian report sent to the owner?
- [ ] ⚠️ یادآوری امنیتی: رمزهای افشاشده در چت را به کاربر گوشزد کن. / Security reminder sent.

## ۶. مرجع مهندسی / Engineering reference (release contract)

**Source of truth — canonical artifacts:**

- Deploy engine (77 persistent methods): `plan_executor/executor.py`
- MTF test registry (82 entries): `deploy/methods_registry.json` + `deploy/engine/mtf/`
- Failover FSM (tested): `tunnelguard/tfd/`
- Development state: `docs/development/` (CURRENT_STATE, BASELINE, TASK_LEDGER, CATALOG_INVENTORY)

**Verification policy:**

- A method is verified only by real data-plane evidence (receipt), never by
  "process started / port listening". Test verdicts live in `docs/TEST-REPORT.md`
  and per-run receipts in the panel DB.
- Statuses stay honest: PASS / PARTIAL / FAIL / BLOCKED — see `docs/development/BASELINE.md`.

**Production safety:**

- Never flush firewall state, never touch unowned interfaces/services, always go
  through the port manager (`mtf/portmgr.py`) for allocations.
- Disaster recovery export/restore:
  `scripts/export-production-state.sh` → `scripts/restore-production-state.sh`
  (encrypted, double-confirm; restore must be tested before calling DR "done").
- Credentials: rotate anything ever committed (see
  `docs/development/CURRENT_STATE.md` §Security + SECRET_HYGIENE.md).


## 2026-10-13 disposable-node validation

Historical RC2 baseline (superseded by RC3): 32 PASS / 23 PARTIAL / 27 FAIL in the isolated legacy lab, six real kernel methods and the WG-to-GRE drill. See docs/releases/v0.9.0-rc2/REAL_VALIDATION.md.


## 2026-10-14 real panel benchmark verification

Latest two-node NORMAL results: 82 PASS, derived from the full matrix (76 PASS/6 FAILED) and explicit corrected-profile reruns. Fresh software suites: 533 canonical + 100 TunnelGuard + 1 backend PASS. Real canonical node registration, pinned SSH, encrypted credentials and panel jobs are wired. See docs/releases/v0.9.0-rc3/REAL_BENCHMARK.md. Latest five selected DEEP profiles PASS (initial 4 PASS/1 FAILED retained; unchanged sing-box rerun PASS). Public pinned install on both nodes and full node-B lifecycle PASS. Python 3.11/3.12, Linux installer, security and shell CI PASS at e6a2c419; final delivery commit verification follows. Zero live ownership allocations; historical orphan receipt preserved. Native Hedioum rapid short-connection churn remains a documented diagnostic limitation; sustained TUN speed uses bidirectional iperf3. Supplied credentials never belong in tracked files.
