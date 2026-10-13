# Real two-node benchmark / بنچمارک واقعی دو سروری

The canonical panel now starts real deployments on two registered SSH nodes. Node credentials are encrypted with the installation secret; a pinned SHA256 SSH host key is mandatory. SUPER_ADMIN registers nodes, OPERATOR/SUPER_ADMIN start or cancel benchmarks, and all three roles can read results. Validation errors never echo credentials. Keep the installation secret with the encrypted database when backing up or restoring it.

پنل اکنون روش‌ها را روی دو سرور ثبت‌شده واقعاً نصب و آزمایش می‌کند. اطلاعات SSH با کلید نصب رمز می‌شود و اثر انگشت SHA256 سرور اجباری است. ثبت سرور با مدیر، اجرای آزمون با مدیر یا اپراتور، و مشاهده نتیجه با هر سه نقش مجاز است. خطای ورودی، رمز یا کلید خصوصی را برنمی‌گرداند. هنگام پشتیبان‌گیری یا بازیابی، کلید نصب و دیتابیس رمز‌شده را کنار هم حفظ کنید.

## Panel workflow / روند پنل

1. Open `/ranking` through the panel's SSH forward and enter an operator/admin API token. Tokens stay in memory and are cleared from the input after connection.
2. Register both nodes with their credentials and host-key fingerprints, then inspect them.
3. Select source, destination, methods and profile. Results appear as each method finishes. Cancellation still attempts owned-resource cleanup.
4. Use benchmark history to reopen receipts after reloading the page. Sort the final table and save a selection for failover planning.

در `/ranking` توکن را وارد کنید، دو سرور را با اثر انگشت ثبت و بررسی کنید و روش‌ها و پروفایل را انتخاب کنید. نتیجه هر روش هنگام پایان آن نمایش داده می‌شود. سوابق، رسیدها و تعداد نتایج پس از بازکردن دوباره صفحه قابل مشاهده‌اند. لغو آزمون نیز پاک‌سازی منابع متعلق به همان آزمون را انجام می‌دهد.

## What is measured / معیارهای واقعی

- QUICK checks deployment and actual traffic; it does not claim a sustained speed or restart test.
- NORMAL uses 30 latency probes, a 10-second transfer per direction for L3/TUN and an owned-service restart/recovery check.
- DEEP uses 100 latency probes and 60-second transfers with the same integrity and recovery gates.
- L3 methods use bidirectional inner-address ICMP and bidirectional TCP iperf3; scoped TUN profiles also use bidirectional TCP iperf3. Proxy/forward methods verify an independently generated server nonce and SHA256-checked HTTP blobs. UDP methods verify unique echoed payloads with a 64-datagram window.
- TUN probes use a disposable unprivileged account and a port-scoped mark. Tunnel daemons' outbound sockets are excluded, avoiding routing feedback loops. SSH management routes are checked before deployment, after deployment and after cleanup.
- CPU and RAM are explicitly whole-node samples. HTTP transaction timings include SSH command execution overhead; compare methods with the same probe basis. Receipts retain the measurement tool and transfer counts.
- Composite and full native HajSaman receipts include traffic failing when the actual carrier is stopped, followed by dependency-ordered restoration. A successful carrier alone is insufficient.

QUICK عبور واقعی ترافیک را بررسی می‌کند. NORMAL شامل ۳۰ نمونه تأخیر، انتقال ۱۰ ثانیه‌ای و آزمون بازیابی پس از ری‌استارت است؛ DEEP تعداد نمونه را به ۱۰۰ و زمان انتقال را به ۶۰ ثانیه افزایش می‌دهد. روش‌های لایه ۳ با ICMP و iperf3 در هر دو جهت، پراکسی‌ها با محتوای یکتا و بررسی SHA256، و UDP با محتوای تأییدشده آزمایش می‌شوند. مصرف منابع مربوط به کل سرور است. زمان تراکنش HTTP سربار اجرای فرمان SSH را نیز دارد؛ مقایسه روش‌های دارای معیار یکسان دقیق‌تر است.

## Ownership and implementation / مالکیت و پیاده‌سازی

Per-run service, interface, file, rule and temporary-account ownership is recorded before mutation. A partial configuration still has a cleanup journal. Existing interfaces/services are refused rather than removed. Cleanup failure prevents PASS and retains the unreleased ledger for recovery. No firewall flush is used. Paqet rules carry an exact per-run comment; its cleanup cannot remove an identical unowned rule.

Hedioum uses its real authenticated TLS pool and TUN support with private config mounts. Native HajSaman SIT/WG/FULL profiles build the appropriate SIT, WG-over-SIT and Xray-mark/policy/SNAT stages. FULL verifies SNAT against an owned remote namespace origin; this is a two-node full-stack test, not a claim about an untested three-server deployment.

مالکیت سرویس، رابط، فایل، قانون شبکه و حساب موقت پیش از تغییر ثبت می‌شود. منابع نامرتبط حذف نمی‌شوند. شکست پاک‌سازی نتیجه را ناموفق می‌کند و سابقه منابع آزاد نشده حفظ می‌شود. Hedioum از استخر TLS و TUN واقعی خود استفاده می‌کند. HajSaman بومی، مراحل SIT، WireGuard روی SIT و مسیر Xray/علامت‌گذاری/NAT را بر اساس پروفایل می‌سازد؛ این شواهد مربوط به دو سرور است.

## Verification state / وضعیت تأیید

Latest NORMAL results: **82 PASS / 0 incomplete / 0 failed**, derived from the complete matrix and the corrected-profile reruns. The first complete matrix was 76 PASS / 6 FAILED; those failures remain in the evidence and history. Final results require actual traffic, positive measured throughput, successful restart recovery and released cleanup.

نتیجهٔ آخرین NORMAL هر ۸۲ روش موفق است. اجرای نخست ۷۶ موفق و ۶ ناموفق بود؛ نتایج ناموفق حذف نشده‌اند و بازآزمایی‌ها جداگانه ثبت شده‌اند. سرعت مثبت، عبور داده، بازیابی و پاک‌سازی برای هر نتیجهٔ نهایی بررسی شده است.

Fresh software verification: **534 canonical + 100 TunnelGuard + 1 backend PASS**, no failures/skips. Canonical lint, shell syntax/ShellCheck and catalog checks passed.

Five selected DEEP profiles have latest **5 PASS**: WIREGUARD, GOST_SSH, WATERWALL_REVERSE, SINGBOX_TUN and native HEDIOUM_TUN. The initial DEEP job was 4 PASS / 1 FAILED (sing-box repeated HTTP probe); its failed receipt is preserved. An independent 100-probe reproduction and unchanged panel rerun passed. This intermittent failure remains visible; no assertion was relaxed.

Pinned public installation at `e6a2c419e3cccce613cb558ab1dfbb7b9733e43c` passed on both nodes, preserving configuration. Node B passed backup/mutate/restore, pinned upgrade, custom-port persistence, safe uninstall and fresh source reinstall. CI portable Python 3.11/3.12, installer integration, secrets/dependency checks and shell checks all passed at that source revision. Final delivery also pins and verifies the final documentation commit.

آخرین نتیجهٔ پنج روش منتخب DEEP موفق است. اجرای نخست چهار موفق و یک خطای بررسی HTTP در sing-box داشت؛ رسید ناموفق حذف نشد. بازتولید مستقل با ۱۰۰ بررسی و بازآزمایی بدون تغییر معیار موفق بودند؛ این رفتار متناوب همچنان در شواهد دیده می‌شود. نصب عمومی روی هر دو سرور و چرخهٔ نصب، بازیابی و حذف امن روی سرور دوم موفق بود.

Ownership audit: zero live allocations. Eleven historical VTI6 allocations were reconciled only after exact paths were absent and owned units inactive; the original failed receipt remains unchanged.


### Measurement limits / محدودیت معیارها

Sustained TUN throughput uses bidirectional iperf3. The repeated short-connection HTTP workload previously stressed native Hedioum's source-port/connection reuse and produced timeouts. That connection-churn result is retained as a known limitation; it is not relabeled as success. NORMAL/DEEP speed measures sustained transfer, while latency and recovery retain fresh remote-nonce checks.

سرعت پایدار TUN با iperf3 دوطرفه اندازه‌گیری می‌شود. آزمون اتصال‌های کوتاه و پیاپی در TUN بومی Hedioum timeout داشت؛ آن شواهد به‌عنوان محدودیت حفظ شده و موفق اعلام نشده است. سرعت پایدار، تأخیر و بازیابی معیارهای جدا هستند.

HTTP transfer blobs are a remote nonce plus zero-filled bytes, checked with SHA256. These are application payload rates and may benefit from compression; they are not a claim about raw line capacity. The two endpoints are nearby and do not verify arbitrary NAT, blocked networks or three-server multi-hop operation.

### Latest NORMAL table

| Method | Status | Mbps (measured) | Recovery s | Receipt job |
|---|---|---:|---:|---|
| AUTOSSH_REVERSE | PASS | 179.25 | 0.662 | f0debd5b |
| CHISEL_REVERSE_SOCKS5 | PASS | 348.62 | 0.145 | f0debd5b |
| CHISEL_REVERSE_TCP | PASS | 328.69 | 0.707 | f0debd5b |
| CHISEL_REVERSE_UDP | PASS | 100.21 | 0.152 | f0debd5b |
| CHISEL_SOCKS5 | PASS | 423.34 | 0.144 | f0debd5b |
| CHISEL_TCP | PASS | 430.76 | 0.145 | f0debd5b |
| CHISEL_UDP | PASS | 122.05 | 1.105 | f0debd5b |
| FRP_KCP | PASS | 51.15 | 10.278 | f0debd5b |
| FRP_QUIC | PASS | 293.43 | 1.201 | f0debd5b |
| FRP_STCP | PASS | 359.68 | 5.509 | f0debd5b |
| FRP_TCP | PASS | 393.69 | 5.377 | f0debd5b |
| FRP_UDP | PASS | 89.31 | 10.861 | f0debd5b |
| FRP_XTCP | PASS | 306.32 | 11.743 | f0debd5b |
| GOST_GRPC | PASS | 355.61 | 1.275 | f0debd5b |
| GOST_HTTP | PASS | 475.92 | 1.236 | f0debd5b |
| GOST_HTTP2 | PASS | 474.53 | 1.268 | f0debd5b |
| GOST_KCP_FORWARD | PASS | 444.72 | 1.215 | f0debd5b |
| GOST_QUIC | PASS | 254.05 | 1.236 | f0debd5b |
| GOST_REMOTE_TCP | PASS | 341.94 | 2.295 | f0debd5b |
| GOST_REMOTE_UDP | PASS | 83.25 | 10.905 | f0debd5b |
| GOST_SOCKS5 | PASS | 417.03 | 1.240 | f0debd5b |
| GOST_SOCKS5_KCP | PASS | 9.54 | 1.270 | f0debd5b |
| GOST_SSH | PASS | 424.75 | 1.257 | afc506d7 |
| GOST_TAP | PASS | 329.77 | 6.270 | f0debd5b |
| GOST_TCP_FORWARD | PASS | 557.53 | 1.210 | f0debd5b |
| GOST_TUN | PASS | 345.54 | 6.265 | f0debd5b |
| GOST_UDP_FORWARD | PASS | 12.20 | 10.831 | f0debd5b |
| GOST_WS | PASS | 277.53 | 1.219 | f0debd5b |
| GRE | PASS | 1845.83 | 6.267 | f0debd5b |
| GRETAP | PASS | 1889.74 | 6.269 | f0debd5b |
| GRETAP_OVER_GOST | PASS | 153.39 | 6.382 | f0debd5b |
| GRE_OVER_GOST | PASS | 161.15 | 6.343 | f0debd5b |
| GRE_OVER_SSH | PASS | 169.85 | 7.448 | f0debd5b |
| GRE_OVER_WIREGUARD | PASS | 572.31 | 6.575 | f0debd5b |
| HAJSAMAN_FULL | PASS | 180.45 | 0.688 | f0debd5b |
| HAJSAMAN_SIT | PASS | 1892.64 | 6.274 | f0debd5b |
| HAJSAMAN_WG | PASS | 466.07 | 6.590 | f0debd5b |
| HEDIOUM_POOL_SOCKS | PASS | 455.40 | 0.143 | f0debd5b |
| HEDIOUM_TUN | PASS | 598.71 | 0.277 | df45e5c5 |
| HYSTERIA2 | PASS | 163.16 | 0.145 | f0debd5b |
| IKEV2_IPSEC | PASS | 864.00 | 6.429 | afc506d7 |
| IP6GRE | PASS | 1808.64 | 6.293 | f0debd5b |
| IP6GRETAP | PASS | 1808.34 | 6.272 | f0debd5b |
| IPIP | PASS | 1907.43 | 6.242 | f0debd5b |
| L2TP_IPSEC | PASS | 800.75 | 12.345 | afc506d7 |
| OPENVPN | PASS | 249.33 | 6.232 | f0debd5b |
| PAQET_RAW_KCP | PASS | 64.40 | 0.203 | f0debd5b |
| PAQET_SOCKS5 | PASS | 39.94 | 0.258 | f0debd5b |
| RATHOLE_NOISE | PASS | 109.67 | 0.716 | f0debd5b |
| RATHOLE_TCP | PASS | 432.44 | 0.695 | f0debd5b |
| RATHOLE_TLS | PASS | 116.55 | 0.726 | f0debd5b |
| RATHOLE_UDP | PASS | 142.71 | 10.882 | f0debd5b |
| RATHOLE_WEBSOCKET | PASS | 115.38 | 0.748 | f0debd5b |
| SHADOWSOCKS | PASS | 475.32 | 0.173 | f0debd5b |
| SINGBOX_TUN | PASS | 701.00 | 0.293 | df45e5c5 |
| SIT_6IN4 | PASS | 1861.05 | 6.265 | f0debd5b |
| SIT_OVER_GOST | PASS | 164.32 | 6.247 | f0debd5b |
| SIT_OVER_SSH | PASS | 165.03 | 7.448 | f0debd5b |
| SSH_DYNAMIC_SOCKS | PASS | 451.29 | 0.709 | f0debd5b |
| SSH_LOCAL_FORWARD | PASS | 502.11 | 0.681 | f0debd5b |
| SSH_REMOTE_FORWARD | PASS | 185.02 | 0.695 | f0debd5b |
| SSH_TAP_L2 | PASS | 180.23 | 7.280 | f0debd5b |
| SSH_TUN_L3 | PASS | 187.26 | 7.256 | f0debd5b |
| TROJAN_TLS | PASS | 377.67 | 0.154 | f0debd5b |
| TUIC | PASS | 331.07 | 0.163 | f0debd5b |
| VLESS_GRPC | PASS | 426.61 | 0.186 | f0debd5b |
| VLESS_REALITY | PASS | 380.58 | 9.093 | f0debd5b |
| VLESS_TCP | PASS | 306.53 | 0.153 | f0debd5b |
| VLESS_VISION_REALITY | PASS | 408.33 | 9.092 | f0debd5b |
| VLESS_WS | PASS | 299.45 | 0.193 | f0debd5b |
| VLESS_XHTTP | PASS | 369.88 | 0.635 | f0debd5b |
| VLESS_XHTTP_REALITY | PASS | 413.52 | 9.125 | f0debd5b |
| VTI | PASS | 615.25 | 6.440 | afc506d7 |
| VTI6 | PASS | 710.48 | 6.468 | afc506d7 |
| VXLAN | PASS | 1867.36 | 6.284 | f0debd5b |
| WATERWALL_DIRECT | PASS | 392.96 | 0.155 | f0debd5b |
| WATERWALL_REVERSE | PASS | 361.82 | 0.160 | afc506d7 |
| WATERWALL_TLS_MUX | PASS | 412.22 | 0.153 | f0debd5b |
| WIREGUARD | PASS | 755.58 | 6.439 | f0debd5b |
| WSTUNNEL_SOCKS5 | PASS | 458.47 | 0.654 | f0debd5b |
| WSTUNNEL_TCP | PASS | 462.99 | 0.159 | f0debd5b |
| WSTUNNEL_UDP | PASS | 178.89 | 0.147 | f0debd5b |

The JSON report includes the original attempts, final rows, per-job methodology and sanitized receipts.

### Latest selected DEEP results

| Method | Status | Mbps | Recovery s | Receipt job |
|---|---|---:|---:|---|
| WIREGUARD | PASS | 747.14 | 20.952 | b21a24b4 |
| HEDIOUM_TUN | PASS | 465.16 | 0.299 | b21a24b4 |
| GOST_SSH | PASS | 422.98 | 1.248 | b21a24b4 |
| WATERWALL_REVERSE | PASS | 389.21 | 0.154 | b21a24b4 |
| SINGBOX_TUN | PASS | 671.11 | 0.281 | ad5f0e04 |

![Actual panel NORMAL rerun](../../shots/panel-real-benchmark.jpg)

Final access acceptance adds authenticated node listing for VIEWER/OPERATOR/SUPER_ADMIN. The missing-token regression was reproduced before the fix and passed afterward. Fresh complete software suites: 534 canonical + 100 TunnelGuard + 1 backend PASS.
