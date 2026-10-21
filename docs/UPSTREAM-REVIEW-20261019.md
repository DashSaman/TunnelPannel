# Targeted upstream review — 2026-10-19

Installed follow-up evidence: [English](COMMERCIAL-OWNER-VALIDATION.md) · [فارسی](COMMERCIAL-OWNER-VALIDATION-fa.md). Four WaterWall profiles passed both directions on commercial e85 (8 results); the later CI-approved97 guard fix passed new paired HajSaman SIT/WG acceptance (4 results) with existing workers preserved. The [Arange comparison](ARANGE-COMPARISON-20261019.md) records further proposed coverage; those upstream adapters are not newly installed.

This updates the three requested sources from the historical
[2026-10-15 inventory](MESH-SOURCES.md); it is not a fresh review of every other
repository. Current branches were read through the owner's GitHub connection.

| Source | Immutable main revision | Relevant result |
|---|---|---|
| T6 (private) | `5543bc0f25b26aac0314562fb9ef05f5c5eab8ec` | Newer stability/recovery, one-way-path verification, ownership and shared-SIT MTU behavior since the earlier review. No private source/diff is imported or published. |
| [GoldWaterTunnel](https://github.com/DashSaman/GoldWaterTunnel) | `5eb9edf1686fdf5ac2bafdaf5bbe8a23bf805a51` | CPU-aware checksum verification and staged/isolated instance update with rollback. These are standalone binary packaging protections, not evidence of a new transport speed gain. |
| [WaterWall-H](https://github.com/DashSaman/WaterWall-H) | `613bb32c93db40b09cb915070e5f7ff09ad3c81d` | Matches the panel's already pinned source. Keep the panel's accepted receive-order, bounded H2 queue and FIN/input-drain fixes. |

The panel's clean implementation now reads both current SIT interface MTUs and
caps WireGuard at the lower carrier ceiling minus IPv6/WireGuard overhead.
It does not change a shared carrier. Missing/malformed MTU inventory fails
closed; owned WireGuard configuration records the selected MTU for restart.
The normal owned-carrier ceiling remains1480/1400; lower shared carriers clamp
the child. This is a targeted adapter correction, not a claim that all T6
recovery features or Gold's standalone manager were transplanted into the panel.
Existing allocations already select free routing priority/table; no additional
unproven recovery daemon or arbitrary combination was added.

The existing WaterWall source-built cache separates immutable source/patch
identities. Replacing it with a different standalone Gold binary is not justified
by README performance claims. The existing four profiles/compositions and
historical failing receipts remain. Fresh paired receipts must be reported
separately after installing the new panel; earlier accepted measurements are in
[WaterWall validation](WATERWALL-GATEWAY-VALIDATION.md).

مرور فعلی فقط سه منبع درخواستی را پوشش می‌دهد. t6 بعد از مرور قبلی اصلاحاتی دارد،
اما سورس خصوصی آن کپی نشده است. کنترل MTU حامل مشترک به‌صورت مستقل پیاده شد.
تغییر Gold مربوط به نصب و به‌روزرسانی باینری است و ادعای سرعت README اندازه‌گیری ما
محسوب نمی‌شود. نسخهٔ upstream واتروال با pin موجود یکسان است. نتیجهٔ تست واقعی
نسخهٔ تازه باید جدا از شواهد تاریخی ثبت شود.
