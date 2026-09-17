/* ============================================================
   MTF Panel app — vanilla JS, zero dependencies.
   Bilingual fa/en (RTL/LTR), self-drawn SVG charts, live polling.
   ============================================================ */
"use strict";

/* ------------------------------------------------ i18n dictionary */
const I18N = {
  fa: {
    brandSub: "چندتونلی · فیلاور", navDash: "داشبورد", navTun: "تانل‌ها (۸۲)",
    navSt: "تانل‌های سرورها", navPorts: "پورت‌ها و تداخل", navProbe: "پروب سرورها",
    navReco: "پیشنهاد تونل", navInst: "استقرار روی سرور", navSet: "تنظیمات",
    noActive: "بدون تانل فعال",
    kpiActive: "تانل فعال", kpiVip: "VIP فیلاور", kpiUp: "آپ / کل", kpiMode: "حالت",
    chHost: "سلامت میزبان — CPU / RAM", chNet: "ترافیک شبکه (Bps)", chStates: "وضعیت ۸۲ متد",
    chHealth: "امتیاز سلامت", chTimeline: "رویدادهای زنده", chRtt: "تأخیر بهترین تانل‌ها (ms)",
    estab: "اتصال TCP", refresh: "به‌روزرسانی",
    tTitle: "۸۲ متد تونل", tSearch: "جست‌وجو…", tStar: "ستاره‌دار", tApply: "اعمال انتخاب‌شده‌ها",
    thId: "شناسه", thFam: "خانواده", thState: "وضعیت", thRtt: "RTT", thLoss: "لاس",
    thDetail: "جزئیات", thAct: "عملیات", thVerdict: "نتیجه", thWhen: "زمان", thEv: "شواهد",
    thSide: "سرور", thIface: "واحد/اینترفیس",
    tReceipts: "رسیدهای تست (آخرین)",
    stTitle: "تانل‌های روی سرورها — اسکن و نصب", stScan: "اسکن همه سرورها",
    stHint: "سرورهای SSH را اضافه کنید؛ پنل همه تانل‌های موجود (کرنلی، WireGuard، پروسس‌ها، سرویس‌ها، پورت‌ها) را شناسایی می‌کند. سپس از کاتالوگ پایین، متدها را تیک بزنید و بین دو سرور نصب کنید. پسوردها ذخیره نمی‌شوند.",
    stAdd: "+ افزودن سرور", stFound: "تانل‌های شناسایی‌شده", stCatalog: "کاتالوگ نصب ماندگار",
    stSideA: "سمت A (کلاینت)", stSideB: "سمت B (سرور)",
    stPairMode: "حالت جفتی (تانل واقعی دوطرفه)", stInstall: "نصب موارد تیک‌خورده",
    stBook: "تانل‌های نصب‌شده (کتاب)", scanning: "در حال اسکن", deploy: "در حال نصب",
    pTitle: "مدیریت پورت و تداخل", pScan: "اسکن پورت‌ها",
    pHint: "پنل پورت‌های اشغال TCP/UDP هر سرور + پروتکل‌های سطح IP (GRE/IPIP/SIT/ESP) را جمع می‌کند، پورت‌های سیستمی را همیشه رزرو می‌کند و برای هر تانل به‌صورت خودکار پورت آزادِ بدون تداخل (روی v4 و v6) انتخاب می‌کند.",
    pTcp: "TCP اشغال", pUdp: "UDP اشغال", pProto: "پروتکل‌های IP در استفاده",
    pListen: "پورت‌های شنیده‌شده هر سرور", pAddr: "آدرس:پورت", pProc: "پروسس",
    pAssign: "تخصیص خودکار پورت", pAssignBtn: "پورت آزاد تخصیص بده", pAlloc: "پورت‌ها",
    prTitle: "پروب SSH سرورها", prRun: "اجرای پروب", prAdd: "+ افزودن سرور",
    prHint: "آی‌پی، پورت SSH، نام کاربری و رمز هر سرور را بدهید؛ پنل معماری، ماژول‌های کرنل، دسترسی‌ها و کیفیت لینک را می‌سنجد و مبنای پیشنهاد تونل می‌شود.",
    prResult: "نتیجه پروب", prMatrix: "ماتریس قابلیت‌ها", thCap: "قابلیت",
    reTitle: "پیشنهاد هوشمند تونل", reRun: "محاسبه پیشنهاد", reEmpty: "ابتدا پروب را اجرا کنید…",
    inTitle: "استقرار/تست ۸۲ متد روی سرور واقعی (SSH)",
    inHint: "هدف نصب را بدهید؛ پنل همان هارنس تست را روی سرور واقعی اجرا و شواهد ثبت می‌کند. برای تانل ماندگار دوطرفه از تب «تانل‌های سرورها» استفاده کنید.",
    inAll: "همه متدهای تأییدشده (PASS+PARTIAL)", inStart: "شروع استقرار",
    sFailover: "فیلاور", sMode: "حالت", sAuto: "خودکار", sManual: "دستی", sSave: "ذخیره تنظیمات",
    sCred: "اعتبار ورود", sUser: "نام کاربری", sPass: "رمز جدید", sChange: "تغییر اعتبار",
    sWarn: "پس از تغییر، دفعه بعد با اعتبار جدید وارد شوید.",
    manualSwitch: "سوییچ دستی", removed: "حذف شد", confirmRemove: "این تانل حذف شود؟",
    saved: "ذخیره شد", ok: "موفق", err: "خطا", pass: "PASS", partial: "PARTIAL", fail: "FAIL",
    empty: "موردی نیست", scanDone: "اسکن کامل شد", deployDone: "نصب تمام شد",
    portAssigned: "پورت تخصیص یافت", health: "امتیاز", up: "آپ", degraded: "تقلیل‌یافته",
    stopped: "خاموش", error: "خطا", deploying: "در حال استقرار",
    kernel: "تانل کرنلی", wg: "وایرگارد", proc: "پروسس", svc: "سرویس", port: "پورت",
    ours: "مال پنل", press: "کلید برای انتخاب",
  },
  en: {
    brandSub: "Multi-Tunnel · Failover", navDash: "Dashboard", navTun: "Tunnels (82)",
    navSt: "Server Tunnels", navPorts: "Ports & Conflicts", navProbe: "Server Probe",
    navReco: "Recommend", navInst: "Remote Deploy", navSet: "Settings",
    noActive: "no active tunnel",
    kpiActive: "Active tunnel", kpiVip: "Failover VIP", kpiUp: "UP / total", kpiMode: "Mode",
    chHost: "Host health — CPU / RAM", chNet: "Network traffic (Bps)", chStates: "82 methods state",
    chHealth: "Health score", chTimeline: "Live events", chRtt: "Best tunnels latency (ms)",
    estab: "TCP established", refresh: "Refresh",
    tTitle: "82 tunnel methods", tSearch: "Search…", tStar: "Starred", tApply: "Apply selected",
    thId: "ID", thFam: "Family", thState: "State", thRtt: "RTT", thLoss: "Loss",
    thDetail: "Detail", thAct: "Action", thVerdict: "Verdict", thWhen: "Time", thEv: "Evidence",
    thSide: "Server", thIface: "Unit/Iface",
    tReceipts: "Test receipts (latest)",
    stTitle: "Server tunnels — scan & install", stScan: "Scan all servers",
    stHint: "Add SSH servers; the panel discovers every existing tunnel (kernel, WireGuard, processes, services, ports). Then tick methods in the catalog below and install them between two sides. Passwords are never stored.",
    stAdd: "+ Add server", stFound: "Discovered tunnels", stCatalog: "Persistent install catalog",
    stSideA: "Side A (client)", stSideB: "Side B (server)",
    stPairMode: "Pair mode (real two-sided tunnel)", stInstall: "Install ticked methods",
    stBook: "Installed tunnels (book)", scanning: "Scanning", deploy: "Installing",
    pTitle: "Port & conflict manager", pScan: "Scan ports",
    pHint: "The panel collects every TCP/UDP listener per server plus IP-level protocols (GRE/IPIP/SIT/ESP), always reserves system ports, and auto-picks a conflict-free port (v4 & v6) per tunnel.",
    pTcp: "TCP busy", pUdp: "UDP busy", pProto: "IP protocols in use",
    pListen: "Listeners per server", pAddr: "Address:port", pProc: "Process",
    pAssign: "Auto port assignment", pAssignBtn: "Assign free port", pAlloc: "Ports",
    prTitle: "SSH server probe", prRun: "Run probe", prAdd: "+ Add server",
    prHint: "Give IP, SSH port, user and password; the panel scores architecture, kernel modules, capabilities and link quality to feed the recommender.",
    prResult: "Probe result", prMatrix: "Capability matrix", thCap: "Capability",
    reTitle: "Smart tunnel recommendation", reRun: "Compute", reEmpty: "Run the probe first…",
    inTitle: "Deploy/test 82 methods on a real server (SSH)",
    inHint: "Give a target; the panel runs the same test harness on the real host and records evidence. For persistent two-sided tunnels use the Server Tunnels tab.",
    inAll: "All verified methods (PASS+PARTIAL)", inStart: "Start deploy",
    sFailover: "Failover", sMode: "Mode", sAuto: "Auto", sManual: "Manual", sSave: "Save settings",
    sCred: "Login credentials", sUser: "Username", sPass: "New password", sChange: "Update credentials",
    sWarn: "After changing, sign in with the new credentials next time.",
    manualSwitch: "Manual switch", removed: "removed", confirmRemove: "Remove this tunnel?",
    saved: "Saved", ok: "OK", err: "Error", pass: "PASS", partial: "PARTIAL", fail: "FAIL",
    empty: "Nothing here", scanDone: "Scan complete", deployDone: "Install finished",
    portAssigned: "Port assigned", health: "Score", up: "UP", degraded: "Degraded",
    stopped: "Stopped", error: "Error", deploying: "Deploying",
    kernel: "Kernel tunnel", wg: "WireGuard", proc: "Process", svc: "Service", port: "Port",
    ours: "panel's", press: "click to select",
  }
};

let LANG = localStorage.getItem("mtf-lang") || "fa";
const $ = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
const t = (k) => (I18N[LANG] && I18N[LANG][k]) || I18N.fa[k] || k;

function applyLang() {
  const fa = LANG === "fa";
  document.documentElement.lang = LANG;
  document.documentElement.dir = fa ? "rtl" : "ltr";
  $("#langLabel").textContent = fa ? "EN" : "FA";
  $$("[data-i18n]").forEach(el => { el.textContent = t(el.dataset.i18n); });
  $$("[data-i18n-ph]").forEach(el => { el.placeholder = t(el.dataset.i18nPh); });
}
$("#langBtn").onclick = () => { LANG = LANG === "fa" ? "en" : "fa";
  localStorage.setItem("mtf-lang", LANG); applyLang(); renderAll(); };

/* ------------------------------------------------ tiny helpers */
async function api(path, opt) {
  const r = await fetch(path, opt);
  if (r.status === 401) { location.href = "/login"; throw new Error("auth"); }
  if (!r.ok) throw new Error((await r.text().catch(() => "")).slice(0, 120) || r.status);
  return r.json();
}
function toast(msg, kind) {
  const el = document.createElement("div");
  el.className = "toast " + (kind || "");
  el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), 4200);
}
const fmtTime = ts => new Date(ts * 1000).toLocaleTimeString(LANG === "fa" ? "fa-IR" : "en-GB", { hour12: false });
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const fmtBps = v => v == null ? "—" :
  v >= 1e6 ? (v / 1e6).toFixed(1) + " MB/s" :
  v >= 1e3 ? (v / 1e3).toFixed(1) + " KB/s" : Math.round(v) + " B/s";

/* ------------------------------------------------ SVG chart engine
   Charts are hand-drawn SVG (no CDN): a11y per ui-ux-pro-max rules —
   direct value labels, focusable, never color-only.               */
const NS = "http://www.w3.org/2000/svg";
const el = (name, attrs, parent) => {
  const e = document.createElementNS(NS, name);
  for (const k in (attrs || {})) e.setAttribute(k, attrs[k]);
  if (parent) parent.appendChild(e);
  return e;
};

function chartLine(svg, series, opt = {}) {
  // series: [{data:[{y}], color, dash, label}]
  svg.textContent = "";
  const W = +svg.viewBox.baseVal.width, H = +svg.viewBox.baseVal.height;
  const padB = 16, padT = 8;
  const all = series.flatMap(s => s.data).filter(v => v != null);
  if (!all.length) {
    el("text", { x: W / 2, y: H / 2, "text-anchor": "middle", fill: "var(--text-low)", "font-size": 11 }, svg).textContent = t("empty");
    return;
  }
  const ymin = opt.zero === false ? Math.min(...all) : Math.min(0, ...all);
  const ymax = Math.max(...all, 1);
  const n = Math.max(...series.map(s => s.data.length), 2);
  const X = i => (i / (n - 1)) * W;
  const Y = v => padT + (1 - (v - ymin) / (ymax - ymin || 1)) * (H - padT - padB);
  // gridlines + y labels
  for (let g = 0; g <= 2; g++) {
    const v = ymin + (ymax - ymin) * (g / 2);
    el("line", { x1: 0, x2: W, y1: Y(v), y2: Y(v), stroke: "var(--border)", "stroke-dasharray": "3 5" }, svg);
    el("text", { x: 4, y: Y(v) - 3, fill: "var(--text-low)", "font-size": 9, "font-family": "monospace" }, svg)
      .textContent = opt.fmt ? opt.fmt(v) : Math.round(v);
  }
  series.forEach((s, si) => {
    const pts = s.data.map((v, i) => v == null ? null : [X(i), Y(v)]);
    const seg = pts.filter(Boolean);
    if (seg.length < 2) return;
    if (opt.fill && si === 0) {
      el("path", { d: `M${seg[0][0]},${H - padB} L` + seg.map(p => p.join(",")).join(" L ") + ` L${seg[seg.length - 1][0]},${H - padB} Z`, fill: s.color, opacity: .13 }, svg);
    }
    el("polyline", { points: seg.map(p => p.join(",")).join(" "), fill: "none", stroke: s.color,
      "stroke-width": 2, "stroke-dasharray": s.dash || "", "stroke-linejoin": "round", "stroke-linecap": "round" }, svg);
    // last point marker + direct label (a11y: value not color-only)
    const last = seg[seg.length - 1];
    el("circle", { cx: last[0], cy: last[1], r: 3, fill: s.color }, svg);
    el("text", { x: Math.min(last[0], W - 40), y: Math.max(last[1] - 6, 10), fill: s.color, "font-size": 10, "font-family": "monospace" }, svg)
      .textContent = (s.label ? s.label + " " : "") + (opt.fmt ? opt.fmt(s.data.filter(Boolean).at(-1)) : Math.round(s.data.filter(Boolean).at(-1)));
  });
}

function chartBars(svg, rows, opt = {}) {
  // rows: [{label, value, color}] horizontal bars with direct labels
  svg.textContent = "";
  const W = +svg.viewBox.baseVal.width, H = +svg.viewBox.baseVal.height;
  if (!rows.length) { el("text", { x: W / 2, y: H / 2, "text-anchor": "middle", fill: "var(--text-low)", "font-size": 11 }, svg).textContent = t("empty"); return; }
  const max = Math.max(...rows.map(r => r.value), 1);
  const bh = Math.min(26, (H - 10) / rows.length - 6);
  const labW = opt.labW || 130;
  rows.forEach((r, i) => {
    const y = 8 + i * ((H - 10) / rows.length);
    el("text", { x: 0, y: y + bh * .72, fill: "var(--text-mid)", "font-size": 10.5 }, svg).textContent = r.label.slice(0, 16);
    const x0 = labW, w = Math.max(2, (r.value / max) * (W - labW - 60));
    el("rect", { x: x0, y, width: w, height: bh, rx: 4, fill: r.color || "var(--accent)", opacity: .85 }, svg);
    el("text", { x: x0 + w + 6, y: y + bh * .72, fill: "var(--text-hi)", "font-size": 10.5, "font-family": "monospace" }, svg).textContent = r.value;
  });
}

function donut(svg, items) {
  // items: [{label, value, color}]
  svg.textContent = "";
  const total = items.reduce((a, b) => a + b.value, 0) || 1;
  const cx = 100, cy = 100, r = 74, sw = 26;
  let ang = -Math.PI / 2;
  items.forEach(it => {
    if (!it.value) return;
    const a2 = ang + (it.value / total) * Math.PI * 2;
    const large = (a2 - ang) > Math.PI ? 1 : 0;
    const x1 = cx + r * Math.cos(ang), y1 = cy + r * Math.sin(ang);
    const x2 = cx + r * Math.cos(a2 - 0.001), y2 = cy + r * Math.sin(a2 - 0.001);
    el("path", { d: `M${x1},${y1} A${r},${r} 0 ${large} 1 ${x2},${y2}`, fill: "none",
      stroke: it.color, "stroke-width": sw, "stroke-linecap": "butt" }, svg);
    ang = a2;
  });
  el("circle", { cx, cy, r: r - sw / 2 - 4, fill: "none", stroke: "var(--border)", "stroke-width": 1 }, svg);
  el("text", { x: cx, y: cy - 2, "text-anchor": "middle", fill: "var(--text-hi)", "font-size": 26, "font-family": "monospace" }, svg).textContent = total;
  el("text", { x: cx, y: cy + 18, "text-anchor": "middle", fill: "var(--text-low)", "font-size": 10 }, svg).textContent = "methods";
}

function gauge(svg, score) {
  svg.textContent = "";
  const cx = 110, cy = 108, r = 84;
  const a0 = Math.PI, a1 = 0;
  const a = a0 + (a1 - a0) * (score / 100);
  const pt = a => [cx + r * Math.cos(a), cy - r * Math.sin(a)];
  el("path", { d: `M${pt(a0)[0]},${pt(a0)[1]} A${r},${r} 0 0 1 ${pt(a1)[0]},${pt(a1)[1]}`, fill: "none", stroke: "var(--p-navy-800)", "stroke-width": 16, "stroke-linecap": "round" }, svg);
  const col = score >= 80 ? "var(--ok)" : score >= 50 ? "var(--warn)" : "var(--bad)";
  const [ex, ey] = pt(a);
  el("path", { d: `M${pt(a0)[0]},${pt(a0)[1]} A${r},${r} 0 ${score > 50 ? 1 : 0} 1 ${ex},${ey}`, fill: "none", stroke: col, "stroke-width": 16, "stroke-linecap": "round" }, svg);
  el("text", { x: cx, y: cy - 8, "text-anchor": "middle", fill: "var(--text-hi)", "font-size": 34, "font-family": "monospace", "font-weight": 700 }, svg).textContent = score;
  el("text", { x: cx, y: cy + 14, "text-anchor": "middle", fill: "var(--text-low)", "font-size": 11 }, svg).textContent = "/ 100 " + t("health");
}

/* ------------------------------------------------ tabs */
$$(".rail-btn").forEach(b => b.onclick = () => {
  $$(".rail-btn").forEach(x => x.classList.toggle("on", x === b));
  $$(".tabpane").forEach(p => { p.hidden = p.id !== "tab-" + b.dataset.tab; });
  renderTab(b.dataset.tab);
});
function renderTab(name) {
  ({ dash: refreshDash, tun: refreshTun, st: refreshST, ports: refreshPorts,
     probe: refreshProbe, reco: refreshReco, inst: refreshInst, set: refreshSet }[name] || (() => {}))();
}

/* ------------------------------------------------ dashboard */
let lastStatus = null;
async function refreshDash() {
  try {
    const [st, mx] = await Promise.all([api("/api/status"), api("/api/metrics")]);
    lastStatus = st;
    const c = st.counters;
    $("#kpiActive").textContent = st.active || "—";
    $("#kpiVip").textContent = st.vip;
    $("#kpiUp").textContent = `${(c.UP || 0) + (c.DEGRADED || 0)} / 82`;
    $("#kpiMode").textContent = st.mode === "auto" ? t("sAuto") : t("sManual");
    const mb = $("#modeBadge");
    mb.textContent = st.mode.toUpperCase();
    mb.className = "badge " + (st.mode === "auto" ? "badge-auto" : "badge-manual");
    const ab = $("#activeBadge");
    if (st.active) { ab.textContent = st.active; ab.className = "badge badge-active"; }
    else { ab.textContent = t("noActive"); ab.className = "badge badge-off"; }
    // host info
    $("#hostInfo").textContent = `kernel ${mx.info.kernel} · up ${Math.round(mx.info.uptime_s / 3600)}h`;
    $("#kpiCpu").textContent = mx.now.cpu == null ? "—" : mx.now.cpu + "%";
    $("#kpiRam").textContent = mx.now.ram_pct == null ? "—" : mx.now.ram_pct + "%";
    $("#kpiEstab").textContent = mx.now.estab ?? "—";
    $("#kpiRx").textContent = fmtBps(mx.now.rx_bps);
    $("#kpiTx").textContent = fmtBps(mx.now.tx_bps);
    chartLine($("#chartCpu"), [
      { data: mx.hist.cpu, color: "var(--accent)", label: "CPU" },
      { data: mx.hist.ram, color: "var(--vio)", label: "RAM", dash: "6 4" },
    ], { fill: true, fmt: v => Math.round(v) + "%" });
    chartLine($("#chartNet"), [
      { data: mx.hist.rx, color: "var(--accent)", label: "RX" },
      { data: mx.hist.tx, color: "var(--warn)", label: "TX", dash: "6 4" },
    ], { fill: true, fmt: fmtBps });
    // donut
    const items = [
      { label: t("up"), value: c.UP || 0, color: "var(--ok)" },
      { label: t("degraded"), value: c.DEGRADED || 0, color: "var(--warn)" },
      { label: t("deploying"), value: c.DEPLOYING || 0, color: "var(--info)" },
      { label: t("error"), value: c.ERROR || 0, color: "var(--bad)" },
      { label: t("stopped"), value: (c.STOPPED || 0) + (c.DOWN || 0), color: "var(--p-navy-700)" },
    ];
    donut($("#donutStates"), items);
    $("#donutLegend").innerHTML = items.map(i =>
      `<tr><td><i style="background:${i.color}"></i>${i.label}</td><td>${i.value}</td></tr>`).join("");
    // health gauge: share of UP/DEGRADED with traffic + host sanity
    const active = (c.UP || 0) + (c.DEGRADED || 0);
    const score = Math.round(Math.min(100,
      (active / 10) * 60 + (mx.now.cpu != null && mx.now.cpu < 85 ? 20 : 8) +
      ((c.ERROR || 0) === 0 ? 20 : 10)));
    gauge($("#gaugeHealth"), score);
    $("#gaugeNote").textContent = `${active} tunnel(s) verified · host ${mx.now.cpu ?? "?"}% CPU`;
    // timeline
    $("#timeline").innerHTML = st.events.map(e =>
      `<li><span class="lv lv-${esc(e.level)}"></span><time>${fmtTime(e.ts)}</time><span class="ev"><b>${esc(e.src)}</b> ${esc(e.msg)}</span></li>`).join("")
      || `<li>${t("empty")}</li>`;
    // RTT bar chart of best probed methods
    try {
      const mm = await api("/api/methods");
      const best = mm.methods.filter(m => m.rtt_ms != null).sort((a, b) => a.rtt_ms - b.rtt_ms).slice(0, 8);
      chartBars($("#chartRtt"), best.map(m => ({ label: m.id, value: Math.round(m.rtt_ms), color: "var(--accent)" })));
    } catch (_) {}
  } catch (e) { console.warn(e); }
}
$("#evBtn").onclick = refreshDash;

/* ------------------------------------------------ tunnels tab */
let METHODS = [], famFilter = "*", sel = new Set();
async function refreshTun() {
  try {
    const d = await api("/api/methods");
    METHODS = d.methods;
    const fams = [...new Set(METHODS.map(m => m.set))];
    const chips = $("#famChips");
    if (!chips.children.length) {
      chips.innerHTML = `<button class="chip on" data-f="*">ALL</button>` +
        fams.map(f => `<button class="chip" data-f="${esc(f)}">${esc(f.replace("_METHODS", ""))}</button>`).join("");
      $$(".chip", chips).forEach(c => c.onclick = () => {
        famFilter = c.dataset.f;
        $$(".chip", chips).forEach(x => x.classList.toggle("on", x === c));
        drawMethods();
      });
    }
    drawMethods();
    try {
      const rc = await api("/api/receipts");
      $("#receiptTbl tbody").innerHTML = (rc.receipts || []).slice(0, 40).map(r =>
        `<tr><td class="mid">${esc(r.mid)}</td><td>${verdictChip(r.verdict)}</td>
         <td class="mid">${r.ts ? fmtTime(r.ts) : ""}</td>
         <td class="mid" style="max-width:380px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(JSON.stringify(r.evidence)).slice(0, 160)}</td></tr>`).join("")
        || `<tr><td colspan="4" class="muted">${t("empty")}</td></tr>`;
    } catch (_) {}
  } catch (e) { console.warn(e); }
}
function verdictChip(v) {
  const cls = v === "PASS" ? "st-up" : v === "PARTIAL" ? "st-partial" : "st-err";
  return `<span class="st ${cls}"><i></i>${esc(v)}</span>`;
}
function stateChip(s) {
  const map = { UP: "st-up", DEGRADED: "st-partial", ERROR: "st-err", DEPLOYING: "st-dep", STOPPED: "st-off", DOWN: "st-err" };
  return `<span class="st ${map[s] || "st-off"}"><i></i>${esc(s)}</span>`;
}
function drawMethods() {
  const q = ($("#qSearch").value || "").toLowerCase();
  const rows = METHODS.filter(m =>
    (famFilter === "*" || m.set === famFilter) &&
    (!$("#starOnly").checked || m.star) &&
    (!q || m.id.toLowerCase().includes(q) || m.name_en.toLowerCase().includes(q) || m.name_fa.includes(q)));
  $("#methRows").innerHTML = rows.map(m => `
    <tr>
      <td><input type="checkbox" data-mid="${esc(m.id)}" ${sel.has(m.id) ? "checked" : ""} aria-label="select ${esc(m.id)}"></td>
      <td class="mid">${esc(m.id)} ${m.star ? '<span class="tag tag-star">★</span>' : ""}</td>
      <td><span class="tag">${esc(m.set.replace("_METHODS", ""))}</span></td>
      <td>${stateChip(m.state)}</td>
      <td class="mid">${m.rtt_ms != null ? m.rtt_ms + " ms" : "—"}</td>
      <td class="mid">${m.loss_pct != null ? m.loss_pct + "%" : "—"}</td>
      <td class="muted" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(m.detail)}">${esc(m.detail || "—")}</td>
      <td><button class="btn btn-ghost btn-sm" data-sw="${esc(m.id)}">${t("manualSwitch")}</button></td>
    </tr>`).join("") || `<tr><td colspan="8" class="muted">${t("empty")}</td></tr>`;
  $("#selCount").textContent = t("tApply") + ": " + sel.size;
  $$('#methRows input[data-mid]').forEach(cb => cb.onchange = () => {
    cb.checked ? sel.add(cb.dataset.mid) : sel.delete(cb.dataset.mid);
    $("#selCount").textContent = t("tApply") + ": " + sel.size;
  });
  $$('#methRows button[data-sw]').forEach(b => b.onclick = async () => {
    try { await api("/api/manual/" + b.dataset.sw, { method: "POST" }); toast(t("ok") + ": " + b.dataset.sw, "ok"); refreshDash(); }
    catch (e) { toast(t("err") + " " + e.message, "bad"); }
  });
}
$("#qSearch").oninput = drawMethods;
$("#starOnly").onchange = drawMethods;
$("#applyBtn").onclick = async () => {
  if (!sel.size) return toast(t("err") + ": 0", "bad");
  try {
    await api("/api/methods/select", { method: "POST", body: JSON.stringify({ ids: [...sel] }) });
    await api("/api/methods/apply", { method: "POST" });
    toast(t("ok") + " — " + sel.size, "ok");
  } catch (e) { toast(t("err") + " " + e.message, "bad"); }
};

/* ------------------------------------------------ server tunnels tab */
function srvRowHTML(prefix, s = {}) {
  return `<div class="srv-row" data-p="${prefix}">
    <input class="input" data-k="host" placeholder="host / IP" value="${esc(s.host || "")}">
    <input class="input" data-k="ssh_port" placeholder="22" value="${esc(s.ssh_port || 22)}" inputmode="numeric">
    <input class="input" data-k="username" placeholder="root" value="${esc(s.username || "root")}">
    <input class="input" data-k="password" type="password" placeholder="password">
    <button class="btn btn-ghost btn-sm" data-del aria-label="remove row">✕</button>
  </div>`;
}
function collectSrv(prefix) {
  return $$(`.srv-row[data-p="${prefix}"]`).map(r => ({
    host: $('[data-k=host]', r).value.trim(),
    ssh_port: +$('[data-k=ssh_port]', r).value || 22,
    username: $('[data-k=username]', r).value.trim() || "root",
    password: $('[data-k=password]', r).value,
  })).filter(x => x.host);
}
$("#stAddSrv").onclick = () => $("#stSrvRows").insertAdjacentHTML("beforeend", srvRowHTML("st"));
$("#stSrvRows").addEventListener("click", e => { if (e.target.closest("[data-del]")) e.target.closest(".srv-row").remove(); });
$("#stSrvRows").innerHTML = srvRowHTML("st") + srvRowHTML("st");

const ST_CATALOG_DEFAULTS = ["WIREGUARD", "GRE", "GRETAP", "SIT_6IN4", "IPIP", "VXLAN", "VTI", "VTI6",
  "IP6GRE", "IP6GRETAP", "OPENVPN", "HAJSAMAN_SIT", "HAJSAMAN_WG", "HAJSAMAN_FULL",
  "GOST_SOCKS5", "GOST_HTTP", "GOST_WS", "GOST_GRPC", "CHISEL_SOCKS5", "CHISEL_TCP",
  "WSTUNNEL_SOCKS5", "WSTUNNEL_TCP", "RATHOLE_TCP", "RATHOLE_TLS",
  "FRP_TCP", "FRP_KCP", "FRP_QUIC", "VLESS_TCP", "VLESS_WS", "VLESS_GRPC", "VLESS_XHTTP",
  "VLESS_REALITY", "VLESS_VISION_REALITY", "VLESS_XHTTP_REALITY",
  "HYSTERIA2", "TUIC", "TROJAN_TLS", "SHADOWSOCKS",
  "SSH_LOCAL_FORWARD", "SSH_DYNAMIC_SOCKS", "SSH_REMOTE_FORWARD"];
let stSel = new Set(["WIREGUARD"]);
async function refreshST() {
  try {
    const sc = await api("/api/st/scan");
    $("#stScanState").hidden = !sc.running;
    if (sc.running) $($("#stScanState").children[1]).textContent = `${t("scanning")} ${sc.progress} ${sc.phase}`;
    drawDiscovered(sc.results || {});
    const sides = Object.keys(sc.results || {});
    fillSideSel($("#stSideA"), sides);
    fillSideSel($("#stSideB"), sides);
    const bk = await api("/api/st/book");
    $("#stJob").hidden = !bk.job.running;
    if (bk.job.running) $("#stJobTxt").textContent = `${t("deploy")} ${bk.job.done}/${bk.job.total} ${bk.job.current || ""}`;
    drawCatalog(bk.persist || ST_CATALOG_DEFAULTS);
    drawBook(bk.book || {});
  } catch (e) { console.warn(e); }
}
function fillSideSel(selEl, sides) {
  const cur = selEl.value;
  const local = `<option value="local">panel-local</option>`;
  selEl.innerHTML = local + sides.filter(s => s !== "panel-local").map(s => `<option>${esc(s)}</option>`).join("");
  if ([...selEl.options].some(o => o.value === cur || o.text === cur)) selEl.value = cur;
}
function drawDiscovered(results) {
  const box = $("#stDiscovered");
  const ids = Object.keys(results);
  $("#stFoundInfo").textContent = ids.length ? `${ids.length} side(s)` : "";
  if (!ids.length) { box.innerHTML = `<p class="muted">${t("empty")}</p>`; return; }
  box.innerHTML = ids.map(sid => {
    const r = results[sid];
    if (!r.ok) return `<div class="disc"><h4>⚠ ${esc(sid)}</h4><div class="kv">${esc(r.err || "scan failed")}</div></div>`;
    const badge = (txt, ours) => `<span class="tag ${ours ? "tag-ours" : ""}">${esc(txt)}</span>`;
    const k = (r.kernel || []).map(x => `<div class="kv">${badge(x.kind + " · " + x.iface + " · " + x.state, x.ours)}</div>`).join("");
    const w = (r.wireguard || []).map(x => `<div class="kv">${badge("WG · " + x.iface + " · " + (x.peers || 0) + " peers", true)}</div>`).join("");
    const p = (r.processes || []).map(x => `<div class="kv">${badge(x.tool, x.ours)} <b>${esc(x.uptime)}</b> <span title="${esc(x.cmd)}">${esc(x.cmd.slice(0, 90))}</span></div>`).join("");
    const s = (r.services || []).map(x => `<div class="kv">${badge(x.unit, x.ours)} ${esc(x.active)}</div>`).join("");
    const l = (r.ports || []).slice(0, 12).map(x => `<div class="kv">${badge(x.proto + " " + x.local, false)}</div>`).join("");
    const sec = (title, body) => body ? `<div style="margin-top:6px"><b class="muted" style="font-size:11px">${title}</b>${body}</div>` : "";
    return `<div class="disc">
      <h4>${esc(r.name || sid)} ${r.os ? `<span class="tag">${esc(r.os)}</span>` : ""}</h4>
      ${sec(t("kernel"), k)}${sec(t("wg"), w)}${sec(t("proc"), p)}${sec(t("svc"), s)}${sec(t("port"), l)}
    </div>`;
  }).join("");
}
function drawCatalog(persistList) {
  $("#stCatCount").textContent = `${persistList.length} profile(s)`;
  $("#stCatalog").innerHTML = persistList.map(m => `
    <tr><td style="width:36px"><input type="checkbox" data-cat="${esc(m)}" ${stSel.has(m) ? "checked" : ""} aria-label="install ${esc(m)}"></td>
    <td class="mid">${esc(m)}</td></tr>`).join("");
  $$('#stCatalog input[data-cat]').forEach(cb => cb.onchange = () => {
    cb.checked ? stSel.add(cb.dataset.cat) : stSel.delete(cb.dataset.cat);
  });
}
function drawBook(book) {
  const rows = [];
  for (const [sid, entry] of Object.entries(book)) {
    for (const [mid, rec] of Object.entries(entry.methods || {})) {
      rows.push(`<tr><td class="mid">${esc(sid)}</td><td class="mid">${esc(mid)}</td>
        <td>${verdictChip(rec.verdict)}</td><td class="mid">${esc(rec.unit || rec.iface || "")}</td>
        <td><button class="btn btn-danger btn-sm" data-rm="${esc(mid)}" data-side="${esc(sid)}">${t("removed")}</button></td></tr>`);
    }
  }
  $("#stBookRows").innerHTML = rows.join("") || `<tr><td colspan="5" class="muted">${t("empty")}</td></tr>`;
  $$('#stBookRows button[data-rm]').forEach(b => b.onclick = async () => {
    if (!confirm(t("confirmRemove"))) return;
    const sc = await api("/api/st/scan").catch(() => ({ results: {} }));
    const side = (sc.results || {})[b.dataset.side] || {};
    try {
      const r = await api("/api/st/remove", { method: "POST", body: JSON.stringify({
        mid: b.dataset.rm, side: { host: side.id !== "panel-local" ? side.id : "", ssh_port: 22,
        username: "root", password: "" } }) });
      toast((r.ok ? t("ok") : t("err")) + " " + b.dataset.rm, r.ok ? "ok" : "bad");
      refreshST();
    } catch (e) { toast(t("err") + " " + e.message, "bad"); }
  });
}
$("#stScanBtn").onclick = async () => {
  try {
    await api("/api/st/scan", { method: "POST", body: JSON.stringify({ servers: collectSrv("st") }) });
    toast(t("scanning") + "…");
    pollST();
  } catch (e) { toast(t("err") + " " + e.message, "bad"); }
};
async function pollST() {
  for (let i = 0; i < 120; i++) {
    await new Promise(r => setTimeout(r, 2000));
    const sc = await api("/api/st/scan").catch(() => null);
    if (!sc) continue;
    $("#stScanState").hidden = !sc.running;
    if (sc.running) $($("#stScanState").children[1]).textContent = `${t("scanning")} ${sc.progress} ${sc.phase}`;
    if (!sc.running) { toast(t("scanDone"), "ok"); refreshST(); return; }
  }
}
$("#stDeployBtn").onclick = async () => {
  if (!stSel.size) return toast(t("err") + ": 0", "bad");
  const sides = [];
  const a = $("#stSideA").value, b = $("#stSideB").value;
  const mk = (v) => v === "local" ? { local: true }
    : (() => { const f = collectSrv("st").find(s => s.host === v); return f ? { host: f.host, ssh_port: f.ssh_port, username: f.username, password: f.password } : null; })();
  const A = mk(a), B = mk(b);
  if (A) sides.push(A); if (B) sides.push(B);
  if (!sides.length) sides.push({ local: true });
  try {
    await api("/api/st/deploy", { method: "POST", body: JSON.stringify({ methods: [...stSel], sides, pair: $("#stPair").checked && sides.length >= 2 }) });
    toast(t("deploy") + "…");
    pollSTJob();
  } catch (e) { toast(t("err") + " " + e.message, "bad"); }
};
async function pollSTJob() {
  for (let i = 0; i < 300; i++) {
    await new Promise(r => setTimeout(r, 2000));
    const bk = await api("/api/st/book").catch(() => null);
    if (!bk) continue;
    $("#stJob").hidden = !bk.job.running;
    $("#stJobTxt").textContent = `${t("deploy")} ${bk.job.done}/${bk.job.total} ${bk.job.current || ""}`;
    $("#stJobLog").hidden = false;
    $("#stJobLog").textContent = (bk.job.logs || []).join("\n");
    if (!bk.job.running) { toast(t("deployDone"), "ok"); refreshST(); return; }
  }
}

/* ------------------------------------------------ ports tab */
async function refreshPorts() {
  try {
    const rep = await api("/api/ports/report");
    const sides = rep.sides || {};
    let tcp = 0, udp = 0;
    const rows = (rep.rows || []).map(r => {
      if (r.proto === "TCP") tcp++; else if (r.proto === "UDP") udp++;
      return `<tr><td class="mid">${esc(r.side)}</td><td>${r.proto}</td><td class="mid">${esc(r.port)}</td><td class="muted">—</td></tr>`;
    }).join("");
    $("#pTcp").textContent = tcp; $("#pUdp").textContent = udp;
    $("#pListenRows").innerHTML = rows || `<tr><td colspan="4" class="muted">${t("empty")}</td></tr>`;
    const pr = await api("/api/ports/protos");
    const protoTxt = Object.entries(pr.sides || {}).map(([s, ps]) => `${s}: ${ps.join(", ") || "—"}`).join(" · ");
    $("#pProto").textContent = protoTxt || "—";
    const al = await api("/api/ports/allocs");
    $("#pAllocRows").innerHTML = Object.entries(al.allocs || {}).map(([mid, a]) => `
      <tr><td class="mid">${esc(mid)}</td><td class="mid">${Object.entries(a.ports || {}).map(([k, v]) => `${k}=<b>${v}</b>`).join(" · ")}</td>
      <td class="mid">${fmtTime(a.ts)}</td>
      <td><button class="btn btn-ghost btn-sm" data-rel="${esc(mid)}">✕</button></td></tr>`).join("")
      || `<tr><td colspan="4" class="muted">${t("empty")}</td></tr>`;
    $$('#pAllocRows button[data-rel]').forEach(b => b.onclick = async () => {
      await api("/api/ports/release", { method: "POST", body: JSON.stringify({ mid: b.dataset.rel }) });
      refreshPorts();
    });
    $("#pRanges").textContent = `ranges: TCP 21000-25999 · UDP 26000-29999 · ${al.never.length} system ports always reserved`;
    // method select for assignment
    const msel = $("#pAssignMid");
    if (!msel.options.length) {
      const d = await api("/api/methods");
      msel.innerHTML = d.methods.map(m => `<option>${esc(m.id)}</option>`).join("");
    }
  } catch (e) { console.warn(e); }
}
$("#pScanBtn").onclick = async () => {
  try {
    await api("/api/ports/scan", { method: "POST", body: JSON.stringify({ servers: collectSrv("st") }) });
    $("#pState").textContent = t("scanning") + "…";
    setTimeout(async () => {
      $("#pState").textContent = "";
      toast(t("scanDone"), "ok");
      refreshPorts();
    }, 6000);
  } catch (e) { toast(t("err") + " " + e.message, "bad"); }
};
$("#pAssignBtn").onclick = async () => {
  try {
    const r = await api("/api/ports/assign", { method: "POST", body: JSON.stringify({
      mid: $("#pAssignMid").value, proto: $("#pAssignProto").value }) });
    toast(`${t("portAssigned")}: ${JSON.stringify(r.ports)}`, "ok");
    refreshPorts();
  } catch (e) { toast(t("err") + " " + e.message, "bad"); }
};

/* ------------------------------------------------ probe tab */
$("#addSrv").onclick = () => $("#srvRows").insertAdjacentHTML("beforeend", srvRowHTML("pr"));
$("#srvRows").addEventListener("click", e => { if (e.target.closest("[data-del]")) e.target.closest(".srv-row").remove(); });
$("#srvRows").innerHTML = srvRowHTML("pr") + srvRowHTML("pr");
$("#probeBtn").onclick = async () => {
  try {
    await api("/api/probe", { method: "POST", body: JSON.stringify({ servers: collectSrv("pr") }) });
    toast(t("scanning") + "…");
    for (let i = 0; i < 200; i++) {
      await new Promise(r => setTimeout(r, 2000));
      const p = await api("/api/probe");
      $("#probeState").textContent = p.running ? (p.progress || "") : "";
      if (!p.running && p.result) { renderProbe(p.result); toast(t("scanDone"), "ok"); return; }
    }
  } catch (e) { toast(t("err") + " " + e.message, "bad"); }
};
function renderProbe(res) {
  const out = $("#probeOut");
  out.innerHTML = (res.servers || []).map(s => `
    <div class="disc"><h4>${esc(s.host)} ${s.ok ? '<span class="st st-up"><i></i>OK</span>' : '<span class="st st-err"><i></i>FAIL</span>'}</h4>
    <div class="kv">${s.ok ? `os <b>${esc(s.os || "?")}</b> · kernel <b>${esc(s.kernel || "?")}</b> · ssh <b>${esc(s.ssh_ms ?? "?")}ms</b> · ip <b>${esc((s.ips || []).join(", ") || "—")}</b>${s.uptime ? ` · ${esc(s.uptime)}` : ""}` : esc(s.err || "")}</div></div>`).join("")
    || `<p class="muted">${t("empty")}</p>`;
  const mx = res.matrix || [];
  $("#mxRows").innerHTML = mx.map(p => `
    <tr><td>${esc(p.from_name || p.from)} → ${esc(p.to_name || p.to)}</td>
    <td>${p.ok ? `<span class="st st-up"><i></i>${esc(p.via)} ${p.rtt_ms != null ? p.rtt_ms + "ms" : ""}</span>` : '<span class="st st-err"><i></i>' + esc((p.err || "fail").slice(0, 24)) + '</span>'}</td>
    <td class="mid">${p.ok ? `loss ${p.loss_pct ?? "—"}% · jit ${p.jitter_ms ?? "—"}` : "—"}</td></tr>`).join("");
}
async function refreshProbe() {
  try {
    const p = await api("/api/probe");
    if (p.result) renderProbe(p.result);
  } catch (_) {}
}

/* ------------------------------------------------ recommendations */
async function loadReco() {
  const r = await api("/api/recommend");
  if (!r.ok) {
    $("#recoList").innerHTML = `<p class="muted">${esc(r.hint_fa || "")}<br>${esc(r.hint_en || "")}</p>`;
    return;
  }
  const html = [];
  if (r.best_pair) {
    const bp = r.best_pair;
    html.push(`<div class="disc"><h4>★ ${esc(bp.from_name)} → ${esc(bp.to_name)}
      <span class="tag tag-ours">${t("health")} ${bp.score}/100</span></h4>
      <div class="kv">${esc(bp.label || "")} · rtt <b>${esc(bp.rtt_ms ?? "?")}ms</b> · loss <b>${esc(bp.loss_pct ?? "?")}%</b></div></div>`);
  }
  (r.pairs || []).forEach(p => {
    html.push(`<div class="disc"><h4>${esc(p.from_name || p.from)} → ${esc(p.to_name || p.to)}
      <span class="tag tag-star">${t("health")} ${p.score}</span></h4>`);
    (p.recommendations || []).slice(0, 5).forEach(x => {
      html.push(`<div class="kv"><b>${esc(x.rank || "")}. ${esc(x.method || x.family || "?")}</b> (fit ${esc(x.fit ?? "")})
        — ${esc(x.reason_fa || "")}</div>
        <div class="kv" dir="ltr" style="margin-bottom:4px">${esc(x.reason_en || "")}</div>`);
    });
    html.push(`</div>`);
  });
  $("#recoList").innerHTML = html.join("") || `<p class="muted">${t("empty")}</p>`;
}
$("#recoBtn").onclick = () => loadReco().catch(e => toast(t("err") + " " + e.message, "bad"));
async function refreshReco() {
  try { const r = await api("/api/recommend"); if (r && r.ok) await loadReco(); } catch (_) {}
}

/* ------------------------------------------------ install tab */
$("#inBtn").onclick = async () => {
  try {
    let mids = null;
    if (!$("#inAll").checked) mids = [...sel];
    const body = { host: $("#inHost").value.trim(), ssh_port: +$("#inPort").value || 22,
      username: $("#inUser").value.trim() || "root", password: $("#inPass").value };
    if (mids) body.methods = mids;
    await api("/api/install", { method: "POST", body: JSON.stringify(body) });
    toast(t("deploy") + "…");
    for (let i = 0; i < 600; i++) {
      await new Promise(r => setTimeout(r, 2000));
      const d = await api("/api/install");
      const j = d.job || {};
      $("#inJob").hidden = !j.running;
      $("#inJobTxt").textContent = `${t("deploy")} ${j.done || 0}/${j.total || 0} ${j.current || ""}`;
      $("#inState").textContent = j.running ? `${j.done || 0}/${j.total || 0}` : "";
      const dep = d.deployments || {};
      const rows = [];
      for (const [mid, rec] of Object.entries(dep)) {
        rows.push(`<tr><td class="mid">${esc(mid)}</td><td>${verdictChip(rec.verdict || "?")}</td>
          <td class="muted" style="max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc((rec.evidence || []).join(" | ").slice(0, 160))}</td></tr>`);
      }
      $("#instRows").innerHTML = rows.join("") || `<tr><td colspan="3" class="muted">${t("empty")}</td></tr>`;
      if (!j.running) { toast(t("deployDone"), "ok"); return; }
    }
  } catch (e) { toast(t("err") + " " + e.message, "bad"); }
};
async function refreshInst() {
  try {
    const d = await api("/api/install");
    const dep = d.deployments || {};
    $("#instRows").innerHTML = Object.entries(dep).map(([mid, rec]) =>
      `<tr><td class="mid">${esc(mid)}</td><td>${verdictChip(rec.verdict || "?")}</td>
       <td class="muted">${esc((rec.evidence || []).join(" | ").slice(0, 120))}</td></tr>`).join("")
      || `<tr><td colspan="3" class="muted">${t("empty")}</td></tr>`;
  } catch (_) {}
}

/* ------------------------------------------------ settings tab */
async function refreshSet() {
  try {
    const st = await api("/api/status");
    const s = st.settings || {};
    $("#setCooldown").value = s.cooldown_s ?? "";
    $("#setHyst").value = s.hysteresis_n ?? "";
    $("#setLossD").value = s.loss_degraded ?? "";
    $("#setLossX").value = s.loss_down ?? "";
    $("#setRttD").value = s.rtt_degraded ?? "";
    $("#setProbe").value = s.probe_interval_s ?? "";
    $("#modeAuto").classList.toggle("on", st.mode === "auto");
    $("#modeManual").classList.toggle("on", st.mode === "manual");
  } catch (_) {}
}
$("#modeAuto").onclick = async () => { await api("/api/mode", { method: "POST", body: '{"mode":"auto"}' }); refreshSet(); };
$("#modeManual").onclick = async () => { await api("/api/mode", { method: "POST", body: '{"mode":"manual"}' }); refreshSet(); };
$("#setSave").onclick = async () => {
  const body = { cooldown_s: +$("#setCooldown").value, hysteresis_n: +$("#setHyst").value,
    loss_degraded: +$("#setLossD").value, loss_down: +$("#setLossX").value,
    rtt_degraded: +$("#setRttD").value, probe_interval_s: +$("#setProbe").value };
  try { await api("/api/settings", { method: "POST", body: JSON.stringify(body) }); toast(t("saved"), "ok"); }
  catch (e) { toast(t("err") + " " + e.message, "bad"); }
};
$("#credBtn").onclick = async () => {
  const body = {};
  if ($("#credUser").value.trim()) body.username = $("#credUser").value.trim();
  if ($("#credPass").value) body.password = $("#credPass").value;
  if (!Object.keys(body).length) return;
  try { await api("/api/credentials", { method: "POST", body: JSON.stringify(body) });
    toast(t("saved"), "ok"); $("#credPass").value = ""; }
  catch (e) { toast(t("err") + " " + e.message, "bad"); }
};

/* ------------------------------------------------ boot */
function renderAll() { renderTab(($(".rail-btn.on") || {}).dataset?.tab || "dash"); }
setInterval(() => { $("#clock").textContent = new Date().toLocaleTimeString(LANG === "fa" ? "fa-IR" : "en-GB", { hour12: false }); }, 1000);
setInterval(() => { if (!$("#tab-dash").hidden) refreshDash(); }, 5000);
applyLang();
refreshDash();
