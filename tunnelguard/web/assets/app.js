/* TunnelGuard dashboard logic — vanilla JS, Chart.js 4 */
'use strict';

const $ = (sel, root=document) => root.querySelector(sel);
const $$ = (sel, root=document) => [...root.querySelectorAll(sel)];
let TOKEN = localStorage.getItem('tg_token') || '';
let ME = null;
let CHARTS = {};
let STATE = { mode:'auto', active_id:null, sim:false };
let POLL_TIMER = null;

/* ------------------------------------------------ fetch helpers */
async function api(path, opts={}) {
  const res = await fetch(path, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(TOKEN ? {'Authorization': `Bearer ${TOKEN}`} : {}),
      ...(opts.headers||{})
    }
  });
  if (res.status === 401 && !path.includes('/auth/login')) { showLogin(); throw new Error('401'); }
  const data = await res.json().catch(()=>({}));
  if (!res.ok) throw new Error(data.detail || res.statusText);
  return data;
}

/* ------------------------------------------------ i18n / theme */
function applyI18n() {
  document.documentElement.lang = LANG;
  document.documentElement.dir = t('dir');
  $$('[data-i18n]').forEach(el => { el.textContent = t(el.dataset.i18n); });
  $('#btn-lang').textContent = LANG === 'fa' ? 'EN' : 'فا';
  $('#footer-limit').textContent = LANG==='fa'
    ? 'محدودیت واقعی: سشن‌های TCP هنگام سوییچ قطع می‌شوند؛ MTU هر پروتکل متفاوت است (MSS clamp خودکار فعال است).'
    : 'Real limits: TCP sessions break on switch; per-protocol MTU differs (automatic MSS clamping enabled).';
  localStorage.setItem('tg_lang', LANG);
}
function applyTheme() {
  const th = localStorage.getItem('tg_theme') || 'dark';
  document.documentElement.dataset.theme = th;
  $('#btn-theme').textContent = th === 'dark' ? '☀️' : '🌙';
  Object.values(CHARTS).forEach(c => c && c.destroy && c.destroy());
  CHARTS = {};
  refreshAll();
}
$('#btn-theme')?.addEventListener('click', () => {
  localStorage.setItem('tg_theme',
    (localStorage.getItem('tg_theme')||'dark')==='dark' ? 'light':'dark');
  applyTheme();
});
$('#btn-lang')?.addEventListener('click', () => {
  LANG = LANG==='fa' ? 'en':'fa'; applyI18n(); refreshAll();
});

/* ------------------------------------------------ auth */
$('#login-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    const data = await api('/api/auth/login', {method:'POST', body: JSON.stringify({
      username: $('#login-user').value, password: $('#login-pass').value})});
    TOKEN = data.token; localStorage.setItem('tg_token', TOKEN);
    ME = data; showApp();
  } catch (err) {
    $('#login-err').textContent = t('login_fail');
  }
});
$('#btn-logout')?.addEventListener('click', () => {
  TOKEN=''; localStorage.removeItem('tg_token'); showLogin();
});
function showLogin(){ $('#view-app').classList.add('hidden');
  $('#view-login').classList.remove('hidden'); }
function showApp(){ $('#view-login').classList.add('hidden');
  $('#view-app').classList.remove('hidden'); applyI18n(); refreshAll(); startPolling(); }

/* ------------------------------------------------ navigation */
$$('.nav [data-view]').forEach(btn => btn.addEventListener('click', () => {
  const v = btn.dataset.view;
  ['overview','events','settings','detail'].forEach(x =>
    $('#view-'+x).classList.toggle('hidden', x!==v));
  $$('.nav [data-view]').forEach(b => b.classList.toggle('active', b===btn));
  if (v==='events') loadEvents('#events-full');
}));
$('#btn-detail-back')?.addEventListener('click', () => {
  $('#view-detail').classList.add('hidden');
  $('#view-overview').classList.remove('hidden');
});

/* ------------------------------------------------ toast */
function toast(msg, bad=false) {
  const el = document.createElement('div');
  el.className='toast'; el.style.borderColor = bad? 'rgba(239,68,68,.5)':'var(--line)';
  el.textContent = msg; $('#toast-root').appendChild(el);
  setTimeout(()=>el.remove(), 3200);
}

/* ------------------------------------------------ charts */
function chartColors() {
  const dark = (document.documentElement.dataset.theme!=='light');
  return { grid: dark? 'rgba(148,163,184,.12)':'rgba(15,23,42,.08)',
           txt: dark? '#8fa1bd':'#5b6b85' };
}
function makeChart(canvasId, label, color) {
  const el = $('#'+canvasId); if (!el) return null;
  if (CHARTS[canvasId]) return CHARTS[canvasId];
  const cc = chartColors();
  CHARTS[canvasId] = new Chart(el, {
    type:'line',
    data:{datasets:[]},
    options:{
      responsive:true, maintainAspectRatio:false, animation:false,
      interaction:{mode:'nearest',intersect:false},
      scales:{
        x:{type:'linear', grid:{color:cc.grid}, ticks:{color:cc.txt, maxTicksLimit:8,
          callback:(v)=> timeStr(v)}},
        y:{grid:{color:cc.grid}, ticks:{color:cc.txt}}
      },
      plugins:{ legend:{display:true, labels:{color:cc.txt, boxWidth:10, font:{size:11}}},
        tooltip:{callbacks:{title:(it)=>timeStr(it[0].parsed.x)}}}
    }
  });
  return CHARTS[canvasId];
}
function timeStr(ts) {
  const d = new Date(ts*1000);
  return d.toTimeString().slice(0,8);
}
function updateChart(canvasId, seriesMap) {
  const c = makeChart(canvasId);
  if (!c) return;
  c.data.datasets = Object.entries(seriesMap).map(([name, pts],i) => ({
    label: name, data: pts, parsing:false,
    borderColor: PALETTE[i%PALETTE.length], backgroundColor: PALETTE[i%PALETTE.length],
    borderWidth:2, pointRadius:0, tension:.3, spanGaps:true
  }));
  c.update('none');
}
const PALETTE = ['#4f8cff','#22c55e','#f59e0b','#8b5cf6','#ef4444','#06b6d4','#ec4899','#84cc16'];

/* ------------------------------------------------ state & polling */
function startPolling() {
  stopPolling();
  POLL_TIMER = setInterval(refreshAll, 4000);
  connectWS();
}
function stopPolling(){ if (POLL_TIMER) clearInterval(POLL_TIMER); POLL_TIMER=null; }

async function refreshAll() {
  try {
    const st = await api('/api/state');
    STATE = { mode: st.mode, active_id: st.active?.id, sim: st.sim_mode,
              active_name: st.active?.name, vip: st.virtual_ip, flap: st.flap_locked };
    renderStateHeader(st);
    const tl = await api('/api/tunnels');
    renderTunnelCards(tl);
    const m = await api('/api/metrics?range_s=900');
    renderOverviewCharts(m);
    loadEvents('#events-mini', 12);
    if (!$('#view-detail').classList.contains('hidden')) loadDetailMetrics();
  } catch(e){ if (e.message!=='401') console.warn(e); }
}

function renderStateHeader(st) {
  const badge = $('#mode-badge');
  badge.className = 'mode-badge ' + (st.mode==='auto'?'auto':'manual');
  $('#mode-text').textContent = t(st.mode==='auto'?'auto':'manual')
    + (st.sim_mode? ' · '+t('sim_badge'):'');
  $('#hb-mode').textContent = t(st.mode==='auto'?'auto':'manual');
  $('#hb-vip').textContent = st.virtual_ip;
  const activeEl = $('#hb-active');
  if (st.active) {
    activeEl.innerHTML = `${st.active.name} <span class="tag">${st.active.engine}</span>`;
  } else activeEl.textContent = '—';
  $('#hb-status-pill').innerHTML = st.flap_locked
    ? `<span class="pill warn">${t('flap_locked')}</span>`
    : (st.active? `<span class="pill ok">●</span>`:`<span class="pill bad">—</span>`);
}

/* ------------------------------------------------ tunnel cards */
function scoreClass(sc){ return sc>=70?'':(sc>=40?'mid':'low'); }
function renderTunnelCards(data) {
  const grid = $('#tunnel-grid'); if (!grid) return;
  grid.innerHTML = '';
  data.tunnels.forEach(tun => {
    const w = tun.window || {};
    const isActive = data.active_id === tun.id;
    const isDown = w.ok === false;
    const card = document.createElement('div');
    card.className = 'tcard' + (isActive?' active-t':'') + (isDown?' down-t':'');
    const bwUp = (w.score??0) >= 70;
    card.innerHTML = `
      ${isActive? `<span class="badge-active">${t('active_badge')}</span>`:''}
      <div class="head">
        <h3>${esc(tun.name)} ${tun.engine==='sim'? `<span class="tag">${t('sim_badge')}</span>`:''}</h3>
        <span class="tag mt">${tun.engine}</span>
      </div>
      <div class="engine-line">${t('iface')}: <b>${esc(tun.iface)}</b> · MTU ${tun.mtu||'—'}
        ${tun.engine_status?.up ? ' · <span style="color:var(--ok)">⬤</span>' : ' · <span style="color:var(--bad)">⬤</span>'}</div>
      <div class="stat4">
        <div class="s4"><small>${t('rtt')}</small><b>${w.rtt_ms!=null? w.rtt_ms.toFixed(1)+'ms':'—'}</b></div>
        <div class="s4"><small>${t('loss')}</small><b>${w.loss_pct!=null? w.loss_pct.toFixed(0)+'%':'—'}</b></div>
        <div class="s4"><small>${t('jitter')}</small><b>${w.jitter_ms!=null? w.jitter_ms.toFixed(1)+'ms':'—'}</b></div>
        <div class="s4"><small>${t('bw')}</small><b id="bw-${tun.id}">—</b></div>
      </div>
      <div class="scorebar ${scoreClass(w.score||0)}"><i style="width:${(w.score||0)}%"></i></div>
      <div class="spark"><canvas id="spark-${tun.id}"></canvas></div>
      <div class="card-actions">
        ${STATE.mode==='manual' && !isActive
          ? `<button class="btn make-active" data-act="activate" data-id="${tun.id}">${t('make_active')}</button>`:''}
        <button class="btn" data-act="precheck" data-id="${tun.id}">${t('precheck')}</button>
        <button class="btn" data-act="config" data-id="${tun.id}">${t('config')}</button>
        <button class="btn ghost" data-act="detail" data-id="${tun.id}">📈</button>
      </div>`;
    grid.appendChild(card);
  });
  $$('.card-actions .btn').forEach(b => b.addEventListener('click', onCardAction));
  drawSparks();
}
function esc(s){ return String(s??'').replace(/[&<>"']/g, c=>(
  {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

async function drawSparks() {
  try {
    const m = await api('/api/metrics?range_s=900');
    Object.keys(m.series).forEach(tid => {
      const pts = (m.series[tid].probes||[]).filter(p=>p.ok).map(p=>({x:p.ts, y:p.rtt_ms}));
      const c = makeChart('spark-'+tid, 'rtt', PALETTE[0]);
      if (c) {
        c.options.scales.x.ticks.display = false;
        c.options.scales.y.ticks.display = false;
        c.options.plugins.legend.display = false;
        c.data.datasets = [{data:pts, parsing:false, borderColor:PALETTE[0],
          borderWidth:1.5, pointRadius:0, tension:.3, spanGaps:true}];
        c.update('none');
      }
    });
    // bandwidth into cards
    Object.entries(m.series).forEach(([tid, ser]) => {
      const el = $('#bw-'+tid);
      if (!el || !ser.throughput?.length) return;
      const last = ser.throughput[ser.throughput.length-1];
      const mbps = ((last.rx_bps+last.tx_bps)*8/1e6);
      el.textContent = mbps.toFixed(2)+'Mb';
    });
  } catch(e){}
}

function renderOverviewCharts(m) {
  const rttMap = {}, lossMap = {};
  const names = (window.__tnames ||= {});
  Object.entries(m.series).forEach(([tid, ser]) => {
    const name = names[tid] || ('T'+tid);
    rttMap[name] = (ser.probes||[]).filter(p=>p.ok).map(p=>({x:p.ts,y:p.rtt_ms}));
    lossMap[name] = (ser.probes||[]).map(p=>({x:p.ts,y:p.loss_pct}));
  });
  updateChart('chart-rtt', rttMap);
}

/* ------------------------------------------------ card actions */
async function onCardAction(e) {
  const id = e.currentTarget.dataset.id;
  const act = e.currentTarget.dataset.act;
  if (act==='activate') {
    if (!confirm(t('confirm_switch'))) return;
    await api(`/api/failover/switch/${id}`, {method:'POST'});
    toast(t('switch_ok')); refreshAll();
  } else if (act==='precheck') {
    const r = await api(`/api/tunnels/${id}/precheck`, {method:'POST'});
    openModal(t('precheck_title'),
      r.problems.length? `<b style="color:var(--warn)">${t('problems')}:</b>
        <ul>${r.problems.map(p=>`<li style="margin:6px 0">${esc(p)}</li>`).join('')}</ul>`
      : `<span style="color:var(--ok)">✔ ${t('no_problems')}</span>`);
  } else if (act==='config') {
    const r = await api(`/api/tunnels/${id}/config`);
    openModal(t('config'), Object.entries(r.artifacts).map(([p,c]) =>
      `<div style="margin-bottom:10px"><b style="font-size:12px;direction:ltr">${esc(p)}</b>
       <pre class="cfg">${esc(c)}</pre></div>`).join(''));
  } else if (act==='detail') {
    window.__detail_tid = id;
    $('#view-overview').classList.add('hidden');
    $('#view-detail').classList.remove('hidden');
    loadDetailMetrics();
  }
}

async function loadDetailMetrics() {
  const tid = window.__detail_tid; if (!tid) return;
  const m = await api(`/api/metrics?tid=${tid}&range_s=3600`);
  const ser = m.series[tid] || {probes:[],throughput:[]};
  $('#detail-title').textContent = (window.__tnames||{})[tid] || ('Tunnel '+tid);
  updateChart('d-chart-rtt', {rtt: ser.probes.filter(p=>p.ok).map(p=>({x:p.ts,y:p.rtt_ms}))});
  updateChart('d-chart-loss', {loss: ser.probes.map(p=>({x:p.ts,y:p.loss_pct}))});
  updateChart('d-chart-jit', {jit: ser.probes.filter(p=>p.jitter_ms!=null).map(p=>({x:p.ts,y:p.jitter_ms}))});
  updateChart('d-chart-bw', {
    rx: ser.throughput.map(p=>({x:p.ts,y:p.rx_bps*8/1e6})),
    tx: ser.throughput.map(p=>({x:p.ts,y:p.tx_bps*8/1e6}))});
}

/* ------------------------------------------------ events */
async function loadEvents(sel, limit=200) {
  const r = await api(`/api/events?limit=${limit}`);
  const el = $(sel); if (!el) return;
  el.innerHTML = r.events.length? '' : `<p style="color:var(--muted)">${t('no_events')}</p>`;
  r.events.forEach(ev => {
    const row = document.createElement('div');
    row.className = 'event-row';
    row.innerHTML = `<time>${new Date(ev.ts*1000).toLocaleString()}</time>
      <span class="lv-${ev.level}">●</span><span>${esc(ev.message)}</span>`;
    el.appendChild(row);
  });
}

/* ------------------------------------------------ mode controls */
$('#btn-enable-auto')?.addEventListener('click', async () => {
  await api('/api/mode', {method:'POST', body: JSON.stringify({mode:'auto'})});
  toast(t('enable_auto')); refreshAll();
});
$('#btn-reset-flap')?.addEventListener('click', async () => {
  await api('/api/failover/reset-flap', {method:'POST'}); toast('✔'); refreshAll();
});

/* ------------------------------------------------ settings */
const SETTING_GROUPS = {
  'set-probe': ['probe_interval_s','probe_count','probe_timeout_s'],
  'set-fail': ['fail_threshold','loss_threshold_pct','latency_spike_ms'],
  'set-behavior': ['cooldown_s','hysteresis_margin','proactive_k',
                   'flap_window_s','flap_max_switches','flap_lock_s'],
  'set-net': ['virtual_ip','route_mode','weight_loss','weight_latency',
              'weight_jitter','weight_stability'],
};
async function renderSettings() {
  const s = await api('/api/settings');
  Object.entries(SETTING_GROUPS).forEach(([gid, keys]) => {
    const el = $('#'+gid); if (!el) return;
    el.innerHTML = '';
    keys.forEach(k => {
      const v = s[k];
      const div = document.createElement('div');
      div.className = 'set-item';
      if (k === 'route_mode') {
        div.innerHTML = `<label>${t(k)}</label>
          <select data-key="${k}">
            <option value="split" ${v==='split'?'selected':''}>${t('route_split')}</option>
            <option value="default" ${v==='default'?'selected':''}>${t('route_default')}</option>
          </select>`;
      } else {
        div.innerHTML = `<label>${t(k)}</label>
          <input data-key="${k}" value="${esc(String(v))}">`;
      }
      el.appendChild(div);
    });
  });
  // toggles
  const toggles = [['proactive_switch_enabled','#set-behavior'],
                   ['sim_mode','#set-net']];
  toggles.forEach(([k,sel]) => {
    const el = $(sel); if (!el) return;
    const div = document.createElement('div');
    div.className='set-item';
    div.innerHTML = `<label>${t(k)}</label>
      <select data-key="${k}">
        <option value="1" ${s[k]?'selected':''}>ON</option>
        <option value="0" ${s[k]?'':'selected'}>OFF</option>
      </select>`;
    el.appendChild(div);
  });
  $('#set-note').textContent = t('settings_note');
}
$('#btn-save-settings')?.addEventListener('click', async () => {
  const patch = {};
  $$('#view-settings [data-key]').forEach(inp => {
    let v = inp.value;
    if (inp.tagName==='SELECT' && (v==='0'||v==='1')) v = v==='1';
    else if (!isNaN(parseFloat(v)) && /^-?[\d.]+$/.test(v)) v = parseFloat(v);
    patch[inp.dataset.key] = v;
  });
  try {
    await api('/api/settings', {method:'PUT', body: JSON.stringify({patch})});
    toast(t('saved'));
  } catch(e){ toast(String(e.message||e), true); }
});

/* ------------------------------------------------ tunnel CRUD modal */
$('#btn-add-tunnel')?.addEventListener('click', () => tunnelModal());
function openModal(title, html) {
  const root = $('#modal-root');
  root.innerHTML = `<div class="modal-back"><div class="modal">
    <h3>${esc(title)}</h3>${html}
    <div style="margin-top:16px;text-align:${LANG==='fa'?'left':'right'}">
      <button class="btn" onclick="this.closest('.modal-back').remove()">✕</button></div>
  </div></div>`;
  root.querySelector('.modal-back').addEventListener('click', (e)=>{
    if (e.target.classList.contains('modal-back')) e.target.remove();
  });
}
async function tunnelModal(editId=null) {
  const engines = await api('/api/engines');
  let tun = {name:'',engine:'wireguard',local_ip:'',remote_ip:'',remote_lan:'',
             remote_host:'',mtu:1420,config:{},remote_ssh:null};
  if (editId) {
    const tl = await api('/api/tunnels');
    tun = tl.tunnels.find(x=>x.id===editId) || tun;
    tun.config = tun.config||{};
    if (tun.remote_ssh && tun.remote_ssh.host) tun._ssh = tun.remote_ssh;
  }
  const opts = Object.entries(engines.engines)
    .filter(([k])=>k!=='sim' || engines.sim_mode)
    .map(([k,v])=>`<option value="${k}" ${tun.engine===k?'selected':''}>${v.label} (MTU ${v.mtu_default})</option>`).join('');
  const c = tun.config || {};
  openModal(editId? t('edit'): t('add_tunnel'), `
  <div class="row">
    <div class="field"><label>${t('tunnel_name')}</label><input id="t-name" value="${esc(tun.name)}"></div>
    <div class="field"><label>${t('engine')}</label><select id="t-engine">${opts}</select></div>
    <div class="field"><label>${t('iface')}</label><input id="t-iface" value="${esc(tun.iface||'')}"></div>
    <div class="field"><label>${t('mtu')}</label><input id="t-mtu" value="${tun.mtu||''}"></div>
    <div class="field"><label>${t('local_ip')}</label><input id="t-lip" value="${esc(tun.local_ip||'')}" placeholder="10.10.10.1"></div>
    <div class="field"><label>${t('remote_ip')}</label><input id="t-rip" value="${esc(tun.remote_ip||'')}" placeholder="10.10.10.2"></div>
    <div class="field"><label>${t('remote_host')}</label><input id="t-rhost" value="${esc(tun.remote_host||'')}"></div>
    <div class="field"><label>${t('remote_lan')}</label><input id="t-rlan" value="${esc(tun.remote_lan||'')}" placeholder="10.20.0.0/24"></div>
  </div>
  <details><summary style="cursor:pointer;font-size:13px;color:var(--muted)">${t('engine')} config (JSON)</summary>
    <textarea id="t-cfg" class="field" rows="5" style="width:100%;direction:ltr;font-family:monospace">${esc(JSON.stringify(c,null,1))}</textarea></details>
  <details><summary style="cursor:pointer;font-size:13px;color:var(--muted);margin-top:8px">${t('ssh_creds')}</summary>
    <div class="row">
      <div class="field"><label>${t('ssh_host')}</label><input id="t-sshhost" value="${esc(tun._ssh?.host||'')}"></div>
      <div class="field"><label>${t('ssh_user')}</label><input id="t-sshuser" value="${esc(tun._ssh?.username||'root')}"></div>
      <div class="field"><label>${t('ssh_pass')}</label><input id="t-sshpass" value="${esc(tun._ssh?.password||'')}" type="password"></div>
      <div class="field"><label>${t('peer_iface')}</label><input id="t-peeriface" value="${esc(tun._ssh?.peer_iface||'')}"></div>
    </div></details>
  <div style="margin-top:14px;display:flex;gap:8px;justify-content:flex-end">
    ${editId? `<button class="btn danger" id="t-del">${t('delete')}</button>`:''}
    <button class="btn" onclick="this.closest('.modal-back').remove()">${t('cancel')}</button>
    <button class="btn primary" id="t-save">${t('save')}</button>
  </div>`);
  $('#t-save').addEventListener('click', async () => {
    let cfg;
    try { cfg = JSON.parse($('#t-cfg').value || '{}'); }
    catch(e){ toast('config JSON invalid', true); return; }
    const body = {
      name: $('#t-name').value, engine: $('#t-engine').value,
      iface: $('#t-iface').value || null,
      local_ip: $('#t-lip').value || null, remote_ip: $('#t-rip').value || null,
      remote_lan: $('#t-rlan').value || null, remote_host: $('#t-rhost').value || null,
      mtu: parseInt($('#t-mtu').value) || null,
      config: cfg,
      remote_ssh: $('#t-sshhost').value? {host:$('#t-sshhost').value,
        username:$('#t-sshuser').value, password:$('#t-sshpass').value,
        peer_iface:$('#t-peeriface').value} : null,
    };
    try {
      if (editId) await api(`/api/tunnels/${editId}`, {method:'PUT', body:JSON.stringify(body)});
      else await api('/api/tunnels', {method:'POST', body:JSON.stringify(body)});
      $('#modal-root').innerHTML=''; toast(t('saved')); refreshAll();
    } catch(e){ toast(String(e.message||e), true); }
  });
  const delBtn = $('#t-del');
  if (delBtn) delBtn.addEventListener('click', async () => {
    if (!confirm(t('confirm_delete'))) return;
    await api(`/api/tunnels/${editId}`, {method:'DELETE'});
    $('#modal-root').innerHTML=''; refreshAll();
  });
  $('#t-engine').addEventListener('change', (e) => {
    const meta = engines.engines[e.target.value];
    if (meta) $('#t-mtu').value = meta.mtu_default;
  });
}

/* ------------------------------------------------ wizard (quick add) */
$('#btn-wizard')?.addEventListener('click', () => openWizard());
const WIZ_ICONS = { wireguard:'🔒', gre:'🛣️', sit:'🌐', openvpn:'🔓',
  ikev2:'🔐', l2tp:'📡', hedioum:'🎭', hajsaman:'🧩', paqet:'📦', sim:'🧪' };
const WIZ_FIELDS = {
  wireguard: [['private_key','Private key (wg genkey)','text'],
              ['peer_public_key','Peer public key','text'],
              ['endpoint_port','Endpoint port (51820)','number'],
              ['listen_port','Listen port (51820)','number'],
              ['allowed_ips','AllowedIPs (opt, comma list)','text']],
  openvpn:   [['remote_port','Remote port (1194)','number'],
              ['proto','proto (udp/tcp)','text'],
              ['ca_cert','CA cert (PEM, opt)','text'],
              ['client_cert','Client cert (opt)','text'],
              ['client_key','Client key (opt)','text']],
  ikev2:     [['psk','IPsec PSK','text'],['ike_cipher','IKE cipher (opt)','text'],
              ['esp_cipher','ESP cipher (opt)','text']],
  l2tp:      [['session_id','L2TPv3 session id','number'],
              ['cookie','Cookie (hex, opt)','text'],['psk','IPsec PSK','text']],
  hedioum:   [['pairing_token','','pairing'],
              ['foreign_ip','Foreign IP (manual mode)','text'],
              ['foreign_port','Foreign mimic port (manual)','number'],
              ['auth_token','Auth token 32-hex (manual)','text'],
              ['socks_port','Local SOCKS5 port (40001)','number'],
              ['tun_enabled','TUN mode (routable by VIP)','bool'],
              ['dns_enabled','DNS forwarder on TUN gw','bool'],
              ['min_connections','Pool min conns (10)','number'],
              ['max_connections','Pool max conns (20)','number'],
              ['bandwidth_limit_mbps','BW limit per conn Mbps (8)','number'],
              ['bandwidth_jitter_mbps','BW jitter Mbps (2)','number']],
  hajsaman:  [['mode','mode: cli (installed wizard) or native','text'],
              ['slot','Slot name (cli mode, e.g. hst-427)','text'],
              ['role','native role: iran | foreign','text'],
              ['local_public_ip','native: local public IPv4','text'],
              ['foreign_ipv4','native: foreign public IPv4','text'],
              ['wg_listen_port','native: WG port inside SIT (51821)','number'],
              ['private_key','native: WG private key (this side)','text'],
              ['peer_public_key','native: peer WG public key','text'],
              ['psk','native: optional preshared key','text'],
              ['mark','native: fwmark (31400)','number']],
  paqet:     [['role','role: client (Iran) | server (Foreign)','text'],
              ['server_addr','client: paqet server host:port','text'],
              ['listen_addr','server: bind addr (:9999)','text'],
              ['socks_listen','client: SOCKS5 bind (127.0.0.1:1080)','text'],
              ['interface','capture interface (eth0)','text'],
              ['local_ipv4','local ip:port (client port 0)','text'],
              ['router_mac','gateway/router MAC','text'],
              ['kcp_key','KCP shared secret','text'],
              ['kcp_block','encryption block (aes)','text'],
              ['kcp_mode','KCP mode (fast)','text'],
              ['kcp_conn','connections 1-256 (1)','number']],
};
async function openWizard() {
  const engines = await api('/api/engines');
  const meta = engines.engines;
  const entries = Object.entries(meta).filter(([k]) => k!=='sim' || engines.sim_mode);
  const cards = entries.map(([k,v]) => `
    <label class="wcard ${v.pending?'disabled':''}" data-eng="${k}">
      <input type="checkbox" value="${k}" ${v.pending?'disabled':''}>
      <span class="wicon">${WIZ_ICONS[k]||'⛓️'}</span>
      <span class="wbody"><b>${v.label}</b>
        <small>${t(k+'_desc')||v.layer} · MTU ${v.mtu_default}</small>
        <span class="wtag">${v.pending? t('pending_badge')
          : (v.kind==='kernel'? t('kernel_desc')
             : (v.tun_optional? t('tun_optional') : v.layer))}</span>
      </span>
    </label>`).join('');
  openModal(t('wizard_title'), `
    <p class="wstep" id="w-step1">${t('wizard_s1')}</p>
    <div class="wgrid" id="w-catalog">${cards}</div>
    <p class="err" id="w-err"></p>
    <div style="margin-top:14px;display:flex;gap:8px;justify-content:flex-end">
      <button class="btn" onclick="this.closest('.modal-back').remove()">✕</button>
      <button class="btn primary" id="w-next">${t('wizard_next')}</button>
    </div>`);
  $('#w-next').addEventListener('click', () => {
    const sel = $$('#w-catalog input:checked').map(i=>i.value);
    if (!sel.length) { $('#w-err').textContent = t('wizard_none'); return; }
    wizardForms(sel, meta);
  });
  $$('#w-catalog .wcard').forEach(c => c.addEventListener('click', (e) => {
    if (e.target.tagName!=='INPUT') {
      const cb = c.querySelector('input');
      if (!cb.disabled) cb.checked = !cb.checked;
    }
    c.classList.toggle('sel', c.querySelector('input').checked);
  }));
}

function wizardForms(sel, meta) {
  const forms = sel.map((eng,i) => {
    const m = meta[eng];
    const fdefs = WIZ_FIELDS[eng] || [];
    const fields = fdefs.map(([k,label,type]) => {
      const fid = `wf-${i}-${k}`;
      if (type==='pairing') return `
        <div class="field wpair" style="grid-column:1/-1">
          <label>${t('pairing_token')} — ${t('pairing_hint')}</label>
          <div style="display:flex;gap:6px">
            <textarea id="${fid}" rows="2" style="flex:1;direction:ltr;font-family:monospace"></textarea>
            <button class="btn" type="button" data-decode="${fid}" data-i="${i}">⚡</button>
          </div>
          <small class="tokmsg" id="${fid}-msg" style="color:var(--muted)"></small>
        </div>`;
      if (type==='bool') return `
        <div class="field"><label>${label}</label>
          <select id="${fid}"><option value="0">OFF</option><option value="1">ON</option></select></div>`;
      return `<div class="field"><label>${label}</label>
        <input id="${fid}" type="${type==='number'?'number':'text'}" dir="ltr"></div>`;
    }).join('');
    return `
    <fieldset class="wform" data-eng="${eng}">
      <legend>${WIZ_ICONS[eng]||'⛓️'} ${m.label}
        <span class="tag mt">${eng}</span></legend>
      <div class="row">
        <div class="field"><label>${t('tunnel_name')}</label>
          <input class="w-name" value="${eng}-${String(i+1).padStart(2,'0')}" dir="ltr"></div>
        <div class="field"><label>${t('remote_host')}</label>
          <input class="w-rhost" dir="ltr" placeholder="203.0.113.10"></div>
        <div class="field"><label>${t('local_ip')}</label>
          <input class="w-lip" dir="ltr" placeholder="10.10.${i+1}.1"></div>
        <div class="field"><label>${t('remote_ip')}</label>
          <input class="w-rip" dir="ltr" placeholder="10.10.${i+1}.2"></div>
        <div class="field"><label>${t('remote_lan')}</label>
          <input class="w-rlan" dir="ltr" placeholder="10.20.0.0/24"></div>
        <div class="field"><label>${t('mtu')}</label>
          <input class="w-mtu" type="number" value="${m.mtu_default}" dir="ltr"></div>
      </div>
      ${fields? `<div class="row">${fields}</div>`:''}
    </fieldset>`;
  }).join('');
  openModal(t('wizard_title'), `
    <p class="wstep">${t('wizard_s2')} · <small style="color:var(--ok)">${t('active_on_submit')}</small></p>
    <div style="max-height:56vh;overflow:auto;padding-inline-end:4px">${forms}</div>
    <div style="margin-top:14px;display:flex;gap:8px;justify-content:space-between">
      <button class="btn" id="w-back">← ${t('wizard_back')}</button>
      <div style="display:flex;gap:8px">
        <button class="btn" onclick="this.closest('.modal-back').remove()">✕</button>
        <button class="btn primary" id="w-submit">⚡ ${t('wizard_submit')}</button>
      </div>
    </div>`);
  $('#w-back').addEventListener('click', openWizard);
  $$('button[data-decode]').forEach(btn => btn.addEventListener('click', () => {
    const ta = $('#'+btn.dataset.decode);
    const msg = $('#'+btn.dataset.decode+'-msg');
    const info = jsDecodePairing(ta.value.trim());
    if (!info) { msg.textContent = '✖ ' + t('token_bad'); msg.style.color='var(--bad)'; return; }
    const i = btn.dataset.i;
    const set = (suffix, v) => { const el=$(`#wf-${i}-${suffix}`); if (el && v) el.value=v; };
    set('foreign_ip', info.ip); set('auth_token', info.auth);
    if (info.eps) { const ssh = info.eps.ssh || Object.values(info.eps)[0];
      set('foreign_port', ssh); }
    msg.textContent = t('token_ok') + (info.persona? ` (${info.persona})`:'');
    msg.style.color = 'var(--ok)';
  }));
  $('#w-submit').addEventListener('click', submitWizard);
}

function jsDecodePairing(tok) {
  if (!tok || /^[A-Fa-f0-9]{32}$/.test(tok)) return null;
  try {
    const b = tok.replace(/-/g,'+').replace(/_/g,'/');
    const json = decodeURIComponent(escape(atob(b + '='.repeat((4-b.length%4)%4))));
    const p = JSON.parse(json);
    if (p.v !== 2) return null;
    return { ip:p.ip, auth:p.auth, persona:p.persona, sni:p.sni, eps:p.eps };
  } catch(e){ return null; }
}

async function submitWizard() {
  const specs = [];
  $$('.wform').forEach((fs, i) => {
    const eng = fs.dataset.eng;
    const cfg = {};
    $$('input,select,textarea', fs).forEach(inp => {
      if (!inp.id.startsWith(`wf-${i}-`)) return;
      const key = inp.id.slice((`wf-${i}-`).length);
      if (key === 'pairing_token') { if (inp.value.trim()) cfg[key] = inp.value.trim(); return; }
      if (inp.tagName==='SELECT' && (inp.value==='0'||inp.value==='1')) { cfg[key] = inp.value==='1'; return; }
      if (inp.type==='number' && inp.value!=='') { cfg[key] = parseInt(inp.value); return; }
      if (inp.value.trim()!=='') cfg[key] = inp.value.trim();
    });
    specs.push({
      name: $('.w-name', fs).value.trim() || `${eng}-${i+1}`,
      engine: eng,
      remote_host: $('.w-rhost', fs).value || null,
      local_ip: $('.w-lip', fs).value || null,
      remote_ip: $('.w-rip', fs).value || null,
      remote_lan: $('.w-rlan', fs).value || null,
      mtu: parseInt($('.w-mtu', fs).value) || null,
      config: cfg,
    });
  });
  if (!specs.length) return;
  $('#w-submit').disabled = true;
  $('#w-submit').textContent = '⏳ ' + t('wizard_running');
  try {
    const r = await api('/api/tunnels/batch', {
      method:'POST', body: JSON.stringify({tunnels: specs, activate:true})});
    wizardResults(r);
    refreshAll();
  } catch(e) { toast(String(e.message||e), true); $('#w-submit').disabled=false; }
}

function wizardResults(r) {
  const STEPS = { created:'step_created', precheck:'step_precheck',
    engine_up:'step_engine_up', status_check:'step_status',
    first_probe:'step_first_probe', exit_ip_receipt:'step_exit_ip' };
  const rows = r.results.map(res => {
    const steps = (res.steps||[]).map(s => `
      <li class="${s.ok?'sok':'sbad'}">
        <b>${t(STEPS[s.step]||s.step)}</b>
        <small>${esc(s.detail||'')}</small></li>`).join('');
    return `<div class="wres ${res.ok?'rok':'rbad'}">
      <div class="wres-head">
        <span>${WIZ_ICONS[res.engine]||'⛓️'} ${esc(res.name||'')}
          <span class="tag mt">${res.engine}</span></span>
        <span class="${res.ok?'ok-text':'bad-text'}">${res.ok? '✔ ACTIVATED':'✖ FAILED'}</span>
      </div>
      <ul class="wsteps">${steps}</ul>
      ${res.error? `<p class="err">${esc(res.error)}</p>`:''}
    </div>`;
  }).join('');
  openModal(t('wizard_s3'), `
    <p><b style="color:var(--ok)">${r.ok}</b> / ${r.total} ${t('active_on_submit')}</p>
    <div style="max-height:56vh;overflow:auto">${rows}</div>
    <div style="margin-top:14px;text-align:end">
      <button class="btn primary" onclick="this.closest('.modal-back').remove()">${t('back')}</button>
    </div>`);
}

/* ------------------------------------------------ websocket live */
let WS = null;
function connectWS() {
  if (WS) { try{WS.close();}catch(e){} }
  const proto = location.protocol==='https:'?'wss':'ws';
  WS = new WebSocket(`${proto}://${location.host}/ws?token=${TOKEN}`);
  WS.onmessage = (e) => {
    try {
      const ev = JSON.parse(e.data);
      if (ev.type==='switch' || ev.type==='mode') refreshAll();
    } catch(_){}
  };
  WS.onclose = () => setTimeout(()=>{ if(TOKEN) connectWS(); }, 5000);
}

/* ------------------------------------------------ boot */
(async function boot() {
  applyI18n();
  const th = localStorage.getItem('tg_theme') || 'dark';
  document.documentElement.dataset.theme = th;
  $('#btn-theme').textContent = th==='dark'? '☀️':'🌙';
  if (!TOKEN) { showLogin(); return; }
  try {
    ME = await api('/api/me'); showApp();
    // remember tunnel names for chart legends
    const tl = await api('/api/tunnels');
    window.__tnames = {}; tl.tunnels.forEach(x=>window.__tnames[x.id]=x.name);
  } catch(e){ showLogin(); }
})();
