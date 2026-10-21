/* First-party managed TCP services. Session input/proofs stay in memory only. */
window.TPServices = (() => {
  'use strict';
  function renderServices(t, esc) {
    const text = (fa, en) => `<span data-service-label data-fa="${esc(fa)}" data-en="${esc(en)}">${esc(t(fa, en))}</span>`;
    return `<div class="section-head"><div><div class="eyebrow">${text('خدمات تهران‌نتورک · TCP', 'TEHNET SERVICES · TCP')}</div><h2>${text('۵ · سرویس‌ها و فوروارد پورت', '5 · Services & port forwarding')}</h2></div><button type="button" data-service-refresh>${text('تازه‌سازی فهرست', 'Refresh list')}</button></div>
      <p class="help">${text('یک پورت روی سرور مبدأ به ورودیِ مشخصی روی سرور مقصد متصل می‌شود. سرعت، مصرف مشترک و انتخاب تونل را همان گروه مسیر اعمال می‌کند. فیل‌اور برای اتصال‌های جدید است؛ اتصال TCP قبلی دوباره وصل می‌شود.', 'A source port connects to one fixed inbound on the destination server. The existing route group enforces speed, pooled usage and tunnel selection. Failover applies to new connections; existing TCP sessions reconnect.')}</p>
      <div class="service-layout"><form data-service-form class="service-editor"><h3 data-service-heading></h3><p data-service-editor-note class="help"></p><fieldset data-service-fields><div class="form">
      <label>${text('نام سرویس', 'Service name')}<input name="name" required maxlength="80" autocomplete="off"></label>
      <label class="service-wide">${text('گروه مسیر موجود', 'Existing route group')}<select name="route_id" required></select></label>
      <label>${text('آدرس شنود روی مبدأ', 'Listen address on source')}<input name="bind_host" value="127.0.0.1" required dir="ltr" spellcheck="false"></label>
      <label>${text('پورت مبدأ · آزاد و حداقل ۱۰۲۴', 'Source port · free, 1024 or higher')}<input name="bind_port" type="number" min="1024" max="65535" required dir="ltr"></label>
      <label>${text('آدرس سرویس روی مقصد', 'Service address on destination')}<input name="target_host" value="127.0.0.1" required dir="ltr" spellcheck="false"></label>
      <label>${text('پورت ورودی کاربر روی مقصد', 'User inbound port on destination')}<input name="target_port" type="number" min="1" max="65535" required dir="ltr"></label>
      <label class="service-wide">${text('IPهای مجاز مبدأ · CIDR، جدا با ویرگول یا خط جدید', 'Allowed client IPs · CIDRs, comma or newline separated')}<textarea name="source_cidrs" rows="2" dir="ltr" spellcheck="false" placeholder="192.0.2.10/32, 2001:db8::/64"></textarea></label>
      <label class="service-wide service-exposure"><input name="allow_public" type="checkbox">${text('انتشار روی شبکه را آگاهانه فعال می‌کنم؛ فهرست IPهای مجاز لازم است.', 'Explicitly publish on the network; an allowed-client list is required.')}</label>
      </div></fieldset><p class="help">${text('127.0.0.1 در فیلد شنود یعنی فقط روی مبدأ؛ همین آدرس در مقصد یعنی سرویس محلیِ سرور مقصد. پورت مدیریت و پایگاه داده مقصد مجاز نیست. فایروال سراسری تغییر نمی‌کند.', '127.0.0.1 in the listen field means source-local only; in the target field it means a service local to the destination. Management and database targets are blocked. The global firewall is unchanged.')}</p>
      <div class="row service-actions"><button type="button" data-service-preset>${text('الگوی ورودی کاربر 3x-ui', '3x-ui user inbound preset')}</button><button type="submit" data-service-preflight>${text('۱ · بررسی تازهٔ پورت و مسیر', '1 · Fresh port & route inspection')}</button><button type="button" class="primary" data-service-apply disabled>${text('۲ · اعمال تنظیمات تأییدشده', '2 · Apply inspected settings')}</button><button type="button" data-service-cancel>${text('فرم جدید', 'New form')}</button></div>
      <p class="help">${text('الگو فقط آدرس مقصد را localhost و پورت پیشنهادی را ۴۴۳ می‌گذارد؛ پورت واقعی ورودی کاربر را وارد کنید. رمز، UUID یا پنل مدیریت x-ui خوانده نمی‌شود.', 'The preset sets destination localhost and suggests port 443; enter the actual user inbound port. It does not read x-ui passwords, UUIDs or the management panel.')}</p>
      <div class="service-proof" data-service-proof role="status" aria-live="polite"></div><p data-service-message role="status" aria-live="polite"></p></form>
      <div class="service-directory"><div class="row"><h3 class="space">${text('فورواردهای شما', 'Your forwards')}</h3><span class="badge" data-service-count>0</span></div><p class="help">${text('غیرفعال‌سازی فقط منابع همین فوروارد را حذف می‌کند؛ سابقه، مصرف و گروه مسیر حفظ می‌شوند.', 'Disabling removes only this forward’s resources. History, usage and the parent route group remain.')}</p><div data-service-list></div></div></div>`;
  }

  function bindServices(root, {api, t, esc, nodeName, canWrite, requireMonthly, notify}) {
    root.innerHTML = renderServices(t, esc);
    const $ = selector => root.querySelector(selector), form = $('[data-service-form]');
    let routes = [], rows = [], editor = null, proof = null, busy = false, alive = true, epoch = 0, formRevision = 0;
    const details = new Map(), rowBusy = new Set();
    let expiryTimer, routeOptionsKey = '', messageValue = () => '', messageError = false;
    const endpoint = '/api/mesh/services';
    const address = (host, port) => `${String(host).includes(':') ? '[' + host + ']' : host}:${port}`;
    function errorText(error) {
      const value = error.message || String(error);
      if (value === 'fresh service coexistence inspection failed or found a conflict') return t('پورت اشغال است یا بررسی آدرس و سلامت مسیر کامل نشد؛ تنظیمات را بررسی و دوباره تلاش کنید.', value);
      if (value.startsWith('subscription expired;')) return t('کار جدید نیازمند فعال‌سازی اشتراک توسط مدیر است؛ مشاهده و توقف فورواردهای خودتان همچنان مجاز است.', value);
      return value;
    }
    const states = () => ({ACTIVE: t('فعال', 'Active'), APPLYING: t('در حال نصب', 'Applying'),
      UPDATING: t('در حال ویرایش', 'Updating'), STOPPING: t('در حال توقف', 'Stopping'),
      STOPPED: t('غیرفعال · سابقه محفوظ', 'Disabled · history retained'), NEEDS_RECOVERY: t('نیازمند بازیابی', 'Needs recovery')});
    const read = () => ({name: form.elements.name.value.trim(), route_id: form.elements.route_id.value,
      bind_host: form.elements.bind_host.value.trim(), bind_port: Number(form.elements.bind_port.value),
      target_host: form.elements.target_host.value.trim(), target_port: Number(form.elements.target_port.value),
      source_cidrs: form.elements.source_cidrs.value.split(/[,\n]/).map(value => value.trim()).filter(Boolean),
      allow_public: form.elements.allow_public.checked});
    function message(value = '', error = false) {
      messageValue = typeof value === 'function' ? value : () => value;
      messageError = error;
      paintMessage();
    }
    function paintMessage() {
      $('[data-service-message]').textContent = messageValue();
      $('[data-service-message]').classList.toggle('bad', messageError);
    }
    function invalidate() {
      formRevision++; proof = null; clearTimeout(expiryTimer);
      $('[data-service-proof]').replaceChildren();
      $('[data-service-apply]').disabled = true;
    }
    function availability() {
      $('[data-service-fields]').disabled = busy || !canWrite || editor?.recover === true;
      form.elements.route_id.disabled = busy || !canWrite || Boolean(editor);
      $('[data-service-preflight]').disabled = busy || !canWrite || !ready(routes.find(route => route.id === form.elements.route_id.value));
      $('[data-service-preset]').disabled = busy || !canWrite || editor?.recover === true;
      $('[data-service-apply]').disabled = busy || !canWrite || !proof;
      $('[data-service-cancel]').disabled = busy;
    }
    function ready(route) {
      return Boolean(route) && ['COMMITTED', 'DEGRADED'].includes(route.state) && route.observed === true &&
        route.runtime?.traffic_control_version === 1 && (!requireMonthly || route.runtime?.monthly_accounting_version === 1);
    }
    function editorHeading() {
      $('[data-service-heading]').textContent = editor?.recover ? t('بازیابی درخواست ثبت‌شده', 'Recover recorded request') :
        editor ? t('ویرایش فوروارد', 'Edit forward') : t('افزودن سرویس', 'Add service');
      $('[data-service-editor-note]').textContent = !canWrite ? t('این حساب فقط اجازهٔ مشاهده دارد.', 'This account is read-only.') :
        editor?.recover ? t('ابتدا همین تنظیمات درخواستی را بازیابی کنید؛ تغییر بعدی پس از بازیابی انجام می‌شود.', 'Recover these recorded settings first; edit them after recovery.') :
        editor ? t('فقط فوروارد هنگام اعمال ویرایش قطع کوتاهی دارد؛ gateway و تونل‌های گروه ری‌استارت نمی‌شوند.', 'Applying an edit briefly interrupts only this forward; the gateway and group members are not restarted.') :
        t('شروع امن: localhost. برای انتشار روی IP شبکه، تأیید صریح و CIDR لازم است.', 'Start on localhost. A network bind requires explicit acknowledgement and CIDRs.');
    }
    function setRoutes(value) {
      routes = value || [];
      const selected = form.elements.route_id.value || editor?.row.route_id || '';
      const active = routes.filter(route => ['COMMITTED', 'DEGRADED'].includes(route.state));
      const options = `<option value="">${esc(t('یک گروه مسیر آماده انتخاب کنید', 'Select a ready route group'))}</option>` +
        active.map(route => `<option value="${esc(route.id)}" ${ready(route) ? '' : 'disabled'}>${esc(nodeName(route.source))} → ${esc(nodeName(route.destination))} · ${esc(route.id.slice(0, 8))}${ready(route) ? '' : ' · ' + esc(t('سلامت/حسابداری تأیید نشده', 'readiness/accounting unconfirmed'))}</option>`).join('');
      const missing = selected && !active.some(route => route.id === selected) ? selected : '';
      if (routeOptionsKey !== options + missing) {
        form.elements.route_id.innerHTML = options;
        if (missing) {
          const option = document.createElement('option'); option.value = missing;
          option.textContent = t('مسیر انتخاب‌شده اکنون آماده نیست', 'Selected route is not ready'); option.disabled = true;
          form.elements.route_id.append(option);
        }
        routeOptionsKey = options + missing;
      }
      form.elements.route_id.value = selected;
      if (proof && !routes.some(route => route.id === proof.spec.route_id && ready(route))) invalidate();
      availability();
    }
    function edit(row, recover = false, clone = false) {
      invalidate(); message();
      editor = clone ? null : {row, recover};
      const value = recover && row.pending_settings ? row.pending_settings : row;
      for (const key of ['name', 'bind_host', 'bind_port', 'target_host', 'target_port']) form.elements[key].value = value[key] ?? '';
      form.elements.route_id.value = value.route_id;
      form.elements.source_cidrs.value = (value.source_cidrs || []).join('\n');
      form.elements.allow_public.checked = clone ? false : value.allow_public === true;
      if (clone) form.elements.name.value = (value.name + t(' · نسخه جدید', ' · copy')).slice(0, 80);
      setRoutes(routes); form.elements.route_id.value = value.route_id;
      editorHeading(); availability();
      $('[data-service-heading]').scrollIntoView({block: 'nearest'});
      if (!recover) form.elements.name.focus();
    }
    function resetEditor() {
      editor = null; form.reset(); invalidate(); message(); setRoutes(routes); editorHeading(); availability();
    }
    function renderRows() {
      const list = $('[data-service-list]');
      const focus = list.contains(document.activeElement) ? document.activeElement.closest('[data-service-row]')?.dataset.serviceRow : null;
      const focusAction = focus ? document.activeElement.dataset.serviceAction : null;
      $('[data-service-count]').textContent = String(rows.filter(row => row.state !== 'STOPPED').length);
      list.innerHTML = rows.map(row => {
        const detail = details.get(row.id), inherited = detail?.inherited;
        const actual = detail?.revision === row.revision && detail?.state === row.state ? detail : null;
        const stopped = row.state === 'STOPPED', pending = ['APPLYING', 'UPDATING', 'STOPPING'].includes(row.state);
        const disabled = !canWrite || pending || rowBusy.has(row.id);
        const control = (action, label, blocked = false) => `<button type="button" data-service-action="${action}" ${blocked ? 'disabled' : ''}>${esc(label)}</button>`;
        return `<article class="service-card" data-service-row="${esc(row.id)}"><div class="row"><h4 class="space">${esc(row.name)}</h4><span class="badge ${actual?.observed ? 'good' : ''}">${esc(states()[row.state] || row.state)}</span></div>
          <div class="service-endpoints"><div><small>${esc(t('شنود روی مبدأ', 'Source listener'))}</small><code dir="ltr">${esc(address(row.bind_host, row.bind_port))}</code><small>${esc(nodeName(row.source))}</small></div><span aria-hidden="true">→</span><div><small>${esc(t('ورودی روی مقصد', 'Destination inbound'))}</small><code dir="ltr">${esc(address(row.target_host, row.target_port))}</code><small>${esc(nodeName(row.destination))}</small></div></div>
          <p class="help">${row.allow_public ? esc(t('مجوز انتشار شبکه ثبت شده؛ آدرس شنود تعیین‌کننده است', 'Network publishing acknowledged; the bind address determines exposure')) : esc(t('فقط localhost', 'Localhost only'))} · <span dir="ltr">${esc((row.source_cidrs || []).join(', ') || t('محدودهٔ محلی', 'local clients'))}</span></p>
          <p class="help">${esc(t('گروه مسیر', 'Route group'))}: <code dir="ltr">${esc(row.route_id.slice(0, 8))}</code> · ${esc(t('نسخه', 'Revision'))} ${esc(row.revision)}</p>
          ${inherited ? `<div class="service-inherits"><span>${esc(inherited.mode === 'balance' ? t('تقسیم اتصال', 'Connection sharing') : t('فیل‌اور', 'Failover'))}</span><span>${esc(inherited.rate_mbps || t('سقف پلن', 'Plan ceiling'))}${inherited.rate_mbps ? ' Mbps' : ''}</span><span>${esc(inherited.max_connections)} ${esc(t('اتصال مشترک', 'shared connections'))}</span><span>${esc(inherited.shared_customer_usage ? t('مصرف در سهمیهٔ مشترک مشتری', 'Usage joins the customer pool') : t('حسابداری گروه مسیر', 'Route-group accounting'))}</span></div>` : `<p class="help">${esc(t('سقف سرعت و مصرف از گروه مسیر به ارث می‌رسد.', 'Speed and usage limits are inherited from the route group.'))}</p>`}
          <p class="help">${esc(actual?.observed ? t('worker و شنود تأیید شدند؛ سلامت برنامهٔ مقصد اندازه‌گیری نشده است.', 'Worker and listener verified; destination application health is not measured.') : stopped ? t('منابع اجرایی حذف شده‌اند؛ تعریف و سابقه حفظ شده است.', 'Runtime resources removed; definition and history retained.') : t('برای مشاهدهٔ تازهٔ worker، وضعیت را بررسی کنید.', 'Check status for a fresh worker observation.'))}</p>
          ${row.error ? `<p class="bad">${esc(t('این عملیات نیازمند بررسی و بازیابی است.', row.error))}</p>` : ''}
          <div class="row service-actions">${control('status', t('بررسی وضعیت', 'Check status'), rowBusy.has(row.id))}
          ${stopped ? control('clone', t('ساخت مشابه', 'Create similar'), !canWrite) : row.state === 'NEEDS_RECOVERY' ? control('recover', t('بررسی و بازیابی', 'Inspect & recover'), disabled) : control('edit', t('ویرایش', 'Edit'), disabled || row.state !== 'ACTIVE')}
          ${!stopped ? control('stop', t('غیرفعال و حذف منابع فوروارد', 'Disable & remove forward resources'), !canWrite || rowBusy.has(row.id) || row.state === 'STOPPING') : ''}</div></article>`;
      }).join('') || `<div class="empty service-empty">${esc(t('هنوز فورواردی ندارید. ابتدا یک گروه مسیر آماده انتخاب کنید.', 'No forwards yet. Select a ready route group to get started.'))}</div>`;
      if (focus && focusAction) list.querySelector(`[data-service-row="${CSS.escape(focus)}"] [data-service-action="${CSS.escape(focusAction)}"]`)?.focus();
    }
    async function refresh() {
      const generation = epoch, value = await api(endpoint);
      if (!alive || generation !== epoch) return;
      rows = value;
      for (const [id, detail] of details) if (!rows.some(row => row.id === id && row.revision === detail.revision && row.state === detail.state)) details.delete(id);
      renderRows();
    }
    form.oninput = form.onchange = () => {invalidate(); message(); availability();};
    form.onsubmit = async event => {
      event.preventDefault(); if (busy || !canWrite || !form.reportValidity()) return;
      invalidate(); busy = true; availability(); message(() => t('در حال بررسی روی نودها…', 'Inspecting on the nodes…'));
      const generation = epoch, inspectedForm = formRevision;
      try {
        const value = read(), request = editor ? {...value, service_id: editor.row.id, expected_revision: editor.row.revision} : value;
        const result = await api(endpoint + '/preflight', request);
        if (!alive || generation !== epoch || inspectedForm !== formRevision) return;
        proof = result;
        $('[data-service-proof]').textContent = t('بررسی موفق؛ فقط همین تنظیمات تا دو دقیقه قابل اعمال است.', 'Inspection passed; only these settings can be applied for up to two minutes.');
        expiryTimer = setTimeout(() => {invalidate(); if (alive) message(() => t('اعتبار بررسی تمام شد؛ دوباره بررسی کنید.', 'Inspection expired; inspect again.'));}, Math.max(0, Math.min(120000, result.expires_at * 1000 - Date.now())));
        message();
      } catch (error) {if (alive && generation === epoch && inspectedForm === formRevision) message(() => errorText(error), true);}
      finally {if (alive && generation === epoch) {busy = false; availability();}}
    };
    root.onclick = async event => {
      const button = event.target.closest('button'); if (!button || !root.contains(button)) return;
      if (button.hasAttribute('data-service-cancel')) {resetEditor(); return;}
      if (button.hasAttribute('data-service-preset')) {
        if (!canWrite || busy) return;
        form.elements.target_host.value = '127.0.0.1'; form.elements.target_port.value = '443';
        if (!form.elements.name.value) form.elements.name.value = t('ورودی کاربر', 'User inbound');
        invalidate(); message(() => t('پورت واقعی ورودی کاربر را تأیید کنید؛ الگو به‌تنهایی سرویس نمی‌سازد.', 'Confirm the actual user inbound port; the preset does not create a service.')); return;
      }
      const generation = epoch;
      if (button.hasAttribute('data-service-refresh')) {
        button.disabled = true;
        try {await refresh();} catch (error) {if (alive && generation === epoch) message(() => errorText(error), true);}
        finally {if (alive && generation === epoch) button.disabled = false;} return;
      }
      if (button.hasAttribute('data-service-apply')) {
        if (busy || !canWrite || !proof) return;
        const accepted = proof, editing = editor;
        const request = {...accepted.spec, request_id: [...crypto.getRandomValues(new Uint8Array(16))].map(value => value.toString(16).padStart(2, '0')).join(''),
          preflight_id: accepted.id, preflight_token: accepted.token,
          ...(editing ? {expected_revision: editing.row.revision} : {})};
        invalidate(); busy = true; availability(); message(() => t('در حال ثبت درخواست…', 'Submitting request…'));
        try {
          const path = editing ? endpoint + '/' + encodeURIComponent(editing.row.id) + (editing.recover ? '/reconcile' : '') : endpoint;
          await api(path, request, editing && !editing.recover ? 'PUT' : 'POST');
          if (!alive || generation !== epoch) return;
          busy = false; resetEditor(); message(() => t('درخواست ثبت شد؛ وضعیت نود را بررسی کنید. گروه مسیر حفظ شده است.', 'Request accepted. Check node status; the parent route group is preserved.'));
          await refresh();
        } catch (error) {if (alive && generation === epoch) {message(() => errorText(error), true); await refresh().catch(() => {});}}
        finally {if (alive && generation === epoch) {busy = false; availability();}} return;
      }
      const card = button.closest('[data-service-row]'), action = button.dataset.serviceAction;
      const row = card && rows.find(value => value.id === card.dataset.serviceRow);
      if (!row || !action || rowBusy.has(row.id)) return;
      if (action === 'edit' || action === 'recover' || action === 'clone') {
        if (canWrite && !busy) edit(row, action === 'recover', action === 'clone'); return;
      }
      if (action === 'stop' && !canWrite) return;
      rowBusy.add(row.id); renderRows();
      try {
        const path = endpoint + '/' + encodeURIComponent(row.id);
        if (action === 'stop') {
          await api(path, undefined, 'DELETE');
          if (!alive || generation !== epoch) return;
          if (editor?.row.id === row.id) resetEditor();
          message(() => t('توقف فقط همین فوروارد ثبت شد؛ گروه مسیر و مصرف حفظ می‌شوند.', 'Stop accepted for this forward only; the route group and usage remain.'));
          await refresh();
        } else if (action === 'status') {
          const detail = await api(path);
          if (!alive || generation !== epoch) return;
          details.set(row.id, detail); rows = rows.map(value => value.id === row.id ? detail : value);
        }
      } catch (error) {if (alive && generation === epoch) {message(() => errorText(error), true); notify?.(errorText(error), true);}}
      finally {if (alive && generation === epoch) {rowBusy.delete(row.id); renderRows();}}
    };
    function translate() {
      root.querySelectorAll('[data-service-label]').forEach(element => {element.textContent = t(element.dataset.fa, element.dataset.en);});
      if (proof) $('[data-service-proof]').textContent = t('بررسی موفق؛ فقط همین تنظیمات تا دو دقیقه قابل اعمال است.', 'Inspection passed; only these settings can be applied for up to two minutes.');
      paintMessage(); editorHeading(); setRoutes(routes); renderRows();
    }
    const timer = setInterval(() => {
      let expired = false;
      for (const detail of details.values()) if (detail.observed && Date.now() / 1000 - (detail.runtime?.updated_at || 0) >= 30) {
        detail.observed = false; expired = true;
      }
      if (alive && expired && !document.hidden) renderRows();
      if (alive && !busy && !document.hidden && rows.some(row => ['APPLYING', 'UPDATING', 'STOPPING'].includes(row.state))) refresh().catch(() => {});
    }, 4000);
    resetEditor();
    return {refresh, setRoutes, translate, destroy() {
      alive = false; epoch++; clearInterval(timer); clearTimeout(expiryTimer); proof = null;
      details.clear(); rows = []; routes = []; editor = null; messageValue = () => ''; root.onclick = null; root.replaceChildren();
    }};
  }
  return {renderServices, bindServices};
})();
