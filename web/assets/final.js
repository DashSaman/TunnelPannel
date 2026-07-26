'use strict';

const FINAL_TEXT = {
  en: {
    refresh: 'Refresh', jobs_title: 'Jobs and operations', jobs_help: 'Recent discovery, inventory and precheck operations.',
    settings_title: 'System settings', settings_help: 'Operational status, users, XHTTP profiles and audit logs.',
    no_jobs: 'No jobs have been recorded.', open: 'Open', users: 'Users', audit: 'Audit log', system: 'System status',
    save: 'Save settings', create_user: 'Create user', username: 'Username', email: 'Email', temporary_password: 'Temporary password',
    role: 'Role', active: 'Active', reset_password: 'Reset password', update: 'Update', configured: 'Configured', not_configured: 'Not configured',
    force_prompt: 'Normal deletion is protected by related records. To permanently remove this endpoint and all related plans/runs/jobs, type its exact name:',
    force_warning: 'This is a database force-delete. Remote tunnel cleanup cannot run on a server that no longer exists.',
    deleted: 'Endpoint deleted.', settings_saved: 'Settings saved.', user_created: 'User created.',
    error: 'Operation failed', direct: 'Direct', cdn: 'CDN', executable: 'Executable', unavailable: 'Not executable yet',
  },
  fa: {
    refresh: 'به‌روزرسانی', jobs_title: 'عملیات‌ها و Jobها', jobs_help: 'تاریخچه شناسایی سرور، Inventory و پیش‌بررسی‌ها.',
    settings_title: 'تنظیمات سیستم', settings_help: 'وضعیت سرویس، کاربران، حالت‌های XHTTP و Audit Log.',
    no_jobs: 'هنوز عملیاتی ثبت نشده است.', open: 'بازکردن', users: 'کاربران', audit: 'گزارش تغییرات', system: 'وضعیت سیستم',
    save: 'ذخیره تنظیمات', create_user: 'ساخت کاربر', username: 'نام کاربری', email: 'ایمیل', temporary_password: 'رمز موقت',
    role: 'نقش', active: 'فعال', reset_password: 'ریست رمز', update: 'اعمال', configured: 'تنظیم شده', not_configured: 'تنظیم نشده',
    force_prompt: 'حذف معمولی به‌خاطر اطلاعات وابسته محافظت شده است. برای حذف دائمی Endpoint و تمام Plan/Run/Jobهای آن، نام دقیقش را وارد کن:',
    force_warning: 'این حذف از دیتابیس اجباری است و برای سروری که دیگر وجود ندارد پاک‌سازی Remote انجام نمی‌شود.',
    deleted: 'Endpoint حذف شد.', settings_saved: 'تنظیمات ذخیره شد.', user_created: 'کاربر ساخته شد.',
    error: 'عملیات ناموفق بود', direct: 'مستقیم', cdn: 'CDN', executable: 'قابل اجرا', unavailable: 'فعلاً غیرقابل اجرا',
  },
  ru: {
    refresh: 'Обновить', jobs_title: 'Задачи и операции', jobs_help: 'Последние операции обнаружения, инвентаризации и проверки.',
    settings_title: 'Настройки системы', settings_help: 'Состояние, пользователи, профили XHTTP и аудит.',
    no_jobs: 'Задачи отсутствуют.', open: 'Открыть', users: 'Пользователи', audit: 'Аудит', system: 'Состояние системы',
    save: 'Сохранить', create_user: 'Создать пользователя', username: 'Имя', email: 'Email', temporary_password: 'Временный пароль',
    role: 'Роль', active: 'Активен', reset_password: 'Сбросить пароль', update: 'Обновить', configured: 'Настроено', not_configured: 'Не настроено',
    force_prompt: 'Обычное удаление защищено связанными данными. Введите точное имя endpoint для полного удаления:',
    force_warning: 'Это принудительное удаление из базы данных без удалённой очистки.', deleted: 'Endpoint удалён.', settings_saved: 'Настройки сохранены.', user_created: 'Пользователь создан.',
    error: 'Ошибка операции', direct: 'Прямой', cdn: 'CDN', executable: 'Исполняемый', unavailable: 'Пока недоступно',
  },
  'zh-CN': {
    refresh: '刷新', jobs_title: '作业与操作', jobs_help: '最近的发现、清单和预检查操作。', settings_title: '系统设置', settings_help: '服务状态、用户、XHTTP 配置和审计。',
    no_jobs: '没有作业。', open: '打开', users: '用户', audit: '审计日志', system: '系统状态', save: '保存设置', create_user: '创建用户', username: '用户名', email: '邮箱', temporary_password: '临时密码',
    role: '角色', active: '启用', reset_password: '重置密码', update: '更新', configured: '已配置', not_configured: '未配置', force_prompt: '普通删除受关联记录保护。请输入端点的准确名称以强制删除：',
    force_warning: '这是数据库强制删除，不会在不存在的远程服务器上清理。', deleted: '端点已删除。', settings_saved: '设置已保存。', user_created: '用户已创建。', error: '操作失败', direct: '直连', cdn: 'CDN', executable: '可执行', unavailable: '暂不可执行',
  },
  de: {
    refresh: 'Aktualisieren', jobs_title: 'Jobs und Vorgänge', jobs_help: 'Letzte Erkennungs-, Inventar- und Vorprüfungsjobs.', settings_title: 'Systemeinstellungen', settings_help: 'Systemstatus, Benutzer, XHTTP-Profile und Audit-Protokoll.',
    no_jobs: 'Keine Jobs vorhanden.', open: 'Öffnen', users: 'Benutzer', audit: 'Audit-Protokoll', system: 'Systemstatus', save: 'Speichern', create_user: 'Benutzer anlegen', username: 'Benutzername', email: 'E-Mail', temporary_password: 'Temporäres Passwort',
    role: 'Rolle', active: 'Aktiv', reset_password: 'Passwort zurücksetzen', update: 'Aktualisieren', configured: 'Konfiguriert', not_configured: 'Nicht konfiguriert', force_prompt: 'Die normale Löschung ist durch verknüpfte Datensätze geschützt. Exakten Endpoint-Namen für die endgültige Löschung eingeben:',
    force_warning: 'Dies ist eine erzwungene Datenbanklöschung ohne Remote-Bereinigung.', deleted: 'Endpoint gelöscht.', settings_saved: 'Einstellungen gespeichert.', user_created: 'Benutzer erstellt.', error: 'Vorgang fehlgeschlagen', direct: 'Direkt', cdn: 'CDN', executable: 'Ausführbar', unavailable: 'Noch nicht ausführbar',
  },
};

function ft(key) {
  return FINAL_TEXT[state.language]?.[key] || FINAL_TEXT.en[key] || key;
}

function finalApiError(data, fallback) {
  const detail = data?.detail ?? data;
  if (typeof detail === 'string') return detail;
  if (detail?.message) return detail.message;
  if (detail?.code) return detail.code;
  try { return JSON.stringify(detail); } catch (_) { return fallback; }
}

function ensureFinalSections() {
  const content = document.querySelector('.content');
  if (!content || document.getElementById('jobsHistorySection')) return;

  const jobs = document.createElement('div');
  jobs.id = 'jobsHistorySection';
  jobs.className = 'card section page-section hidden';
  jobs.innerHTML = `
    <div class="toolbar"><div><h2 id="finalJobsTitle"></h2><small id="finalJobsHelp"></small></div>
    <button class="btn" onclick="loadJobsSection()" id="finalJobsRefresh"></button></div>
    <div id="finalJobsBody" class="final-table-wrap"></div>`;

  const settingsSection = document.createElement('div');
  settingsSection.id = 'settingsSection';
  settingsSection.className = 'card section page-section hidden';
  settingsSection.innerHTML = `
    <div class="toolbar"><div><h2 id="finalSettingsTitle"></h2><small id="finalSettingsHelp"></small></div>
    <button class="btn" onclick="loadSettingsSection()" id="finalSettingsRefresh"></button></div>
    <div id="finalOverview" class="final-metrics"></div>
    <div id="finalSettingsBody"></div>`;

  content.appendChild(jobs);
  content.appendChild(settingsSection);

  document.querySelectorAll('.nav-btn[data-i18n="jobs"]').forEach(button => {
    button.dataset.section = 'jobsHistory';
    button.onclick = loadJobsSection;
  });

  document.querySelectorAll('.nav-btn[data-i18n="settings"]').forEach(button => {
    button.dataset.section = 'settings';
    button.onclick = loadSettingsSection;
  });

  applyFinalLanguage();
}

function applyFinalLanguage() {
  if (!document.getElementById('jobsHistorySection')) return;
  el('finalJobsTitle').textContent = ft('jobs_title');
  el('finalJobsHelp').textContent = ft('jobs_help');
  el('finalJobsRefresh').textContent = ft('refresh');
  el('finalSettingsTitle').textContent = ft('settings_title');
  el('finalSettingsHelp').textContent = ft('settings_help');
  el('finalSettingsRefresh').textContent = ft('refresh');
}

const originalSetLanguage = window.setLanguage || setLanguage;
window.setLanguage = function finalSetLanguage(language) {
  originalSetLanguage(language);
  applyFinalLanguage();
};

async function loadJobsSection() {
  ensureFinalSections();
  showSection('jobsHistory');
  const body = el('finalJobsBody');
  body.innerHTML = '<div class="final-loading">…</div>';

  try {
    const result = await api('/api/v1/ops/jobs?limit=200');
    const items = result.items || [];

    if (!items.length) {
      body.innerHTML = `<div class="empty">${escapeHtml(ft('no_jobs'))}</div>`;
      return;
    }

    body.innerHTML = `
      <table class="final-table"><thead><tr><th>#</th><th>Type</th><th>Endpoint</th><th>Status</th><th>%</th><th>Step</th><th>Time</th><th></th></tr></thead>
      <tbody>${items.map(item => `
        <tr>
          <td>${item.id}</td><td>${escapeHtml(item.job_type)}</td><td>${escapeHtml(item.endpoint_name || '-')}</td>
          <td><span class="badge ${escapeHtml(item.status)}">${escapeHtml(item.status)}</span></td>
          <td>${Number(item.progress || 0)}%</td><td>${escapeHtml(item.current_step || '-')}</td>
          <td>${escapeHtml(item.created_at || '-')}</td>
          <td><button class="btn" onclick="openHistoricalJob(${item.id},${item.endpoint_id || 'null'})">${escapeHtml(ft('open'))}</button></td>
        </tr>
        ${item.error_message ? `<tr class="final-error-row"><td colspan="8">${escapeHtml(item.error_message)}</td></tr>` : ''}
      `).join('')}</tbody></table>`;
  } catch (error) {
    body.innerHTML = `<div class="message error">${escapeHtml(error.message || ft('error'))}</div>`;
  }
}

function openHistoricalJob(jobId, endpointId) {
  startJob(Number(jobId), endpointId ? Number(endpointId) : null, 'history');
}

function metric(label, value) {
  return `<div class="final-metric"><small>${escapeHtml(label)}</small><strong>${escapeHtml(value)}</strong></div>`;
}

function environmentRows(environment) {
  return Object.entries(environment || {}).map(([key, value]) => `
    <div class="final-kv"><span>${escapeHtml(key)}</span><strong>${escapeHtml(
      typeof value === 'boolean' ? (value ? ft('configured') : ft('not_configured')) : value
    )}</strong></div>`).join('');
}

function renderSettingsForm(values) {
  const isSuper = state.user?.role === 'SUPER_ADMIN';
  const fields = [
    ['brand_name', 'Brand name', 'text'], ['brand_short_name', 'Short name', 'text'],
    ['base_url', 'Base URL', 'url'], ['default_language', 'Default language', 'text'],
    ['terminal_retention_days', 'Terminal retention days', 'number'], ['backup_retention_days', 'Backup retention days', 'number'],
    ['xhttp_direct_enabled', 'XHTTP direct enabled', 'checkbox'], ['xhttp_cdn_enabled', 'XHTTP CDN enabled', 'checkbox'],
    ['xhttp_cdn_provider', 'CDN provider', 'text'], ['xhttp_cdn_note', 'CDN note', 'text'],
  ];

  return `<section class="final-block"><h3>⚙️ ${escapeHtml(ft('settings_title'))}</h3>
    <div class="final-form-grid">${fields.map(([key, label, type]) => {
      const value = values?.[key];
      if (type === 'checkbox') {
        return `<label class="final-check"><input id="setting_${key}" type="checkbox" ${value ? 'checked' : ''} ${isSuper ? '' : 'disabled'}><span>${escapeHtml(label)}</span></label>`;
      }
      return `<label><span>${escapeHtml(label)}</span><input id="setting_${key}" type="${type}" value="${escapeHtml(value ?? '')}" ${isSuper ? '' : 'disabled'}></label>`;
    }).join('')}</div>
    ${isSuper ? `<button class="btn btn-primary" onclick="saveFinalSettings()">${escapeHtml(ft('save'))}</button>` : ''}
  </section>`;
}

function renderXhttp(profiles) {
  return `<section class="final-block"><h3>XHTTP</h3><div class="final-profile-grid">${(profiles || []).map(profile => `
    <article class="final-profile"><h4>${escapeHtml(profile.name)}</h4>
    <p>${profile.requires_cdn ? ft('cdn') : ft('direct')} · ${profile.executable ? ft('executable') : ft('unavailable')}</p>
    <code>${escapeHtml(profile.id)}</code>${profile.note ? `<small>${escapeHtml(profile.note)}</small>` : ''}</article>`).join('')}</div></section>`;
}

function renderUsers(users) {
  if (!['ADMIN', 'SUPER_ADMIN'].includes(state.user?.role)) return '';
  const superAdmin = state.user?.role === 'SUPER_ADMIN';

  return `<section class="final-block"><h3>👥 ${escapeHtml(ft('users'))}</h3>
    ${superAdmin ? `<div class="final-user-create">
      <input id="newUserUsername" placeholder="${escapeHtml(ft('username'))}">
      <input id="newUserEmail" type="email" placeholder="${escapeHtml(ft('email'))}">
      <input id="newUserPassword" type="password" placeholder="${escapeHtml(ft('temporary_password'))}">
      <select id="newUserRole"><option>USER</option><option>ADMIN</option><option>SUPER_ADMIN</option></select>
      <button class="btn btn-primary" onclick="createFinalUser()">${escapeHtml(ft('create_user'))}</button>
    </div>` : ''}
    <div class="final-table-wrap"><table class="final-table"><thead><tr><th>#</th><th>${escapeHtml(ft('username'))}</th><th>${escapeHtml(ft('email'))}</th><th>${escapeHtml(ft('role'))}</th><th>${escapeHtml(ft('active'))}</th><th>Telegram</th><th></th></tr></thead>
    <tbody>${(users || []).map(item => `<tr><td>${item.id}</td><td>${escapeHtml(item.username)}</td><td>${escapeHtml(item.email || '-')}</td>
      <td>${superAdmin ? `<select id="userRole_${item.id}"><option ${item.role==='USER'?'selected':''}>USER</option><option ${item.role==='ADMIN'?'selected':''}>ADMIN</option><option ${item.role==='SUPER_ADMIN'?'selected':''}>SUPER_ADMIN</option></select>` : escapeHtml(item.role)}</td>
      <td>${superAdmin ? `<input id="userActive_${item.id}" type="checkbox" ${item.is_active?'checked':''}>` : (item.is_active ? '✓' : '✗')}</td>
      <td>${escapeHtml(item.telegram_id || '-')}</td><td>${superAdmin ? `<button class="btn" onclick="updateFinalUser(${item.id})">${escapeHtml(ft('update'))}</button> <button class="btn" onclick="resetFinalUserPassword(${item.id})">${escapeHtml(ft('reset_password'))}</button>` : ''}</td></tr>`).join('')}</tbody></table></div></section>`;
}

function renderAudit(items) {
  if (!['ADMIN', 'SUPER_ADMIN'].includes(state.user?.role)) return '';
  return `<section class="final-block"><h3>📜 ${escapeHtml(ft('audit'))}</h3><div class="final-table-wrap"><table class="final-table"><thead><tr><th>#</th><th>Action</th><th>Target</th><th>User</th><th>Time</th></tr></thead>
  <tbody>${(items || []).map(item => `<tr title="${escapeHtml(item.details || '')}"><td>${item.id}</td><td>${escapeHtml(item.action)}</td><td>${escapeHtml(`${item.target_type || '-'} #${item.target_id || '-'}`)}</td><td>${escapeHtml(item.actor_user_id || '-')}</td><td>${escapeHtml(item.created_at || '-')}</td></tr>`).join('')}</tbody></table></div></section>`;
}

async function loadSettingsSection() {
  ensureFinalSections();
  showSection('settings');
  el('finalSettingsBody').innerHTML = '<div class="final-loading">…</div>';

  try {
    const [overview, settingsData, xhttp, users, auditData] = await Promise.all([
      api('/api/v1/ops/overview'), api('/api/v1/ops/settings'), api('/api/v1/ops/xhttp-profiles'),
      ['ADMIN','SUPER_ADMIN'].includes(state.user?.role) ? api('/api/v1/ops/users') : Promise.resolve({items:[]}),
      ['ADMIN','SUPER_ADMIN'].includes(state.user?.role) ? api('/api/v1/ops/audit?limit=100') : Promise.resolve({items:[]}),
    ]);

    const counts = overview.counts || {};
    el('finalOverview').innerHTML = [
      metric('Endpoints', `${counts.endpoints?.ready || 0}/${counts.endpoints?.total || 0}`),
      metric('Active jobs', counts.jobs?.active || 0), metric('Failed jobs', counts.jobs?.failed || 0),
      metric('Plans', counts.plans?.total || 0), metric('Version', overview.version || '-'),
    ].join('');

    el('finalSettingsBody').innerHTML = `
      <section class="final-block"><h3>🩺 ${escapeHtml(ft('system'))}</h3><div class="final-kv-grid">${environmentRows(settingsData.environment)}</div></section>
      ${renderSettingsForm(settingsData.values)}${renderXhttp(xhttp.profiles)}${renderUsers(users.items)}${renderAudit(auditData.items)}`;
  } catch (error) {
    el('finalSettingsBody').innerHTML = `<div class="message error">${escapeHtml(error.message || ft('error'))}</div>`;
  }
}

async function saveFinalSettings() {
  try {
  const values = {};
  ['brand_name','brand_short_name','base_url','default_language','xhttp_cdn_provider','xhttp_cdn_note'].forEach(key => {
    values[key] = el(`setting_${key}`).value.trim();
  });
  ['terminal_retention_days','backup_retention_days'].forEach(key => { values[key] = Number(el(`setting_${key}`).value || 0); });
  ['xhttp_direct_enabled','xhttp_cdn_enabled'].forEach(key => { values[key] = el(`setting_${key}`).checked; });
  await api('/api/v1/ops/settings', {method:'PUT', body:{values}});
  alert(ft('settings_saved'));
  await loadSettingsSection();
  } catch (error) { alert(error.message || ft('error')); }
}

async function createFinalUser() {
  try {
  const body = {
    username: el('newUserUsername').value.trim(), email: el('newUserEmail').value.trim() || null,
    password: el('newUserPassword').value, role: el('newUserRole').value, is_active: true,
  };
  await api('/api/v1/ops/users', {method:'POST', body});
  alert(ft('user_created'));
  await loadSettingsSection();
  } catch (error) { alert(error.message || ft('error')); }
}

async function updateFinalUser(userId) {
  try {
    await api(`/api/v1/ops/users/${userId}`, {method:'PATCH', body:{role:el(`userRole_${userId}`).value,is_active:el(`userActive_${userId}`).checked}});
    await loadSettingsSection();
  } catch (error) { alert(error.message || ft('error')); }
}

async function resetFinalUserPassword(userId) {
  try {
    const result = await api(`/api/v1/ops/users/${userId}/reset-password`, {method:'POST', body:{}});
    if (result.temporary_password) alert(`${ft('temporary_password')}:\n${result.temporary_password}`);
  } catch (error) { alert(error.message || ft('error')); }
}

async function finalDeleteEndpoint(endpointId) {
  const endpoint = state.endpointMap?.[String(endpointId)];
  if (!endpoint || !confirm(t('confirm_delete'))) return;

  const headers = state.token ? {Authorization:`Bearer ${state.token}`} : {};
  const response = await fetch(`/api/v1/endpoints/${endpointId}`, {method:'DELETE', headers});
  let data = {};
  try { data = await response.json(); } catch (_) {}

  if (response.ok) {
    alert(ft('deleted'));
    await loadEndpoints();
    return;
  }

  if (state.user?.role !== 'SUPER_ADMIN') {
    alert(finalApiError(data, ft('error')));
    return;
  }

  const typed = prompt(`${ft('force_prompt')}\n\n${ft('force_warning')}\n\n${endpoint.name}`);
  if (typed !== endpoint.name) return;

  const force = await fetch(`/api/v1/ops/endpoints/${endpointId}/force?confirmation=${encodeURIComponent(typed)}`, {method:'DELETE', headers});
  let forceData = {};
  try { forceData = await force.json(); } catch (_) {}
  if (!force.ok) {
    alert(finalApiError(forceData, ft('error')));
    return;
  }
  alert(ft('deleted'));
  await loadEndpoints();
}

window.loadJobsSection = loadJobsSection;
window.loadSettingsSection = loadSettingsSection;
window.openHistoricalJob = openHistoricalJob;
window.saveFinalSettings = saveFinalSettings;
window.createFinalUser = createFinalUser;
window.updateFinalUser = updateFinalUser;
window.resetFinalUserPassword = resetFinalUserPassword;
window.deleteEndpoint = finalDeleteEndpoint;
window.removeEndpoint = finalDeleteEndpoint;

ensureFinalSections();
