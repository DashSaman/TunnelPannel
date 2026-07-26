'use strict';

(() => {
  const TEXT = {
    en: {
      dashboard: 'Dashboard',
      endpoints: 'Endpoints',
      connectivity: 'Connectivity check',
      composer: 'Tunnel builder',
      jobs: 'Jobs',
      users: 'Users',
      audit: 'Audit log',
      settings: 'Settings',
      dashboard_title: 'Operations dashboard',
      dashboard_help: 'Live status of endpoints, jobs and tunnel plans.',
      ready_endpoints: 'Ready endpoints',
      active_jobs: 'Active jobs',
      failed_jobs: 'Failed jobs',
      tunnel_plans: 'Tunnel plans',
      quick_actions: 'Quick actions',
      recent_jobs: 'Recent jobs',
      add_endpoint: 'Add endpoint',
      run_precheck: 'Run bidirectional precheck',
      build_tunnel: 'Build tunnel plan',
      open_jobs: 'Open jobs',
      refresh: 'Refresh',
      no_jobs: 'No jobs have been recorded.',
      no_access: 'You do not have permission to open this section.',
      create_user: 'Create user',
      username: 'Username',
      email: 'Email',
      password: 'Temporary password',
      role: 'Role',
      active: 'Active',
      update: 'Update',
      reset_password: 'Reset password',
      user_created: 'User created.',
      user_updated: 'User updated.',
      password_reset: 'Temporary password',
      action: 'Action',
      target: 'Target',
      actor: 'User',
      time: 'Time',
      system_ready: 'System is online',
      public_landing: 'Public landing page',
      api_docs: 'API documentation',
      control_panel: 'Control panel',
      user_panel: 'User panel'
    },
    fa: {
      dashboard: 'داشبورد',
      endpoints: 'سرورها',
      connectivity: 'پیش‌بررسی ارتباط',
      composer: 'ساخت تونل',
      jobs: 'عملیات‌ها',
      users: 'کاربران',
      audit: 'گزارش تغییرات',
      settings: 'تنظیمات',
      dashboard_title: 'داشبورد عملیات',
      dashboard_help: 'وضعیت زنده سرورها، عملیات‌ها و پلن‌های تونل.',
      ready_endpoints: 'سرور آماده',
      active_jobs: 'عملیات فعال',
      failed_jobs: 'عملیات ناموفق',
      tunnel_plans: 'پلن تونل',
      quick_actions: 'دسترسی سریع',
      recent_jobs: 'آخرین عملیات‌ها',
      add_endpoint: 'افزودن سرور',
      run_precheck: 'اجرای پیش‌بررسی دوطرفه',
      build_tunnel: 'ساخت پلن تونل',
      open_jobs: 'مشاهده عملیات‌ها',
      refresh: 'به‌روزرسانی',
      no_jobs: 'هنوز عملیاتی ثبت نشده است.',
      no_access: 'اجازه مشاهده این بخش را نداری.',
      create_user: 'ساخت کاربر',
      username: 'نام کاربری',
      email: 'ایمیل',
      password: 'رمز موقت',
      role: 'نقش',
      active: 'فعال',
      update: 'اعمال',
      reset_password: 'ریست رمز',
      user_created: 'کاربر ساخته شد.',
      user_updated: 'کاربر به‌روزرسانی شد.',
      password_reset: 'رمز موقت',
      action: 'عملیات',
      target: 'هدف',
      actor: 'کاربر',
      time: 'زمان',
      system_ready: 'سامانه آنلاین است',
      public_landing: 'صفحه عمومی',
      api_docs: 'مستندات API',
      control_panel: 'پنل مدیریت',
      user_panel: 'پنل کاربر'
    },
    ru: {
      dashboard: 'Панель',
      endpoints: 'Серверы',
      connectivity: 'Проверка связи',
      composer: 'Конструктор туннелей',
      jobs: 'Задачи',
      users: 'Пользователи',
      audit: 'Аудит',
      settings: 'Настройки',
      dashboard_title: 'Операционная панель',
      dashboard_help: 'Состояние серверов, задач и планов туннелей.',
      ready_endpoints: 'Готовые серверы',
      active_jobs: 'Активные задачи',
      failed_jobs: 'Ошибки',
      tunnel_plans: 'Планы туннелей',
      quick_actions: 'Быстрые действия',
      recent_jobs: 'Последние задачи',
      add_endpoint: 'Добавить сервер',
      run_precheck: 'Двусторонняя проверка',
      build_tunnel: 'Создать туннель',
      open_jobs: 'Открыть задачи',
      refresh: 'Обновить',
      no_jobs: 'Задач пока нет.',
      no_access: 'Недостаточно прав.',
      create_user: 'Создать пользователя',
      username: 'Имя',
      email: 'Email',
      password: 'Временный пароль',
      role: 'Роль',
      active: 'Активен',
      update: 'Обновить',
      reset_password: 'Сбросить пароль',
      user_created: 'Пользователь создан.',
      user_updated: 'Пользователь обновлён.',
      password_reset: 'Временный пароль',
      action: 'Действие',
      target: 'Объект',
      actor: 'Пользователь',
      time: 'Время',
      system_ready: 'Система работает',
      public_landing: 'Главная',
      api_docs: 'API',
      control_panel: 'Панель управления',
      user_panel: 'Панель пользователя'
    },
    'zh-CN': {
      dashboard: '仪表盘',
      endpoints: '服务器',
      connectivity: '连接检查',
      composer: '隧道构建器',
      jobs: '任务',
      users: '用户',
      audit: '审计日志',
      settings: '设置',
      dashboard_title: '运维仪表盘',
      dashboard_help: '服务器、任务和隧道计划的实时状态。',
      ready_endpoints: '就绪服务器',
      active_jobs: '活动任务',
      failed_jobs: '失败任务',
      tunnel_plans: '隧道计划',
      quick_actions: '快捷操作',
      recent_jobs: '最近任务',
      add_endpoint: '添加服务器',
      run_precheck: '双向预检查',
      build_tunnel: '创建隧道计划',
      open_jobs: '查看任务',
      refresh: '刷新',
      no_jobs: '暂无任务。',
      no_access: '没有权限。',
      create_user: '创建用户',
      username: '用户名',
      email: '邮箱',
      password: '临时密码',
      role: '角色',
      active: '启用',
      update: '更新',
      reset_password: '重置密码',
      user_created: '用户已创建。',
      user_updated: '用户已更新。',
      password_reset: '临时密码',
      action: '操作',
      target: '目标',
      actor: '用户',
      time: '时间',
      system_ready: '系统在线',
      public_landing: '主页',
      api_docs: 'API 文档',
      control_panel: '管理面板',
      user_panel: '用户面板'
    },
    de: {
      dashboard: 'Dashboard',
      endpoints: 'Server',
      connectivity: 'Verbindungsprüfung',
      composer: 'Tunnel-Builder',
      jobs: 'Aufgaben',
      users: 'Benutzer',
      audit: 'Audit-Protokoll',
      settings: 'Einstellungen',
      dashboard_title: 'Betriebsübersicht',
      dashboard_help: 'Live-Status von Servern, Aufgaben und Tunnelplänen.',
      ready_endpoints: 'Bereite Server',
      active_jobs: 'Aktive Aufgaben',
      failed_jobs: 'Fehlgeschlagen',
      tunnel_plans: 'Tunnelpläne',
      quick_actions: 'Schnellzugriff',
      recent_jobs: 'Letzte Aufgaben',
      add_endpoint: 'Server hinzufügen',
      run_precheck: 'Bidirektionale Prüfung',
      build_tunnel: 'Tunnelplan erstellen',
      open_jobs: 'Aufgaben öffnen',
      refresh: 'Aktualisieren',
      no_jobs: 'Noch keine Aufgaben.',
      no_access: 'Keine Berechtigung.',
      create_user: 'Benutzer erstellen',
      username: 'Benutzername',
      email: 'E-Mail',
      password: 'Temporäres Passwort',
      role: 'Rolle',
      active: 'Aktiv',
      update: 'Aktualisieren',
      reset_password: 'Passwort zurücksetzen',
      user_created: 'Benutzer erstellt.',
      user_updated: 'Benutzer aktualisiert.',
      password_reset: 'Temporäres Passwort',
      action: 'Aktion',
      target: 'Ziel',
      actor: 'Benutzer',
      time: 'Zeit',
      system_ready: 'System ist online',
      public_landing: 'Startseite',
      api_docs: 'API-Dokumentation',
      control_panel: 'Verwaltung',
      user_panel: 'Benutzerbereich'
    }
  };

  const ws = {
    firstDashboardOpen: false
  };

  function lang() {
    const value =
      (
        typeof state !== 'undefined' &&
        state.language
      ) ||
      localStorage.getItem('netauto_language') ||
      'en';
    return TEXT[value] ? value : 'en';
  }

  function tr(key) {
    return TEXT[lang()]?.[key] || TEXT.en[key] || key;
  }

  function esc(value) {
    if (typeof window.escapeHtml === 'function') {
      return window.escapeHtml(String(value ?? ''));
    }
    const node = document.createElement('div');
    node.textContent = String(value ?? '');
    return node.innerHTML;
  }

  function byId(id) {
    return document.getElementById(id);
  }

  function currentRole() {
    const stateRole =
      typeof state !== 'undefined'
        ? state.user?.role
        : null;

    if (stateRole) {
      return stateRole;
    }

    const account =
      byId('accountName')?.textContent ||
      '';

    if (account.includes('SUPER_ADMIN')) {
      return 'SUPER_ADMIN';
    }

    if (account.includes('ADMIN')) {
      return 'ADMIN';
    }

    if (account.includes('USER')) {
      return 'USER';
    }

    return null;
  }

  function isAdmin() {
    return ['ADMIN', 'SUPER_ADMIN'].includes(
      currentRole()
    );
  }

  function isSuperAdmin() {
    return currentRole() === 'SUPER_ADMIN';
  }

  function show(name) {
    if (typeof window.showSection === 'function') {
      window.showSection(name);
    }
  }

  function badge(status) {
    const safe = esc(status || 'UNKNOWN');
    return `<span class="badge ${safe}">${safe}</span>`;
  }

  function formatTime(value) {
    if (!value) return '-';
    try {
      return new Intl.DateTimeFormat(lang(), {
        dateStyle: 'medium',
        timeStyle: 'short'
      }).format(new Date(value));
    } catch (_) {
      return value;
    }
  }

  function metric(icon, label, value, tone = '') {
    return `
      <article class="ws-metric ${tone}">
        <div class="ws-metric-icon">${icon}</div>
        <div>
          <small>${esc(label)}</small>
          <strong>${esc(value)}</strong>
        </div>
      </article>
    `;
  }

  function ensureSections() {
    const content = document.querySelector('.content');
    if (!content || byId('workspaceDashboardSection')) return;

    const dashboard = document.createElement('section');
    dashboard.id = 'workspaceDashboardSection';
    dashboard.className = 'card section page-section hidden';
    dashboard.innerHTML = `
      <div class="toolbar ws-toolbar">
        <div>
          <h2 id="wsDashboardTitle"></h2>
          <small id="wsDashboardHelp"></small>
        </div>
        <button class="btn" id="wsDashboardRefresh" type="button"></button>
      </div>
      <div id="wsDashboardMetrics" class="ws-metrics"></div>
      <section class="ws-panel">
        <h3 id="wsQuickTitle"></h3>
        <div class="ws-quick-actions">
          <button class="ws-action" id="wsAddEndpoint" type="button">＋</button>
          <button class="ws-action" id="wsPrecheck" type="button">⇄</button>
          <button class="ws-action" id="wsComposer" type="button">🧩</button>
          <button class="ws-action" id="wsJobs" type="button">▦</button>
        </div>
      </section>
      <section class="ws-panel">
        <div class="ws-panel-head">
          <h3 id="wsRecentJobsTitle"></h3>
          <button class="btn" id="wsOpenJobs" type="button"></button>
        </div>
        <div id="wsRecentJobs"></div>
      </section>
    `;

    const users = document.createElement('section');
    users.id = 'workspaceUsersSection';
    users.className = 'card section page-section hidden';
    users.innerHTML = `
      <div class="toolbar">
        <div>
          <h2 id="wsUsersTitle"></h2>
          <small id="wsUsersHelp"></small>
        </div>
        <button class="btn" id="wsUsersRefresh" type="button"></button>
      </div>
      <div id="wsUsersBody"></div>
    `;

    const audit = document.createElement('section');
    audit.id = 'workspaceAuditSection';
    audit.className = 'card section page-section hidden';
    audit.innerHTML = `
      <div class="toolbar">
        <div>
          <h2 id="wsAuditTitle"></h2>
          <small id="wsAuditHelp"></small>
        </div>
        <button class="btn" id="wsAuditRefresh" type="button"></button>
      </div>
      <div id="wsAuditBody"></div>
    `;

    content.prepend(dashboard);
    content.append(users, audit);

    byId('wsDashboardRefresh').onclick = loadDashboard;
    byId('wsAddEndpoint').onclick = () => window.startWizard?.();
    byId('wsPrecheck').onclick = () => window.showPrecheck?.();
    byId('wsComposer').onclick = () => {
      window.location.href = '/composer';
    };
    byId('wsJobs').onclick = () => window.loadJobsSection?.();
    byId('wsOpenJobs').onclick = () => window.loadJobsSection?.();
    byId('wsUsersRefresh').onclick = loadUsers;
    byId('wsAuditRefresh').onclick = loadAudit;

    applyLanguage();
  }

  function navButton(section, key, icon, handler, extraClass = '') {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `nav-btn ${extraClass}`.trim();
    button.dataset.section = section;
    button.dataset.wsText = key;
    button.innerHTML = `<span class="ws-nav-icon">${icon}</span><span>${esc(tr(key))}</span>`;
    button.onclick = handler;
    return button;
  }

  function patchSidebar() {
    const sidebar = document.querySelector('.sidebar');
    if (!sidebar || sidebar.dataset.workspaceV2 === '1') return;

    sidebar.dataset.workspaceV2 = '1';
    sidebar.innerHTML = '';

    sidebar.append(
      navButton('workspaceDashboard', 'dashboard', '⌂', loadDashboard),
      navButton('endpoints', 'endpoints', '▣', () => window.loadEndpoints?.()),
      navButton('precheck', 'connectivity', '⇄', () => window.showPrecheck?.()),
      navButton('composer', 'composer', '◇', () => {
        window.location.href = '/composer';
      }),
      navButton('jobsHistory', 'jobs', '▦', () => window.loadJobsSection?.()),
      navButton('workspaceUsers', 'users', '♙', loadUsers, 'ws-admin-only'),
      navButton('workspaceAudit', 'audit', '≡', loadAudit, 'ws-admin-only'),
      navButton('settings', 'settings', '⚙', () => window.loadSettingsSection?.())
    );

    updateRoleVisibility();
    applyLanguage();
  }

  function updateRoleVisibility() {
    document.querySelectorAll('.ws-admin-only').forEach((item) => {
      item.classList.toggle('hidden', !isAdmin());
    });
  }

  function applyLanguage() {
    const rtl = lang() === 'fa';
    document.documentElement.lang = lang();
    document.documentElement.dir = rtl ? 'rtl' : 'ltr';

    document.querySelectorAll('[data-ws-text]').forEach((node) => {
      const key = node.dataset.wsText;
      const span = node.querySelector('span:last-child');
      if (span) span.textContent = tr(key);
      else node.textContent = tr(key);
    });

    const textMap = {
      wsDashboardTitle: 'dashboard_title',
      wsDashboardHelp: 'dashboard_help',
      wsDashboardRefresh: 'refresh',
      wsQuickTitle: 'quick_actions',
      wsRecentJobsTitle: 'recent_jobs',
      wsOpenJobs: 'open_jobs',
      wsUsersTitle: 'users',
      wsUsersHelp: 'create_user',
      wsUsersRefresh: 'refresh',
      wsAuditTitle: 'audit',
      wsAuditHelp: 'audit',
      wsAuditRefresh: 'refresh'
    };

    Object.entries(textMap).forEach(([id, key]) => {
      const node = byId(id);
      if (node) node.textContent = tr(key);
    });

    const actionLabels = [
      ['wsAddEndpoint', 'add_endpoint', '＋'],
      ['wsPrecheck', 'run_precheck', '⇄'],
      ['wsComposer', 'build_tunnel', '🧩'],
      ['wsJobs', 'open_jobs', '▦']
    ];

    actionLabels.forEach(([id, key, icon]) => {
      const node = byId(id);

      if (!node) {
        return;
      }

      node.innerHTML =
        `<strong>${esc(icon)}</strong>` +
        `<span>${esc(tr(key))}</span>`;
    });
  }

  function recentJobsTable(items) {
    if (!items?.length) {
      return `<div class="empty">${esc(tr('no_jobs'))}</div>`;
    }

    return `
      <div class="ws-table-wrap">
        <table class="ws-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Type</th>
              <th>Endpoint</th>
              <th>Status</th>
              <th>%</th>
              <th>${esc(tr('time'))}</th>
            </tr>
          </thead>
          <tbody>
            ${items.map((item) => `
              <tr>
                <td>${esc(item.id)}</td>
                <td>${esc(item.job_type)}</td>
                <td>${esc(item.endpoint_name || '-')}</td>
                <td>${badge(item.status)}</td>
                <td>${esc(Number(item.progress || 0))}%</td>
                <td>${esc(formatTime(item.created_at))}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  async function loadDashboard() {
    ensureSections();
    patchSidebar();
    show('workspaceDashboard');
    updateRoleVisibility();

    const metrics = byId('wsDashboardMetrics');
    const jobsBox = byId('wsRecentJobs');
    metrics.innerHTML = '<div class="ws-loading">…</div>';
    jobsBox.innerHTML = '<div class="ws-loading">…</div>';

    try {
      const [overview, jobs] = await Promise.all([
        window.api('/api/v1/ops/overview'),
        window.api('/api/v1/ops/jobs?limit=8')
      ]);

      const counts = overview.counts || {};
      metrics.innerHTML = [
        metric('✓', tr('ready_endpoints'), `${counts.endpoints?.ready || 0}/${counts.endpoints?.total || 0}`, 'success'),
        metric('↻', tr('active_jobs'), counts.jobs?.active || 0, 'info'),
        metric('!', tr('failed_jobs'), counts.jobs?.failed || 0, 'danger'),
        metric('◇', tr('tunnel_plans'), counts.plans?.total || 0, 'purple')
      ].join('');

      jobsBox.innerHTML = recentJobsTable(jobs.items || []);
    } catch (error) {
      metrics.innerHTML = `<div class="message error">${esc(error.message || 'Error')}</div>`;
      jobsBox.innerHTML = '';
    }
  }

  function usersTable(items) {
    const createForm = isSuperAdmin() ? `
      <div class="ws-create-user">
        <input id="wsNewUsername" placeholder="${esc(tr('username'))}">
        <input id="wsNewEmail" type="email" placeholder="${esc(tr('email'))}">
        <input id="wsNewPassword" type="password" placeholder="${esc(tr('password'))}">
        <select id="wsNewRole">
          <option>USER</option>
          <option>ADMIN</option>
          <option>SUPER_ADMIN</option>
        </select>
        <button class="btn btn-primary" type="button" onclick="workspaceCreateUser()">${esc(tr('create_user'))}</button>
      </div>
    ` : '';

    return `
      ${createForm}
      <div class="ws-table-wrap">
        <table class="ws-table">
          <thead>
            <tr>
              <th>#</th>
              <th>${esc(tr('username'))}</th>
              <th>${esc(tr('email'))}</th>
              <th>${esc(tr('role'))}</th>
              <th>${esc(tr('active'))}</th>
              <th>Telegram</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            ${(items || []).map((item) => `
              <tr>
                <td>${item.id}</td>
                <td>${esc(item.username)}</td>
                <td>${esc(item.email || '-')}</td>
                <td>
                  ${isSuperAdmin() ? `
                    <select id="wsRole_${item.id}">
                      <option ${item.role === 'USER' ? 'selected' : ''}>USER</option>
                      <option ${item.role === 'ADMIN' ? 'selected' : ''}>ADMIN</option>
                      <option ${item.role === 'SUPER_ADMIN' ? 'selected' : ''}>SUPER_ADMIN</option>
                    </select>
                  ` : esc(item.role)}
                </td>
                <td>
                  ${isSuperAdmin() ? `
                    <input id="wsActive_${item.id}" type="checkbox" ${item.is_active ? 'checked' : ''}>
                  ` : (item.is_active ? '✓' : '✗')}
                </td>
                <td>${esc(item.telegram_id || '-')}</td>
                <td class="ws-row-actions">
                  ${isSuperAdmin() ? `
                    <button class="btn" type="button" onclick="workspaceUpdateUser(${item.id})">${esc(tr('update'))}</button>
                    <button class="btn" type="button" onclick="workspaceResetPassword(${item.id})">${esc(tr('reset_password'))}</button>
                  ` : ''}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  async function loadUsers() {
    ensureSections();
    patchSidebar();
    show('workspaceUsers');

    const body = byId('wsUsersBody');
    if (!isAdmin()) {
      body.innerHTML = `<div class="message error">${esc(tr('no_access'))}</div>`;
      return;
    }

    body.innerHTML = '<div class="ws-loading">…</div>';

    try {
      const result = await window.api('/api/v1/ops/users');
      body.innerHTML = usersTable(result.items || []);
    } catch (error) {
      body.innerHTML = `<div class="message error">${esc(error.message || 'Error')}</div>`;
    }
  }

  async function createUser() {
    const body = {
      username: byId('wsNewUsername').value.trim(),
      email: byId('wsNewEmail').value.trim() || null,
      password: byId('wsNewPassword').value,
      role: byId('wsNewRole').value,
      is_active: true
    };

    try {
      await window.api('/api/v1/ops/users', {
        method: 'POST',
        body
      });
      window.alert(tr('user_created'));
      await loadUsers();
    } catch (error) {
      window.alert(error.message || 'Error');
    }
  }

  async function updateUser(userId) {
    try {
      await window.api(`/api/v1/ops/users/${userId}`, {
        method: 'PATCH',
        body: {
          role: byId(`wsRole_${userId}`).value,
          is_active: byId(`wsActive_${userId}`).checked
        }
      });
      window.alert(tr('user_updated'));
      await loadUsers();
    } catch (error) {
      window.alert(error.message || 'Error');
    }
  }

  async function resetPassword(userId) {
    try {
      const result = await window.api(`/api/v1/ops/users/${userId}/reset-password`, {
        method: 'POST',
        body: {}
      });
      if (result.temporary_password) {
        window.alert(`${tr('password_reset')}:\n${result.temporary_password}`);
      }
    } catch (error) {
      window.alert(error.message || 'Error');
    }
  }

  async function loadAudit() {
    ensureSections();
    patchSidebar();
    show('workspaceAudit');

    const body = byId('wsAuditBody');
    if (!isAdmin()) {
      body.innerHTML = `<div class="message error">${esc(tr('no_access'))}</div>`;
      return;
    }

    body.innerHTML = '<div class="ws-loading">…</div>';

    try {
      const result = await window.api('/api/v1/ops/audit?limit=300');
      const items = result.items || [];
      body.innerHTML = `
        <div class="ws-table-wrap">
          <table class="ws-table">
            <thead>
              <tr>
                <th>#</th>
                <th>${esc(tr('action'))}</th>
                <th>${esc(tr('target'))}</th>
                <th>${esc(tr('actor'))}</th>
                <th>${esc(tr('time'))}</th>
              </tr>
            </thead>
            <tbody>
              ${items.map((item) => `
                <tr title="${esc(item.details || '')}">
                  <td>${item.id}</td>
                  <td>${esc(item.action)}</td>
                  <td>${esc(`${item.target_type || '-'} #${item.target_id || '-'}`)}</td>
                  <td>${esc(item.actor_user_id || '-')}</td>
                  <td>${esc(formatTime(item.created_at))}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;
    } catch (error) {
      body.innerHTML = `<div class="message error">${esc(error.message || 'Error')}</div>`;
    }
  }

  function patchHeader() {
    const topbar = document.querySelector('.topbar');
    if (!topbar || topbar.dataset.workspaceV2 === '1') return;
    topbar.dataset.workspaceV2 = '1';

    const identity = topbar.querySelector('div:first-child');
    if (identity) {
      identity.classList.add('ws-identity');
      const status = document.createElement('span');
      status.className = 'ws-online';
      status.textContent = tr('system_ready');
      identity.appendChild(status);
    }
  }

  const priorSetLanguage = window.setLanguage;
  if (typeof priorSetLanguage === 'function') {
    window.setLanguage = function workspaceSetLanguage(value) {
      priorSetLanguage(value);
      applyLanguage();
    };
  }

  window.workspaceCreateUser = createUser;
  window.workspaceUpdateUser = updateUser;
  window.workspaceResetPassword = resetPassword;
  window.loadWorkspaceDashboard = loadDashboard;
  window.loadWorkspaceUsers = loadUsers;
  window.loadWorkspaceAudit = loadAudit;

  function initialize() {
    ensureSections();
    patchSidebar();
    patchHeader();
    applyLanguage();

    const dashboard = byId('dashboard');
    if (!dashboard) return;

    const openWhenReady = () => {
      if (
        dashboard.classList.contains('hidden') ||
        !(
          typeof state !== 'undefined' &&
          state.user
        ) ||
        ws.firstDashboardOpen
      ) {
        return;
      }

      ws.firstDashboardOpen = true;
      updateRoleVisibility();
      setTimeout(loadDashboard, 120);
    };

    new MutationObserver(openWhenReady).observe(dashboard, {
      attributes: true,
      attributeFilter: ['class']
    });

    const timer = window.setInterval(() => {
      openWhenReady();
      if (ws.firstDashboardOpen) window.clearInterval(timer);
    }, 250);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
  } else {
    initialize();
  }
})();
