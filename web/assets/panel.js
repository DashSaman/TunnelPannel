const I18N = {
  en: {
    brand_subtitle: 'Network management and automation platform',
    login_title: 'Sign in',
    username: 'Username',
    password: 'Password',
    login: 'Sign in',
    logout: 'Logout',
    endpoints: '🖥 Endpoints',
    tunnels: '🔐 Tunnels',
    jobs: '🧰 Jobs',
    settings: '⚙️ Settings',
    endpoint_subtitle: 'Manage Ubuntu and Linux servers',
    add_endpoint: '➕ Add Endpoint',
    no_endpoint: 'No endpoints have been registered.',
    waiting_detection: 'Waiting for detection',
    hostname: 'Hostname',
    interface: 'Interface',
    edit: '✏️ Edit',
    delete: '🗑 Delete',
    confirm_delete: 'Delete this endpoint?',
    previous: '← Previous',
    cancel: 'Cancel',
    continue: 'Continue',
    create_start: 'Create and verify',
    save_start: 'Save and verify again',
    wizard_create: 'Register Ubuntu Endpoint',
    wizard_edit: 'Edit Endpoint',
    running_operation: 'Running operation',
    live_real_steps: 'Real steps are displayed live',
    terminal_title: 'NETAUTO SECURE TERMINAL — READ ONLY',
    pause: 'Pause',
    resume: 'Resume',
    copy: 'Copy',
    download: 'Download',
    tunnel_later: 'Tunnel creation will be enabled after two endpoints are ready.',
    jobs_later: 'The full jobs page will be enabled next.',
    settings_later: 'Settings will be enabled next.',
    required: 'This value is required.',
    invalid_port: 'Port must be between 1 and 65535.',
    error_generic: 'Operation failed.',
    endpoint_deleted: 'Endpoint deleted.',
    secret_received: 'Credentials received securely',
    secret_kept: 'Existing credentials will be kept',
    keep_secret: 'Leave empty to keep the existing credential.',
    show_password: 'Show password',
    hide_password: 'Hide password',

    step_name: 'Endpoint display name',
    help_name: 'Example: Germany Frankfurt Server',
    step_host: 'Server IP address or hostname',
    help_host: 'Enter an IPv4, IPv6 or direct hostname.',
    step_port: 'SSH port',
    help_port: 'The default SSH port is 22.',
    step_ssh_username: 'SSH username',
    help_ssh_username: 'Example: root or ubuntu',
    step_display_location: 'Country, city and datacenter',
    help_display_location: 'Example: Germany — Frankfurt — Hetzner',
    step_auth_method: 'SSH authentication method',
    help_auth_method: 'Choose password or private key.',
    step_secret: 'SSH credential',
    help_secret: 'The credential is encrypted before storage.',
    step_sudo_mode: 'Administrative access',
    help_sudo_mode: 'Select the sudo access type.',
    step_sudo_password: 'Sudo password',
    help_sudo_password: 'This password will be encrypted.',
    step_description: 'Description',
    help_description: 'Optional endpoint notes.',
    step_review: 'Review and confirm',
    password_auth: 'Password',
    key_auth: 'Private Key',
    sudo_none: 'No sudo',
    sudo_nopass: 'Passwordless sudo',
    sudo_password: 'Sudo with password',
    optional: 'Optional',
    endpoint_name: 'Endpoint name',
    host: 'Host',
    port: 'SSH port',
    ssh_user: 'SSH username',
    location: 'Location',
    auth_method: 'Authentication',
    sudo_mode: 'Sudo mode',
    description: 'Description',
    login_secret: 'Credential',


    precheck_title: 'Bidirectional connectivity precheck',
    precheck_help: 'Test routing, ICMP and TCP from A to B and from B to A before creating a tunnel.',
    endpoint_a: 'Endpoint A',
    endpoint_b: 'Endpoint B',
    start_precheck: 'Start bidirectional precheck',
    need_two_ready: 'At least two READY endpoints are required.',
    same_endpoint: 'Select two different endpoints.',
    job_connect_a: 'Connecting securely to endpoint A',
    job_connect_b: 'Connecting securely to endpoint B',
    job_ping_ab: 'Testing ICMP from A to B',
    job_route_ab: 'Inspecting route from A to B',
    job_tcp_ab: 'Testing TCP from A to B',
    job_ping_ba: 'Testing ICMP from B to A',
    job_route_ba: 'Inspecting route from B to A',
    job_tcp_ba: 'Testing TCP from B to A',
    job_summary: 'Preparing bidirectional connectivity result',

    job_queue: 'Waiting in the execution queue',
    job_validate: 'Validating endpoint details',
    job_tcp: 'Checking SSH port connectivity',
    job_ssh: 'Creating secure SSH session',
    job_os: 'Detecting operating system',
    job_arch: 'Detecting system architecture',
    job_hostname: 'Reading hostname',
    job_interfaces: 'Inspecting network interfaces',
    job_route: 'Inspecting default route',
    job_privilege: 'Checking access level',
    job_sudo: 'Checking sudo access',
    job_complete: 'Endpoint is ready',
    job_failed: 'Operation failed'
  },

  fa: {
    brand_subtitle: 'سامانه مدیریت و اتوماسیون شبکه',
    login_title: 'ورود به سامانه',
    username: 'نام کاربری',
    password: 'رمز عبور',
    login: 'ورود',
    logout: 'خروج',
    endpoints: '🖥 Endpointها',
    tunnels: '🔐 تونل‌ها',
    jobs: '🧰 عملیات و Jobها',
    settings: '⚙️ تنظیمات',
    endpoint_subtitle: 'مدیریت سرورهای Ubuntu و Linux',
    add_endpoint: '➕ افزودن Endpoint',
    no_endpoint: 'هنوز هیچ Endpoint ثبت نشده است.',
    waiting_detection: 'در انتظار شناسایی',
    hostname: 'Hostname',
    interface: 'Interface',
    edit: '✏️ ویرایش',
    delete: '🗑 حذف',
    confirm_delete: 'این Endpoint حذف شود؟',
    previous: 'مرحله قبل',
    cancel: 'لغو',
    continue: 'ادامه',
    create_start: 'ثبت و شروع بررسی',
    save_start: 'ذخیره و بررسی مجدد',
    wizard_create: 'ثبت Ubuntu Endpoint',
    wizard_edit: 'ویرایش Endpoint',
    running_operation: 'اجرای عملیات',
    live_real_steps: 'مراحل واقعی به‌صورت زنده نمایش داده می‌شوند',
    terminal_title: 'NETAUTO SECURE TERMINAL — فقط خواندنی',
    pause: 'توقف',
    resume: 'ادامه',
    copy: 'کپی',
    download: 'دانلود',
    tunnel_later: 'بعد از آماده‌شدن دو Endpoint، ساخت تونل فعال می‌شود.',
    jobs_later: 'صفحه کامل Jobها در مرحله بعد فعال می‌شود.',
    settings_later: 'تنظیمات در مرحله بعد فعال می‌شود.',
    required: 'واردکردن این مقدار الزامی است.',
    invalid_port: 'پورت باید بین ۱ تا ۶۵۵۳۵ باشد.',
    error_generic: 'عملیات ناموفق بود.',
    endpoint_deleted: 'Endpoint حذف شد.',
    secret_received: 'اطلاعات ورود امن دریافت شد',
    secret_kept: 'اطلاعات ورود قبلی حفظ می‌شود',
    keep_secret: 'برای حفظ رمز قبلی، این قسمت را خالی بگذار.',
    show_password: 'نمایش رمز',
    hide_password: 'مخفی‌کردن رمز',

    step_name: 'نام نمایشی Endpoint',
    help_name: 'مثلاً سرور آلمان فرانکفورت',
    step_host: 'IP یا دامنه سرور',
    help_host: 'IPv4، IPv6 یا دامنه مستقیم سرور را وارد کن.',
    step_port: 'پورت SSH',
    help_port: 'پورت پیش‌فرض SSH برابر ۲۲ است.',
    step_ssh_username: 'نام کاربری SSH',
    help_ssh_username: 'مثلاً root یا ubuntu',
    step_display_location: 'کشور، شهر و دیتاسنتر',
    help_display_location: 'مثلاً Germany — Frankfurt — Hetzner',
    step_auth_method: 'روش ورود SSH',
    help_auth_method: 'رمز عبور یا Private Key را انتخاب کن.',
    step_secret: 'اطلاعات ورود SSH',
    help_secret: 'اطلاعات ورود پیش از ذخیره رمزنگاری می‌شود.',
    step_sudo_mode: 'دسترسی مدیریتی',
    help_sudo_mode: 'نوع دسترسی sudo را انتخاب کن.',
    step_sudo_password: 'رمز sudo',
    help_sudo_password: 'رمز sudo به‌صورت رمزنگاری‌شده ذخیره می‌شود.',
    step_description: 'توضیحات',
    help_description: 'توضیحات اختیاری Endpoint',
    step_review: 'بررسی و تأیید نهایی',
    password_auth: 'رمز عبور',
    key_auth: 'Private Key',
    sudo_none: 'بدون sudo',
    sudo_nopass: 'sudo بدون رمز',
    sudo_password: 'sudo با رمز',
    optional: 'اختیاری',
    endpoint_name: 'نام Endpoint',
    host: 'آدرس',
    port: 'پورت SSH',
    ssh_user: 'نام کاربری SSH',
    location: 'موقعیت',
    auth_method: 'روش ورود',
    sudo_mode: 'نوع sudo',
    description: 'توضیحات',
    login_secret: 'اطلاعات ورود',


    precheck_title: 'بررسی ارتباط دوطرفه',
    precheck_help: 'پیش از ساخت تونل، مسیر، Ping و TCP از A به B و از B به A بررسی می‌شود.',
    endpoint_a: 'Endpoint اول',
    endpoint_b: 'Endpoint دوم',
    start_precheck: 'شروع بررسی دوطرفه',
    need_two_ready: 'حداقل دو Endpoint با وضعیت READY لازم است.',
    same_endpoint: 'دو Endpoint متفاوت انتخاب کن.',
    job_connect_a: 'اتصال امن به Endpoint اول',
    job_connect_b: 'اتصال امن به Endpoint دوم',
    job_ping_ab: 'بررسی Ping از A به B',
    job_route_ab: 'بررسی مسیر از A به B',
    job_tcp_ab: 'بررسی TCP از A به B',
    job_ping_ba: 'بررسی Ping از B به A',
    job_route_ba: 'بررسی مسیر از B به A',
    job_tcp_ba: 'بررسی TCP از B به A',
    job_summary: 'آماده‌سازی نتیجه ارتباط دوطرفه',

    job_queue: 'در صف اجرای عملیات',
    job_validate: 'بررسی مشخصات Endpoint',
    job_tcp: 'بررسی دسترسی پورت SSH',
    job_ssh: 'ایجاد نشست امن SSH',
    job_os: 'شناسایی سیستم‌عامل',
    job_arch: 'شناسایی معماری سیستم',
    job_hostname: 'دریافت نام میزبان',
    job_interfaces: 'بررسی Interfaceهای شبکه',
    job_route: 'بررسی مسیر پیش‌فرض',
    job_privilege: 'بررسی سطح دسترسی',
    job_sudo: 'بررسی دسترسی sudo',
    job_complete: 'Endpoint آماده استفاده است',
    job_failed: 'عملیات ناموفق بود'
  },

  ru: {
    brand_subtitle: 'Платформа управления и автоматизации сети',
    login_title: 'Вход',
    username: 'Имя пользователя',
    password: 'Пароль',
    login: 'Войти',
    logout: 'Выйти',
    endpoints: '🖥 Серверы',
    tunnels: '🔐 Туннели',
    jobs: '🧰 Задачи',
    settings: '⚙️ Настройки',
    endpoint_subtitle: 'Управление серверами Ubuntu и Linux',
    add_endpoint: '➕ Добавить сервер',
    no_endpoint: 'Серверы еще не зарегистрированы.',
    waiting_detection: 'Ожидание определения',
    hostname: 'Имя хоста',
    interface: 'Интерфейс',
    edit: '✏️ Изменить',
    delete: '🗑 Удалить',
    confirm_delete: 'Удалить этот сервер?',
    previous: '← Назад',
    cancel: 'Отмена',
    continue: 'Продолжить',
    create_start: 'Создать и проверить',
    save_start: 'Сохранить и проверить',
    wizard_create: 'Регистрация Ubuntu сервера',
    wizard_edit: 'Изменение сервера',
    running_operation: 'Выполнение операции',
    live_real_steps: 'Реальные этапы отображаются в реальном времени',
    terminal_title: 'NETAUTO SECURE TERMINAL — ТОЛЬКО ЧТЕНИЕ',
    pause: 'Пауза',
    resume: 'Продолжить',
    copy: 'Копировать',
    download: 'Скачать',
    tunnel_later: 'Туннели станут доступны после подготовки двух серверов.',
    jobs_later: 'Полная страница задач будет добавлена далее.',
    settings_later: 'Настройки будут добавлены далее.',
    required: 'Это поле обязательно.',
    invalid_port: 'Порт должен быть от 1 до 65535.',
    error_generic: 'Операция не выполнена.',
    endpoint_deleted: 'Сервер удален.',
    secret_received: 'Данные доступа получены',
    secret_kept: 'Текущие данные доступа будут сохранены',
    keep_secret: 'Оставьте пустым, чтобы сохранить текущие данные.',
    show_password: 'Показать пароль',
    hide_password: 'Скрыть пароль',

    step_name: 'Название сервера',
    help_name: 'Например: Germany Frankfurt Server',
    step_host: 'IP-адрес или домен',
    help_host: 'Введите IPv4, IPv6 или домен.',
    step_port: 'SSH-порт',
    help_port: 'Стандартный SSH-порт: 22.',
    step_ssh_username: 'Пользователь SSH',
    help_ssh_username: 'Например: root или ubuntu',
    step_display_location: 'Страна, город и дата-центр',
    help_display_location: 'Например: Germany — Frankfurt — Hetzner',
    step_auth_method: 'Метод аутентификации SSH',
    help_auth_method: 'Выберите пароль или приватный ключ.',
    step_secret: 'Данные доступа SSH',
    help_secret: 'Данные будут зашифрованы.',
    step_sudo_mode: 'Административный доступ',
    help_sudo_mode: 'Выберите тип доступа sudo.',
    step_sudo_password: 'Пароль sudo',
    help_sudo_password: 'Пароль будет зашифрован.',
    step_description: 'Описание',
    help_description: 'Необязательные заметки.',
    step_review: 'Проверка и подтверждение',
    password_auth: 'Пароль',
    key_auth: 'Приватный ключ',
    sudo_none: 'Без sudo',
    sudo_nopass: 'sudo без пароля',
    sudo_password: 'sudo с паролем',
    optional: 'Необязательно',
    endpoint_name: 'Название',
    host: 'Адрес',
    port: 'SSH-порт',
    ssh_user: 'Пользователь SSH',
    location: 'Расположение',
    auth_method: 'Аутентификация',
    sudo_mode: 'Режим sudo',
    description: 'Описание',
    login_secret: 'Данные доступа',


    precheck_title: 'Двусторонняя проверка соединения',
    precheck_help: 'Перед созданием туннеля проверяются маршрут, ICMP и TCP в обоих направлениях.',
    endpoint_a: 'Сервер A',
    endpoint_b: 'Сервер B',
    start_precheck: 'Начать проверку',
    need_two_ready: 'Требуются как минимум два готовых сервера.',
    same_endpoint: 'Выберите два разных сервера.',
    job_connect_a: 'Подключение к серверу A',
    job_connect_b: 'Подключение к серверу B',
    job_ping_ab: 'Проверка ICMP от A к B',
    job_route_ab: 'Проверка маршрута от A к B',
    job_tcp_ab: 'Проверка TCP от A к B',
    job_ping_ba: 'Проверка ICMP от B к A',
    job_route_ba: 'Проверка маршрута от B к A',
    job_tcp_ba: 'Проверка TCP от B к A',
    job_summary: 'Подготовка результата проверки',

    job_queue: 'Ожидание в очереди',
    job_validate: 'Проверка параметров',
    job_tcp: 'Проверка SSH-порта',
    job_ssh: 'Создание защищенной SSH-сессии',
    job_os: 'Определение операционной системы',
    job_arch: 'Определение архитектуры',
    job_hostname: 'Получение имени хоста',
    job_interfaces: 'Проверка сетевых интерфейсов',
    job_route: 'Проверка маршрута',
    job_privilege: 'Проверка прав',
    job_sudo: 'Проверка sudo',
    job_complete: 'Сервер готов',
    job_failed: 'Операция не выполнена'
  },

  'zh-CN': {
    brand_subtitle: '网络管理与自动化平台',
    login_title: '登录',
    username: '用户名',
    password: '密码',
    login: '登录',
    logout: '退出',
    endpoints: '🖥 服务器',
    tunnels: '🔐 隧道',
    jobs: '🧰 任务',
    settings: '⚙️ 设置',
    endpoint_subtitle: '管理 Ubuntu 和 Linux 服务器',
    add_endpoint: '➕ 添加服务器',
    no_endpoint: '尚未注册服务器。',
    waiting_detection: '等待检测',
    hostname: '主机名',
    interface: '网络接口',
    edit: '✏️ 编辑',
    delete: '🗑 删除',
    confirm_delete: '确定删除此服务器吗？',
    previous: '← 上一步',
    cancel: '取消',
    continue: '继续',
    create_start: '创建并验证',
    save_start: '保存并重新验证',
    wizard_create: '注册 Ubuntu 服务器',
    wizard_edit: '编辑服务器',
    running_operation: '正在执行',
    live_real_steps: '实时显示真实执行步骤',
    terminal_title: 'NETAUTO 安全终端 — 只读',
    pause: '暂停',
    resume: '继续',
    copy: '复制',
    download: '下载',
    tunnel_later: '两个服务器准备完成后即可创建隧道。',
    jobs_later: '完整任务页面将在下一阶段启用。',
    settings_later: '设置将在下一阶段启用。',
    required: '此项为必填项。',
    invalid_port: '端口必须在 1 到 65535 之间。',
    error_generic: '操作失败。',
    endpoint_deleted: '服务器已删除。',
    secret_received: '登录凭据已安全接收',
    secret_kept: '将保留现有登录凭据',
    keep_secret: '留空可保留现有凭据。',
    show_password: '显示密码',
    hide_password: '隐藏密码',

    step_name: '服务器显示名称',
    help_name: '例如：Germany Frankfurt Server',
    step_host: '服务器 IP 或域名',
    help_host: '请输入 IPv4、IPv6 或域名。',
    step_port: 'SSH 端口',
    help_port: '默认 SSH 端口为 22。',
    step_ssh_username: 'SSH 用户名',
    help_ssh_username: '例如 root 或 ubuntu',
    step_display_location: '国家、城市和数据中心',
    help_display_location: '例如 Germany — Frankfurt — Hetzner',
    step_auth_method: 'SSH 认证方式',
    help_auth_method: '选择密码或私钥。',
    step_secret: 'SSH 登录凭据',
    help_secret: '凭据将在保存前加密。',
    step_sudo_mode: '管理员权限',
    help_sudo_mode: '选择 sudo 访问方式。',
    step_sudo_password: 'sudo 密码',
    help_sudo_password: '密码将被加密。',
    step_description: '说明',
    help_description: '可选服务器说明。',
    step_review: '检查并确认',
    password_auth: '密码',
    key_auth: '私钥',
    sudo_none: '无 sudo',
    sudo_nopass: '免密 sudo',
    sudo_password: '密码 sudo',
    optional: '可选',
    endpoint_name: '服务器名称',
    host: '地址',
    port: 'SSH 端口',
    ssh_user: 'SSH 用户名',
    location: '位置',
    auth_method: '认证方式',
    sudo_mode: 'sudo 模式',
    description: '说明',
    login_secret: '登录凭据',


    precheck_title: '双向连接预检查',
    precheck_help: '创建隧道前检查 A 到 B 和 B 到 A 的路由、ICMP 与 TCP。',
    endpoint_a: '服务器 A',
    endpoint_b: '服务器 B',
    start_precheck: '开始双向检查',
    need_two_ready: '至少需要两个 READY 状态的服务器。',
    same_endpoint: '请选择两个不同的服务器。',
    job_connect_a: '安全连接服务器 A',
    job_connect_b: '安全连接服务器 B',
    job_ping_ab: '检查 A 到 B 的 ICMP',
    job_route_ab: '检查 A 到 B 的路由',
    job_tcp_ab: '检查 A 到 B 的 TCP',
    job_ping_ba: '检查 B 到 A 的 ICMP',
    job_route_ba: '检查 B 到 A 的路由',
    job_tcp_ba: '检查 B 到 A 的 TCP',
    job_summary: '生成双向连接结果',

    job_queue: '等待执行',
    job_validate: '验证服务器信息',
    job_tcp: '检查 SSH 端口',
    job_ssh: '创建安全 SSH 会话',
    job_os: '检测操作系统',
    job_arch: '检测系统架构',
    job_hostname: '读取主机名',
    job_interfaces: '检查网络接口',
    job_route: '检查默认路由',
    job_privilege: '检查权限',
    job_sudo: '检查 sudo 权限',
    job_complete: '服务器已准备完成',
    job_failed: '操作失败'
  },

  de: {
    brand_subtitle: 'Plattform für Netzwerkverwaltung und Automatisierung',
    login_title: 'Anmelden',
    username: 'Benutzername',
    password: 'Passwort',
    login: 'Anmelden',
    logout: 'Abmelden',
    endpoints: '🖥 Server',
    tunnels: '🔐 Tunnel',
    jobs: '🧰 Aufgaben',
    settings: '⚙️ Einstellungen',
    endpoint_subtitle: 'Ubuntu- und Linux-Server verwalten',
    add_endpoint: '➕ Server hinzufügen',
    no_endpoint: 'Noch keine Server registriert.',
    waiting_detection: 'Erkennung ausstehend',
    hostname: 'Hostname',
    interface: 'Schnittstelle',
    edit: '✏️ Bearbeiten',
    delete: '🗑 Löschen',
    confirm_delete: 'Diesen Server löschen?',
    previous: '← Zurück',
    cancel: 'Abbrechen',
    continue: 'Weiter',
    create_start: 'Erstellen und prüfen',
    save_start: 'Speichern und erneut prüfen',
    wizard_create: 'Ubuntu-Server registrieren',
    wizard_edit: 'Server bearbeiten',
    running_operation: 'Vorgang wird ausgeführt',
    live_real_steps: 'Reale Schritte werden live angezeigt',
    terminal_title: 'NETAUTO SECURE TERMINAL — NUR LESEN',
    pause: 'Pause',
    resume: 'Fortsetzen',
    copy: 'Kopieren',
    download: 'Herunterladen',
    tunnel_later: 'Tunnel werden nach zwei bereiten Servern aktiviert.',
    jobs_later: 'Die vollständige Aufgabenseite folgt als Nächstes.',
    settings_later: 'Die Einstellungen folgen als Nächstes.',
    required: 'Dieses Feld ist erforderlich.',
    invalid_port: 'Der Port muss zwischen 1 und 65535 liegen.',
    error_generic: 'Vorgang fehlgeschlagen.',
    endpoint_deleted: 'Server gelöscht.',
    secret_received: 'Zugangsdaten sicher empfangen',
    secret_kept: 'Vorhandene Zugangsdaten bleiben erhalten',
    keep_secret: 'Leer lassen, um vorhandene Zugangsdaten zu behalten.',
    show_password: 'Passwort anzeigen',
    hide_password: 'Passwort ausblenden',

    step_name: 'Anzeigename des Servers',
    help_name: 'Beispiel: Germany Frankfurt Server',
    step_host: 'Server-IP oder Hostname',
    help_host: 'IPv4, IPv6 oder Hostname eingeben.',
    step_port: 'SSH-Port',
    help_port: 'Der Standard-SSH-Port ist 22.',
    step_ssh_username: 'SSH-Benutzername',
    help_ssh_username: 'Beispiel: root oder ubuntu',
    step_display_location: 'Land, Stadt und Rechenzentrum',
    help_display_location: 'Beispiel: Germany — Frankfurt — Hetzner',
    step_auth_method: 'SSH-Authentifizierung',
    help_auth_method: 'Passwort oder privaten Schlüssel auswählen.',
    step_secret: 'SSH-Zugangsdaten',
    help_secret: 'Die Zugangsdaten werden verschlüsselt.',
    step_sudo_mode: 'Administratorzugriff',
    help_sudo_mode: 'Art des sudo-Zugriffs auswählen.',
    step_sudo_password: 'sudo-Passwort',
    help_sudo_password: 'Das Passwort wird verschlüsselt.',
    step_description: 'Beschreibung',
    help_description: 'Optionale Serverbeschreibung.',
    step_review: 'Prüfen und bestätigen',
    password_auth: 'Passwort',
    key_auth: 'Privater Schlüssel',
    sudo_none: 'Kein sudo',
    sudo_nopass: 'sudo ohne Passwort',
    sudo_password: 'sudo mit Passwort',
    optional: 'Optional',
    endpoint_name: 'Servername',
    host: 'Adresse',
    port: 'SSH-Port',
    ssh_user: 'SSH-Benutzer',
    location: 'Standort',
    auth_method: 'Authentifizierung',
    sudo_mode: 'sudo-Modus',
    description: 'Beschreibung',
    login_secret: 'Zugangsdaten',


    precheck_title: 'Bidirektionale Verbindungsprüfung',
    precheck_help: 'Vor dem Tunnelbau werden Route, ICMP und TCP von A nach B sowie von B nach A geprüft.',
    endpoint_a: 'Server A',
    endpoint_b: 'Server B',
    start_precheck: 'Bidirektionale Prüfung starten',
    need_two_ready: 'Mindestens zwei bereite Server sind erforderlich.',
    same_endpoint: 'Zwei unterschiedliche Server auswählen.',
    job_connect_a: 'Sichere Verbindung zu Server A',
    job_connect_b: 'Sichere Verbindung zu Server B',
    job_ping_ab: 'ICMP von A nach B prüfen',
    job_route_ab: 'Route von A nach B prüfen',
    job_tcp_ab: 'TCP von A nach B prüfen',
    job_ping_ba: 'ICMP von B nach A prüfen',
    job_route_ba: 'Route von B nach A prüfen',
    job_tcp_ba: 'TCP von B nach A prüfen',
    job_summary: 'Ergebnis der bidirektionalen Prüfung erstellen',

    job_queue: 'Warten in der Warteschlange',
    job_validate: 'Serverdaten werden geprüft',
    job_tcp: 'SSH-Port wird geprüft',
    job_ssh: 'Sichere SSH-Sitzung wird erstellt',
    job_os: 'Betriebssystem wird erkannt',
    job_arch: 'Systemarchitektur wird erkannt',
    job_hostname: 'Hostname wird gelesen',
    job_interfaces: 'Netzwerkschnittstellen werden geprüft',
    job_route: 'Standardroute wird geprüft',
    job_privilege: 'Berechtigungen werden geprüft',
    job_sudo: 'sudo-Zugriff wird geprüft',
    job_complete: 'Server ist bereit',
    job_failed: 'Vorgang fehlgeschlagen'
  }
};


Object.assign(I18N.en, {
  inventory_title: 'Network Inventory',
  inventory_help: 'Read-only discovery of addresses, routes, tunnels, ports and Docker networks.',
  inventory_view: '📡 Inventory',
  inventory_refresh: '🔄 Refresh inventory',
  inventory_not_scanned: 'Inventory has not been scanned.',
  inventory_scanning: 'Inventory scan is running.',
  inventory_interfaces: 'Interfaces',
  inventory_addresses: 'IP addresses',
  inventory_routes: 'Routes',
  inventory_tunnels: 'Tunnel interfaces',
  inventory_ports: 'Listening ports',
  inventory_wireguard: 'WireGuard',
  inventory_docker: 'Docker networks',
  inventory_namespaces: 'Network namespaces',
  inventory_warnings: 'Scan warnings',
  inventory_last_scan: 'Last scan',
  inventory_resources: 'Reserved resources',
  precheck_title: 'Bidirectional connectivity precheck',
  precheck_help: 'Test routing, ICMP and TCP in both directions before tunnel creation.',
  endpoint_a: 'Endpoint A',
  endpoint_b: 'Endpoint B',
  start_precheck: 'Start bidirectional precheck',
  need_two_ready: 'At least two READY endpoints are required.',
  same_endpoint: 'Select two different endpoints.',
  job_inventory_queue: 'Inventory scan queued',
  job_inventory_connect: 'Connecting for read-only inventory',
  job_inventory_addresses: 'Collecting IP addresses',
  job_inventory_links: 'Collecting interfaces and tunnels',
  job_inventory_routes: 'Collecting network routes',
  job_inventory_ports: 'Collecting listening ports',
  job_inventory_wireguard: 'Collecting WireGuard metadata',
  job_inventory_docker: 'Collecting Docker networks',
  job_inventory_namespaces: 'Collecting network namespaces',
  job_inventory_xfrm: 'Collecting IPsec/XFRM metadata',
  job_inventory_complete: 'Network inventory completed',
  job_connect_a: 'Connecting to Endpoint A',
  job_connect_b: 'Connecting to Endpoint B',
  job_ping_ab: 'Testing ICMP from A to B',
  job_route_ab: 'Inspecting route from A to B',
  job_tcp_ab: 'Testing TCP from A to B',
  job_ping_ba: 'Testing ICMP from B to A',
  job_route_ba: 'Inspecting route from B to A',
  job_tcp_ba: 'Testing TCP from B to A',
  job_summary: 'Preparing connectivity summary'
});

Object.assign(I18N.fa, {
  inventory_title: 'فهرست شبکه Endpoint',
  inventory_help: 'شناسایی فقط‌خواندنی IPها، Routeها، Tunnelها، پورت‌ها و شبکه‌های Docker.',
  inventory_view: '📡 مشاهده شبکه',
  inventory_refresh: '🔄 اسکن مجدد',
  inventory_not_scanned: 'هنوز اطلاعات شبکه این Endpoint اسکن نشده است.',
  inventory_scanning: 'اسکن اطلاعات شبکه در حال اجرا است.',
  inventory_interfaces: 'Interfaceها',
  inventory_addresses: 'آدرس‌های IP',
  inventory_routes: 'Routeها',
  inventory_tunnels: 'Tunnel Interfaceها',
  inventory_ports: 'پورت‌های در حال Listen',
  inventory_wireguard: 'WireGuard',
  inventory_docker: 'شبکه‌های Docker',
  inventory_namespaces: 'Network Namespaceها',
  inventory_warnings: 'هشدارهای اسکن',
  inventory_last_scan: 'آخرین اسکن',
  inventory_resources: 'منابع رزروشده',
  precheck_title: 'بررسی ارتباط دوطرفه',
  precheck_help: 'پیش از ساخت Tunnel، مسیر، Ping و TCP در هر دو جهت بررسی می‌شود.',
  endpoint_a: 'Endpoint اول',
  endpoint_b: 'Endpoint دوم',
  start_precheck: 'شروع بررسی دوطرفه',
  need_two_ready: 'حداقل دو Endpoint با وضعیت READY لازم است.',
  same_endpoint: 'دو Endpoint متفاوت انتخاب کن.',
  job_inventory_queue: 'اسکن اطلاعات شبکه وارد صف شد',
  job_inventory_connect: 'اتصال برای اسکن فقط‌خواندنی',
  job_inventory_addresses: 'جمع‌آوری آدرس‌های IP',
  job_inventory_links: 'شناسایی Interfaceها و Tunnelها',
  job_inventory_routes: 'جمع‌آوری Routeها',
  job_inventory_ports: 'جمع‌آوری پورت‌های در حال Listen',
  job_inventory_wireguard: 'شناسایی WireGuard',
  job_inventory_docker: 'شناسایی شبکه‌های Docker',
  job_inventory_namespaces: 'شناسایی Network Namespaceها',
  job_inventory_xfrm: 'شناسایی IPsec و XFRM',
  job_inventory_complete: 'اسکن شبکه با موفقیت کامل شد',
  job_connect_a: 'اتصال به Endpoint اول',
  job_connect_b: 'اتصال به Endpoint دوم',
  job_ping_ab: 'بررسی Ping از A به B',
  job_route_ab: 'بررسی مسیر از A به B',
  job_tcp_ab: 'بررسی TCP از A به B',
  job_ping_ba: 'بررسی Ping از B به A',
  job_route_ba: 'بررسی مسیر از B به A',
  job_tcp_ba: 'بررسی TCP از B به A',
  job_summary: 'آماده‌سازی نتیجه ارتباط'
});

Object.assign(I18N.ru, {
  inventory_title: 'Сетевая инвентаризация',
  inventory_help: 'Сканирование IP-адресов, маршрутов, туннелей, портов и Docker-сетей только для чтения.',
  inventory_view: '📡 Инвентаризация',
  inventory_refresh: '🔄 Обновить',
  inventory_not_scanned: 'Инвентаризация еще не выполнена.',
  inventory_scanning: 'Выполняется сканирование сети.',
  inventory_interfaces: 'Интерфейсы',
  inventory_addresses: 'IP-адреса',
  inventory_routes: 'Маршруты',
  inventory_tunnels: 'Туннельные интерфейсы',
  inventory_ports: 'Открытые порты',
  inventory_wireguard: 'WireGuard',
  inventory_docker: 'Сети Docker',
  inventory_namespaces: 'Сетевые пространства имен',
  inventory_warnings: 'Предупреждения',
  inventory_last_scan: 'Последнее сканирование',
  inventory_resources: 'Зарезервированные ресурсы',
  precheck_title: 'Двусторонняя проверка связи',
  precheck_help: 'Проверка маршрутов, ICMP и TCP в обоих направлениях.',
  endpoint_a: 'Сервер A',
  endpoint_b: 'Сервер B',
  start_precheck: 'Начать проверку',
  need_two_ready: 'Требуются два готовых сервера.',
  same_endpoint: 'Выберите разные серверы.',
  job_inventory_queue: 'Сканирование добавлено в очередь',
  job_inventory_connect: 'Подключение для инвентаризации',
  job_inventory_addresses: 'Сбор IP-адресов',
  job_inventory_links: 'Сбор интерфейсов и туннелей',
  job_inventory_routes: 'Сбор маршрутов',
  job_inventory_ports: 'Сбор открытых портов',
  job_inventory_wireguard: 'Сбор данных WireGuard',
  job_inventory_docker: 'Сбор сетей Docker',
  job_inventory_namespaces: 'Сбор сетевых пространств имен',
  job_inventory_xfrm: 'Сбор данных IPsec/XFRM',
  job_inventory_complete: 'Инвентаризация завершена',
  job_connect_a: 'Подключение к серверу A',
  job_connect_b: 'Подключение к серверу B',
  job_ping_ab: 'ICMP от A к B',
  job_route_ab: 'Маршрут от A к B',
  job_tcp_ab: 'TCP от A к B',
  job_ping_ba: 'ICMP от B к A',
  job_route_ba: 'Маршрут от B к A',
  job_tcp_ba: 'TCP от B к A',
  job_summary: 'Подготовка результата'
});

Object.assign(I18N['zh-CN'], {
  inventory_title: '网络资产清单',
  inventory_help: '以只读方式扫描 IP、路由、隧道、端口和 Docker 网络。',
  inventory_view: '📡 查看网络',
  inventory_refresh: '🔄 重新扫描',
  inventory_not_scanned: '尚未扫描此服务器的网络信息。',
  inventory_scanning: '正在扫描网络信息。',
  inventory_interfaces: '网络接口',
  inventory_addresses: 'IP 地址',
  inventory_routes: '路由',
  inventory_tunnels: '隧道接口',
  inventory_ports: '监听端口',
  inventory_wireguard: 'WireGuard',
  inventory_docker: 'Docker 网络',
  inventory_namespaces: '网络命名空间',
  inventory_warnings: '扫描警告',
  inventory_last_scan: '上次扫描',
  inventory_resources: '已占用资源',
  precheck_title: '双向连接预检查',
  precheck_help: '创建隧道前检查双向路由、ICMP 和 TCP。',
  endpoint_a: '服务器 A',
  endpoint_b: '服务器 B',
  start_precheck: '开始双向检查',
  need_two_ready: '至少需要两个 READY 状态的服务器。',
  same_endpoint: '请选择两个不同的服务器。',
  job_inventory_queue: '扫描任务已进入队列',
  job_inventory_connect: '连接服务器进行只读扫描',
  job_inventory_addresses: '收集 IP 地址',
  job_inventory_links: '收集接口和隧道',
  job_inventory_routes: '收集路由',
  job_inventory_ports: '收集监听端口',
  job_inventory_wireguard: '收集 WireGuard 信息',
  job_inventory_docker: '收集 Docker 网络',
  job_inventory_namespaces: '收集网络命名空间',
  job_inventory_xfrm: '收集 IPsec/XFRM 信息',
  job_inventory_complete: '网络扫描完成',
  job_connect_a: '连接服务器 A',
  job_connect_b: '连接服务器 B',
  job_ping_ab: '检查 A 到 B 的 ICMP',
  job_route_ab: '检查 A 到 B 的路由',
  job_tcp_ab: '检查 A 到 B 的 TCP',
  job_ping_ba: '检查 B 到 A 的 ICMP',
  job_route_ba: '检查 B 到 A 的路由',
  job_tcp_ba: '检查 B 到 A 的 TCP',
  job_summary: '生成连接结果'
});

Object.assign(I18N.de, {
  inventory_title: 'Netzwerkinventar',
  inventory_help: 'Schreibgeschützte Erkennung von IPs, Routen, Tunneln, Ports und Docker-Netzen.',
  inventory_view: '📡 Netzwerk anzeigen',
  inventory_refresh: '🔄 Neu scannen',
  inventory_not_scanned: 'Das Netzwerkinventar wurde noch nicht gescannt.',
  inventory_scanning: 'Das Netzwerk wird gescannt.',
  inventory_interfaces: 'Schnittstellen',
  inventory_addresses: 'IP-Adressen',
  inventory_routes: 'Routen',
  inventory_tunnels: 'Tunnel-Schnittstellen',
  inventory_ports: 'Lauschende Ports',
  inventory_wireguard: 'WireGuard',
  inventory_docker: 'Docker-Netzwerke',
  inventory_namespaces: 'Netzwerk-Namespaces',
  inventory_warnings: 'Scan-Warnungen',
  inventory_last_scan: 'Letzter Scan',
  inventory_resources: 'Reservierte Ressourcen',
  precheck_title: 'Bidirektionale Verbindungsprüfung',
  precheck_help: 'Routen, ICMP und TCP werden in beide Richtungen geprüft.',
  endpoint_a: 'Server A',
  endpoint_b: 'Server B',
  start_precheck: 'Prüfung starten',
  need_two_ready: 'Mindestens zwei bereite Server sind erforderlich.',
  same_endpoint: 'Zwei unterschiedliche Server auswählen.',
  job_inventory_queue: 'Inventarisierung wurde eingeplant',
  job_inventory_connect: 'Verbindung für schreibgeschützten Scan',
  job_inventory_addresses: 'IP-Adressen werden gesammelt',
  job_inventory_links: 'Schnittstellen und Tunnel werden gesammelt',
  job_inventory_routes: 'Routen werden gesammelt',
  job_inventory_ports: 'Lauschende Ports werden gesammelt',
  job_inventory_wireguard: 'WireGuard-Daten werden gesammelt',
  job_inventory_docker: 'Docker-Netzwerke werden gesammelt',
  job_inventory_namespaces: 'Netzwerk-Namespaces werden gesammelt',
  job_inventory_xfrm: 'IPsec/XFRM-Daten werden gesammelt',
  job_inventory_complete: 'Netzwerkinventar abgeschlossen',
  job_connect_a: 'Verbindung zu Server A',
  job_connect_b: 'Verbindung zu Server B',
  job_ping_ab: 'ICMP von A nach B',
  job_route_ab: 'Route von A nach B',
  job_tcp_ab: 'TCP von A nach B',
  job_ping_ba: 'ICMP von B nach A',
  job_route_ba: 'Route von B nach A',
  job_tcp_ba: 'TCP von B nach A',
  job_summary: 'Verbindungsergebnis wird erstellt'
});


const state = {
  token: sessionStorage.getItem('netauto_access_token'),
  user: null,
  language: localStorage.getItem('netauto_language') || detectLanguage(),
  endpointMap: {},
  inventory_endpoint_id: null,
  currentJobKind: 'endpoint',
  editingEndpointId: null,
  wizardIndex: 0,
  form: {},
  currentJob: null,
  currentEndpointId: null,
  currentJobKind: 'endpoint',
  lastEventId: 0,
  terminalQueue: [],
  terminalWriting: false,
  terminalPaused: false,
  terminalSpeed: 4
};

function detectLanguage() {
  const lang = navigator.language || 'en';

  if (lang.startsWith('fa')) return 'fa';
  if (lang.startsWith('ru')) return 'ru';
  if (lang.startsWith('zh')) return 'zh-CN';
  if (lang.startsWith('de')) return 'de';

  return 'en';
}

function t(key) {
  return I18N[state.language]?.[key] ??
    I18N.en[key] ??
    key;
}

function el(id) {
  return document.getElementById(id);
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function setLanguage(language) {
  if (!I18N[language]) language = 'en';

  state.language = language;
  localStorage.setItem('netauto_language', language);

  applyLanguage();

  if (!el('endpointsSection').classList.contains('hidden')) {
    loadEndpoints();
  }

  if (!el('wizardSection').classList.contains('hidden')) {
    renderWizard();
  }
}

function applyLanguage() {
  const rtl = state.language === 'fa';

  document.documentElement.lang = state.language;
  document.documentElement.dir = rtl ? 'rtl' : 'ltr';

  document.querySelectorAll('.language-select').forEach(select => {
    select.value = state.language;
  });

  document.querySelectorAll('[data-i18n]').forEach(node => {
    node.textContent = t(node.dataset.i18n);
  });
}

function togglePassword(inputId, button) {
  const input = el(inputId);

  if (input.type === 'password') {
    input.type = 'text';
    button.textContent = '🙈';
    button.title = t('hide_password');
  } else {
    input.type = 'password';
    button.textContent = '👁';
    button.title = t('show_password');
  }
}

function showMessage(text, type = 'error') {
  const box = el('loginMessage');
  box.className = `message ${type}`;
  box.textContent = text;
  box.classList.remove('hidden');
}

async function api(path, options = {}) {
  const headers = {...(options.headers || {})};

  if (state.token) {
    headers.Authorization = `Bearer ${state.token}`;
  }

  if (options.body && typeof options.body !== 'string') {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }

  const response = await fetch(path, {
    ...options,
    headers
  });

  let data = {};

  try {
    data = await response.json();
  } catch {}

  if (!response.ok) {
    if (response.status === 401) logout();
    throw new Error(data.detail || t('error_generic'));
  }

  return data;
}

async function login() {
  const button = el('loginButton');

  button.disabled = true;

  try {
    const data = await api('/api/v1/auth/login', {
      method: 'POST',
      body: {
        username: el('username').value.trim(),
        password: el('password').value
      }
    });

    state.token = data.access_token;

    sessionStorage.setItem(
      'netauto_access_token',
      state.token
    );

    await boot();

  } catch (error) {
    showMessage(error.message);
  } finally {
    button.disabled = false;
    button.textContent = t('login');
  }
}

function logout() {
  sessionStorage.removeItem('netauto_access_token');
  state.token = null;
  state.user = null;

  el('dashboard').classList.add('hidden');
  el('loginView').classList.remove('hidden');
}

async function boot() {
  applyLanguage();

  if (!state.token) {
    el('loginView').classList.remove('hidden');
    return;
  }

  try {
    state.user = await api('/api/v1/auth/me');

    el('loginView').classList.add('hidden');
    el('dashboard').classList.remove('hidden');

    el('accountName').textContent =
      `${state.user.username} — ${state.user.role}`;

    const technical =
      ['ADMIN', 'SUPER_ADMIN'].includes(state.user.role);

    el('technicalControls').classList.toggle(
      'hidden',
      !technical
    );

    await loadEndpoints();

  } catch {
    logout();
  }
}

function showSection(name) {
  document.querySelectorAll('.page-section').forEach(section => {
    section.classList.add('hidden');
  });

  document.querySelectorAll('.nav-btn').forEach(button => {
    button.classList.remove('active');
  });

  el(`${name}Section`).classList.remove('hidden');

  document
    .querySelector(`[data-section="${name}"]`)
    ?.classList.add('active');
}

function placeholder(key) {
  alert(t(key));
}


async function showPrecheck() {
  showSection('precheck');

  const result = await api('/api/v1/endpoints');
  const ready = (result.items || []).filter(
    item => item.status === 'READY'
  );

  const selectA = el('precheckEndpointA');
  const selectB = el('precheckEndpointB');
  const notice = el('precheckNotice');
  const button = el('startPrecheckButton');

  const options = ready.map(item => `
    <option value="${item.id}">
      #${item.id} — ${escapeHtml(item.name)}
      (${escapeHtml(item.host)})
    </option>
  `).join('');

  selectA.innerHTML = options;
  selectB.innerHTML = options;

  if (ready.length > 1) {
    selectB.selectedIndex = 1;
    notice.classList.add('hidden');
    button.disabled = false;
  } else {
    notice.textContent = t('need_two_ready');
    notice.className = 'message error';
    button.disabled = true;
  }
}


async function startPrecheck() {
  const endpointA = Number(
    el('precheckEndpointA').value
  );

  const endpointB = Number(
    el('precheckEndpointB').value
  );

  if (!endpointA || !endpointB) {
    alert(t('need_two_ready'));
    return;
  }

  if (endpointA === endpointB) {
    alert(t('same_endpoint'));
    return;
  }

  const button = el('startPrecheckButton');
  button.disabled = true;

  try {
    const result = await api(
      '/api/v1/prechecks',
      {
        method: 'POST',
        body: {
          endpoint_a_id: endpointA,
          endpoint_b_id: endpointB
        }
      }
    );

    startJob(
      result.job_id,
      null,
      'precheck'
    );

  } catch (error) {
    alert(error.message);
    button.disabled = false;
  }
}


async function loadEndpoints() {
  showSection('endpoints');

  const result = await api('/api/v1/endpoints');
  const items = result.items || [];

  state.endpointMap = Object.fromEntries(
    items.map(item => [String(item.id), item])
  );

  const container = el('endpointList');

  if (!items.length) {
    container.innerHTML =
      `<div class="empty">${escapeHtml(t('no_endpoint'))}</div>`;
    return;
  }

  container.innerHTML = items.map(item => `
    <article class="endpoint-item">
      <div>
        <h3>${escapeHtml(item.name)}</h3>
        <p>${escapeHtml(item.host)}:${item.port}</p>

        <p>
          ${escapeHtml(item.detected_os || t('waiting_detection'))}
          ${escapeHtml(item.detected_version || '')}
          — ${escapeHtml(item.display_location || '-')}
        </p>

        <p class="inventory-mini">
          📡
          ${escapeHtml(
            item.inventory?.status || 'NOT_SCANNED'
          )}
          |
          IP: ${item.inventory?.summary?.addresses || 0}
          |
          Tunnel: ${item.inventory?.summary?.tunnels || 0}
          |
          Port: ${item.inventory?.summary?.listening_ports || 0}
        </p>

        <p>
          ${escapeHtml(t('hostname'))}:
          ${escapeHtml(item.detected_hostname || '-')}
          |
          ${escapeHtml(t('interface'))}:
          ${escapeHtml(item.primary_interface || '-')}
        </p>

        ${
          item.last_error
            ? `<p style="color:#fb7185">${escapeHtml(item.last_error)}</p>`
            : ''
        }
      </div>

      <div class="endpoint-actions">
        <span class="badge ${escapeHtml(item.status)}">
          ${escapeHtml(item.status)}
        </span>

        <button
          class="btn"
          onclick="showInventory(${item.id})"
        >
          ${escapeHtml(t('inventory_view'))}
        </button>

        <button
          class="btn"
          onclick="refreshInventory(${item.id})"
        >
          ${escapeHtml(t('inventory_refresh'))}
        </button>

        <button
          class="btn btn-edit"
          onclick="startEditEndpoint(${item.id})"
        >
          ${escapeHtml(t('edit'))}
        </button>

        <button
          class="btn btn-danger"
          onclick="deleteEndpoint(${item.id})"
        >
          ${escapeHtml(t('delete'))}
        </button>
      </div>
    </article>
  `).join('');
}


async function showInventory(endpointId) {
  state.inventory_endpoint_id = endpointId;
  showSection('inventory');

  el('inventoryStatus').innerHTML =
    `<div class="message success">${escapeHtml(
      t('inventory_scanning')
    )}</div>`;

  el('inventorySummary').innerHTML = '';
  el('inventoryDetails').innerHTML = '';

  try {
    const result = await api(
      `/api/v1/endpoints/${endpointId}/inventory`
    );

    renderInventory(result);

  } catch (error) {
    el('inventoryStatus').innerHTML =
      `<div class="message error">${escapeHtml(
        error.message
      )}</div>`;
  }
}


async function refreshInventory(endpointId) {
  state.inventory_endpoint_id = endpointId;

  try {
    const result = await api(
      `/api/v1/endpoints/${endpointId}/inventory/refresh`,
      {
        method: 'POST'
      }
    );

    startJob(
      result.job_id,
      endpointId,
      'inventory'
    );

  } catch (error) {
    alert(error.message);
  }
}


function refreshCurrentInventory() {
  if (state.inventory_endpoint_id) {
    refreshInventory(
      state.inventory_endpoint_id
    );
  }
}


function inventoryList(title, items, renderer) {
  const safeItems = Array.isArray(items)
    ? items
    : [];

  return `
    <details class="inventory-group">
      <summary>
        ${escapeHtml(title)}
        <span>${safeItems.length}</span>
      </summary>

      <div class="inventory-table">
        ${
          safeItems.length
            ? safeItems.map(renderer).join('')
            : '<div class="empty">—</div>'
        }
      </div>
    </details>
  `;
}


function renderInventory(result) {
  const summary = result.summary || {};
  const data = result.data || {};

  if (result.status === 'NOT_SCANNED') {
    el('inventoryStatus').innerHTML =
      `<div class="message error">${escapeHtml(
        t('inventory_not_scanned')
      )}</div>`;

    el('inventorySummary').innerHTML = '';
    el('inventoryDetails').innerHTML = '';
    return;
  }

  const statusClass =
    result.status === 'READY'
      ? 'success'
      : 'error';

  el('inventoryStatus').innerHTML = `
    <div class="message ${statusClass}">
      ${escapeHtml(result.status)}
      ${
        result.scanned_at
          ? ` — ${escapeHtml(
              t('inventory_last_scan')
            )}: ${escapeHtml(
              new Date(
                result.scanned_at
              ).toLocaleString()
            )}`
          : ''
      }
    </div>
  `;

  const cards = [
    ['inventory_interfaces', summary.interfaces],
    ['inventory_addresses', summary.addresses],
    ['inventory_routes', summary.routes],
    ['inventory_tunnels', summary.tunnels],
    ['inventory_ports', summary.listening_ports],
    ['inventory_wireguard', summary.wireguard_interfaces],
    ['inventory_docker', summary.docker_networks],
    ['inventory_namespaces', summary.namespaces]
  ];

  el('inventorySummary').innerHTML =
    cards.map(([label, value]) => `
      <div class="inventory-stat">
        <strong>${Number(value || 0)}</strong>
        <span>${escapeHtml(t(label))}</span>
      </div>
    `).join('');

  const sections = [];

  sections.push(
    inventoryList(
      t('inventory_addresses'),
      data.addresses,
      item => `
        <div class="inventory-row">
          <code>${escapeHtml(item.cidr)}</code>
          <span>${escapeHtml(item.interface)}</span>
          <small>${escapeHtml(item.scope || '')}</small>
        </div>
      `
    )
  );

  sections.push(
    inventoryList(
      t('inventory_tunnels'),
      data.tunnels,
      item => `
        <div class="inventory-row">
          <code>${escapeHtml(item.interface)}</code>
          <span>${escapeHtml(item.kind)}</span>
          <small>
            ${escapeHtml(item.local || '-')}
            →
            ${escapeHtml(item.remote || '-')}
          </small>
        </div>
      `
    )
  );

  sections.push(
    inventoryList(
      t('inventory_ports'),
      data.listening_ports,
      item => `
        <div class="inventory-row">
          <code>
            ${escapeHtml(item.protocol)}/${escapeHtml(item.port)}
          </code>
          <span>${escapeHtml(item.address || '*')}</span>
          <small>${escapeHtml(item.source || '')}</small>
        </div>
      `
    )
  );

  sections.push(
    inventoryList(
      t('inventory_routes'),
      data.routes,
      item => `
        <div class="inventory-row">
          <code>${escapeHtml(item.destination)}</code>
          <span>${escapeHtml(item.interface || '-')}</span>
          <small>${escapeHtml(item.gateway || '-')}</small>
        </div>
      `
    )
  );

  sections.push(
    inventoryList(
      t('inventory_docker'),
      data.docker_networks,
      item => `
        <div class="inventory-row">
          <code>${escapeHtml(item.name || '-')}</code>
          <span>${escapeHtml(item.driver || '-')}</span>
          <small>${escapeHtml(
            (item.subnets || []).join(', ')
          )}</small>
        </div>
      `
    )
  );

  sections.push(
    inventoryList(
      t('inventory_wireguard'),
      data.wireguard,
      item => `
        <div class="inventory-row">
          <code>${escapeHtml(item.interface || '-')}</code>
          <span>
            UDP ${escapeHtml(item.listen_port || 0)}
          </span>
          <small>
            Peers: ${Number(
              item.peers?.length || 0
            )}
          </small>
        </div>
      `
    )
  );

  sections.push(
    inventoryList(
      t('inventory_namespaces'),
      data.namespaces,
      item => `
        <div class="inventory-row">
          <code>${escapeHtml(item)}</code>
        </div>
      `
    )
  );

  if (data.resources) {
    sections.push(`
      <details class="inventory-group">
        <summary>
          ${escapeHtml(t('inventory_resources'))}
        </summary>
        <pre class="inventory-json">${escapeHtml(
          JSON.stringify(
            data.resources,
            null,
            2
          )
        )}</pre>
      </details>
    `);
  }

  if (data.raw) {
    sections.push(`
      <details class="inventory-group">
        <summary>Technical raw output</summary>
        <pre class="inventory-json">${escapeHtml(
          JSON.stringify(
            data.raw,
            null,
            2
          )
        )}</pre>
      </details>
    `);
  }

  el('inventoryDetails').innerHTML =
    sections.join('');
}


async function showPrecheck() {
  showSection('precheck');

  const result = await api(
    '/api/v1/endpoints'
  );

  const ready = (
    result.items || []
  ).filter(
    item => item.status === 'READY'
  );

  const selectA = el(
    'precheckEndpointA'
  );

  const selectB = el(
    'precheckEndpointB'
  );

  const notice = el(
    'precheckNotice'
  );

  const button = el(
    'startPrecheckButton'
  );

  const options = ready.map(
    item => `
      <option value="${item.id}">
        #${item.id} —
        ${escapeHtml(item.name)}
        (${escapeHtml(item.host)})
      </option>
    `
  ).join('');

  selectA.innerHTML = options;
  selectB.innerHTML = options;

  if (ready.length >= 2) {
    selectB.selectedIndex = 1;
    notice.classList.add('hidden');
    button.disabled = false;
  } else {
    notice.textContent = t(
      'need_two_ready'
    );
    notice.className =
      'message error';
    button.disabled = true;
  }
}


async function startPrecheck() {
  const endpointA = Number(
    el('precheckEndpointA').value
  );

  const endpointB = Number(
    el('precheckEndpointB').value
  );

  if (!endpointA || !endpointB) {
    alert(t('need_two_ready'));
    return;
  }

  if (endpointA === endpointB) {
    alert(t('same_endpoint'));
    return;
  }

  try {
    const result = await api(
      '/api/v1/prechecks',
      {
        method: 'POST',
        body: {
          endpoint_a_id: endpointA,
          endpoint_b_id: endpointB
        }
      }
    );

    startJob(
      result.job_id,
      null,
      'precheck'
    );

  } catch (error) {
    alert(error.message);
  }
}


async function deleteEndpoint(endpointId) {
  if (!confirm(t('confirm_delete'))) return;

  try {
    await api(`/api/v1/endpoints/${endpointId}`, {
      method: 'DELETE'
    });

    await loadEndpoints();

  } catch (error) {
    alert(error.message);
  }
}

function defaultForm() {
  return {
    port: 22,
    auth_method: 'PASSWORD',
    sudo_mode: 'NONE',
    description: ''
  };
}

const baseSteps = [
  {key:'name', type:'text'},
  {key:'host', type:'text', direction:'ltr'},
  {key:'port', type:'number'},
  {key:'ssh_username', type:'text', direction:'ltr'},
  {key:'display_location', type:'text'},
  {
    key:'auth_method',
    type:'select',
    choices:[
      ['PASSWORD','password_auth'],
      ['PRIVATE_KEY','key_auth']
    ]
  },
  {key:'secret', type:'secret'},
  {
    key:'sudo_mode',
    type:'select',
    choices:[
      ['NONE','sudo_none'],
      ['PASSWORDLESS','sudo_nopass'],
      ['PASSWORD','sudo_password']
    ]
  },
  {
    key:'sudo_password',
    type:'password',
    conditional: () => state.form.sudo_mode === 'PASSWORD'
  },
  {key:'description', type:'text', optional:true},
  {key:'review', type:'review'}
];

function steps() {
  return baseSteps.filter(step =>
    !step.conditional || step.conditional()
  );
}

function startWizard() {
  state.editingEndpointId = null;
  state.wizardIndex = 0;
  state.form = defaultForm();
  resetWizardButton();
  showSection('wizard');
  renderWizard();
}

async function startEditEndpoint(endpointId) {
  try {
    const endpoint = await api(
      `/api/v1/endpoints/${endpointId}`
    );

    state.editingEndpointId = endpointId;
    state.wizardIndex = 0;

    state.form = {
      name: endpoint.name || '',
      host: endpoint.host || '',
      port: endpoint.port || 22,
      ssh_username: endpoint.ssh_username || '',
      display_location: endpoint.display_location || '',
      auth_method: endpoint.auth_method || 'PASSWORD',
      secret: '',
      sudo_mode: endpoint.sudo_mode || 'NONE',
      sudo_password: '',
      description: endpoint.description || ''
    };

    resetWizardButton();
    showSection('wizard');
    renderWizard();

  } catch (error) {
    alert(error.message);
  }
}

function resetWizardButton() {
  const button = el('nextButton');

  if (button) {
    button.disabled = false;
  }
}

function cancelWizard() {
  state.editingEndpointId = null;
  state.form = {};
  loadEndpoints();
}

function renderWizard() {
  const currentSteps = steps();

  if (state.wizardIndex >= currentSteps.length) {
    state.wizardIndex = currentSteps.length - 1;
  }

  const step = currentSteps[state.wizardIndex];

  el('wizardHeading').textContent =
    state.editingEndpointId
      ? t('wizard_edit')
      : t('wizard_create');

  el('wizardProgress').innerHTML =
    currentSteps.map((_, index) => {
      const className =
        index < state.wizardIndex
          ? 'done'
          : index === state.wizardIndex
            ? 'current'
            : '';

      return `<span class="progress-dot ${className}"></span>`;
    }).join('');

  el('wizardTitle').textContent =
    t(`step_${step.key}`);

  el('wizardHelp').textContent =
    t(`help_${step.key}`);

  const field = el('wizardField');
  const nextButton = el('nextButton');

  if (step.type === 'review') {
    field.innerHTML = reviewHtml();

    nextButton.textContent =
      state.editingEndpointId
        ? t('save_start')
        : t('create_start');

    return;
  }

  nextButton.textContent = t('continue');

  if (step.type === 'select') {
    field.innerHTML = `
      <select id="wizardInput">
        ${step.choices.map(([value, label]) => `
          <option
            value="${value}"
            ${state.form[step.key] === value ? 'selected' : ''}
          >
            ${escapeHtml(t(label))}
          </option>
        `).join('')}
      </select>
    `;
    return;
  }

  if (step.type === 'secret') {
    if (state.form.auth_method === 'PRIVATE_KEY') {
      field.innerHTML = `
        <textarea
          id="wizardInput"
          dir="ltr"
          autocomplete="off"
          placeholder="Private SSH key"
        >
        </textarea>

        ${
          state.editingEndpointId
            ? `<p class="field-note">${escapeHtml(t('keep_secret'))}</p>`
            : ''
        }
      `;
    } else {
      field.innerHTML = passwordField(
        'wizardInput',
        state.form.secret || '',
        state.editingEndpointId
          ? t('keep_secret')
          : t('step_secret')
      );
    }
    return;
  }

  if (step.type === 'password') {
    field.innerHTML = passwordField(
      'wizardInput',
      state.form[step.key] || '',
      state.editingEndpointId
        ? t('keep_secret')
        : t(`step_${step.key}`)
    );
    return;
  }

  field.innerHTML = `
    <input
      id="wizardInput"
      type="${step.type}"
      ${step.direction ? `dir="${step.direction}"` : ''}
      autocomplete="off"
      value="${escapeHtml(state.form[step.key] ?? '')}"
    >
  `;
}

function passwordField(id, value, placeholder) {
  return `
    <div class="secret-field">
      <input
        id="${id}"
        type="password"
        autocomplete="new-password"
        value="${escapeHtml(value)}"
        placeholder="${escapeHtml(placeholder)}"
      >

      <button
        type="button"
        class="secret-toggle"
        onclick="togglePassword('${id}',this)"
        title="${escapeHtml(t('show_password'))}"
      >👁</button>
    </div>

    ${
      state.editingEndpointId
        ? `<p class="field-note">${escapeHtml(t('keep_secret'))}</p>`
        : ''
    }
  `;
}

function reviewHtml() {
  const values = [
    [t('endpoint_name'), state.form.name],
    [t('host'), state.form.host],
    [t('port'), state.form.port],
    [t('ssh_user'), state.form.ssh_username],
    [t('location'), state.form.display_location],
    [
      t('auth_method'),
      state.form.auth_method === 'PRIVATE_KEY'
        ? t('key_auth')
        : t('password_auth')
    ],
    [
      t('sudo_mode'),
      {
        NONE: t('sudo_none'),
        PASSWORDLESS: t('sudo_nopass'),
        PASSWORD: t('sudo_password')
      }[state.form.sudo_mode]
    ],
    [t('description'), state.form.description || '-'],
    [
      t('login_secret'),
      state.editingEndpointId && !state.form.secret
        ? t('secret_kept')
        : t('secret_received')
    ]
  ];

  return `
    <div class="review">
      ${values.map(([key,value]) => `
        <div class="review-row">
          <strong>${escapeHtml(key)}</strong>
          <span>${escapeHtml(value || '-')}</span>
        </div>
      `).join('')}
    </div>
  `;
}

function previousWizardStep() {
  if (state.wizardIndex > 0) {
    state.wizardIndex--;
    renderWizard();
  } else {
    cancelWizard();
  }
}

async function nextWizardStep() {
  const currentSteps = steps();
  const step = currentSteps[state.wizardIndex];

  if (step.type === 'review') {
    await submitEndpoint();
    return;
  }

  const input = el('wizardInput');
  const value = input?.value.trim() || '';

  const mayKeepExisting =
    Boolean(state.editingEndpointId) &&
    ['secret','sudo_password'].includes(step.key);

  if (!value && !step.optional && !mayKeepExisting) {
    alert(t('required'));
    return;
  }

  if (
    step.key === 'port' &&
    (Number(value) < 1 || Number(value) > 65535)
  ) {
    alert(t('invalid_port'));
    return;
  }

  state.form[step.key] =
    step.key === 'port'
      ? Number(value)
      : value;

  state.wizardIndex++;
  renderWizard();
}

async function submitEndpoint() {
  const button = el('nextButton');
  button.disabled = true;

  const body = {
    name: state.form.name,
    host: state.form.host,
    port: state.form.port || 22,
    ssh_username: state.form.ssh_username,
    display_location: state.form.display_location || null,
    auth_method: state.form.auth_method,
    sudo_mode: state.form.sudo_mode || 'NONE',
    description: state.form.description || null
  };

  if (state.form.secret) {
    body.secret = state.form.secret;
  }

  if (state.form.sudo_password) {
    body.sudo_password = state.form.sudo_password;
  }

  try {
    const editingId = state.editingEndpointId;

    const result = await api(
      editingId
        ? `/api/v1/endpoints/${editingId}`
        : '/api/v1/endpoints',
      {
        method: editingId ? 'PUT' : 'POST',
        body
      }
    );

    const endpointId =
      result.endpoint?.id ||
      state.editingEndpointId;

    state.form.secret = null;
    state.form.sudo_password = null;
    state.editingEndpointId = null;

    startJob(
      result.job_id,
      endpointId
    );

  } catch (error) {
    alert(error.message);
    button.disabled = false;
    renderWizard();
  }
}

function startJob(jobId, endpointId, kind = 'endpoint') {
  state.currentJob = jobId;
  state.currentEndpointId = endpointId;
  state.currentJobKind = kind;
  state.lastEventId = 0;
  state.terminalQueue = [];
  state.terminalWriting = false;
  state.terminalPaused = false;

  el('terminal').textContent = '';
  el('timeline').innerHTML = '';
  el('jobProgress').style.width = '0%';
  el('jobPercent').textContent = '0%';
  el('jobStatus').textContent = 'QUEUED';

  showSection('job');

  enqueueTerminal([
    '[SYSTEM] Initializing secure workflow...',
    `[JOB] ID=${jobId}`,
    '[QUEUE] Waiting for worker...'
  ]);

  pollJob();
}

function localizedJobMessage(event) {
  const key = `job_${event.step}`;

  return (
    I18N[state.language]?.[key] ??
    I18N.en[key] ??
    event.message
  );
}

async function pollJob() {
  if (!state.currentJob) return;

  try {
    const job = await api(
      `/api/v1/jobs/${state.currentJob}` +
      `?after_id=${state.lastEventId}`
    );

    el('jobProgress').style.width = `${job.progress || 0}%`;
    el('jobPercent').textContent = `${job.progress || 0}%`;
    el('jobStatus').textContent = job.status || 'RUNNING';
    el('jobStatus').className = `badge ${job.status || 'RUNNING'}`;

    for (const event of job.events || []) {
      state.lastEventId = Math.max(state.lastEventId, event.id);

      const message = localizedJobMessage(event);
      appendTimeline(event, message);

      const lines = [
        `[${event.level}] ${message}`
      ];

      if (event.command) {
        lines.push(`root@remote:~# ${event.command}`);
      }

      if (event.output) {
        lines.push(...String(event.output).split('\n'));
      }

      enqueueTerminal(lines);
    }

    if (['SUCCESS','FAILED'].includes(job.status)) {
      enqueueTerminal([
        '',
        `[SYSTEM] Final status: ${job.status}`
      ]);

      if (job.status === 'FAILED') {
        renderJobFailure(job);
      } else {
        setTimeout(
          () => {
            if (
              window.netautoPrecheckReturnPending ||
              sessionStorage.getItem(
                'netauto_precheck_return_pending'
              ) === '1'
            ) {
              netautoReturnToPrecheckResult();
            } else {
              loadEndpoints();
            }
          },
          1400
        );
      }

      return;
    }

  } catch (error) {
    enqueueTerminal(`[NETWORK] ${error.message}`);
  }

  setTimeout(pollJob, 700);
}

function appendTimeline(event, message) {
  const row = document.createElement('div');
  row.className = `timeline-row ${event.level}`;
  row.textContent = message;
  el('timeline').appendChild(row);
}

function enqueueTerminal(lines) {
  if (!Array.isArray(lines)) lines = [lines];

  state.terminalQueue.push(...lines);
  processTerminalQueue();
}

async function processTerminalQueue() {
  if (state.terminalWriting || state.terminalPaused) return;

  state.terminalWriting = true;

  while (state.terminalQueue.length && !state.terminalPaused) {
    await typeTerminalLine(state.terminalQueue.shift());
  }

  state.terminalWriting = false;
}

async function typeTerminalLine(line) {
  const terminal = el('terminal');

  const technical =
    state.user &&
    ['ADMIN','SUPER_ADMIN'].includes(state.user.role);

  const delay = technical
    ? Math.max(0, 5 / state.terminalSpeed)
    : 0;

  const lineBox = document.createElement('div');
  terminal.appendChild(lineBox);

  for (const character of String(line)) {
    while (state.terminalPaused) {
      await new Promise(resolve => setTimeout(resolve, 80));
    }

    lineBox.textContent += character;
    terminal.scrollTop = terminal.scrollHeight;

    if (delay > 0) {
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}


function friendlyJobError(rawError) {
  const error = String(rawError || '');
  const language = state.language;

  const messages = {
    en: {
      auth: 'SSH authentication failed. The server and SSH port are reachable, but the username, password, private key, or root-login permission is incorrect.',
      timeout: 'The connection timed out. Check the server address, SSH port, firewall, and routing.',
      refused: 'The server rejected the SSH connection. SSH may be stopped or the selected port is incorrect.',
      dns: 'The hostname could not be resolved. Check the domain and DNS records.',
      key: 'The private-key format is unsupported or the key is invalid.',
      unknown: 'The operation failed. Review the technical error below.'
    },

    fa: {
      auth: 'احراز هویت SSH ناموفق بود. سرور و پورت SSH در دسترس هستند، اما نام کاربری، رمز، Private Key یا اجازه ورود root صحیح نیست.',
      timeout: 'اتصال Timeout شد. آدرس سرور، پورت SSH، Firewall و مسیر شبکه را بررسی کن.',
      refused: 'سرور اتصال SSH را رد کرد. احتمالاً سرویس SSH خاموش است یا پورت اشتباه وارد شده.',
      dns: 'دامنه قابل شناسایی نیست. دامنه و تنظیمات DNS را بررسی کن.',
      key: 'فرمت Private Key پشتیبانی نمی‌شود یا کلید نامعتبر است.',
      unknown: 'عملیات ناموفق بود. جزئیات فنی خطا را بررسی کن.'
    },

    ru: {
      auth: 'Ошибка аутентификации SSH. Сервер и SSH-порт доступны, но имя пользователя, пароль, приватный ключ или разрешение root неверны.',
      timeout: 'Время подключения истекло. Проверьте адрес, SSH-порт, брандмауэр и маршрут.',
      refused: 'Сервер отклонил SSH-соединение. Служба SSH может быть остановлена или порт указан неверно.',
      dns: 'Не удалось определить имя хоста. Проверьте домен и DNS.',
      key: 'Формат приватного ключа не поддерживается или ключ недействителен.',
      unknown: 'Операция завершилась ошибкой. Проверьте технические сведения.'
    },

    'zh-CN': {
      auth: 'SSH 身份验证失败。服务器和 SSH 端口可访问，但用户名、密码、私钥或 root 登录权限不正确。',
      timeout: '连接超时。请检查服务器地址、SSH 端口、防火墙和路由。',
      refused: '服务器拒绝 SSH 连接。SSH 服务可能未运行或端口不正确。',
      dns: '无法解析主机名。请检查域名和 DNS。',
      key: '私钥格式不受支持或私钥无效。',
      unknown: '操作失败。请查看下面的技术错误。'
    },

    de: {
      auth: 'SSH-Authentifizierung fehlgeschlagen. Server und SSH-Port sind erreichbar, aber Benutzername, Passwort, privater Schlüssel oder Root-Anmeldung sind falsch.',
      timeout: 'Zeitüberschreitung bei der Verbindung. Serveradresse, SSH-Port, Firewall und Routing prüfen.',
      refused: 'Der Server hat die SSH-Verbindung abgelehnt. SSH ist möglicherweise gestoppt oder der Port ist falsch.',
      dns: 'Der Hostname konnte nicht aufgelöst werden. Domain und DNS prüfen.',
      key: 'Das Format des privaten Schlüssels wird nicht unterstützt oder der Schlüssel ist ungültig.',
      unknown: 'Der Vorgang ist fehlgeschlagen. Technische Details prüfen.'
    }
  };

  const text = messages[language] || messages.en;
  const lower = error.toLowerCase();

  if (
    lower.includes('authenticationexception') ||
    lower.includes('authentication failed')
  ) {
    return text.auth;
  }

  if (
    lower.includes('timeout') ||
    lower.includes('timed out')
  ) {
    return text.timeout;
  }

  if (
    lower.includes('connection refused') ||
    lower.includes('novalidconnections')
  ) {
    return text.refused;
  }

  if (
    lower.includes('gaierror') ||
    lower.includes('name or service not known')
  ) {
    return text.dns;
  }

  if (
    lower.includes('private_key_format_unsupported') ||
    lower.includes('invalid key')
  ) {
    return text.key;
  }

  return text.unknown;
}


function renderJobFailure(job) {
  document
    .getElementById('jobFailureBox')
    ?.remove();

  const technical =
    state.user &&
    ['ADMIN', 'SUPER_ADMIN'].includes(
      state.user.role
    );

  const box = document.createElement('div');

  box.id = 'jobFailureBox';
  box.className = 'failure-summary';

  box.innerHTML = `
    <strong>❌ ${escapeHtml(t('job_failed'))}</strong>

    <p>
      ${escapeHtml(
        friendlyJobError(job.error_message)
      )}
    </p>

    ${
      technical && job.error_message
        ? `
          <details>
            <summary>Technical error</summary>
            <pre>${escapeHtml(job.error_message)}</pre>
          </details>
        `
        : ''
    }

    <div class="job-result-actions">
      <button
        class="btn btn-edit"
        onclick="startEditEndpoint(
          state.currentEndpointId
        )"
      >
        ${escapeHtml(t('edit'))}
      </button>

      <button
        class="btn btn-danger"
        onclick="deleteEndpoint(
          state.currentEndpointId
        )"
      >
        ${escapeHtml(t('delete'))}
      </button>

      <button
        class="btn"
        onclick="loadEndpoints()"
      >
        ${escapeHtml(t('endpoints'))}
      </button>
    </div>
  `;

  el('timeline').appendChild(box);
  box.scrollIntoView({
    behavior: 'smooth',
    block: 'center'
  });
}


function toggleTerminalPause() {
  state.terminalPaused = !state.terminalPaused;

  el('pauseTerminal').textContent =
    state.terminalPaused ? t('resume') : t('pause');

  if (!state.terminalPaused) {
    processTerminalQueue();
  }
}

function changeTerminalSpeed() {
  state.terminalSpeed =
    Number(el('terminalSpeed').value || 4);
}

function copyTerminal() {
  navigator.clipboard.writeText(el('terminal').innerText);
}

function downloadTerminal() {
  const blob = new Blob(
    [el('terminal').innerText],
    {type:'text/plain;charset=utf-8'}
  );

  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `netauto-job-${state.currentJob || 'log'}.txt`;
  link.click();
  URL.revokeObjectURL(link.href);
}

document.addEventListener('keydown', event => {
  if (
    event.key === 'Enter' &&
    !el('loginView').classList.contains('hidden')
  ) {
    login();
  }
});

boot();


/* NETAUTO_PRECHECK_PERSISTENT_BEGIN */

Object.assign(I18N.en, {
  precheck_history: 'Previous connectivity checks',
  precheck_result: 'Connectivity result',
  precheck_waiting: 'The connectivity check is running.',
  precheck_empty: 'No connectivity checks have been recorded.',
  precheck_direction_ab: 'Endpoint A → Endpoint B',
  precheck_direction_ba: 'Endpoint B → Endpoint A',
  precheck_ping: 'ICMP / Ping',
  precheck_route: 'Route',
  precheck_tcp: 'TCP connectivity',
  precheck_bidirectional: 'Bidirectional connectivity is available.',
  precheck_a_only: 'Only Endpoint A can reach Endpoint B.',
  precheck_b_only: 'Only Endpoint B can reach Endpoint A.',
  precheck_blocked: 'Connectivity is blocked in both directions.',
  precheck_failed: 'The connectivity check failed.',
  precheck_view: 'View result',
  precheck_back: 'Back to result'
});

Object.assign(I18N.fa, {
  precheck_history: 'تاریخچه بررسی‌های ارتباط',
  precheck_result: 'نتیجه بررسی ارتباط',
  precheck_waiting: 'بررسی ارتباط در حال اجرا است.',
  precheck_empty: 'هنوز نتیجه‌ای ثبت نشده است.',
  precheck_direction_ab: 'Endpoint اول → Endpoint دوم',
  precheck_direction_ba: 'Endpoint دوم → Endpoint اول',
  precheck_ping: 'Ping / ICMP',
  precheck_route: 'Route',
  precheck_tcp: 'ارتباط TCP',
  precheck_bidirectional: 'ارتباط دوطرفه برقرار است.',
  precheck_a_only: 'فقط Endpoint اول به Endpoint دوم دسترسی دارد.',
  precheck_b_only: 'فقط Endpoint دوم به Endpoint اول دسترسی دارد.',
  precheck_blocked: 'ارتباط در هر دو جهت مسدود است.',
  precheck_failed: 'بررسی ارتباط ناموفق بود.',
  precheck_view: 'مشاهده نتیجه',
  precheck_back: 'بازگشت به نتیجه'
});

Object.assign(I18N.ru, {
  precheck_history: 'История проверок соединения',
  precheck_result: 'Результат проверки',
  precheck_waiting: 'Проверка соединения выполняется.',
  precheck_empty: 'Результаты проверок отсутствуют.',
  precheck_direction_ab: 'Сервер A → Сервер B',
  precheck_direction_ba: 'Сервер B → Сервер A',
  precheck_ping: 'ICMP / Ping',
  precheck_route: 'Маршрут',
  precheck_tcp: 'TCP-соединение',
  precheck_bidirectional: 'Двустороннее соединение доступно.',
  precheck_a_only: 'Только сервер A может подключиться к серверу B.',
  precheck_b_only: 'Только сервер B может подключиться к серверу A.',
  precheck_blocked: 'Соединение заблокировано в обоих направлениях.',
  precheck_failed: 'Проверка соединения завершилась ошибкой.',
  precheck_view: 'Показать результат',
  precheck_back: 'Вернуться к результату'
});

Object.assign(I18N['zh-CN'], {
  precheck_history: '连接检查历史',
  precheck_result: '连接检查结果',
  precheck_waiting: '连接检查正在运行。',
  precheck_empty: '暂无连接检查结果。',
  precheck_direction_ab: '服务器 A → 服务器 B',
  precheck_direction_ba: '服务器 B → 服务器 A',
  precheck_ping: 'ICMP / Ping',
  precheck_route: '路由',
  precheck_tcp: 'TCP 连接',
  precheck_bidirectional: '双向连接可用。',
  precheck_a_only: '只有服务器 A 可以连接服务器 B。',
  precheck_b_only: '只有服务器 B 可以连接服务器 A。',
  precheck_blocked: '双向连接均被阻止。',
  precheck_failed: '连接检查失败。',
  precheck_view: '查看结果',
  precheck_back: '返回结果'
});

Object.assign(I18N.de, {
  precheck_history: 'Verlauf der Verbindungsprüfungen',
  precheck_result: 'Ergebnis der Verbindungsprüfung',
  precheck_waiting: 'Die Verbindungsprüfung wird ausgeführt.',
  precheck_empty: 'Noch keine Prüfungsergebnisse vorhanden.',
  precheck_direction_ab: 'Server A → Server B',
  precheck_direction_ba: 'Server B → Server A',
  precheck_ping: 'ICMP / Ping',
  precheck_route: 'Route',
  precheck_tcp: 'TCP-Verbindung',
  precheck_bidirectional: 'Bidirektionale Verbindung ist verfügbar.',
  precheck_a_only: 'Nur Server A kann Server B erreichen.',
  precheck_b_only: 'Nur Server B kann Server A erreichen.',
  precheck_blocked: 'Die Verbindung ist in beide Richtungen blockiert.',
  precheck_failed: 'Die Verbindungsprüfung ist fehlgeschlagen.',
  precheck_view: 'Ergebnis anzeigen',
  precheck_back: 'Zurück zum Ergebnis'
});


let netautoLastPrecheckResult = null;


function ensurePersistentPrecheckUI() {
  const section = el('precheckSection');

  if (!section) {
    return false;
  }

  if (!el('precheckResult')) {
    const resultArea =
      document.createElement('div');

    resultArea.id = 'precheckResult';
    resultArea.className =
      'precheck-result-area';

    const startButton =
      el('startPrecheckButton');

    if (
      startButton &&
      startButton.parentNode
    ) {
      startButton.insertAdjacentElement(
        'afterend',
        resultArea
      );
    } else {
      section.appendChild(resultArea);
    }
  }

  if (!el('precheckHistory')) {
    const divider =
      document.createElement('div');

    divider.className =
      'section-divider';

    const heading =
      document.createElement('h3');

    heading.id =
      'precheckHistoryTitle';

    heading.textContent =
      t('precheck_history');

    const history =
      document.createElement('div');

    history.id =
      'precheckHistory';

    history.className =
      'precheck-history';

    section.appendChild(divider);
    section.appendChild(heading);
    section.appendChild(history);
  }

  const heading =
    el('precheckHistoryTitle');

  if (heading) {
    heading.textContent =
      t('precheck_history');
  }

  return true;
}


function precheckTestStatus(test) {
  if (test?.success) {
    return `
      <span class="precheck-ok">
        ✅ OK
      </span>
    `;
  }

  return `
    <span class="precheck-fail">
      ❌ FAILED
    </span>
  `;
}


function precheckDirectionCard(
  title,
  direction
) {
  const value = direction || {};

  return `
    <div class="precheck-direction">
      <h4>${escapeHtml(title)}</h4>

      <div class="precheck-test-row">
        <span>
          ${escapeHtml(t('precheck_ping'))}
        </span>

        ${precheckTestStatus(value.ping)}
      </div>

      <div class="precheck-test-row">
        <span>
          ${escapeHtml(t('precheck_route'))}
        </span>

        ${precheckTestStatus(value.route)}
      </div>

      <div class="precheck-test-row">
        <span>
          ${escapeHtml(t('precheck_tcp'))}
        </span>

        ${precheckTestStatus(value.tcp)}
      </div>
    </div>
  `;
}


function precheckSummaryText(
  connectivity
) {
  const mapping = {
    BIDIRECTIONAL:
      'precheck_bidirectional',

    A_TO_B_ONLY:
      'precheck_a_only',

    B_TO_A_ONLY:
      'precheck_b_only',

    BLOCKED:
      'precheck_blocked'
  };

  return t(
    mapping[connectivity] ||
    'precheck_failed'
  );
}


function renderPersistentPrecheck(
  item
) {
  ensurePersistentPrecheckUI();

  netautoLastPrecheckResult = item;

  const target = el('precheckResult');

  if (!target) {
    return;
  }

  const status = item?.status || 'QUEUED';

  if (
    status === 'QUEUED' ||
    status === 'RUNNING'
  ) {
    target.innerHTML = `
      <div class="precheck-waiting-card">
        <div class="precheck-spinner"></div>

        <strong>
          ${escapeHtml(
            t('precheck_waiting')
          )}
        </strong>
      </div>
    `;

    return;
  }

  const result = item?.result || {};

  const endpointA =
    item?.endpoint_a || {};

  const endpointB =
    item?.endpoint_b || {};

  const connectivity =
    result.connectivity || status;

  const success =
    connectivity === 'BIDIRECTIONAL';

  const technicalAccess =
    state.user &&
    (
      state.user.role === 'ADMIN' ||
      state.user.role === 'SUPER_ADMIN'
    );

  target.innerHTML = `
    <article class="precheck-result-card">
      <div class="precheck-result-head">
        <div>
          <h3>
            ${escapeHtml(
              t('precheck_result')
            )}
          </h3>

          <p>
            ${escapeHtml(
              endpointA.name || '-'
            )}

            <strong>↔</strong>

            ${escapeHtml(
              endpointB.name || '-'
            )}
          </p>
        </div>

        <span class="badge ${
          success
            ? 'SUCCESS'
            : 'FAILED'
        }">
          ${escapeHtml(connectivity)}
        </span>
      </div>

      <div class="${
        success
          ? 'precheck-overall-success'
          : 'precheck-overall-error'
      }">
        ${escapeHtml(
          precheckSummaryText(
            result.connectivity
          )
        )}
      </div>

      <div class="precheck-directions">
        ${precheckDirectionCard(
          t('precheck_direction_ab'),
          result.a_to_b
        )}

        ${precheckDirectionCard(
          t('precheck_direction_ba'),
          result.b_to_a
        )}
      </div>

      ${
        technicalAccess &&
        item.job_error
          ? `
            <details class="precheck-technical">
              <summary>
                Technical error
              </summary>

              <pre>${escapeHtml(
                item.job_error
              )}</pre>
            </details>
          `
          : ''
      }

      ${
        item.finished_at
          ? `
            <small class="muted">
              ${escapeHtml(
                new Date(
                  item.finished_at
                ).toLocaleString()
              )}
            </small>
          `
          : ''
      }
    </article>
  `;
}


async function loadPersistentPrecheck(
  precheckId
) {
  ensurePersistentPrecheckUI();

  try {
    const item = await api(
      `/api/v1/precheck-result/${precheckId}`
    );

    renderPersistentPrecheck(item);

    el('precheckResult')
      ?.scrollIntoView({
        behavior: 'smooth',
        block: 'start'
      });

  } catch (error) {
    el('precheckResult').innerHTML = `
      <div class="message error">
        ${escapeHtml(error.message)}
      </div>
    `;
  }
}


async function loadPrecheckHistory() {
  ensurePersistentPrecheckUI();

  const container =
    el('precheckHistory');

  if (!container) {
    return;
  }

  try {
    const response = await api(
      '/api/v1/precheck-results'
    );

    const items =
      response.items || [];

    if (!items.length) {
      container.innerHTML = `
        <div class="empty">
          ${escapeHtml(
            t('precheck_empty')
          )}
        </div>
      `;

      return;
    }

    container.innerHTML =
      items.map(item => {
        const connectivity =
          item.result?.connectivity ||
          item.status;

        return `
          <article
            class="precheck-history-item"
          >
            <div>
              <strong>
                ${escapeHtml(
                  item.endpoint_a?.name ||
                  '-'
                )}

                ↔

                ${escapeHtml(
                  item.endpoint_b?.name ||
                  '-'
                )}
              </strong>

              <p>
                ${escapeHtml(connectivity)}
              </p>
            </div>

            <button
              class="btn"
              onclick="
                loadPersistentPrecheck(
                  ${item.id}
                )
              "
            >
              ${escapeHtml(
                t('precheck_view')
              )}
            </button>
          </article>
        `;
      }).join('');

  } catch (error) {
    container.innerHTML = `
      <div class="message error">
        ${escapeHtml(error.message)}
      </div>
    `;
  }
}


async function watchPrecheckResult(
  precheckId,
  jobId
) {
  for (
    let attempt = 0;
    attempt < 300;
    attempt++
  ) {
    try {
      const job = await api(
        `/api/v1/jobs/${jobId}` +
        '?after_id=0'
      );

      if (
        job.status === 'SUCCESS' ||
        job.status === 'FAILED'
      ) {
        if (
          typeof netautoOriginalShowPrecheck
          === 'function'
        ) {
          await netautoOriginalShowPrecheck();
        } else {
          showSection('precheck');
        }

        ensurePersistentPrecheckUI();

        await loadPersistentPrecheck(
          precheckId
        );

        await loadPrecheckHistory();

        return;
      }

    } catch {}

    await new Promise(
      resolve => setTimeout(
        resolve,
        1000
      )
    );
  }
}


const netautoOriginalShowPrecheck =
  typeof window.showPrecheck
  === 'function'
    ? window.showPrecheck
    : null;


window.showPrecheck =
async function () {
  if (
    typeof netautoOriginalShowPrecheck
    === 'function'
  ) {
    await netautoOriginalShowPrecheck();
  } else {
    showSection('precheck');
  }

  ensurePersistentPrecheckUI();

  if (netautoLastPrecheckResult) {
    renderPersistentPrecheck(
      netautoLastPrecheckResult
    );
  }

  await loadPrecheckHistory();
};


window.startPrecheck =
async function () {
  ensurePersistentPrecheckUI();

  const endpointA = Number(
    el('precheckEndpointA')?.value
  );

  const endpointB = Number(
    el('precheckEndpointB')?.value
  );

  if (!endpointA || !endpointB) {
    alert(t('need_two_ready'));
    return;
  }

  if (endpointA === endpointB) {
    alert(t('same_endpoint'));
    return;
  }

  const button =
    el('startPrecheckButton');

  if (button) {
    button.disabled = true;
  }

  try {
    const response = await api(
      '/api/v1/prechecks',
      {
        method: 'POST',
        body: {
          endpoint_a_id: endpointA,
          endpoint_b_id: endpointB
        }
      }
    );

    window.netautoCurrentPrecheckId =
      response.precheck_id;

    window.netautoPrecheckReturnPending = true;

    sessionStorage.setItem(
      'netauto_current_precheck_id',
      String(response.precheck_id)
    );

    sessionStorage.setItem(
      'netauto_precheck_return_pending',
      '1'
    );

    try {
      state.currentJobKind = 'precheck';
    } catch {}

    window.netautoCurrentPrecheckId =
      response.precheck_id;

    window.netautoPrecheckReturnPending = true;

    sessionStorage.setItem(
      'netauto_current_precheck_id',
      String(response.precheck_id)
    );

    sessionStorage.setItem(
      'netauto_precheck_return_pending',
      '1'
    );

    try {
      state.currentJobKind = 'precheck';
    } catch {}

    renderPersistentPrecheck({
      status: 'RUNNING',
      endpoint_a:
        response.endpoint_a,
      endpoint_b:
        response.endpoint_b,
      result: {}
    });

    try {
      state.currentJobKind =
        'precheck';
    } catch {}

    startJob(
      response.job_id,
      null,
      'precheck'
    );

    watchPrecheckResult(
      response.precheck_id,
      response.job_id
    );

  } catch (error) {
    alert(error.message);

    if (button) {
      button.disabled = false;
    }
  }
};

/* NETAUTO_PRECHECK_PERSISTENT_END */


/* NETAUTO_PRECHECK_NAV_FIX_BEGIN */

window.netautoCurrentPrecheckId =
  window.netautoCurrentPrecheckId ||
  Number(
    sessionStorage.getItem(
      'netauto_current_precheck_id'
    ) || 0
  );

window.netautoPrecheckReturnPending =
  window.netautoPrecheckReturnPending ||
  sessionStorage.getItem(
    'netauto_precheck_return_pending'
  ) === '1';


async function netautoReturnToPrecheckResult() {
  const precheckId = Number(
    window.netautoCurrentPrecheckId ||
    sessionStorage.getItem(
      'netauto_current_precheck_id'
    ) ||
    0
  );

  /*
   * ابتدا Flag را پاک نمی‌کنیم؛ چون بعضی نسخه‌های قدیمی
   * pollJob دو بار loadEndpoints را صدا می‌زنند.
   */
  try {
    state.currentJobKind = 'precheck-result';
  } catch {}

  /*
   * صفحه Precheck را بدون اجرای Navigation قدیمی باز می‌کنیم.
   */
  if (
    typeof netautoOriginalShowPrecheck
    === 'function'
  ) {
    await netautoOriginalShowPrecheck();

  } else if (
    typeof showSection === 'function'
  ) {
    showSection('precheck');
  }

  if (
    typeof ensurePersistentPrecheckUI
    === 'function'
  ) {
    ensurePersistentPrecheckUI();
  }

  if (
    precheckId &&
    typeof loadPersistentPrecheck
    === 'function'
  ) {
    await loadPersistentPrecheck(
      precheckId
    );
  }

  if (
    typeof loadPrecheckHistory
    === 'function'
  ) {
    await loadPrecheckHistory();
  }

  window.netautoPrecheckReturnPending = false;

  sessionStorage.removeItem(
    'netauto_precheck_return_pending'
  );

  /*
   * شناسه را نگه می‌داریم تا با Refresh هم آخرین نتیجه
   * قابل نمایش باشد.
   */
  if (precheckId) {
    sessionStorage.setItem(
      'netauto_current_precheck_id',
      String(precheckId)
    );
  }

  setTimeout(
    () => {
      el('precheckResult')
        ?.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
    },
    150
  );
}


/*
 * محافظ نهایی:
 * اگر کد قدیمی مستقیماً loadEndpoints را پس از Precheck
 * اجرا کند، آن را به صفحه نتیجه هدایت می‌کنیم.
 */
const netautoRealLoadEndpoints =
  window.loadEndpoints;


window.loadEndpoints =
async function (...args) {
  const mustReturnToResult =
    window.netautoPrecheckReturnPending ||
    sessionStorage.getItem(
      'netauto_precheck_return_pending'
    ) === '1';

  if (mustReturnToResult) {
    await netautoReturnToPrecheckResult();
    return;
  }

  return netautoRealLoadEndpoints(
    ...args
  );
};


/*
 * بعد از Refresh صفحه، اگر نتیجه قبلی وجود داشت،
 * با ورود به صفحه Tunnel همان نتیجه دوباره نمایش داده می‌شود.
 */
const netautoNavigationShowPrecheck =
  window.showPrecheck;


window.showPrecheck =
async function (...args) {
  if (
    typeof netautoNavigationShowPrecheck
    === 'function'
  ) {
    await netautoNavigationShowPrecheck(
      ...args
    );

  } else if (
    typeof showSection === 'function'
  ) {
    showSection('precheck');
  }

  const savedId = Number(
    sessionStorage.getItem(
      'netauto_current_precheck_id'
    ) || 0
  );

  if (
    savedId &&
    typeof loadPersistentPrecheck
    === 'function'
  ) {
    await loadPersistentPrecheck(
      savedId
    );
  }

  if (
    typeof loadPrecheckHistory
    === 'function'
  ) {
    await loadPrecheckHistory();
  }
};

/* NETAUTO_PRECHECK_NAV_FIX_END */


/* NETAUTO_COMPOSER_BUTTON */
Object.assign(I18N.en,{composer_open:'🧩 Advanced Tunnel Composer'});
Object.assign(I18N.fa,{composer_open:'🧩 ساخت پلن چندسروری و چندتونلی'});
Object.assign(I18N.ru,{composer_open:'🧩 Расширенный Tunnel Composer'});
Object.assign(I18N['zh-CN'],{composer_open:'🧩 高级隧道编排器'});
Object.assign(I18N.de,{composer_open:'🧩 Erweiterter Tunnel-Composer'});
function ensureComposerButton(){const s=document.getElementById('precheckSection');if(!s||document.getElementById('composerButton'))return;const b=document.createElement('button');b.id='composerButton';b.className='btn btn-primary btn-wide';b.style.marginBottom='16px';b.textContent=t('composer_open');b.onclick=()=>location.href='/composer.html';s.prepend(b)}
setTimeout(ensureComposerButton,300);setInterval(ensureComposerButton,1500);

/* NETAUTO_SAFE_ENDPOINT_DELETE_BEGIN */
(() => {
  const messages = {
    en: {
      confirm:
        'Delete this endpoint and its inventory, completed jobs, prechecks and draft plans? Active or executed tunnel plans are protected and will not be deleted.',
      success: 'Endpoint deleted successfully.',
      ENDPOINT_HAS_ACTIVE_JOB:
        'This endpoint has an active job. Wait for it to finish or cancel it first.',
      ENDPOINT_HAS_ACTIVE_PRECHECK:
        'A bidirectional precheck is still running for this endpoint.',
      ENDPOINT_HAS_ACTIVE_TUNNEL_RUN:
        'A tunnel run is active for this endpoint. Cancel or finish the run first.',
      ENDPOINT_HAS_PERSISTED_TUNNEL_PLANS:
        'This endpoint belongs to an executed or non-draft tunnel plan. Roll back or remove that plan first.',
      ENDPOINT_DELETE_CONFLICT:
        'The endpoint still has protected related data and cannot be deleted safely.',
      ENDPOINT_NOT_FOUND:
        'Endpoint not found.',
      ENDPOINT_ACCESS_DENIED:
        'You do not have permission to delete this endpoint.',
      generic:
        'Endpoint deletion failed.'
    },
    fa: {
      confirm:
        'این Endpoint همراه Inventory، عملیات‌های تمام‌شده، پیش‌بررسی‌ها و پلن‌های پیش‌نویس حذف شود؟ پلن‌های اجراشده یا فعال برای امنیت حذف نمی‌شوند.',
      success: 'Endpoint با موفقیت حذف شد.',
      ENDPOINT_HAS_ACTIVE_JOB:
        'برای این Endpoint یک عملیات فعال وجود دارد؛ ابتدا صبر کن تمام شود یا آن را لغو کن.',
      ENDPOINT_HAS_ACTIVE_PRECHECK:
        'پیش‌بررسی دوطرفه این Endpoint هنوز در حال اجرا است.',
      ENDPOINT_HAS_ACTIVE_TUNNEL_RUN:
        'یک اجرای تونل برای این Endpoint فعال است؛ ابتدا اجرا را لغو یا تمام کن.',
      ENDPOINT_HAS_PERSISTED_TUNNEL_PLANS:
        'این Endpoint داخل یک پلن اجراشده یا غیرپیش‌نویس استفاده شده است؛ ابتدا همان پلن را Rollback یا حذف کن.',
      ENDPOINT_DELETE_CONFLICT:
        'هنوز اطلاعات وابسته محافظت‌شده برای این Endpoint وجود دارد و حذف امن ممکن نیست.',
      ENDPOINT_NOT_FOUND:
        'Endpoint پیدا نشد.',
      ENDPOINT_ACCESS_DENIED:
        'اجازه حذف این Endpoint را نداری.',
      generic:
        'حذف Endpoint ناموفق بود.'
    },
    ru: {
      confirm:
        'Удалить endpoint, его инвентаризацию, завершённые задачи, проверки и черновые планы? Активные и выполненные планы защищены.',
      success: 'Endpoint удалён.',
      ENDPOINT_HAS_ACTIVE_JOB:
        'У endpoint есть активная задача.',
      ENDPOINT_HAS_ACTIVE_PRECHECK:
        'Для endpoint выполняется двусторонняя проверка.',
      ENDPOINT_HAS_ACTIVE_TUNNEL_RUN:
        'Для endpoint выполняется запуск туннеля.',
      ENDPOINT_HAS_PERSISTED_TUNNEL_PLANS:
        'Endpoint используется в выполненном или нечерновом плане. Сначала откатите или удалите план.',
      ENDPOINT_DELETE_CONFLICT:
        'Endpoint содержит защищённые связанные данные.',
      ENDPOINT_NOT_FOUND:
        'Endpoint не найден.',
      ENDPOINT_ACCESS_DENIED:
        'Нет права на удаление endpoint.',
      generic:
        'Не удалось удалить endpoint.'
    },
    'zh-CN': {
      confirm:
        '删除此端点及其网络清单、已完成作业、预检查和草稿计划？活动或已执行计划将受到保护。',
      success: '端点已删除。',
      ENDPOINT_HAS_ACTIVE_JOB:
        '此端点仍有活动作业。',
      ENDPOINT_HAS_ACTIVE_PRECHECK:
        '此端点的双向预检查仍在运行。',
      ENDPOINT_HAS_ACTIVE_TUNNEL_RUN:
        '此端点仍有活动隧道运行。',
      ENDPOINT_HAS_PERSISTED_TUNNEL_PLANS:
        '此端点用于已执行或非草稿计划，请先回滚或删除该计划。',
      ENDPOINT_DELETE_CONFLICT:
        '此端点仍有关联的受保护数据。',
      ENDPOINT_NOT_FOUND:
        '未找到端点。',
      ENDPOINT_ACCESS_DENIED:
        '无权删除此端点。',
      generic:
        '删除端点失败。'
    },
    de: {
      confirm:
        'Diesen Endpoint samt Inventar, abgeschlossenen Jobs, Vorprüfungen und Entwurfsplänen löschen? Aktive oder ausgeführte Tunnelpläne bleiben geschützt.',
      success: 'Endpoint wurde gelöscht.',
      ENDPOINT_HAS_ACTIVE_JOB:
        'Für diesen Endpoint läuft noch ein Job.',
      ENDPOINT_HAS_ACTIVE_PRECHECK:
        'Für diesen Endpoint läuft noch eine bidirektionale Vorprüfung.',
      ENDPOINT_HAS_ACTIVE_TUNNEL_RUN:
        'Für diesen Endpoint läuft noch ein Tunnel-Run.',
      ENDPOINT_HAS_PERSISTED_TUNNEL_PLANS:
        'Der Endpoint wird in einem ausgeführten oder nicht als Entwurf gespeicherten Plan verwendet. Den Plan zuerst zurückrollen oder entfernen.',
      ENDPOINT_DELETE_CONFLICT:
        'Der Endpoint besitzt noch geschützte abhängige Daten.',
      ENDPOINT_NOT_FOUND:
        'Endpoint nicht gefunden.',
      ENDPOINT_ACCESS_DENIED:
        'Keine Berechtigung zum Löschen.',
      generic:
        'Endpoint konnte nicht gelöscht werden.'
    }
  };

  function currentLanguage() {
    const value =
      localStorage.getItem('netauto_language') ||
      localStorage.getItem('language') ||
      'en';

    return messages[value] ? value : 'en';
  }

  function endpointDeleteMessage(detail) {
    const table = messages[currentLanguage()];

    const code =
      typeof detail === 'string'
        ? detail
        : (
            detail?.code ||
            detail?.detail?.code ||
            ''
          );

    let message =
      table[code] ||
      table.generic;

    const plans =
      detail?.plans ||
      detail?.detail?.plans;

    if (
      code ===
        'ENDPOINT_HAS_PERSISTED_TUNNEL_PLANS'
      &&
      Array.isArray(plans)
      &&
      plans.length
    ) {
      message +=
        '\n\n' +
        plans
          .slice(0, 8)
          .map(
            plan =>
              `#${plan.id} ${plan.name} (${plan.status})`
          )
          .join('\n');
    }

    return message;
  }

  async function safeDeleteEndpoint(endpointId) {
    const table = messages[currentLanguage()];

    if (!window.confirm(table.confirm)) {
      return;
    }

    const token =
      sessionStorage.getItem(
        'netauto_access_token'
      );

    try {
      const response = await fetch(
        `/api/v1/endpoints/${Number(endpointId)}`,
        {
          method: 'DELETE',
          headers: token
            ? {
                Authorization: `Bearer ${token}`
              }
            : {}
        }
      );

      let data = {};

      try {
        data = await response.json();
      } catch (_) {
        data = {};
      }

      if (!response.ok) {
        window.alert(
          endpointDeleteMessage(
            data.detail || data
          )
        );
        return;
      }

      window.alert(table.success);
      window.location.reload();
    } catch (_) {
      window.alert(table.generic);
    }
  }

  window.deleteEndpoint =
    safeDeleteEndpoint;

  window.removeEndpoint =
    safeDeleteEndpoint;
})();
/* NETAUTO_SAFE_ENDPOINT_DELETE_END */

