#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo; echo "❌ UPDATE FAILED — SSH session remains open."' ERR

cd /opt/network-automation

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="backups/composer-simple-extra-${STAMP}"
mkdir -p "$BACKUP"

cp backend/app/tunnel_catalog.py "$BACKUP/tunnel_catalog.py"
cp web/assets/composer.js "$BACKUP/composer.js"
cp web/assets/composer.css "$BACKUP/composer.css"
cp web/composer.html "$BACKUP/composer.html"

echo "Backup: /opt/network-automation/$BACKUP"

python3 - <<'PY'
from pathlib import Path
import re

path = Path("backend/app/tunnel_catalog.py")
text = path.read_text(encoding="utf-8")

begin = "# NETAUTO_EXTRA_TUNNEL_METHODS_BEGIN"
end = "# NETAUTO_EXTRA_TUNNEL_METHODS_END"

if begin in text and end in text:
    text = re.sub(
        re.escape(begin) + r".*?" + re.escape(end),
        "",
        text,
        count=1,
        flags=re.S,
    )

patch = r'''

# NETAUTO_EXTRA_TUNNEL_METHODS_BEGIN

def extra_method(
    method_id,
    name,
    category,
    layer,
    description,
    *,
    directions=None,
    flags=None,
    parameters=None,
    simple_defaults=None,
):
    item = method(
        method_id,
        name,
        category,
        layer,
        description=description,
        directions=directions,
        flags=flags,
        parameters=parameters,
    )
    item["simple_supported"] = True
    item["advanced_supported"] = True
    item["simple_defaults"] = simple_defaults or {
        "traffic_direction": (
            "BIDIRECTIONAL"
            if "BIDIRECTIONAL" in item["directions"]
            else item["directions"][0]
        ),
        "initiator": "AUTO",
        "carrier_method_id": None,
        "config": {
            "mode": "SIMPLE",
            "auto_allocate": True,
            "auto_install": True,
        },
    }
    return item


EXTRA_METHODS = [
    extra_method(
        "WATERWALL_DIRECT",
        "WaterWall Direct",
        "WATERWALL",
        "STREAM",
        "Direct WaterWall node-based TCP tunnel profile.",
        directions=["A_TO_B", "B_TO_A", "BIDIRECTIONAL"],
        flags=["MULTI_INSTANCE", "TCP", "MUX", "AUTO_RECONNECT"],
        parameters=["listen_port", "target_host", "target_port", "mux"],
    ),
    extra_method(
        "WATERWALL_REVERSE",
        "WaterWall Reverse",
        "WATERWALL",
        "STREAM",
        "Reverse WaterWall tunnel profile.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "TCP", "REVERSE", "MUX", "AUTO_RECONNECT"],
        parameters=["listen_port", "target_host", "target_port", "mux"],
        simple_defaults={
            "traffic_direction": "B_TO_A",
            "initiator": "B",
            "carrier_method_id": None,
            "config": {
                "mode": "SIMPLE",
                "auto_allocate": True,
                "auto_install": True,
                "reverse": True,
                "mux": True,
            },
        },
    ),
    extra_method(
        "WATERWALL_TLS_MUX",
        "WaterWall TLS + MUX",
        "WATERWALL",
        "STREAM",
        "WaterWall encrypted multiplexed tunnel profile.",
        directions=["A_TO_B", "B_TO_A", "BIDIRECTIONAL"],
        flags=["MULTI_INSTANCE", "TCP", "TLS", "MUX", "ENCRYPTED"],
        parameters=["listen_port", "server_name", "target_host", "target_port"],
    ),
    extra_method(
        "PAQET_RAW_KCP",
        "Paqet Raw KCP",
        "PAQET",
        "PROXY",
        "Bidirectional Paqet raw-packet KCP profile.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "RAW_SOCKET", "KCP", "PCAP", "ENCRYPTED"],
        parameters=["interface", "gateway_mac", "listen_port", "socks_port"],
    ),
    extra_method(
        "PAQET_SOCKS5",
        "Paqet SOCKS5",
        "PAQET",
        "PROXY",
        "Paqet client/server profile with a local SOCKS5 endpoint.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "RAW_SOCKET", "KCP", "SOCKS5"],
        parameters=["interface", "gateway_mac", "socks_port"],
    ),
    extra_method(
        "RATHOLE_TCP",
        "Rathole TCP",
        "RATHOLE",
        "STREAM",
        "Rathole reverse TCP service exposure.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "TCP", "REVERSE", "TOKEN"],
        parameters=["control_port", "remote_port", "local_host", "local_port"],
    ),
    extra_method(
        "RATHOLE_UDP",
        "Rathole UDP",
        "RATHOLE",
        "DATAGRAM",
        "Rathole reverse UDP service exposure.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "UDP", "REVERSE", "TOKEN"],
        parameters=["control_port", "remote_port", "local_host", "local_port"],
    ),
    extra_method(
        "RATHOLE_TLS",
        "Rathole TLS",
        "RATHOLE",
        "STREAM",
        "Rathole reverse tunnel with TLS transport.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "TCP", "REVERSE", "TLS", "TOKEN"],
        parameters=["control_port", "remote_port", "local_host", "local_port"],
    ),
    extra_method(
        "RATHOLE_NOISE",
        "Rathole Noise",
        "RATHOLE",
        "STREAM",
        "Rathole reverse tunnel with Noise transport.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "TCP", "REVERSE", "NOISE", "TOKEN"],
        parameters=["control_port", "remote_port", "local_host", "local_port"],
    ),
    extra_method(
        "RATHOLE_WEBSOCKET",
        "Rathole WebSocket",
        "RATHOLE",
        "STREAM",
        "Rathole reverse tunnel over WebSocket.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "TCP", "REVERSE", "WEBSOCKET"],
        parameters=["control_port", "remote_port", "local_host", "local_port"],
    ),
    extra_method(
        "CHISEL_TCP",
        "Chisel TCP",
        "CHISEL",
        "STREAM",
        "Chisel TCP tunnel over HTTP.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "TCP", "HTTP", "SSH_SECURITY"],
        parameters=["server_port", "local_port", "target_host", "target_port"],
    ),
    extra_method(
        "CHISEL_UDP",
        "Chisel UDP",
        "CHISEL",
        "DATAGRAM",
        "Chisel UDP tunnel over HTTP.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "UDP", "HTTP", "SSH_SECURITY"],
        parameters=["server_port", "local_port", "target_host", "target_port"],
    ),
    extra_method(
        "CHISEL_REVERSE_TCP",
        "Chisel Reverse TCP",
        "CHISEL",
        "STREAM",
        "Chisel reverse TCP tunnel.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "TCP", "REVERSE", "HTTP", "SSH_SECURITY"],
        parameters=["server_port", "remote_port", "target_host", "target_port"],
        simple_defaults={
            "traffic_direction": "B_TO_A",
            "initiator": "B",
            "carrier_method_id": None,
            "config": {
                "mode": "SIMPLE",
                "auto_allocate": True,
                "auto_install": True,
                "reverse": True,
            },
        },
    ),
    extra_method(
        "CHISEL_REVERSE_UDP",
        "Chisel Reverse UDP",
        "CHISEL",
        "DATAGRAM",
        "Chisel reverse UDP tunnel.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "UDP", "REVERSE", "HTTP", "SSH_SECURITY"],
        parameters=["server_port", "remote_port", "target_host", "target_port"],
    ),
    extra_method(
        "CHISEL_SOCKS5",
        "Chisel SOCKS5",
        "CHISEL",
        "PROXY",
        "SOCKS5 proxy through Chisel.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "SOCKS5", "HTTP", "SSH_SECURITY"],
        parameters=["server_port", "socks_port"],
    ),
    extra_method(
        "CHISEL_REVERSE_SOCKS5",
        "Chisel Reverse SOCKS5",
        "CHISEL",
        "PROXY",
        "Reverse SOCKS5 proxy through Chisel.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "SOCKS5", "REVERSE", "HTTP", "SSH_SECURITY"],
        parameters=["server_port", "socks_port"],
    ),
    extra_method(
        "FRP_TCP",
        "FRP TCP",
        "FRP",
        "STREAM",
        "FRP TCP reverse proxy.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "TCP", "REVERSE"],
        parameters=["control_port", "remote_port", "local_host", "local_port"],
    ),
    extra_method(
        "FRP_UDP",
        "FRP UDP",
        "FRP",
        "DATAGRAM",
        "FRP UDP reverse proxy.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "UDP", "REVERSE"],
        parameters=["control_port", "remote_port", "local_host", "local_port"],
    ),
    extra_method(
        "FRP_STCP",
        "FRP STCP",
        "FRP",
        "STREAM",
        "FRP secret TCP service.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "TCP", "SECRET"],
        parameters=["control_port", "local_host", "local_port"],
    ),
    extra_method(
        "FRP_XTCP",
        "FRP XTCP",
        "FRP",
        "P2P",
        "FRP peer-to-peer TCP profile.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "TCP", "P2P"],
        parameters=["control_port", "local_host", "local_port"],
    ),
    extra_method(
        "FRP_KCP",
        "FRP KCP",
        "FRP",
        "CARRIER",
        "FRP forwarding using KCP transport.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "KCP", "UDP"],
        parameters=["control_port", "remote_port", "local_host", "local_port"],
    ),
    extra_method(
        "FRP_QUIC",
        "FRP QUIC",
        "FRP",
        "CARRIER",
        "FRP forwarding using QUIC transport.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "QUIC", "UDP"],
        parameters=["control_port", "remote_port", "local_host", "local_port"],
    ),
    extra_method(
        "WSTUNNEL_TCP",
        "wstunnel TCP",
        "WSTUNNEL",
        "STREAM",
        "TCP tunnel transported over WebSocket.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "TCP", "WEBSOCKET"],
        parameters=["server_port", "path", "local_port", "target_host", "target_port"],
    ),
    extra_method(
        "WSTUNNEL_UDP",
        "wstunnel UDP",
        "WSTUNNEL",
        "DATAGRAM",
        "UDP tunnel transported over WebSocket.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "UDP", "WEBSOCKET"],
        parameters=["server_port", "path", "local_port", "target_host", "target_port"],
    ),
    extra_method(
        "WSTUNNEL_SOCKS5",
        "wstunnel SOCKS5",
        "WSTUNNEL",
        "PROXY",
        "SOCKS5 tunnel transported over WebSocket.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "SOCKS5", "WEBSOCKET"],
        parameters=["server_port", "path", "socks_port"],
    ),
    extra_method(
        "HYSTERIA2",
        "Hysteria 2",
        "MODERN_PROXY",
        "PROXY",
        "Hysteria 2 client/server profile.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "QUIC", "UDP", "TLS"],
        parameters=["listen_port", "server_name", "auth_mode", "obfs_mode"],
    ),
    extra_method(
        "TUIC",
        "TUIC",
        "MODERN_PROXY",
        "PROXY",
        "TUIC client/server profile.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "QUIC", "UDP", "TLS"],
        parameters=["listen_port", "server_name", "uuid_mode"],
    ),
    extra_method(
        "TROJAN_TLS",
        "Trojan TLS",
        "MODERN_PROXY",
        "PROXY",
        "Trojan proxy protected by TLS.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "TCP", "TLS"],
        parameters=["listen_port", "server_name", "password_mode"],
    ),
    extra_method(
        "SHADOWSOCKS",
        "Shadowsocks",
        "MODERN_PROXY",
        "PROXY",
        "Shadowsocks proxy profile.",
        directions=["A_TO_B", "B_TO_A"],
        flags=["MULTI_INSTANCE", "TCP_UDP", "ENCRYPTED"],
        parameters=["listen_port", "method", "password_mode"],
    ),
    extra_method(
        "SINGBOX_TUN",
        "sing-box TUN",
        "MODERN_PROXY",
        "L3",
        "sing-box TUN routing profile.",
        directions=["A_TO_B", "B_TO_A", "BIDIRECTIONAL"],
        flags=["MULTI_INSTANCE", "TUN", "ROUTING"],
        parameters=["interface", "subnet", "mtu", "route_mode"],
    ),
]

existing_ids = {item["id"] for item in CATALOG}

for item in EXTRA_METHODS:
    if item["id"] not in existing_ids:
        CATALOG.append(item)
        existing_ids.add(item["id"])

for item in CATALOG:
    item.setdefault("simple_supported", True)
    item.setdefault("advanced_supported", True)

    default_direction = (
        "B_TO_A"
        if (
            "REVERSE" in item.get("flags", [])
            and "B_TO_A" in item.get("directions", [])
        )
        else (
            "BIDIRECTIONAL"
            if "BIDIRECTIONAL" in item.get("directions", [])
            else item.get("directions", ["A_TO_B"])[0]
        )
    )

    item.setdefault(
        "simple_defaults",
        {
            "traffic_direction": default_direction,
            "initiator": (
                "B"
                if default_direction == "B_TO_A"
                else "AUTO"
            ),
            "carrier_method_id": None,
            "config": {
                "mode": "SIMPLE",
                "auto_allocate": True,
                "auto_install": True,
            },
        },
    )

METHOD_MAP.clear()
METHOD_MAP.update({item["id"]: item for item in CATALOG})

# NETAUTO_EXTRA_TUNNEL_METHODS_END
'''

text = text.rstrip() + "\n" + patch + "\n"
path.write_text(text, encoding="utf-8")
print("Extra methods added.")
PY

python3 - <<'PY'
from pathlib import Path
import re

targets = [
    (
        Path("web/assets/composer.js"),
        "/* NETAUTO_SIMPLE_COMPOSER_BEGIN */",
        "/* NETAUTO_SIMPLE_COMPOSER_END */",
    ),
    (
        Path("web/assets/composer.css"),
        "/* NETAUTO SIMPLE COMPOSER */",
        None,
    ),
]

js_path, begin, end = targets[0]
js = js_path.read_text(encoding="utf-8")

if begin in js and end in js:
    js = re.sub(
        re.escape(begin) + r".*?" + re.escape(end),
        "",
        js,
        count=1,
        flags=re.S,
    )

js_path.write_text(js.rstrip() + "\n", encoding="utf-8")

css_path = targets[1][0]
css = css_path.read_text(encoding="utf-8")
css_marker = targets[1][1]

if css_marker in css:
    css = css[:css.index(css_marker)]

css_path.write_text(css.rstrip() + "\n", encoding="utf-8")
PY

cat >> web/assets/composer.js <<'JS'


/* NETAUTO_SIMPLE_COMPOSER_BEGIN */

Object.assign(LANG.en, {
  simple_mode: 'Simple mode',
  advanced_mode: 'Advanced mode',
  simple_help: 'Choose methods, direction and quantity. IPs, ports, interfaces and safe defaults are selected automatically.',
  advanced_help: 'Show carriers, initiator and advanced JSON options.',
  quantity: 'Quantity',
  automatic: 'Automatic settings',
  method_count: 'methods'
});

Object.assign(LANG.fa, {
  simple_mode: 'حالت ساده',
  advanced_mode: 'حالت پیشرفته',
  simple_help: 'فقط روش، جهت و تعداد را انتخاب کن؛ IP، پورت، Interface و تنظیمات امن خودکار انتخاب می‌شوند.',
  advanced_help: 'حامل، سمت آغازکننده و تنظیمات JSON پیشرفته نمایش داده می‌شوند.',
  quantity: 'تعداد',
  automatic: 'تنظیم خودکار',
  method_count: 'روش'
});

Object.assign(LANG.ru, {
  simple_mode: 'Простой режим',
  advanced_mode: 'Расширенный режим',
  simple_help: 'Выберите метод, направление и количество. IP, порты и безопасные настройки выбираются автоматически.',
  advanced_help: 'Показывает носитель, инициатора и расширенный JSON.',
  quantity: 'Количество',
  automatic: 'Автоматически',
  method_count: 'методов'
});

Object.assign(LANG['zh-CN'], {
  simple_mode: '简单模式',
  advanced_mode: '高级模式',
  simple_help: '只需选择方法、方向和数量；IP、端口、接口和安全默认值将自动分配。',
  advanced_help: '显示承载方式、发起端和高级 JSON 选项。',
  quantity: '数量',
  automatic: '自动设置',
  method_count: '种方法'
});

Object.assign(LANG.de, {
  simple_mode: 'Einfacher Modus',
  advanced_mode: 'Erweiterter Modus',
  simple_help: 'Methode, Richtung und Anzahl wählen. IPs, Ports und sichere Einstellungen werden automatisch gewählt.',
  advanced_help: 'Zeigt Träger, Initiator und erweiterte JSON-Optionen.',
  quantity: 'Anzahl',
  automatic: 'Automatisch',
  method_count: 'Methoden'
});

state.composerMode =
  localStorage.getItem('netauto_composer_mode')
  || 'SIMPLE';

const netautoAdvancedRenderCatalog =
  window.renderCatalog;

const netautoAdvancedAddSelectedMethods =
  window.addSelectedMethods;

function ensureComposerModeControl() {
  if (document.getElementById('composerModeControl')) {
    updateComposerModeControl();
    return;
  }

  const firstSection =
    document.querySelector('.composer-section');

  if (!firstSection) return;

  const box = document.createElement('div');
  box.id = 'composerModeControl';
  box.className = 'composer-mode-control';
  box.innerHTML = `
    <div class="composer-mode-buttons">
      <button
        id="simpleModeButton"
        class="btn"
        onclick="setComposerMode('SIMPLE')"
      ></button>

      <button
        id="advancedModeButton"
        class="btn"
        onclick="setComposerMode('ADVANCED')"
      ></button>
    </div>

    <p id="composerModeHelp"></p>
  `;

  firstSection.prepend(box);
  updateComposerModeControl();
}

function updateComposerModeControl() {
  const simpleButton =
    document.getElementById('simpleModeButton');

  const advancedButton =
    document.getElementById('advancedModeButton');

  const help =
    document.getElementById('composerModeHelp');

  if (!simpleButton) return;

  simpleButton.textContent =
    `⚡ ${t('simple_mode')}`;

  advancedButton.textContent =
    `🛠 ${t('advanced_mode')}`;

  simpleButton.classList.toggle(
    'btn-primary',
    state.composerMode === 'SIMPLE'
  );

  advancedButton.classList.toggle(
    'btn-primary',
    state.composerMode === 'ADVANCED'
  );

  help.textContent =
    state.composerMode === 'SIMPLE'
      ? t('simple_help')
      : t('advanced_help');
}

function setComposerMode(mode) {
  state.composerMode =
    mode === 'ADVANCED'
      ? 'ADVANCED'
      : 'SIMPLE';

  localStorage.setItem(
    'netauto_composer_mode',
    state.composerMode
  );

  updateComposerModeControl();
  renderCatalog();
}

function simpleDirectionOptions(method) {
  const preferred =
    method.simple_defaults?.traffic_direction;

  return (method.directions || [])
    .map(value => `
      <option
        value="${esc(value)}"
        ${value === preferred ? 'selected' : ''}
      >
        ${esc(value)}
      </option>
    `)
    .join('');
}

function renderSimpleCatalog() {
  const target = el('catalog');
  if (!target) return;

  const search = (
    el('methodSearch')?.value || ''
  ).trim().toLowerCase();

  const category =
    el('categoryFilter')?.value || '';

  const filtered =
    state.methods.filter(method => {
      const searchable = [
        method.id,
        method.name,
        method.description,
        method.category,
        ...(method.flags || [])
      ].join(' ').toLowerCase();

      return (
        method.simple_supported !== false
        &&
        (!search || searchable.includes(search))
        &&
        (!category || method.category === category)
      );
    });

  const grouped = {};

  for (const method of filtered) {
    grouped[method.category] ||= [];
    grouped[method.category].push(method);
  }

  target.innerHTML =
    Object.entries(grouped)
      .map(([group, methods]) => `
        <details class="simple-category" open>
          <summary>
            <strong>${esc(group)}</strong>
            <span>
              ${methods.length}
              ${esc(t('method_count'))}
            </span>
          </summary>

          <div class="simple-method-list">
            ${methods.map(method => `
              <article
                class="simple-method-card"
                id="simple-card-${esc(method.id)}"
              >
                <label
                  class="simple-method-head"
                  for="simple-method-${esc(method.id)}"
                >
                  <input
                    type="checkbox"
                    id="simple-method-${esc(method.id)}"
                    onchange="
                      document
                        .getElementById(
                          'simple-card-${esc(method.id)}'
                        )
                        .classList
                        .toggle(
                          'selected',
                          this.checked
                        )
                    "
                  >

                  <span>
                    <strong>${esc(method.name)}</strong>
                    <small>
                      ${esc(method.layer)}
                      ·
                      ${esc(method.id)}
                    </small>
                  </span>
                </label>

                <p>${esc(method.description)}</p>

                <div class="simple-method-options">
                  <div>
                    <small>${esc(t('direction'))}</small>
                    <select
                      id="simple-direction-${esc(method.id)}"
                    >
                      ${simpleDirectionOptions(method)}
                    </select>
                  </div>

                  <div>
                    <small>${esc(t('quantity'))}</small>
                    <select
                      id="simple-quantity-${esc(method.id)}"
                    >
                      ${[1,2,3,4,5,6,7,8,9,10]
                        .map(number => `
                          <option value="${number}">
                            ${number}
                          </option>
                        `)
                        .join('')}
                    </select>
                  </div>
                </div>

                <div class="simple-auto-label">
                  ⚙️ ${esc(t('automatic'))}
                </div>
              </article>
            `).join('')}
          </div>
        </details>
      `)
      .join('');
}

window.renderCatalog = function () {
  ensureComposerModeControl();

  if (state.composerMode === 'ADVANCED') {
    return netautoAdvancedRenderCatalog();
  }

  return renderSimpleCatalog();
};

function countQueuedMethod(
  methodId,
  endpointA,
  endpointB
) {
  return state.queue.filter(
    item =>
      item.method_id === methodId
      &&
      item.endpoint_a_id === endpointA
      &&
      item.endpoint_b_id === endpointB
  ).length;
}

function addSimpleSelectedMethods() {
  const endpointA = Number(el('endpointA').value);
  const endpointB = Number(el('endpointB').value);

  if (
    !endpointA ||
    !endpointB ||
    endpointA === endpointB
  ) {
    alert(t('different_endpoints'));
    return;
  }

  const selected =
    state.methods.filter(
      method =>
        document.getElementById(
          `simple-method-${method.id}`
        )?.checked
    );

  if (!selected.length) {
    alert(t('choose_method'));
    return;
  }

  for (const method of selected) {
    const quantity = Number(
      document.getElementById(
        `simple-quantity-${method.id}`
      )?.value || 1
    );

    const direction =
      document.getElementById(
        `simple-direction-${method.id}`
      )?.value
      ||
      method.simple_defaults?.traffic_direction
      ||
      method.directions?.[0]
      ||
      'A_TO_B';

    const startingIndex =
      countQueuedMethod(
        method.id,
        endpointA,
        endpointB
      );

    for (let offset = 1; offset <= quantity; offset++) {
      const sequence = startingIndex + offset;

      const defaults =
        JSON.parse(
          JSON.stringify(
            method.simple_defaults?.config || {}
          )
        );

      const carrier =
        method.simple_defaults?.carrier_method_id
        ||
        (
          method.category === 'COMPOSITE'
            ? method.carrier_options?.[0]?.id
            : null
        )
        ||
        null;

      state.queue.push({
        endpoint_a_id: endpointA,
        endpoint_b_id: endpointB,
        method_id: method.id,
        method_name: `${method.name} #${sequence}`,
        carrier_method_id: carrier,
        traffic_direction: direction,
        initiator:
          method.simple_defaults?.initiator
          ||
          (
            direction === 'B_TO_A'
              ? 'B'
              : 'AUTO'
          ),
        config: {
          ...defaults,
          mode: 'SIMPLE',
          auto_allocate: true,
          auto_install: true,
          auto_precheck: true,
          auto_inventory_refresh: true,
          instance_number: sequence,
          display_name: `${method.name} #${sequence}`,
        }
      });
    }

    document.getElementById(
      `simple-method-${method.id}`
    ).checked = false;

    document.getElementById(
      `simple-card-${method.id}`
    )?.classList.remove('selected');
  }

  renderQueue();
}

window.addSelectedMethods = function () {
  if (state.composerMode === 'ADVANCED') {
    return netautoAdvancedAddSelectedMethods();
  }

  return addSimpleSelectedMethods();
};

setTimeout(ensureComposerModeControl, 100);

/* NETAUTO_SIMPLE_COMPOSER_END */
JS

cat >> web/assets/composer.css <<'CSS'

/* NETAUTO SIMPLE COMPOSER */

.composer-mode-control {
  display: grid;
  gap: 9px;
  margin-bottom: 18px;
  padding: 13px;
  border: 1px solid #2a3d58;
  border-radius: 13px;
  background: #07101c;
}

.composer-mode-buttons {
  display: flex;
  gap: 9px;
}

.composer-mode-buttons .btn {
  flex: 1;
}

.composer-mode-control p {
  margin: 0;
  color: #9fb0c9;
  line-height: 1.8;
}

.simple-category {
  margin: 13px 0;
  overflow: hidden;
  border: 1px solid #263449;
  border-radius: 13px;
  background: #08111e;
}

.simple-category > summary {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  padding: 14px 16px;
  cursor: pointer;
  background: #0e1929;
}

.simple-category > summary span {
  color: #91a3be;
  font-size: 12px;
}

.simple-method-list {
  display: grid;
  grid-template-columns:
    repeat(auto-fill, minmax(270px, 1fr));
  gap: 9px;
  padding: 10px;
}

.simple-method-card {
  padding: 13px;
  border: 1px solid #253650;
  border-radius: 12px;
  background: #07101c;
}

.simple-method-card.selected {
  border-color: #6366f1;
  background: #17255455;
  box-shadow: 0 0 0 1px #6366f155;
}

.simple-method-head {
  display: flex;
  align-items: flex-start;
  gap: 9px;
  cursor: pointer;
}

.simple-method-head input {
  width: auto;
  margin-top: 4px;
}

.simple-method-head span {
  display: grid;
  gap: 3px;
}

.simple-method-head small {
  direction: ltr;
  color: #7690b4;
  font-size: 10px;
}

.simple-method-card p {
  min-height: 37px;
  margin: 9px 0;
  color: #9fb0c9;
  font-size: 12px;
  line-height: 1.6;
}

.simple-method-options {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 8px;
}

.simple-method-options small {
  display: block;
  margin-bottom: 4px;
}

.simple-auto-label {
  margin-top: 9px;
  padding: 6px 8px;
  border-radius: 8px;
  color: #86efac;
  background: #064e3b55;
  font-size: 11px;
}

@media (max-width: 620px) {
  .composer-mode-buttons {
    flex-direction: column;
  }

  .simple-method-options {
    grid-template-columns: 1fr;
  }
}
CSS

python3 - "$STAMP" <<'PY'
from pathlib import Path
import re
import sys

stamp = sys.argv[1]
path = Path("web/composer.html")
html = path.read_text(encoding="utf-8")

html = re.sub(
    r'/assets/composer\.css(?:\?v=[^"]*)?',
    f'/assets/composer.css?v={stamp}',
    html,
)

html = re.sub(
    r'/assets/composer\.js(?:\?v=[^"]*)?',
    f'/assets/composer.js?v={stamp}',
    html,
)

path.write_text(html, encoding="utf-8")
PY

echo "===== PYTHON SYNTAX ====="

python3 -m py_compile \
  backend/app/tunnel_catalog.py

echo "Python syntax OK."

echo "===== BUILD API ====="

docker compose build api

docker compose up -d \
  --force-recreate \
  api web

sleep 20

echo "===== HEALTH ====="

curl -fsS \
  http://127.0.0.1:18080/api/v1/health
echo

echo "===== CATALOG CHECK ====="

docker compose exec -T api python - <<'PY'
from app.tunnel_catalog import CATALOG

required = {
    "WATERWALL_DIRECT",
    "WATERWALL_REVERSE",
    "PAQET_RAW_KCP",
    "RATHOLE_TCP",
    "CHISEL_REVERSE_TCP",
    "FRP_TCP",
    "WSTUNNEL_TCP",
    "HYSTERIA2",
    "TUIC",
}

ids = {item["id"] for item in CATALOG}
missing = required - ids

if missing:
    raise SystemExit(
        f"Missing methods: {sorted(missing)}"
    )

print(f"Catalog methods: {len(CATALOG)}")
print("Simple mode available for all methods.")
PY

echo "===== WEB CHECK ====="

curl -fsS -o /dev/null \
  -w "Composer HTTP: %{http_code}\n" \
  http://127.0.0.1:18080/composer.html

grep -q \
  "NETAUTO_SIMPLE_COMPOSER_BEGIN" \
  web/assets/composer.js

rm -f \
  /tmp/netauto-*.txt \
  /root/netauto-*.txt \
  2>/dev/null || true

echo "===== SERVICES ====="

docker compose ps \
  api web worker bot

echo
echo "✅ SIMPLE MODE + EXTRA METHODS READY"
echo "Refresh: https://tunnel.softarg.ir/composer.html"
