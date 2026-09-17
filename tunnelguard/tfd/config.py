"""TunnelGuard — centralized configuration & tunable settings.

All failover-sensitive knobs (check interval, thresholds, cooldown,
anti-flapping) live here with safe defaults and are editable at runtime
via PUT /api/settings (persisted in SQLite).
"""
from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------- paths
APP_NAME = "TunnelGuard"
_default_data_dir = Path("/var/lib/tunnelguard")
DATA_DIR = Path(os.environ.get("TF_DATA_DIR")
                or (_default_data_dir if os.access(_default_data_dir, os.W_OK)
                    or (_default_data_dir.exists() and os.access(_default_data_dir, os.W_OK))
                    else Path.home() / ".tunnelguard"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "tunnelguard.db"
STATE_PATH = DATA_DIR / "state.json"

SECRET_KEY_FILE = DATA_DIR / "secret.key"

# System paths (overridable for tests / unusual layouts)
ETC_DIR = os.environ.get("TF_ETC_DIR", "/etc/tunnelguard")
WG_CONF_DIR = os.environ.get("TF_WG_CONF_DIR", "/etc/wireguard")
SWANCTL_DIR = os.environ.get("TF_SWANCTL_DIR", "/etc/swanctl/conf.d")
NFT_CONF = os.environ.get("TF_NFT_CONF", "/etc/tunnelguard/nft-tunnelguard.conf")

# ---------------------------------------------------------------- security
JWT_ALGORITHM = "HS256"
JWT_TTL_HOURS = int(os.environ.get("TF_JWT_TTL_HOURS", "12"))

# ---------------------------------------------------------------- defaults
# These are the defaults written to the `settings` table on first run.
# Operators tune them live from the dashboard (Settings drawer).
DEFAULT_SETTINGS: dict = {
    # --- probing ---------------------------------------------------------
    "probe_interval_s": 3,            # seconds between probe cycles
    "probe_count": 5,                 # ICMP packets per cycle
    "probe_timeout_s": 2,             # per-packet timeout
    "probe_target_mode": "tunnel",    # 'tunnel' | 'internet' | 'both'
    "internet_probe_target": "1.1.1.1",
    "tcp_fallback_enabled": True,     # TCP :443 probe when ICMP degrades
    "tcp_fallback_port": 443,
    # --- failure detection ----------------------------------------------
    "fail_threshold": 3,              # consecutive bad cycles => tunnel DOWN
    "loss_threshold_pct": 50.0,       # loss% above which a cycle is "bad"
    "latency_spike_ms": 2000,         # avg rtt above which a cycle is "bad"
    # --- failover behaviour ----------------------------------------------
    "mode": "auto",                   # 'auto' | 'manual'
    "auto_switch_enabled": True,      # master switch for auto failover
    "cooldown_s": 60,                 # min seconds between switches
    "hysteresis_margin": 8.0,         # candidate must beat active by N points
    "flap_window_s": 300,             # anti-flap sliding window
    "flap_max_switches": 4,           # > N switches in window => flap lock
    "flap_lock_s": 900,               # how long a flap-lock persists
    # --- scoring weights (sum should be 100) ------------------------------
    "weight_loss": 40,
    "weight_latency": 30,
    "weight_jitter": 20,
    "weight_stability": 10,
    "rtt_reference_ms": 300,          # rtt considered "worst acceptable"
    "jitter_reference_ms": 50,        # jitter considered "worst acceptable"
    # --- networking / virtual IP ------------------------------------------
    "virtual_ip": "10.10.10.5",       # /32 identity that must never change
    "vip_enabled": True,
    "route_mode": "split",            # 'split' (dest routes) | 'default' (gw)
    "remote_sync_enabled": True,      # SSH-sync return route on peer
    "mss_clamp_enabled": True,
    # --- bandwidth ---------------------------------------------------------
    "throughput_sample_s": 5,         # /sys counters sampling interval
    "iperf_enabled": False,           # scheduled iperf3 bench (costly)
    "iperf_interval_min": 30,
    "iperf_duration_s": 5,
    # --- demo / lab ---------------------------------------------------------
    "sim_mode": False,                # Sim engines: no system commands
}

# Engines that can be selected in the UI. Truth lives in tfd/engines.
# kind: kernel = L3 iface routed by VIP manager; proxy = userspace ingress
# (SOCKS5); tun-optional = proxy that becomes routable in TUN mode.
ENGINE_META = {
    "wireguard": {"label": "WireGuard", "mtu_default": 1420, "layer": "L3",
                  "kind": "kernel", "fields": ["private_key", "peer_public_key",
                                               "endpoint_host", "endpoint_port",
                                               "listen_port", "allowed_ips"]},
    "gre":       {"label": "GRE",       "mtu_default": 1476, "layer": "L3",
                  "kind": "kernel", "fields": []},
    "sit":       {"label": "SIT 6in4",  "mtu_default": 1480, "layer": "L3-IPv6",
                  "kind": "kernel", "fields": []},
    "openvpn":   {"label": "OpenVPN",   "mtu_default": 1440, "layer": "L3",
                  "kind": "kernel", "fields": ["remote_port", "proto",
                                               "ca_cert", "client_cert",
                                               "client_key", "tls_auth"]},
    "ikev2":     {"label": "IKEv2/IPsec VTI", "mtu_default": 1436, "layer": "L3",
                  "kind": "kernel", "fields": ["psk", "ike_cipher",
                                               "esp_cipher"]},
    "l2tp":      {"label": "L2TPv3/IPsec",    "mtu_default": 1410, "layer": "L3",
                  "kind": "kernel", "fields": ["session_id", "cookie",
                                               "psk"]},
    "hedioum":   {"label": "Hedioum Pool Tunnel", "mtu_default": 1500,
                  "layer": "L3-TUN/userspace", "kind": "proxy",
                  "tun_optional": True,
                  "fields": ["pairing_token", "foreign_ip", "foreign_port",
                             "auth_token", "mimic", "socks_port",
                             "tun_enabled", "tun_addr", "dns_enabled",
                             "min_connections", "max_connections",
                             "bandwidth_limit_mbps",
                             "bandwidth_jitter_mbps"]},
    "hajsaman":  {"label": "HajSaman Tunnel (WG-in-SIT)", "mtu_default": 1420,
                  "layer": "L3 · WG inside SIT (proto 41)", "kind": "kernel",
                  "fields": ["mode", "slot", "role", "local_public_ip",
                             "foreign_ipv4", "wg_listen_port", "private_key",
                             "peer_public_key", "psk", "mark", "table",
                             "sit_mtu", "wg_mtu"]},
    "paqet":     {"label": "Paqet (raw-TCP/KCP)", "mtu_default": 1350,
                  "layer": "userspace SOCKS5 · KCP over raw packets",
                  "kind": "proxy",
                  "fields": ["role", "server_addr", "listen_addr",
                             "socks_listen", "interface", "local_ipv4",
                             "router_mac", "kcp_key", "kcp_block",
                             "kcp_mode", "kcp_conn", "forward",
                             "tcp_flags", "iptables_setup"]},
    "sim":       {"label": "Simulation", "mtu_default": 1500, "layer": "virtual",
                  "kind": "virtual", "fields": ["base_rtt_ms", "jitter_ms",
                                                "loss_pct", "script"]},
}


def load_secret_key() -> bytes:
    """Persistent master secret (JWT signing + Fernet credential encryption)."""
    import base64

    env = os.environ.get("TF_SECRET_KEY")
    if env:
        return env.encode()
    if SECRET_KEY_FILE.exists():
        return SECRET_KEY_FILE.read_bytes()
    key = base64.urlsafe_b64encode(os.urandom(32))
    SECRET_KEY_FILE.write_bytes(key)
    try:
        SECRET_KEY_FILE.chmod(0o600)
    except OSError:
        pass
    return key
