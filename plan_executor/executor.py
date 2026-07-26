import base64
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import shlex
import time
import uuid
from contextlib import contextmanager
from datetime import datetime

import paramiko
import psycopg
from cryptography.fernet import Fernet
from psycopg.rows import dict_row
from redis import Redis

DATABASE_URL = os.environ["DATABASE_URL"].replace(
    "postgresql+psycopg://", "postgresql://"
)
REDIS_URL = os.environ["REDIS_URL"]
APP_SECRET_KEY = os.environ["APP_SECRET_KEY"]

redis_client = Redis.from_url(REDIS_URL, decode_responses=True)
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("netauto-plan-executor")

SUPPORTED = {
    "GRE",
    "GRETAP",
    "IPIP",
    "SIT_6IN4",
    "IP6GRE",
    "IP6GRETAP",
    "VXLAN",
    "WIREGUARD",
    "SSH_LOCAL_FORWARD",
    "SSH_REMOTE_FORWARD",
    "SSH_DYNAMIC_SOCKS",
    "AUTOSSH_REVERSE",
    "SSH_TUN_L3",
    "SSH_TAP_L2",
    "GOST_TCP_FORWARD",
    "GOST_UDP_FORWARD",
    "GOST_REMOTE_TCP",
    "GOST_REMOTE_UDP",
    "GOST_SOCKS5",
    "GOST_HTTP",
    "GOST_WS",
    "GOST_HTTP2",
    "GOST_GRPC",
    "GOST_QUIC",
    "GOST_SSH",
    "GOST_TUN",
    "GOST_TAP",
    "GOST_KCP_FORWARD",
    "GOST_SOCKS5_KCP",
    "CHISEL_REVERSE_SOCKS5",
    "CHISEL_REVERSE_TCP",
    "CHISEL_REVERSE_UDP",
    "CHISEL_SOCKS5",
    "CHISEL_TCP",
    "CHISEL_UDP",
    "FRP_KCP",
    "FRP_QUIC",
    "FRP_STCP",
    "FRP_TCP",
    "FRP_UDP",
    "FRP_XTCP",
    "RATHOLE_NOISE",
    "RATHOLE_TCP",
    "RATHOLE_TLS",
    "RATHOLE_UDP",
    "RATHOLE_WEBSOCKET",
    "WSTUNNEL_SOCKS5",
    "WSTUNNEL_TCP",
    "WSTUNNEL_UDP",
    "IKEV2_IPSEC",
    "L2TP_IPSEC",
    "OPENVPN",
    "VTI",
    "VTI6",
    "VLESS_TCP",
    "VLESS_WS",
    "VLESS_GRPC",
    "VLESS_XHTTP",
    "VLESS_REALITY",
    "VLESS_VISION_REALITY",
    "VLESS_XHTTP_REALITY",
    "HYSTERIA2",
    "TUIC",
    "TROJAN_TLS",
    "SHADOWSOCKS",
    "SINGBOX_TUN",
    "WATERWALL_DIRECT",
    "WATERWALL_REVERSE",
    "WATERWALL_TLS_MUX",
    "PAQET_RAW_KCP",
    "PAQET_SOCKS5",
    "SIT_OVER_GOST",
    "GRE_OVER_GOST",
    "GRETAP_OVER_GOST",
    "SIT_OVER_SSH",
    "GRE_OVER_SSH",
    "GRE_OVER_WIREGUARD",
}


def db_connect():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def decrypt_secret(value: str) -> str:
    digest = hashlib.sha256(APP_SECRET_KEY.encode("utf-8")).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key).decrypt(value.encode("utf-8")).decode("utf-8")


def add_event(
    connection,
    run_id: int,
    message: str,
    *,
    run_item_id: int | None = None,
    level: str = "INFO",
    details: dict | None = None,
):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO tunnel_plan_run_events (
                run_id,run_item_id,level,message,details_json
            ) VALUES (%s,%s,%s,%s,%s)
            """,
            (
                run_id,
                run_item_id,
                level,
                message,
                json.dumps(details or {}, ensure_ascii=False),
            ),
        )
    connection.commit()


def load_private_key(raw: str):
    for loader in (
        paramiko.RSAKey,
        paramiko.ECDSAKey,
        paramiko.Ed25519Key,
    ):
        try:
            return loader.from_private_key(io.StringIO(raw))
        except Exception:
            pass
    raise RuntimeError("PRIVATE_KEY_FORMAT_UNSUPPORTED")




def ssh_fingerprint(key) -> str:
    return ":".join(f"{byte:02x}" for byte in key.get_fingerprint()).lower()


class EndpointHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """TOFU on first discovery; strict fingerprint pinning afterwards."""

    def __init__(self, expected: str | None):
        self.expected = (expected or "").strip().lower()

    def missing_host_key(self, client, hostname, key):
        actual = ssh_fingerprint(key)
        if self.expected and actual != self.expected:
            raise paramiko.SSHException("SSH_HOST_KEY_MISMATCH")
        client._host_keys.add(hostname, key.get_name(), key)


def load_endpoint(connection, endpoint_id: int):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT e.*,c.encrypted_blob
            FROM endpoints e
            JOIN endpoint_credentials c ON c.endpoint_id=e.id
            WHERE e.id=%s
            """,
            (endpoint_id,),
        )
        row = cursor.fetchone()

    if row is None:
        raise RuntimeError("ENDPOINT_NOT_FOUND")
    if row["status"] != "READY":
        raise RuntimeError("ENDPOINT_NOT_READY")

    credentials = json.loads(decrypt_secret(row["encrypted_blob"]))
    return dict(row), credentials


class Remote:
    def __init__(self, endpoint: dict, credentials: dict):
        self.endpoint = endpoint
        self.credentials = credentials
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(
            EndpointHostKeyPolicy(endpoint.get("host_key_fingerprint"))
        )

    def connect(self):
        kwargs = {
            "hostname": self.endpoint["host"],
            "port": int(self.endpoint["port"]),
            "username": self.endpoint["ssh_username"],
            "timeout": 20,
            "banner_timeout": 20,
            "auth_timeout": 20,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if self.credentials["auth_method"] == "PASSWORD":
            kwargs["password"] = self.credentials["secret"]
        else:
            kwargs["pkey"] = load_private_key(self.credentials["secret"])

        self.client.connect(**kwargs)
        transport = self.client.get_transport()
        expected = (self.endpoint.get("host_key_fingerprint") or "").lower()
        if transport and expected:
            actual = ssh_fingerprint(transport.get_remote_server_key())
            if actual != expected:
                self.client.close()
                raise RuntimeError("SSH_HOST_KEY_MISMATCH")
        return self

    def close(self):
        self.client.close()

    def run(
        self,
        command: str,
        *,
        root: bool = False,
        timeout: int = 180,
        check: bool = True,
    ) -> dict:
        stdin_data = None
        if root:
            quoted = shlex.quote(command)
            if self.endpoint["ssh_username"] == "root":
                final = f"bash -lc {quoted}"
            elif self.credentials.get("sudo_mode") == "PASSWORD":
                final = f"sudo -S -p '' bash -lc {quoted}"
                stdin_data = self.credentials.get("sudo_password", "") + "\n"
            else:
                final = f"sudo -n bash -lc {quoted}"
        else:
            final = "bash -lc " + shlex.quote(command)

        stdin, stdout, stderr = self.client.exec_command(
            final,
            timeout=timeout,
            get_pty=False,
        )
        if stdin_data:
            stdin.write(stdin_data)
            stdin.flush()

        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")
        code = stdout.channel.recv_exit_status()
        if check and code != 0:
            raise RuntimeError(
                (error.strip() or output.strip() or f"REMOTE_COMMAND_FAILED_{code}")[-4000:]
            )
        return {"code": code, "stdout": output, "stderr": error}


@contextmanager
def remote_pair(connection, endpoint_a_id: int, endpoint_b_id: int):
    endpoint_a, credentials_a = load_endpoint(connection, endpoint_a_id)
    endpoint_b, credentials_b = load_endpoint(connection, endpoint_b_id)
    remote_a = Remote(endpoint_a, credentials_a).connect()
    try:
        remote_b = Remote(endpoint_b, credentials_b).connect()
    except Exception:
        remote_a.close()
        raise
    try:
        yield remote_a, remote_b, endpoint_a, endpoint_b
    finally:
        remote_a.close()
        remote_b.close()


def short_name(prefix: str, run_id: int, item_id: int) -> str:
    return f"{prefix}{run_id:x}{item_id:x}"[:15]


def unit_name(run_id: int, item_id: int) -> str:
    return f"netauto-tunnel-{run_id}-{item_id}"


def parse_addressing(config: dict) -> dict:
    required = {
        "source_ip_a": config.get("source_ip_a"),
        "source_ip_b": config.get("source_ip_b"),
        "tunnel_cidr": config.get("tunnel_cidr"),
        "tunnel_ip_a": config.get("tunnel_ip_a"),
        "tunnel_ip_b": config.get("tunnel_ip_b"),
    }
    missing = [key for key, value in required.items() if not value]
    if missing:
        raise RuntimeError("MISSING_ADDRESSING: " + ", ".join(missing))

    source_a = ipaddress.ip_address(required["source_ip_a"])
    source_b = ipaddress.ip_address(required["source_ip_b"])
    network = ipaddress.ip_network(required["tunnel_cidr"], strict=False)
    address_a = ipaddress.ip_interface(required["tunnel_ip_a"])
    address_b = ipaddress.ip_interface(required["tunnel_ip_b"])

    if address_a.ip not in network or address_b.ip not in network:
        raise RuntimeError("INTERNAL_IP_OUTSIDE_CIDR")
    if address_a.ip == address_b.ip:
        raise RuntimeError("DUPLICATE_INTERNAL_IP")

    return {
        **required,
        "source_a": source_a,
        "source_b": source_b,
        "network": network,
        "address_a": address_a,
        "address_b": address_b,
    }


def install_iproute(remote: Remote):
    remote.run(
        "command -v ip >/dev/null 2>&1 || { apt-get update; apt-get install -y iproute2; }",
        root=True,
        timeout=240,
    )


def ensure_source(remote: Remote, source):
    remote.run(
        "ip -o addr show | awk '{print $4}' | cut -d/ -f1 "
        f"| grep -Fx -- {shlex.quote(str(source))}",
        root=True,
    )


def address_command(interface_name: str, address) -> str:
    family = "-6 " if address.version == 6 else ""
    return (
        f"ip {family}addr replace {shlex.quote(str(address))} "
        f"dev {shlex.quote(interface_name)}"
    )


def ping_command(destination) -> str:
    family = "-6 " if destination.version == 6 else ""
    return f"ping {family}-c 3 -W 4 {shlex.quote(str(destination))}"



def create_unit(
    remote: Remote,
    name: str,
    start_script: str,
    stop_script: str,
):
    unit = (
        "[Unit]\n"
        f"Description=TehranNetwork {name}\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "StartLimitIntervalSec=0\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        f"ExecStart=/bin/bash -lc {shlex.quote(start_script)}\n"
        f"ExecStop=/bin/bash -lc {shlex.quote(stop_script)}\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "TimeoutStartSec=120\n"
        "TimeoutStopSec=60\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    path = f"/etc/systemd/system/{name}.service"
    remote.run(
        "cat > "
        + shlex.quote(path)
        + " <<'UNIT'\n"
        + unit
        + "UNIT\n"
        + "systemctl daemon-reload\n"
        + f"systemctl enable --now {shlex.quote(name)}.service",
        root=True,
        timeout=180,
    )


def remove_kernel_unit(remote: Remote, name: str, interface_name: str):
    remote.run(
        "set +e\n"
        f"systemctl disable --now {shlex.quote(name)}.service\n"
        f"rm -f /etc/systemd/system/{shlex.quote(name)}.service\n"
        f"ip link del {shlex.quote(interface_name)} 2>/dev/null\n"
        "systemctl daemon-reload",
        root=True,
        check=False,
    )


def deploy_kernel(
    method: str,
    run: dict,
    run_item: dict,
    config: dict,
    remote_a: Remote,
    remote_b: Remote,
) -> dict:
    addr = parse_addressing(config)
    install_iproute(remote_a)
    install_iproute(remote_b)
    ensure_source(remote_a, addr["source_a"])
    ensure_source(remote_b, addr["source_b"])

    ipv4_outer = {"GRE", "GRETAP", "IPIP", "SIT_6IN4", "VXLAN"}
    ipv6_outer = {"IP6GRE", "IP6GRETAP"}
    if method in ipv4_outer and (
        addr["source_a"].version != 4 or addr["source_b"].version != 4
    ):
        raise RuntimeError("OUTER_IPV4_REQUIRED")
    if method in ipv6_outer and (
        addr["source_a"].version != 6 or addr["source_b"].version != 6
    ):
        raise RuntimeError("OUTER_IPV6_REQUIRED")
    if method == "SIT_6IN4" and (
        addr["address_a"].version != 6 or addr["address_b"].version != 6
    ):
        raise RuntimeError("SIT_REQUIRES_INNER_IPV6")

    prefixes = {
        "GRE": "ngr",
        "GRETAP": "ngt",
        "IPIP": "nip",
        "SIT_6IN4": "nsi",
        "IP6GRE": "n6g",
        "IP6GRETAP": "n6t",
        "VXLAN": "nvx",
    }
    safe_prefixes = {
        "GRE": "ngr",
        "GRETAP": "ngt",
        "IPIP": "nip",
        "SIT_6IN4": "nsi",
        "IP6GRE": "n6g",
        "IP6GRETAP": "n6t",
        "VXLAN": "nvx",
    }

    safe_prefix = safe_prefixes[method]

    interface_name = (
        f"{safe_prefix}"
        f"{int(run['id']) % 1000:03d}"
        f"{int(run_item['id']) % 1000:03d}"
    )[:15]
    name = unit_name(run["id"], run_item["id"])
    source_a = str(addr["source_a"])
    source_b = str(addr["source_b"])
    vni = None
    port = None

    if method == "GRE":
        create_a = f"ip tunnel add {interface_name} mode gre local {source_a} remote {source_b} ttl 255"
        create_b = f"ip tunnel add {interface_name} mode gre local {source_b} remote {source_a} ttl 255"
    elif method == "GRETAP":
        create_a = f"ip link add {interface_name} type gretap local {source_a} remote {source_b}"
        create_b = f"ip link add {interface_name} type gretap local {source_b} remote {source_a}"
    elif method == "IPIP":
        create_a = f"ip tunnel add {interface_name} mode ipip local {source_a} remote {source_b} ttl 255"
        create_b = f"ip tunnel add {interface_name} mode ipip local {source_b} remote {source_a} ttl 255"
    elif method == "SIT_6IN4":
        create_a = f"ip tunnel add {interface_name} mode sit local {source_a} remote {source_b} ttl 255"
        create_b = f"ip tunnel add {interface_name} mode sit local {source_b} remote {source_a} ttl 255"
    elif method == "IP6GRE":
        create_a = f"ip -6 tunnel add {interface_name} mode ip6gre local {source_a} remote {source_b}"
        create_b = f"ip -6 tunnel add {interface_name} mode ip6gre local {source_b} remote {source_a}"
    elif method == "IP6GRETAP":
        create_a = f"ip link add {interface_name} type ip6gretap local {source_a} remote {source_b}"
        create_b = f"ip link add {interface_name} type ip6gretap local {source_b} remote {source_a}"
    elif method == "VXLAN":
        vni = int(config.get("vxlan_vni") or (10000 + run_item["id"]))
        port = int(config.get("port") or 4789)
        if not 1 <= vni <= 16777215:
            raise RuntimeError("INVALID_VXLAN_VNI")
        create_a = (
            f"ip link add {interface_name} type vxlan id {vni} "
            f"local {source_a} remote {source_b} dstport {port} nolearning"
        )
        create_b = (
            f"ip link add {interface_name} type vxlan id {vni} "
            f"local {source_b} remote {source_a} dstport {port} nolearning"
        )
    else:
        raise RuntimeError("UNSUPPORTED_KERNEL_METHOD")

    mtu = int(config.get("mtu") or (1360 if method == "SIT_6IN4" else 1400))
    start_a = "; ".join(
        [
            "set -Eeuo pipefail",
            f"ip link del {interface_name} 2>/dev/null || true",
            create_a,
            f"ip link set {interface_name} mtu {mtu} up",
            address_command(interface_name, addr["address_a"]),
        ]
    )
    start_b = "; ".join(
        [
            "set -Eeuo pipefail",
            f"ip link del {interface_name} 2>/dev/null || true",
            create_b,
            f"ip link set {interface_name} mtu {mtu} up",
            address_command(interface_name, addr["address_b"]),
        ]
    )
    stop = f"ip link del {interface_name} 2>/dev/null || true"

    try:
        create_unit(remote_a, name, start_a, stop)
        create_unit(remote_b, name, start_b, stop)
        remote_a.run(ping_command(addr["address_b"].ip), root=True, timeout=30)
        remote_b.run(ping_command(addr["address_a"].ip), root=True, timeout=30)
    except Exception:
        remove_kernel_unit(remote_a, name, interface_name)
        remove_kernel_unit(remote_b, name, interface_name)
        raise

    return {
        "method": method,
        "interface_name": interface_name,
        "systemd_unit": name,
        "source_ip_a": source_a,
        "source_ip_b": source_b,
        "tunnel_cidr": str(addr["network"]),
        "tunnel_ip_a": str(addr["address_a"]),
        "tunnel_ip_b": str(addr["address_b"]),
        "mtu": mtu,
        "vxlan_vni": vni,
        "vxlan_port": port,
    }


def install_wireguard(remote: Remote):
    remote.run(
        """
        if ! command -v wg >/dev/null 2>&1; then
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools
        fi
        install -d -m 0700 /etc/wireguard
        """,
        root=True,
        timeout=300,
    )


def free_udp_port(remote: Remote, preferred: int) -> int:
    result = remote.run(
        "ss -H -lun | awk '{print $5}' | sed 's/.*://' | sort -n -u",
        root=True,
        check=False,
    )
    used = {
        int(line.strip())
        for line in result["stdout"].splitlines()
        if line.strip().isdigit()
    }
    for port in range(preferred, min(preferred + 2000, 65535)):
        if port not in used:
            return port
    raise RuntimeError("NO_FREE_UDP_PORT")


def wg_keypair(remote: Remote):
    result = remote.run(
        "umask 077; private=$(wg genkey); public=$(printf '%s' \"$private\" | wg pubkey); printf '%s\\n%s\\n' \"$private\" \"$public\"",
        root=True,
    )
    lines = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
    if len(lines) < 2:
        raise RuntimeError("WIREGUARD_KEY_GENERATION_FAILED")
    return lines[0], lines[1]


def allow_udp(remote: Remote, port: int):
    remote.run(
        "if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; "
        f"then ufw allow {port}/udp comment 'TehranNetwork WireGuard'; fi",
        root=True,
        check=False,
    )


def remove_wireguard(remote: Remote, interface_name: str):
    remote.run(
        "set +e\n"
        f"systemctl disable --now wg-quick@{shlex.quote(interface_name)}.service\n"
        f"rm -f /etc/wireguard/{shlex.quote(interface_name)}.conf\n"
        "systemctl daemon-reload",
        root=True,
        check=False,
    )


def deploy_wireguard(
    run: dict,
    run_item: dict,
    config: dict,
    remote_a: Remote,
    remote_b: Remote,
) -> dict:
    addr = parse_addressing(config)
    install_wireguard(remote_a)
    install_wireguard(remote_b)
    ensure_source(remote_a, addr["source_a"])
    ensure_source(remote_b, addr["source_b"])

    interface_name = short_name("nwg", run["id"], run_item["id"])
    port_a = free_udp_port(
        remote_a,
        int(config.get("listen_port_a") or (51820 + run_item["id"] % 500)),
    )
    port_b = free_udp_port(
        remote_b,
        int(config.get("listen_port_b") or (52320 + run_item["id"] % 500)),
    )
    private_a, public_a = wg_keypair(remote_a)
    private_b, public_b = wg_keypair(remote_b)

    host_a = str(addr["source_a"])
    host_b = str(addr["source_b"])
    if addr["source_a"].version == 6:
        host_a = f"[{host_a}]"
    if addr["source_b"].version == 6:
        host_b = f"[{host_b}]"

    allowed_a = f"{addr['address_a'].ip}/{'32' if addr['address_a'].version == 4 else '128'}"
    allowed_b = f"{addr['address_b'].ip}/{'32' if addr['address_b'].version == 4 else '128'}"

    config_a = (
        "[Interface]\n"
        f"Address = {addr['address_a']}\n"
        f"ListenPort = {port_a}\n"
        f"PrivateKey = {private_a}\n"
        "MTU = 1420\n"
        "SaveConfig = false\n\n"
        "[Peer]\n"
        f"PublicKey = {public_b}\n"
        f"AllowedIPs = {allowed_b}\n"
        f"Endpoint = {host_b}:{port_b}\n"
        "PersistentKeepalive = 25\n"
    )
    config_b = (
        "[Interface]\n"
        f"Address = {addr['address_b']}\n"
        f"ListenPort = {port_b}\n"
        f"PrivateKey = {private_b}\n"
        "MTU = 1420\n"
        "SaveConfig = false\n\n"
        "[Peer]\n"
        f"PublicKey = {public_a}\n"
        f"AllowedIPs = {allowed_a}\n"
        f"Endpoint = {host_a}:{port_a}\n"
        "PersistentKeepalive = 25\n"
    )

    def install_config(remote: Remote, content: str):
        path = f"/etc/wireguard/{interface_name}.conf"
        remote.run(
            "cat > "
            + shlex.quote(path)
            + " <<'WGCONF'\n"
            + content
            + "WGCONF\n"
            + f"chmod 600 {shlex.quote(path)}\n"
            + f"systemctl enable wg-quick@{shlex.quote(interface_name)}.service\n"
            + f"systemctl restart wg-quick@{shlex.quote(interface_name)}.service",
            root=True,
            timeout=180,
        )

    try:
        allow_udp(remote_a, port_a)
        allow_udp(remote_b, port_b)
        install_config(remote_a, config_a)
        install_config(remote_b, config_b)
        time.sleep(4)
        remote_a.run(ping_command(addr["address_b"].ip), root=True, timeout=30)
        remote_b.run(ping_command(addr["address_a"].ip), root=True, timeout=30)
    except Exception:
        remove_wireguard(remote_a, interface_name)
        remove_wireguard(remote_b, interface_name)
        raise

    return {
        "method": "WIREGUARD",
        "interface_name": interface_name,
        "source_ip_a": str(addr["source_a"]),
        "source_ip_b": str(addr["source_b"]),
        "tunnel_cidr": str(addr["network"]),
        "tunnel_ip_a": str(addr["address_a"]),
        "tunnel_ip_b": str(addr["address_b"]),
        "listen_port_a": port_a,
        "listen_port_b": port_b,
        "public_key_a": public_a,
        "public_key_b": public_b,
        "mtu": 1420,
    }



# ==========================================================
# PACK 2 — SSH AND GOST ENGINES
# ==========================================================

SSH_METHODS = {
    "SSH_LOCAL_FORWARD",
    "SSH_REMOTE_FORWARD",
    "SSH_DYNAMIC_SOCKS",
    "AUTOSSH_REVERSE",
    "SSH_TUN_L3",
    "SSH_TAP_L2",
}

GOST_METHODS = {
    "GOST_TCP_FORWARD",
    "GOST_UDP_FORWARD",
    "GOST_REMOTE_TCP",
    "GOST_REMOTE_UDP",
    "GOST_SOCKS5",
    "GOST_HTTP",
    "GOST_WS",
    "GOST_HTTP2",
    "GOST_GRPC",
    "GOST_QUIC",
    "GOST_SSH",
    "GOST_TUN",
    "GOST_TAP",
    "GOST_KCP_FORWARD",
    "GOST_SOCKS5_KCP",
}


def stable_secret(run_id: int, item_id: int, label: str, length: int = 24) -> str:
    raw = f"{APP_SECRET_KEY}:{run_id}:{item_id}:{label}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:length]


def choose_sides(item: dict, remote_a: Remote, remote_b: Remote, endpoint_a: dict, endpoint_b: dict):
    initiator = str(item.get("initiator") or "AUTO").upper()
    direction = str(item.get("traffic_direction") or "BIDIRECTIONAL").upper()
    side = "B" if initiator == "B" or (initiator == "AUTO" and direction == "B_TO_A") else "A"
    if side == "A":
        return {
            "client_side": "A",
            "server_side": "B",
            "client": remote_a,
            "server": remote_b,
            "client_endpoint": endpoint_a,
            "server_endpoint": endpoint_b,
        }
    return {
        "client_side": "B",
        "server_side": "A",
        "client": remote_b,
        "server": remote_a,
        "client_endpoint": endpoint_b,
        "server_endpoint": endpoint_a,
    }


def install_packages(
    remote: Remote,
    packages: list[str],
):
    package_list = " ".join(
        shlex.quote(value)
        for value in packages
    )

    remote.run(
        (
            "set -Eeuo pipefail; "
            "export "
            "DEBIAN_FRONTEND=noninteractive "
            "DEBCONF_NONINTERACTIVE_SEEN=true "
            "NEEDRESTART_MODE=a; "
            "apt-get update; "
            "apt-get install -y "
            "-o Dpkg::Options::=--force-confold "
            "-o Dpkg::Options::=--force-confdef "
            f"{package_list}"
        ),
        root=True,
        timeout=600,
    )



def free_port(remote: Remote, protocol: str, preferred: int) -> int:
    flag = "-lun" if protocol.lower() == "udp" else "-ltn"
    result = remote.run(
        f"ss -H {flag} | awk '{{print $5}}' | sed 's/.*://' | sort -n -u",
        root=True,
        check=False,
    )
    used = {
        int(line.strip())
        for line in result["stdout"].splitlines()
        if line.strip().isdigit()
    }
    for port in range(max(1025, preferred), 65000):
        if port not in used:
            return port
    raise RuntimeError("NO_FREE_PORT")



def persistent_service(
    remote: Remote,
    name: str,
    command: str,
    environment: dict | None = None,
):
    env_lines = "".join(
        f"Environment={shlex.quote(str(key) + '=' + str(value))}\n"
        for key, value in (environment or {}).items()
    )
    unit = (
        "[Unit]\n"
        f"Description=TehranNetwork {name}\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "StartLimitIntervalSec=0\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"{env_lines}"
        f"ExecStart=/bin/bash -lc {shlex.quote(command)}\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "TimeoutStartSec=120\n"
        "TimeoutStopSec=60\n"
        "KillMode=mixed\n"
        "LimitNOFILE=1048576\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    unit_path = f"/etc/systemd/system/{name}.service"
    remote.run(
        "cat > " + shlex.quote(unit_path) + " <<'UNIT'\n"
        + unit
        + "UNIT\n"
        + "systemctl daemon-reload\n"
        + f"systemctl enable --now {shlex.quote(name)}.service",
        root=True,
        timeout=240,
    )



def oneshot_service(
    remote: Remote,
    name: str,
    start_script: str,
    stop_script: str,
):
    unit = (
        "[Unit]\n"
        f"Description=TehranNetwork {name}\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "StartLimitIntervalSec=0\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        f"ExecStart=/bin/bash -lc {shlex.quote(start_script)}\n"
        f"ExecStop=/bin/bash -lc {shlex.quote(stop_script)}\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "TimeoutStartSec=180\n"
        "TimeoutStopSec=90\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    unit_path = f"/etc/systemd/system/{name}.service"
    remote.run(
        "cat > " + shlex.quote(unit_path) + " <<'UNIT'\n"
        + unit
        + "UNIT\n"
        + "systemctl daemon-reload\n"
        + f"systemctl enable --now {shlex.quote(name)}.service",
        root=True,
        timeout=240,
    )


def remove_services(remote: Remote, names: list[str], files: list[str] | None = None, interfaces: list[str] | None = None):
    commands = ["set +e"]
    for name in names:
        commands.extend(
            [
                f"systemctl disable --now {shlex.quote(name)}.service",
                f"rm -f /etc/systemd/system/{shlex.quote(name)}.service",
            ]
        )
    for value in files or []:
        commands.append(f"rm -rf {shlex.quote(value)}")
    for value in interfaces or []:
        commands.append(f"ip link del {shlex.quote(value)} 2>/dev/null")
    commands.append("systemctl daemon-reload")
    remote.run("\n".join(commands), root=True, check=False)


def wait_service(remote: Remote, name: str):
    remote.run(
        f"systemctl is-active --quiet {shlex.quote(name)}.service",
        root=True,
        timeout=30,
    )


def wait_listener(remote: Remote, protocol: str, port: int):
    flag = "-lun" if protocol.lower() == "udp" else "-ltn"
    remote.run(
        "for i in $(seq 1 20); do "
        f"ss -H {flag} | awk '{{print $5}}' | grep -Eq ':{port}$' && exit 0; "
        "sleep 1; done; exit 1",
        root=True,
        timeout=30,
    )


def ensure_ssh_tunnel_server(remote: Remote):
    remote.run(
        "install -d -m 0755 /etc/ssh/sshd_config.d; "
        "cat > /etc/ssh/sshd_config.d/99-netauto-tunnel.conf <<'CONF'\n"
        "PermitTunnel yes\n"
        "AllowTcpForwarding yes\n"
        "GatewayPorts clientspecified\n"
        "CONF\n"
        "sshd -t; "
        "systemctl restart ssh || systemctl restart sshd",
        root=True,
        timeout=120,
    )


def prepare_ssh_identity(client: Remote, server: Remote, server_endpoint: dict, name: str):
    install_packages(client, ["openssh-client", "autossh"])
    key_dir = f"/etc/netauto/ssh/{name}"
    key_path = f"{key_dir}/id_ed25519"
    known_hosts = f"{key_dir}/known_hosts"
    host = str(server_endpoint["host"])
    port = int(server_endpoint.get("port") or 22)
    username = str(server_endpoint["ssh_username"])

    client.run(
        f"install -d -m 0700 {shlex.quote(key_dir)}; "
        f"test -f {shlex.quote(key_path)} || ssh-keygen -q -t ed25519 -N '' -f {shlex.quote(key_path)}; "
        f"ssh-keyscan -p {port} -H {shlex.quote(host)} > {shlex.quote(known_hosts)}; "
        f"chmod 600 {shlex.quote(key_path)} {shlex.quote(known_hosts)}",
        root=True,
        timeout=120,
    )
    public_key = client.run(
        f"cat {shlex.quote(key_path)}.pub",
        root=True,
    )["stdout"].strip()
    marker = f"netauto:{name}"
    server.run(
        "user=" + shlex.quote(username) + "; "
        "home=$(getent passwd \"$user\" | cut -d: -f6); "
        "test -n \"$home\"; "
        "install -d -m 0700 -o \"$user\" -g \"$(id -gn \"$user\")\" \"$home/.ssh\"; "
        "touch \"$home/.ssh/authorized_keys\"; "
        "chown \"$user:$(id -gn \"$user\")\" \"$home/.ssh/authorized_keys\"; "
        "chmod 600 \"$home/.ssh/authorized_keys\"; "
        f"sed -i '/{re.escape(marker)}/d' \"$home/.ssh/authorized_keys\"; "
        f"printf '%s %s\\n' {shlex.quote('no-agent-forwarding,no-X11-forwarding,no-pty')} {shlex.quote(public_key + ' ' + marker)} >> \"$home/.ssh/authorized_keys\"",
        root=True,
        timeout=120,
    )
    return {
        "key_dir": key_dir,
        "key_path": key_path,
        "known_hosts": known_hosts,
        "host": host,
        "port": port,
        "username": username,
        "marker": marker,
    }


def remove_authorized_marker(remote: Remote, username: str, marker: str):
    remote.run(
        "user=" + shlex.quote(username) + "; "
        "home=$(getent passwd \"$user\" | cut -d: -f6); "
        "test -z \"$home\" || "
        f"sed -i '/{re.escape(marker)}/d' \"$home/.ssh/authorized_keys\"",
        root=True,
        check=False,
    )


def ssh_common_options(identity: dict, bind_source: str | None = None) -> str:
    parts = [
        "-N",
        "-o BatchMode=yes",
        "-o StrictHostKeyChecking=yes",
        f"-o UserKnownHostsFile={shlex.quote(identity['known_hosts'])}",
        "-o ExitOnForwardFailure=yes",
        "-o ServerAliveInterval=15",
        "-o ServerAliveCountMax=3",
        "-o TCPKeepAlive=yes",
        f"-i {shlex.quote(identity['key_path'])}",
        f"-p {identity['port']}",
    ]
    if bind_source:
        parts.append(f"-b {shlex.quote(bind_source)}")
    return " ".join(parts)


def deploy_ssh_forward(method: str, run: dict, item: dict, config: dict, remote_a: Remote, remote_b: Remote, endpoint_a: dict, endpoint_b: dict) -> dict:
    sides = choose_sides(item, remote_a, remote_b, endpoint_a, endpoint_b)
    client = sides["client"]
    server = sides["server"]
    client_endpoint = sides["client_endpoint"]
    server_endpoint = sides["server_endpoint"]
    name = f"netauto-ssh-{run['id']}-{item['id']}"
    identity = prepare_ssh_identity(client, server, server_endpoint, name)

    source_key = "source_ip_a" if sides["client_side"] == "A" else "source_ip_b"
    source_ip = config.get(source_key) or client_endpoint["host"]
    listen_port = free_port(
        server if method in {"SSH_REMOTE_FORWARD", "AUTOSSH_REVERSE"} else client,
        "tcp",
        int(config.get("listen_port") or (24000 + item["id"] % 12000)),
    )
    bind_address = str(config.get("bind_address") or "127.0.0.1")
    target_host = str(config.get("target_host") or "127.0.0.1")
    target_port = int(config.get("target_port") or client_endpoint.get("port") or 22)
    options = ssh_common_options(identity, str(source_ip))
    destination = f"{shlex.quote(identity['username'])}@{shlex.quote(identity['host'])}"

    if method == "SSH_LOCAL_FORWARD":
        forward = f"-L {shlex.quote(bind_address + ':' + str(listen_port) + ':' + target_host + ':' + str(target_port))}"
        command = f"exec /usr/bin/ssh {options} {forward} {destination}"
        listener_remote = client
        listener_side = sides["client_side"]
        environment = None
    elif method == "SSH_DYNAMIC_SOCKS":
        forward = f"-D {shlex.quote(bind_address + ':' + str(listen_port))}"
        command = f"exec /usr/bin/ssh {options} {forward} {destination}"
        listener_remote = client
        listener_side = sides["client_side"]
        environment = None
    else:
        forward = f"-R {shlex.quote(bind_address + ':' + str(listen_port) + ':' + target_host + ':' + str(target_port))}"
        if method == "AUTOSSH_REVERSE":
            command = f"exec /usr/bin/autossh -M 0 {options} {forward} {destination}"
            environment = {"AUTOSSH_GATETIME": "0", "AUTOSSH_POLL": "30"}
        else:
            command = f"exec /usr/bin/ssh {options} {forward} {destination}"
            environment = None
        listener_remote = server
        listener_side = sides["server_side"]

    try:
        persistent_service(client, name, command, environment)
        wait_service(client, name)
        wait_listener(listener_remote, "tcp", listen_port)
    except Exception:
        remove_services(client, [name], [identity["key_dir"]])
        remove_authorized_marker(server, identity["username"], identity["marker"])
        raise

    return {
        "method": method,
        "services_a": [name] if sides["client_side"] == "A" else [],
        "services_b": [name] if sides["client_side"] == "B" else [],
        "files_a": [identity["key_dir"]] if sides["client_side"] == "A" else [],
        "files_b": [identity["key_dir"]] if sides["client_side"] == "B" else [],
        "authorized_marker_a": identity["marker"] if sides["server_side"] == "A" else None,
        "authorized_marker_b": identity["marker"] if sides["server_side"] == "B" else None,
        "authorized_user_a": identity["username"] if sides["server_side"] == "A" else None,
        "authorized_user_b": identity["username"] if sides["server_side"] == "B" else None,
        "client_side": sides["client_side"],
        "listener_side": listener_side,
        "listen_address": bind_address,
        "listen_port": listen_port,
        "target_host": target_host,
        "target_port": target_port,
        "source_ip": str(source_ip),
    }


def tunnel_config_service(remote: Remote, name: str, interface_name: str, address: str):
    start = (
        "set -Eeuo pipefail; "
        "for i in $(seq 1 60); do "
        f"ip link show {shlex.quote(interface_name)} >/dev/null 2>&1 && break; "
        "sleep 1; done; "
        f"ip link show {shlex.quote(interface_name)} >/dev/null 2>&1; "
        f"ip link set {shlex.quote(interface_name)} up; "
        + address_command(interface_name, ipaddress.ip_interface(address))
    )
    stop = f"ip link set {shlex.quote(interface_name)} down 2>/dev/null || true"
    oneshot_service(remote, name, start, stop)


def deploy_ssh_tunnel(method: str, run: dict, item: dict, config: dict, remote_a: Remote, remote_b: Remote, endpoint_a: dict, endpoint_b: dict) -> dict:
    addr = parse_addressing(config)
    sides = choose_sides(item, remote_a, remote_b, endpoint_a, endpoint_b)
    client = sides["client"]
    server = sides["server"]
    client_endpoint = sides["client_endpoint"]
    server_endpoint = sides["server_endpoint"]
    ensure_ssh_tunnel_server(server)
    name = f"netauto-sshdev-{run['id']}-{item['id']}"
    identity = prepare_ssh_identity(client, server, server_endpoint, name)
    device_id = int(config.get("ssh_tunnel_id") or (100 + item["id"] % 100))
    is_tap = method == "SSH_TAP_L2"
    interface_name = ("tap" if is_tap else "tun") + str(device_id)
    mode = "ethernet" if is_tap else "point-to-point"
    source_ip = str(addr["source_a"] if sides["client_side"] == "A" else addr["source_b"])
    options = ssh_common_options(identity, source_ip)
    destination = f"{shlex.quote(identity['username'])}@{shlex.quote(identity['host'])}"
    command = (
        f"exec /usr/bin/ssh {options} "
        f"-o Tunnel={mode} -w {device_id}:{device_id} {destination}"
    )
    config_name = name + "-if"
    address_client = str(addr["address_a"] if sides["client_side"] == "A" else addr["address_b"])
    address_server = str(addr["address_b"] if sides["client_side"] == "A" else addr["address_a"])

    try:
        persistent_service(client, name, command)
        tunnel_config_service(client, config_name, interface_name, address_client)
        tunnel_config_service(server, config_name, interface_name, address_server)
        peer = addr["address_b"].ip if sides["client_side"] == "A" else addr["address_a"].ip
        reverse_peer = addr["address_a"].ip if sides["client_side"] == "A" else addr["address_b"].ip
        client.run(ping_command(peer), root=True, timeout=35)
        server.run(ping_command(reverse_peer), root=True, timeout=35)
    except Exception:
        remove_services(client, [config_name, name], [identity["key_dir"]], [interface_name])
        remove_services(server, [config_name], [], [interface_name])
        remove_authorized_marker(server, identity["username"], identity["marker"])
        raise

    return {
        "method": method,
        "interface_name": interface_name,
        "services_a": [name, config_name] if sides["client_side"] == "A" else [config_name],
        "services_b": [name, config_name] if sides["client_side"] == "B" else [config_name],
        "interfaces_a": [interface_name],
        "interfaces_b": [interface_name],
        "files_a": [identity["key_dir"]] if sides["client_side"] == "A" else [],
        "files_b": [identity["key_dir"]] if sides["client_side"] == "B" else [],
        "authorized_marker_a": identity["marker"] if sides["server_side"] == "A" else None,
        "authorized_marker_b": identity["marker"] if sides["server_side"] == "B" else None,
        "authorized_user_a": identity["username"] if sides["server_side"] == "A" else None,
        "authorized_user_b": identity["username"] if sides["server_side"] == "B" else None,
        "client_side": sides["client_side"],
        "tunnel_cidr": str(addr["network"]),
        "tunnel_ip_a": str(addr["address_a"]),
        "tunnel_ip_b": str(addr["address_b"]),
    }


GOST_VERSION = "3.2.6"


def install_gost(remote: Remote):
    script = f"""set -Eeuo pipefail
if command -v gost >/dev/null 2>&1 && gost -V 2>&1 | grep -q {shlex.quote(GOST_VERSION)}; then
    exit 0
fi
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a DEBCONF_NONINTERACTIVE_SEEN=true
apt-get update
apt-get install -y curl ca-certificates tar python3
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
case "$(uname -m)" in
  x86_64|amd64) SUFFIX="linux_amd64.tar.gz" ;;
  aarch64|arm64) SUFFIX="linux_arm64.tar.gz" ;;
  *) echo UNSUPPORTED_ARCH >&2; exit 31 ;;
esac
python3 - "$TMP/url" "$SUFFIX" <<'PYG'
import json, sys, urllib.request
output, suffix = sys.argv[1], sys.argv[2]
request = urllib.request.Request(
    "https://api.github.com/repos/go-gost/gost/releases/tags/v{GOST_VERSION}",
    headers={{"Accept":"application/vnd.github+json","User-Agent":"TehranNetwork-Automation"}},
)
with urllib.request.urlopen(request, timeout=30) as response:
    release = json.load(response)
for asset in release.get("assets", []):
    url = asset.get("browser_download_url", "")
    if url.endswith(suffix):
        open(output, "w", encoding="utf-8").write(url)
        break
else:
    raise SystemExit("GOST_ASSET_NOT_FOUND")
PYG
URL=$(cat "$TMP/url")
curl -fL --retry 3 --connect-timeout 20 "$URL" -o "$TMP/gost.tar.gz"
tar -xzf "$TMP/gost.tar.gz" -C "$TMP"
BIN=$(find "$TMP" -type f -name gost | head -n1)
test -n "$BIN"
install -m 0755 "$BIN" /usr/local/bin/gost
/usr/local/bin/gost -V
"""
    remote.run(script, root=True, timeout=420)


def allow_firewall_port(remote: Remote, port: int, protocol: str):
    remote.run(
        "if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then "
        f"ufw allow {port}/{shlex.quote(protocol)} comment 'TehranNetwork tunnel'; fi",
        root=True,
        check=False,
    )


def gost_bind(config: dict, source_ip: str) -> str:
    if config.get("expose_public"):
        return str(config.get("bind_address") or source_ip)
    return str(config.get("bind_address") or "127.0.0.1")


def parse_ping_metrics(output: str) -> dict:
    loss_match = re.search(r"([0-9.]+)% packet loss", output)
    rtt_match = re.search(
        r"(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = "
        r"([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)",
        output,
    )
    return {
        "loss_percent": float(loss_match.group(1)) if loss_match else 100.0,
        "rtt_min_ms": float(rtt_match.group(1)) if rtt_match else None,
        "rtt_avg_ms": float(rtt_match.group(2)) if rtt_match else None,
        "rtt_max_ms": float(rtt_match.group(3)) if rtt_match else None,
        "rtt_jitter_ms": float(rtt_match.group(4)) if rtt_match else None,
    }


def path_probe(remote: Remote, destination: str) -> dict:
    family = "-6 " if ":" in destination else ""
    result = remote.run(
        f"ping {family}-c 8 -W 3 {shlex.quote(destination)}",
        root=True,
        timeout=35,
        check=False,
    )
    return parse_ping_metrics(result["stdout"] + "\n" + result["stderr"])


def choose_kcp_profile(metrics: dict, config: dict) -> dict:
    if config.get("kcp_mode"):
        return {
            "mode": str(config["kcp_mode"]),
            "mtu": int(config.get("kcp_mtu") or 1350),
            "sndwnd": int(config.get("kcp_sndwnd") or 1024),
            "rcvwnd": int(config.get("kcp_rcvwnd") or 1024),
            "datashard": int(config.get("kcp_datashard") or 10),
            "parityshard": int(config.get("kcp_parityshard") or 3),
            "interval": int(config.get("kcp_interval") or 20),
        }

    loss = float(metrics.get("loss_percent") or 0)
    rtt = float(metrics.get("rtt_avg_ms") or 0)

    if loss >= 2 or rtt >= 160:
        return {
            "mode": "fast3",
            "mtu": 1300,
            "sndwnd": 2048,
            "rcvwnd": 2048,
            "datashard": 10,
            "parityshard": 4,
            "interval": 10,
        }
    if loss >= 0.5 or rtt >= 80:
        return {
            "mode": "fast2",
            "mtu": 1320,
            "sndwnd": 1536,
            "rcvwnd": 1536,
            "datashard": 10,
            "parityshard": 3,
            "interval": 15,
        }
    return {
        "mode": "fast",
        "mtu": 1350,
        "sndwnd": 1024,
        "rcvwnd": 1024,
        "datashard": 10,
        "parityshard": 2,
        "interval": 20,
    }


def kcp_query(profile: dict, key: str) -> str:
    from urllib.parse import urlencode
    return urlencode(
        {
            "kcp.key": key,
            "kcp.crypt": "aes",
            "kcp.mode": profile["mode"],
            "kcp.mtu": profile["mtu"],
            "kcp.sndwnd": profile["sndwnd"],
            "kcp.rcvwnd": profile["rcvwnd"],
            "kcp.datashard": profile["datashard"],
            "kcp.parityshard": profile["parityshard"],
            "kcp.interval": profile["interval"],
            "kcp.keepalive": 10,
        }
    )


def deploy_gost_proxy(method: str, run: dict, item: dict, config: dict, remote_a: Remote, remote_b: Remote, endpoint_a: dict, endpoint_b: dict) -> dict:
    sides = choose_sides(item, remote_a, remote_b, endpoint_a, endpoint_b)
    remote = sides["client"]
    endpoint = sides["client_endpoint"]
    source_key = "source_ip_a" if sides["client_side"] == "A" else "source_ip_b"
    source_ip = str(config.get(source_key) or endpoint["host"])
    bind = gost_bind(config, source_ip)
    protocol = "udp" if method in {"GOST_QUIC", "GOST_SOCKS5_KCP"} else "tcp"
    port = free_port(remote, protocol, int(config.get("listen_port") or (30000 + item["id"] % 15000)))
    username = str(config.get("username") or ("na" + stable_secret(run["id"], item["id"], "user", 10)))
    password = str(config.get("password") or stable_secret(run["id"], item["id"], "pass", 24))
    schemes = {
        "GOST_SOCKS5": "socks5",
        "GOST_HTTP": "http",
        "GOST_WS": "socks5+wss",
        "GOST_HTTP2": "http2",
        "GOST_GRPC": "socks5+grpc",
        "GOST_QUIC": "socks5+quic",
        "GOST_SSH": "socks5+ssh",
        "GOST_SOCKS5_KCP": "socks5+kcp",
    }
    scheme = schemes[method]
    query = ""
    kcp_profile = None
    if method == "GOST_SOCKS5_KCP":
        baseline = path_probe(remote, source_ip)
        kcp_profile = choose_kcp_profile(baseline, config)
        key = stable_secret(run["id"], item["id"], "kcp-key", 32)
        query = "?" + kcp_query(kcp_profile, key)
    name = f"netauto-gost-{run['id']}-{item['id']}"
    listener = f"{scheme}://{username}:{password}@{bind}:{port}{query}"
    try:
        install_gost(remote)
        if config.get("expose_public"):
            allow_firewall_port(remote, port, protocol)
        persistent_service(remote, name, f"exec /usr/local/bin/gost -L {shlex.quote(listener)}")
        wait_service(remote, name)
        wait_listener(remote, protocol, port)
    except Exception:
        remove_services(remote, [name])
        raise
    return {
        "method": method,
        "services_a": [name] if sides["client_side"] == "A" else [],
        "services_b": [name] if sides["client_side"] == "B" else [],
        "listener_side": sides["client_side"],
        "listen_address": bind,
        "listen_port": port,
        "protocol": protocol,
        "username": username,
        "password": password,
        "gost_version": GOST_VERSION,
        "tls": method in {"GOST_WS", "GOST_HTTP2", "GOST_GRPC", "GOST_QUIC", "GOST_SSH"},
        "kcp_profile": kcp_profile,
    }


def deploy_gost_kcp_forward(method: str, run: dict, item: dict, config: dict, remote_a: Remote, remote_b: Remote, endpoint_a: dict, endpoint_b: dict) -> dict:
    sides = choose_sides(item, remote_a, remote_b, endpoint_a, endpoint_b)
    client = sides["client"]
    server = sides["server"]
    client_ep = sides["client_endpoint"]
    server_ep = sides["server_endpoint"]
    server_source_key = "source_ip_b" if sides["server_side"] == "B" else "source_ip_a"
    client_source_key = "source_ip_a" if sides["client_side"] == "A" else "source_ip_b"
    server_source = str(config.get(server_source_key) or server_ep["host"])
    client_source = str(config.get(client_source_key) or client_ep["host"])
    baseline = path_probe(client, server_source)
    profile = choose_kcp_profile(baseline, config)
    relay_port = free_port(server, "udp", int(config.get("relay_port") or (36000 + item["id"] % 9000)))
    local_port = free_port(client, "tcp", int(config.get("listen_port") or (46000 + item["id"] % 9000)))
    target_host = str(config.get("target_host") or "127.0.0.1")
    target_port = int(config.get("target_port") or server_ep.get("port") or 22)
    bind = str(config.get("bind_address") or "127.0.0.1")
    username = "na" + stable_secret(run["id"], item["id"], "kcp-user", 10)
    password = stable_secret(run["id"], item["id"], "kcp-pass", 24)
    key = stable_secret(run["id"], item["id"], "kcp-key", 32)
    query = kcp_query(profile, key)
    server_name = f"netauto-kcp-{run['id']}-{item['id']}-s"
    client_name = f"netauto-kcp-{run['id']}-{item['id']}-c"
    server_listener = f"relay+kcp://{username}:{password}@{server_source}:{relay_port}?bind=true&{query}"
    local_listener = f"tcp://{bind}:{local_port}/{target_host}:{target_port}"
    chain = f"relay+kcp://{username}:{password}@{server_source}:{relay_port}?{query}"
    try:
        install_gost(client)
        install_gost(server)
        allow_firewall_port(server, relay_port, "udp")
        persistent_service(server, server_name, f"exec /usr/local/bin/gost -L {shlex.quote(server_listener)}")
        wait_service(server, server_name)
        wait_listener(server, "udp", relay_port)
        persistent_service(client, client_name, f"exec /usr/local/bin/gost -L {shlex.quote(local_listener)} -F {shlex.quote(chain)}")
        wait_service(client, client_name)
        wait_listener(client, "tcp", local_port)
    except Exception:
        remove_services(client, [client_name])
        remove_services(server, [server_name])
        raise
    return {
        "method": method,
        "services_a": [client_name] if sides["client_side"] == "A" else [server_name],
        "services_b": [client_name] if sides["client_side"] == "B" else [server_name],
        "client_side": sides["client_side"],
        "server_side": sides["server_side"],
        "client_source_ip": client_source,
        "server_source_ip": server_source,
        "local_bind": bind,
        "local_port": local_port,
        "target_host": target_host,
        "target_port": target_port,
        "relay_port": relay_port,
        "transport": "KCP",
        "kcp_profile": profile,
        "baseline": baseline,
        "gost_version": GOST_VERSION,
    }


def deploy_gost_forward(method: str, run: dict, item: dict, config: dict, remote_a: Remote, remote_b: Remote, endpoint_a: dict, endpoint_b: dict) -> dict:
    sides = choose_sides(item, remote_a, remote_b, endpoint_a, endpoint_b)
    remote = sides["client"]
    endpoint = sides["client_endpoint"]
    other = sides["server_endpoint"]
    source_key = "source_ip_a" if sides["client_side"] == "A" else "source_ip_b"
    other_key = "source_ip_b" if sides["client_side"] == "A" else "source_ip_a"
    source_ip = str(config.get(source_key) or endpoint["host"])
    target_host = str(config.get("target_host") or config.get(other_key) or other["host"])
    target_port = int(config.get("target_port") or other.get("port") or 22)
    protocol = "udp" if method == "GOST_UDP_FORWARD" else "tcp"
    bind = gost_bind(config, source_ip)
    listen_port = free_port(remote, protocol, int(config.get("listen_port") or (32000 + item["id"] % 12000)))
    scheme = "udp" if protocol == "udp" else "tcp"
    name = f"netauto-gost-{run['id']}-{item['id']}"
    listener = f"{scheme}://{bind}:{listen_port}/{target_host}:{target_port}"
    try:
        install_gost(remote)
        if config.get("expose_public"):
            allow_firewall_port(remote, listen_port, protocol)
        persistent_service(remote, name, f"exec /usr/local/bin/gost -L {shlex.quote(listener)}")
        wait_service(remote, name)
        wait_listener(remote, protocol, listen_port)
    except Exception:
        remove_services(remote, [name])
        raise
    return {
        "method": method,
        "services_a": [name] if sides["client_side"] == "A" else [],
        "services_b": [name] if sides["client_side"] == "B" else [],
        "listener_side": sides["client_side"],
        "listen_address": bind,
        "listen_port": listen_port,
        "protocol": protocol,
        "target_host": target_host,
        "target_port": target_port,
        "gost_version": GOST_VERSION,
    }


def deploy_gost_remote(method: str, run: dict, item: dict, config: dict, remote_a: Remote, remote_b: Remote, endpoint_a: dict, endpoint_b: dict) -> dict:
    sides = choose_sides(item, remote_a, remote_b, endpoint_a, endpoint_b)
    client = sides["client"]
    server = sides["server"]
    client_endpoint = sides["client_endpoint"]
    server_endpoint = sides["server_endpoint"]
    server_source_key = "source_ip_b" if sides["server_side"] == "B" else "source_ip_a"
    server_source = str(config.get(server_source_key) or server_endpoint["host"])
    protocol = "udp" if method == "GOST_REMOTE_UDP" else "tcp"
    relay_port = free_port(server, "tcp", int(config.get("relay_port") or (35000 + item["id"] % 10000)))
    listen_port = free_port(server, protocol, int(config.get("listen_port") or (45000 + item["id"] % 10000)))
    bind = gost_bind(config, server_source)
    target_host = str(config.get("target_host") or "127.0.0.1")
    target_port = int(config.get("target_port") or client_endpoint.get("port") or 22)
    username = "na" + stable_secret(run["id"], item["id"], "relayuser", 10)
    password = stable_secret(run["id"], item["id"], "relaypass", 24)
    relay_name = f"netauto-gostr-{run['id']}-{item['id']}-s"
    client_name = f"netauto-gostr-{run['id']}-{item['id']}-c"
    relay_listener = f"relay+wss://{username}:{password}@{server_source}:{relay_port}?bind=true"
    remote_scheme = "rudp" if protocol == "udp" else "rtcp"
    remote_listener = f"{remote_scheme}://{bind}:{listen_port}/{target_host}:{target_port}"
    chain = f"relay+wss://{username}:{password}@{server_source}:{relay_port}?secure=false"
    try:
        install_gost(client)
        install_gost(server)
        allow_firewall_port(server, relay_port, "tcp")
        if config.get("expose_public"):
            allow_firewall_port(server, listen_port, protocol)
        persistent_service(server, relay_name, f"exec /usr/local/bin/gost -L {shlex.quote(relay_listener)}")
        wait_service(server, relay_name)
        wait_listener(server, "tcp", relay_port)
        persistent_service(client, client_name, f"exec /usr/local/bin/gost -L {shlex.quote(remote_listener)} -F {shlex.quote(chain)}")
        wait_service(client, client_name)
        wait_listener(server, protocol, listen_port)
    except Exception:
        remove_services(client, [client_name])
        remove_services(server, [relay_name])
        raise
    return {
        "method": method,
        "services_a": ([client_name] if sides["client_side"] == "A" else [relay_name]),
        "services_b": ([client_name] if sides["client_side"] == "B" else [relay_name]),
        "client_side": sides["client_side"],
        "listener_side": sides["server_side"],
        "listen_address": bind,
        "listen_port": listen_port,
        "protocol": protocol,
        "target_host": target_host,
        "target_port": target_port,
        "relay_port": relay_port,
        "relay_transport": "WSS",
        "relay_username": username,
        "relay_password": password,
        "gost_version": GOST_VERSION,
    }


def deploy_gost_device(method: str, run: dict, item: dict, config: dict, remote_a: Remote, remote_b: Remote, endpoint_a: dict, endpoint_b: dict) -> dict:
    addr = parse_addressing(config)
    sides = choose_sides(item, remote_a, remote_b, endpoint_a, endpoint_b)
    client = sides["client"]
    server = sides["server"]
    source_client = str(addr["source_a"] if sides["client_side"] == "A" else addr["source_b"])
    source_server = str(addr["source_b"] if sides["client_side"] == "A" else addr["source_a"])
    net_client = str(addr["address_a"] if sides["client_side"] == "A" else addr["address_b"])
    net_server = str(addr["address_b"] if sides["client_side"] == "A" else addr["address_a"])
    scheme = "tap" if method == "GOST_TAP" else "tun"
    interface_name = short_name("ngp" if scheme == "tap" else "ngn", run["id"], item["id"])
    port = free_port(server, "udp", int(config.get("listen_port") or (42000 + item["id"] % 10000)))
    mtu = int(config.get("mtu") or 1400)
    server_name = f"netauto-gostd-{run['id']}-{item['id']}-s"
    client_name = f"netauto-gostd-{run['id']}-{item['id']}-c"
    server_listener = f"{scheme}://{source_server}:{port}?net={net_server}&name={interface_name}&mtu={mtu}"
    client_listener = f"{scheme}://{source_client}:0/{source_server}:{port}?net={net_client}&name={interface_name}&mtu={mtu}&keepalive=true&ttl=10s"
    try:
        install_gost(client)
        install_gost(server)
        allow_firewall_port(server, port, "udp")
        persistent_service(server, server_name, f"exec /usr/local/bin/gost -L {shlex.quote(server_listener)}")
        wait_service(server, server_name)
        persistent_service(client, client_name, f"exec /usr/local/bin/gost -L {shlex.quote(client_listener)}")
        wait_service(client, client_name)
        time.sleep(5)
        peer_client = addr["address_b"].ip if sides["client_side"] == "A" else addr["address_a"].ip
        peer_server = addr["address_a"].ip if sides["client_side"] == "A" else addr["address_b"].ip
        client.run(ping_command(peer_client), root=True, timeout=35)
        server.run(ping_command(peer_server), root=True, timeout=35)
    except Exception:
        remove_services(client, [client_name], [], [interface_name])
        remove_services(server, [server_name], [], [interface_name])
        raise
    return {
        "method": method,
        "services_a": ([client_name] if sides["client_side"] == "A" else [server_name]),
        "services_b": ([client_name] if sides["client_side"] == "B" else [server_name]),
        "interfaces_a": [interface_name],
        "interfaces_b": [interface_name],
        "client_side": sides["client_side"],
        "server_side": sides["server_side"],
        "listen_port": port,
        "transport": "UDP",
        "encrypted": False,
        "warning": "Direct GOST TUN/TAP UDP transport is not encrypted.",
        "tunnel_cidr": str(addr["network"]),
        "tunnel_ip_a": str(addr["address_a"]),
        "tunnel_ip_b": str(addr["address_b"]),
        "interface_name": interface_name,
        "gost_version": GOST_VERSION,
    }


def deploy_ssh_method(method: str, run: dict, item: dict, config: dict, remote_a: Remote, remote_b: Remote, endpoint_a: dict, endpoint_b: dict) -> dict:
    if method in {"SSH_TUN_L3", "SSH_TAP_L2"}:
        return deploy_ssh_tunnel(method, run, item, config, remote_a, remote_b, endpoint_a, endpoint_b)
    return deploy_ssh_forward(method, run, item, config, remote_a, remote_b, endpoint_a, endpoint_b)


def deploy_gost_method(method: str, run: dict, item: dict, config: dict, remote_a: Remote, remote_b: Remote, endpoint_a: dict, endpoint_b: dict) -> dict:
    if method == "GOST_KCP_FORWARD":
        return deploy_gost_kcp_forward(method, run, item, config, remote_a, remote_b, endpoint_a, endpoint_b)
    if method in {"GOST_TCP_FORWARD", "GOST_UDP_FORWARD"}:
        return deploy_gost_forward(method, run, item, config, remote_a, remote_b, endpoint_a, endpoint_b)
    if method in {"GOST_REMOTE_TCP", "GOST_REMOTE_UDP"}:
        return deploy_gost_remote(method, run, item, config, remote_a, remote_b, endpoint_a, endpoint_b)
    if method in {"GOST_TUN", "GOST_TAP"}:
        return deploy_gost_device(method, run, item, config, remote_a, remote_b, endpoint_a, endpoint_b)
    return deploy_gost_proxy(method, run, item, config, remote_a, remote_b, endpoint_a, endpoint_b)



# ==========================================================
# PACK 4 — FRP / RATHOLE / CHISEL / WSTUNNEL
# ==========================================================

FRP_METHODS = {
    "FRP_TCP",
    "FRP_UDP",
    "FRP_STCP",
    "FRP_XTCP",
    "FRP_KCP",
    "FRP_QUIC",
}

RATHOLE_METHODS = {
    "RATHOLE_TCP",
    "RATHOLE_UDP",
    "RATHOLE_TLS",
    "RATHOLE_NOISE",
    "RATHOLE_WEBSOCKET",
}

CHISEL_METHODS = {
    "CHISEL_TCP",
    "CHISEL_UDP",
    "CHISEL_REVERSE_TCP",
    "CHISEL_REVERSE_UDP",
    "CHISEL_SOCKS5",
    "CHISEL_REVERSE_SOCKS5",
}

WSTUNNEL_METHODS = {
    "WSTUNNEL_TCP",
    "WSTUNNEL_UDP",
    "WSTUNNEL_SOCKS5",
}


def config_value(config: dict, *names: str, default=None):
    for name in names:
        value = config.get(name)
        if value not in (None, ""):
            return value
    return default


def config_port(config: dict, *names: str, default: int | None = None) -> int:
    value = config_value(config, *names, default=default)
    if value is None:
        raise RuntimeError("REQUIRED_PORT_MISSING_" + "_".join(names).upper())
    try:
        port = int(value)
    except Exception as exc:
        raise RuntimeError("INVALID_PORT_" + "_".join(names).upper()) from exc
    if port < 1 or port > 65535:
        raise RuntimeError("PORT_OUT_OF_RANGE")
    return port


def endpoint_source(config: dict, side: str, endpoint: dict) -> str:
    value = config.get("source_ip_a" if side == "A" else "source_ip_b")
    return str(value or endpoint["host"])


def write_remote_text(remote: Remote, path: str, content: str, mode: str = "0600"):
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    remote.run(
        f"install -d -m 0700 {shlex.quote(os.path.dirname(path))}; "
        f"printf '%s' {shlex.quote(encoded)} | base64 -d > {shlex.quote(path)}; "
        f"chmod {shlex.quote(mode)} {shlex.quote(path)}",
        root=True,
        timeout=120,
    )


def install_release_binary(
    remote: Remote,
    *,
    repo: str,
    binaries: list[str],
    asset_family: str,
):
    binary_checks = " && ".join(
        f"command -v {shlex.quote(binary)} >/dev/null 2>&1"
        for binary in binaries
    )
    script = r"""
set -Eeuo pipefail
if __BINARY_CHECKS__; then
    exit 0
fi

export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a DEBCONF_NONINTERACTIVE_SEEN=true
apt-get update
apt-get install -y ca-certificates python3 tar gzip unzip

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

python3 - "$TMP_DIR" "__REPO__" "__ASSET_FAMILY__" "__BINARIES__" <<'PYDL'
import gzip
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import tarfile
import urllib.request
import zipfile

out_dir = Path(sys.argv[1])
repo = sys.argv[2]
family = sys.argv[3]
binaries = sys.argv[4].split(",")

machine = platform.machine().lower()
arch_tokens = {
    "x86_64": ["amd64", "x86_64"],
    "amd64": ["amd64", "x86_64"],
    "aarch64": ["arm64", "aarch64"],
    "arm64": ["arm64", "aarch64"],
    "armv7l": ["armv7", "armhf"],
    "armv7": ["armv7", "armhf"],
}.get(machine)

if not arch_tokens:
    raise SystemExit(f"UNSUPPORTED_ARCHITECTURE: {machine}")

request = urllib.request.Request(
    f"https://api.github.com/repos/{repo}/releases/latest",
    headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "TehranNetwork-Automation",
    },
)

with urllib.request.urlopen(request, timeout=30) as response:
    release = json.load(response)

assets = release.get("assets", [])
candidates = []

for asset in assets:
    name = asset.get("name", "")
    lowered = name.lower()
    if not any(token in lowered for token in arch_tokens):
        continue
    if not any(token in lowered for token in ("linux", "unknown-linux")):
        continue
    if any(token in lowered for token in ("sha256", "checksum", ".sig", "source")):
        continue

    score = 0
    if family.lower() in lowered:
        score += 10
    if lowered.endswith((".tar.gz", ".tgz", ".zip", ".gz")):
        score += 4
    if "musl" in lowered:
        score += 2
    candidates.append((score, asset))

if not candidates:
    names = ", ".join(asset.get("name", "") for asset in assets)
    raise SystemExit(
        f"NO_COMPATIBLE_RELEASE_ASSET for {repo} {machine}; assets={names}"
    )

candidates.sort(key=lambda item: item[0], reverse=True)
asset = candidates[0][1]
url = asset["browser_download_url"]
name = asset["name"]

archive = out_dir / name
download = urllib.request.Request(
    url,
    headers={"User-Agent": "TehranNetwork-Automation"},
)
with urllib.request.urlopen(download, timeout=90) as response:
    archive.write_bytes(response.read())

extract_dir = out_dir / "extract"
extract_dir.mkdir()

if name.endswith((".tar.gz", ".tgz")):
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(extract_dir)
elif name.endswith(".zip"):
    with zipfile.ZipFile(archive) as zip_file:
        zip_file.extractall(extract_dir)
elif name.endswith(".gz"):
    target = extract_dir / name[:-3]
    with gzip.open(archive, "rb") as source:
        target.write_bytes(source.read())
    target.chmod(0o755)
else:
    target = extract_dir / name
    shutil.copy2(archive, target)
    target.chmod(0o755)

for binary in binaries:
    matches = [
        path
        for path in extract_dir.rglob("*")
        if path.is_file()
        and path.name == binary
    ]

    if not matches and len(binaries) == 1:
        fallback = [
            path
            for path in extract_dir.rglob("*")
            if path.is_file()
            and not path.name.lower().endswith(
                (".txt", ".md", ".toml", ".json", ".yaml", ".yml")
            )
        ]
        if len(fallback) == 1:
            matches = fallback

    if not matches:
        raise SystemExit(
            f"BINARY_NOT_FOUND: {binary} in asset {name}"
        )

    source = matches[0]
    destination = Path("/usr/local/bin") / binary
    shutil.copy2(source, destination)
    destination.chmod(0o755)

metadata = {
    "repo": repo,
    "tag": release.get("tag_name"),
    "asset": name,
    "machine": machine,
}
(out_dir / "metadata.json").write_text(
    json.dumps(metadata),
    encoding="utf-8",
)
PYDL

cat "$TMP_DIR/metadata.json"
""".replace("__BINARY_CHECKS__", binary_checks)
    script = script.replace("__REPO__", repo)
    script = script.replace("__ASSET_FAMILY__", asset_family)
    script = script.replace("__BINARIES__", ",".join(binaries))

    result = remote.run(
        script,
        root=True,
        timeout=600,
    )
    return result["stdout"].strip()


def prepare_tls_pair(
    server: Remote,
    client: Remote,
    *,
    name: str,
    server_host: str,
    pfx_password: str,
) -> dict:
    install_packages(server, ["openssl", "ca-certificates"])
    install_packages(client, ["ca-certificates"])

    base_dir = f"/etc/netauto/tls/{name}"
    server_dir = base_dir
    client_dir = base_dir

    try:
        ipaddress.ip_address(server_host)
        san = f"IP:{server_host}"
        common_name = server_host
    except ValueError:
        san = f"DNS:{server_host}"
        common_name = server_host

    script = f"""
set -Eeuo pipefail
install -d -m 0700 {shlex.quote(server_dir)}
cd {shlex.quote(server_dir)}

if [[ ! -s ca.crt || ! -s server.crt || ! -s server.key ]]; then
    openssl genrsa -out ca.key 3072
    openssl req -x509 -new -nodes \
        -key ca.key \
        -sha256 \
        -days 3650 \
        -subj {shlex.quote('/CN=TehranNetwork Internal CA ' + name)} \
        -out ca.crt

    openssl genrsa -out server.key 3072
    openssl req -new \
        -key server.key \
        -subj {shlex.quote('/CN=' + common_name)} \
        -out server.csr

    cat > server.ext <<'EXT'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName={san}
EXT

    openssl x509 -req \
        -in server.csr \
        -CA ca.crt \
        -CAkey ca.key \
        -CAcreateserial \
        -out server.crt \
        -days 825 \
        -sha256 \
        -extfile server.ext

    openssl pkcs12 -export \
        -out server.pfx \
        -inkey server.key \
        -in server.crt \
        -certfile ca.crt \
        -password pass:{shlex.quote(pfx_password)}
fi

chmod 0600 ca.key server.key server.pfx
chmod 0644 ca.crt server.crt
cat ca.crt
"""
    ca_pem = server.run(
        script,
        root=True,
        timeout=180,
    )["stdout"]

    write_remote_text(
        client,
        f"{client_dir}/ca.crt",
        ca_pem,
        mode="0644",
    )

    return {
        "server_dir": server_dir,
        "client_dir": client_dir,
        "server_key": f"{server_dir}/server.key",
        "server_cert": f"{server_dir}/server.crt",
        "server_pfx": f"{server_dir}/server.pfx",
        "server_ca": f"{server_dir}/ca.crt",
        "client_ca": f"{client_dir}/ca.crt",
    }


def deploy_frp_method(
    method: str,
    run: dict,
    item: dict,
    config: dict,
    remote_a: Remote,
    remote_b: Remote,
    endpoint_a: dict,
    endpoint_b: dict,
) -> dict:
    sides = choose_sides(
        item,
        remote_a,
        remote_b,
        endpoint_a,
        endpoint_b,
    )
    client = sides["client"]
    server = sides["server"]
    server_host = endpoint_source(
        config,
        sides["server_side"],
        sides["server_endpoint"],
    )

    install_release_binary(
        client,
        repo="fatedier/frp",
        binaries=["frpc"],
        asset_family="frp",
    )
    install_release_binary(
        server,
        repo="fatedier/frp",
        binaries=["frps"],
        asset_family="frp",
    )

    name = f"netauto-frp-{run['id']}-{item['id']}"
    root_dir = f"/etc/netauto/frp/{name}"
    token = stable_secret(
        run["id"],
        item["id"],
        "frp-token",
        48,
    )
    secret = stable_secret(
        run["id"],
        item["id"],
        "frp-secret",
        48,
    )
    control_protocol = (
        "kcp"
        if method == "FRP_KCP"
        else "quic"
        if method == "FRP_QUIC"
        else "tcp"
    )
    control_port = free_port(
        server,
        "udp" if control_protocol in {"kcp", "quic"} else "tcp",
        config_port(
            config,
            "control_port",
            default=7000 + item["id"] % 1000,
        ),
    )
    remote_port = free_port(
        server,
        "udp" if method == "FRP_UDP" else "tcp",
        config_port(
            config,
            "remote_port",
            "listen_port",
            default=20000 + item["id"] % 20000,
        ),
    )
    local_host = str(
        config_value(
            config,
            "local_host",
            "target_host",
            default="127.0.0.1",
        )
    )
    local_port = config_port(
        config,
        "local_port",
        "target_port",
        default=22,
    )
    proxy_name = re.sub(
        r"[^a-zA-Z0-9_-]",
        "-",
        f"p{run['id']}-{item['id']}",
    )
    server_bind = str(
        config_value(
            config,
            "remote_bind_host",
            default="127.0.0.1",
        )
    )

    frps = [
        f'bindAddr = "0.0.0.0"',
        f"bindPort = {control_port}",
        f'proxyBindAddr = "{server_bind}"',
        'auth.method = "token"',
        f'auth.token = "{token}"',
        "transport.tls.force = true",
    ]

    if control_protocol == "kcp":
        frps.append(f"kcpBindPort = {control_port}")
    elif control_protocol == "quic":
        frps.append(f"quicBindPort = {control_port}")

    server_config = "\n".join(frps) + "\n"

    common_client = [
        f'serverAddr = "{server_host}"',
        f"serverPort = {control_port}",
        f'transport.protocol = "{control_protocol}"',
        'auth.method = "token"',
        f'auth.token = "{token}"',
        "transport.tls.enable = true",
    ]

    proxy = []
    visitor = None

    if method in {"FRP_TCP", "FRP_KCP", "FRP_QUIC"}:
        proxy = [
            "[[proxies]]",
            f'name = "{proxy_name}"',
            'type = "tcp"',
            f'localIP = "{local_host}"',
            f"localPort = {local_port}",
            f"remotePort = {remote_port}",
        ]
    elif method == "FRP_UDP":
        proxy = [
            "[[proxies]]",
            f'name = "{proxy_name}"',
            'type = "udp"',
            f'localIP = "{local_host}"',
            f"localPort = {local_port}",
            f"remotePort = {remote_port}",
        ]
    elif method in {"FRP_STCP", "FRP_XTCP"}:
        proxy_type = "stcp" if method == "FRP_STCP" else "xtcp"
        proxy = [
            "[[proxies]]",
            f'name = "{proxy_name}"',
            f'type = "{proxy_type}"',
            f'secretKey = "{secret}"',
            f'localIP = "{local_host}"',
            f"localPort = {local_port}",
        ]
        visitor = [
            *common_client,
            "",
            "[[visitors]]",
            f'name = "{proxy_name}-visitor"',
            f'type = "{proxy_type}"',
            f'serverName = "{proxy_name}"',
            f'secretKey = "{secret}"',
            f'bindAddr = "{server_bind}"',
            f"bindPort = {remote_port}",
        ]

    client_config = "\n".join(
        common_client + [""] + proxy
    ) + "\n"

    server_path = f"{root_dir}/frps.toml"
    client_path = f"{root_dir}/frpc.toml"
    visitor_path = f"{root_dir}/visitor.toml"

    write_remote_text(
        server,
        server_path,
        server_config,
    )
    write_remote_text(
        client,
        client_path,
        client_config,
    )

    server_service = f"{name}-server"
    client_service = f"{name}-client"
    services_server = [server_service]
    files_server = [root_dir]
    services_client = [client_service]
    files_client = [root_dir]

    persistent_service(
        server,
        server_service,
        f"/usr/local/bin/frps -c {shlex.quote(server_path)}",
    )
    wait_service(server, server_service)

    persistent_service(
        client,
        client_service,
        f"/usr/local/bin/frpc -c {shlex.quote(client_path)}",
    )
    wait_service(client, client_service)

    if visitor:
        write_remote_text(
            server,
            visitor_path,
            "\n".join(visitor) + "\n",
        )
        visitor_service = f"{name}-visitor"
        persistent_service(
            server,
            visitor_service,
            f"/usr/local/bin/frpc -c {shlex.quote(visitor_path)}",
        )
        wait_service(server, visitor_service)
        services_server.append(visitor_service)

    wait_listener(
        server,
        "udp" if method == "FRP_UDP" else "tcp",
        remote_port,
    )

    return {
        "method": method,
        "services_a": (
            services_client
            if sides["client_side"] == "A"
            else services_server
        ),
        "services_b": (
            services_client
            if sides["client_side"] == "B"
            else services_server
        ),
        "files_a": (
            files_client
            if sides["client_side"] == "A"
            else files_server
        ),
        "files_b": (
            files_client
            if sides["client_side"] == "B"
            else files_server
        ),
        "client_side": sides["client_side"],
        "server_side": sides["server_side"],
        "server_host": server_host,
        "control_port": control_port,
        "remote_bind_host": server_bind,
        "remote_port": remote_port,
        "local_target": f"{local_host}:{local_port}",
        "control_transport": control_protocol,
        "tls_enabled": True,
        "auth_token_sha256": hashlib.sha256(
            token.encode("utf-8")
        ).hexdigest(),
    }


def generate_noise_server_keypair() -> tuple[str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519

    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return (
        base64.b64encode(private_raw).decode("ascii"),
        base64.b64encode(public_raw).decode("ascii"),
    )


def deploy_rathole_method(
    method: str,
    run: dict,
    item: dict,
    config: dict,
    remote_a: Remote,
    remote_b: Remote,
    endpoint_a: dict,
    endpoint_b: dict,
) -> dict:
    sides = choose_sides(
        item,
        remote_a,
        remote_b,
        endpoint_a,
        endpoint_b,
    )
    client = sides["client"]
    server = sides["server"]
    server_host = endpoint_source(
        config,
        sides["server_side"],
        sides["server_endpoint"],
    )

    install_release_binary(
        client,
        repo="rathole-org/rathole",
        binaries=["rathole"],
        asset_family="rathole",
    )
    install_release_binary(
        server,
        repo="rathole-org/rathole",
        binaries=["rathole"],
        asset_family="rathole",
    )

    name = f"netauto-rathole-{run['id']}-{item['id']}"
    root_dir = f"/etc/netauto/rathole/{name}"
    token = stable_secret(
        run["id"],
        item["id"],
        "rathole-token",
        48,
    )
    protocol = "udp" if method == "RATHOLE_UDP" else "tcp"
    control_port = free_port(
        server,
        "tcp",
        config_port(
            config,
            "control_port",
            default=2333 + item["id"] % 1000,
        ),
    )
    remote_port = free_port(
        server,
        protocol,
        config_port(
            config,
            "remote_port",
            "listen_port",
            default=21000 + item["id"] % 20000,
        ),
    )
    local_host = str(
        config_value(
            config,
            "local_host",
            "target_host",
            default="127.0.0.1",
        )
    )
    local_port = config_port(
        config,
        "local_port",
        "target_port",
        default=22,
    )
    bind_host = str(
        config_value(
            config,
            "remote_bind_host",
            default="127.0.0.1",
        )
    )
    service_id = re.sub(
        r"[^a-zA-Z0-9_]",
        "_",
        f"s{run['id']}_{item['id']}",
    )

    transport_type = "tcp"
    server_transport = [
        "[server.transport]",
        'type = "tcp"',
    ]
    client_transport = [
        "[client.transport]",
        'type = "tcp"',
    ]
    tls = None
    noise_public = None

    if method == "RATHOLE_TLS":
        transport_type = "tls"
        pfx_password = stable_secret(
            run["id"],
            item["id"],
            "rathole-pfx",
            32,
        )
        tls = prepare_tls_pair(
            server,
            client,
            name=name,
            server_host=server_host,
            pfx_password=pfx_password,
        )
        server_transport = [
            "[server.transport]",
            'type = "tls"',
            "",
            "[server.transport.tls]",
            f'pkcs12 = "{tls["server_pfx"]}"',
            f'pkcs12_password = "{pfx_password}"',
        ]
        client_transport = [
            "[client.transport]",
            'type = "tls"',
            "",
            "[client.transport.tls]",
            f'trusted_root = "{tls["client_ca"]}"',
            f'hostname = "{server_host}"',
        ]

    elif method == "RATHOLE_NOISE":
        transport_type = "noise"
        noise_private, noise_public = (
            generate_noise_server_keypair()
        )
        server_transport = [
            "[server.transport]",
            'type = "noise"',
            "",
            "[server.transport.noise]",
            'pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"',
            f'local_private_key = "{noise_private}"',
        ]
        client_transport = [
            "[client.transport]",
            'type = "noise"',
            "",
            "[client.transport.noise]",
            'pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"',
            f'remote_public_key = "{noise_public}"',
        ]

    elif method == "RATHOLE_WEBSOCKET":
        transport_type = "websocket"
        pfx_password = stable_secret(
            run["id"],
            item["id"],
            "rathole-ws-pfx",
            32,
        )
        tls = prepare_tls_pair(
            server,
            client,
            name=name,
            server_host=server_host,
            pfx_password=pfx_password,
        )
        server_transport = [
            "[server.transport]",
            'type = "websocket"',
            "",
            "[server.transport.websocket]",
            "tls = true",
            "",
            "[server.transport.tls]",
            f'pkcs12 = "{tls["server_pfx"]}"',
            f'pkcs12_password = "{pfx_password}"',
        ]
        client_transport = [
            "[client.transport]",
            'type = "websocket"',
            "",
            "[client.transport.websocket]",
            "tls = true",
            "",
            "[client.transport.tls]",
            f'trusted_root = "{tls["client_ca"]}"',
            f'hostname = "{server_host}"',
        ]

    server_config = "\n".join(
        [
            "[server]",
            f'bind_addr = "0.0.0.0:{control_port}"',
            "heartbeat_interval = 20",
            "",
            *server_transport,
            "",
            f"[server.services.{service_id}]",
            f'type = "{protocol}"',
            f'token = "{token}"',
            f'bind_addr = "{bind_host}:{remote_port}"',
            "nodelay = false",
        ]
    ) + "\n"

    client_config = "\n".join(
        [
            "[client]",
            f'remote_addr = "{server_host}:{control_port}"',
            "heartbeat_timeout = 40",
            "retry_interval = 1",
            "",
            *client_transport,
            "",
            f"[client.services.{service_id}]",
            f'type = "{protocol}"',
            f'token = "{token}"',
            f'local_addr = "{local_host}:{local_port}"',
            "nodelay = false",
        ]
    ) + "\n"

    server_path = f"{root_dir}/server.toml"
    client_path = f"{root_dir}/client.toml"

    write_remote_text(
        server,
        server_path,
        server_config,
    )
    write_remote_text(
        client,
        client_path,
        client_config,
    )

    server_service = f"{name}-server"
    client_service = f"{name}-client"

    persistent_service(
        server,
        server_service,
        f"/usr/local/bin/rathole --server {shlex.quote(server_path)}",
        environment={"RUST_LOG": "info"},
    )
    wait_service(server, server_service)

    persistent_service(
        client,
        client_service,
        f"/usr/local/bin/rathole --client {shlex.quote(client_path)}",
        environment={"RUST_LOG": "info"},
    )
    wait_service(client, client_service)
    wait_listener(server, protocol, remote_port)

    server_files = [root_dir]
    client_files = [root_dir]

    if tls:
        server_files.append(tls["server_dir"])
        client_files.append(tls["client_dir"])

    return {
        "method": method,
        "services_a": (
            [client_service]
            if sides["client_side"] == "A"
            else [server_service]
        ),
        "services_b": (
            [client_service]
            if sides["client_side"] == "B"
            else [server_service]
        ),
        "files_a": (
            client_files
            if sides["client_side"] == "A"
            else server_files
        ),
        "files_b": (
            client_files
            if sides["client_side"] == "B"
            else server_files
        ),
        "client_side": sides["client_side"],
        "server_side": sides["server_side"],
        "server_host": server_host,
        "control_port": control_port,
        "remote_bind_host": bind_host,
        "remote_port": remote_port,
        "local_target": f"{local_host}:{local_port}",
        "service_protocol": protocol,
        "transport": transport_type,
        "encrypted": transport_type in {
            "tls",
            "noise",
            "websocket",
        },
        "noise_server_public_key": noise_public,
        "token_sha256": hashlib.sha256(
            token.encode("utf-8")
        ).hexdigest(),
    }


def deploy_chisel_method(
    method: str,
    run: dict,
    item: dict,
    config: dict,
    remote_a: Remote,
    remote_b: Remote,
    endpoint_a: dict,
    endpoint_b: dict,
) -> dict:
    sides = choose_sides(
        item,
        remote_a,
        remote_b,
        endpoint_a,
        endpoint_b,
    )
    client = sides["client"]
    server = sides["server"]
    server_host = endpoint_source(
        config,
        sides["server_side"],
        sides["server_endpoint"],
    )

    install_release_binary(
        client,
        repo="jpillora/chisel",
        binaries=["chisel"],
        asset_family="chisel",
    )
    install_release_binary(
        server,
        repo="jpillora/chisel",
        binaries=["chisel"],
        asset_family="chisel",
    )

    name = f"netauto-chisel-{run['id']}-{item['id']}"
    root_dir = f"/etc/netauto/chisel/{name}"
    username = "netauto"
    password = stable_secret(
        run["id"],
        item["id"],
        "chisel-auth",
        32,
    )
    server_port = free_port(
        server,
        "tcp",
        config_port(
            config,
            "server_port",
            "control_port",
            default=9000 + item["id"] % 1000,
        ),
    )
    local_host = str(
        config_value(
            config,
            "local_host",
            default="127.0.0.1",
        )
    )
    target_host = str(
        config_value(
            config,
            "target_host",
            default="127.0.0.1",
        )
    )
    target_port = config_port(
        config,
        "target_port",
        "local_port",
        default=22,
    )
    listen_port = config_port(
        config,
        "listen_port",
        "local_port",
        "remote_port",
        "socks_port",
        default=22000 + item["id"] % 20000,
    )
    listen_bind = str(
        config_value(
            config,
            "listen_host",
            "remote_bind_host",
            default="127.0.0.1",
        )
    )
    tls = prepare_tls_pair(
        server,
        client,
        name=name,
        server_host=server_host,
        pfx_password="unused",
    )
    key_file = f"{root_dir}/chisel.key"

    server.run(
        f"install -d -m 0700 {shlex.quote(root_dir)}; "
        f"test -s {shlex.quote(key_file)} || "
        f"/usr/local/bin/chisel server --keygen {shlex.quote(key_file)}; "
        f"chmod 0600 {shlex.quote(key_file)}",
        root=True,
        timeout=120,
    )

    reverse_enabled = method in {
        "CHISEL_REVERSE_TCP",
        "CHISEL_REVERSE_UDP",
        "CHISEL_REVERSE_SOCKS5",
    }
    socks_enabled = method in {
        "CHISEL_SOCKS5",
        "CHISEL_REVERSE_SOCKS5",
    }

    server_command = (
        "/usr/local/bin/chisel server "
        f"--host 0.0.0.0 --port {server_port} "
        f"--keyfile {shlex.quote(key_file)} "
        f"--auth {shlex.quote(username + ':' + password)} "
        f"--tls-key {shlex.quote(tls['server_key'])} "
        f"--tls-cert {shlex.quote(tls['server_cert'])} "
        + ("--reverse " if reverse_enabled else "")
        + ("--socks5 " if socks_enabled else "")
    ).strip()

    if method == "CHISEL_TCP":
        remote_spec = (
            f"{listen_bind}:{listen_port}:"
            f"{target_host}:{target_port}"
        )
        listener_side = sides["client_side"]
        listener_protocol = "tcp"
    elif method == "CHISEL_UDP":
        remote_spec = (
            f"{listen_bind}:{listen_port}:"
            f"{target_host}:{target_port}/udp"
        )
        listener_side = sides["client_side"]
        listener_protocol = "udp"
    elif method == "CHISEL_REVERSE_TCP":
        remote_spec = (
            f"R:{listen_bind}:{listen_port}:"
            f"{target_host}:{target_port}"
        )
        listener_side = sides["server_side"]
        listener_protocol = "tcp"
    elif method == "CHISEL_REVERSE_UDP":
        remote_spec = (
            f"R:{listen_bind}:{listen_port}:"
            f"{target_host}:{target_port}/udp"
        )
        listener_side = sides["server_side"]
        listener_protocol = "udp"
    elif method == "CHISEL_SOCKS5":
        remote_spec = (
            f"{listen_bind}:{listen_port}:socks"
        )
        listener_side = sides["client_side"]
        listener_protocol = "tcp"
    elif method == "CHISEL_REVERSE_SOCKS5":
        remote_spec = (
            f"R:{listen_bind}:{listen_port}:socks"
        )
        listener_side = sides["server_side"]
        listener_protocol = "tcp"
    else:
        raise RuntimeError(
            "UNSUPPORTED_CHISEL_METHOD"
        )

    client_command = (
        "/usr/local/bin/chisel client "
        f"--auth {shlex.quote(username + ':' + password)} "
        f"--tls-ca {shlex.quote(tls['client_ca'])} "
        "--keepalive 20s "
        f"https://{server_host}:{server_port} "
        f"{shlex.quote(remote_spec)}"
    )

    server_service = f"{name}-server"
    client_service = f"{name}-client"

    persistent_service(
        server,
        server_service,
        server_command,
    )
    wait_service(server, server_service)
    wait_listener(server, "tcp", server_port)

    persistent_service(
        client,
        client_service,
        client_command,
    )
    wait_service(client, client_service)

    listener_remote = (
        client
        if listener_side == sides["client_side"]
        else server
    )
    wait_listener(
        listener_remote,
        listener_protocol,
        listen_port,
    )

    server_files = [
        root_dir,
        tls["server_dir"],
    ]
    client_files = [
        tls["client_dir"],
    ]

    return {
        "method": method,
        "services_a": (
            [client_service]
            if sides["client_side"] == "A"
            else [server_service]
        ),
        "services_b": (
            [client_service]
            if sides["client_side"] == "B"
            else [server_service]
        ),
        "files_a": (
            client_files
            if sides["client_side"] == "A"
            else server_files
        ),
        "files_b": (
            client_files
            if sides["client_side"] == "B"
            else server_files
        ),
        "client_side": sides["client_side"],
        "server_side": sides["server_side"],
        "server_host": server_host,
        "server_port": server_port,
        "listener_side": listener_side,
        "listener_host": listen_bind,
        "listener_port": listen_port,
        "listener_protocol": listener_protocol,
        "target": (
            "dynamic-socks5"
            if "SOCKS5" in method
            else f"{target_host}:{target_port}"
        ),
        "outer_tls": True,
        "inner_ssh_encryption": True,
        "authentication": "user-password",
    }


def deploy_wstunnel_method(
    method: str,
    run: dict,
    item: dict,
    config: dict,
    remote_a: Remote,
    remote_b: Remote,
    endpoint_a: dict,
    endpoint_b: dict,
) -> dict:
    sides = choose_sides(
        item,
        remote_a,
        remote_b,
        endpoint_a,
        endpoint_b,
    )
    client = sides["client"]
    server = sides["server"]
    server_host = endpoint_source(
        config,
        sides["server_side"],
        sides["server_endpoint"],
    )

    install_release_binary(
        client,
        repo="erebe/wstunnel",
        binaries=["wstunnel"],
        asset_family="wstunnel",
    )
    install_release_binary(
        server,
        repo="erebe/wstunnel",
        binaries=["wstunnel"],
        asset_family="wstunnel",
    )

    name = f"netauto-wstunnel-{run['id']}-{item['id']}"
    path_secret = stable_secret(
        run["id"],
        item["id"],
        "wstunnel-path",
        40,
    )
    server_port = free_port(
        server,
        "tcp",
        config_port(
            config,
            "server_port",
            "control_port",
            default=10000 + item["id"] % 1000,
        ),
    )
    listen_host = str(
        config_value(
            config,
            "listen_host",
            default="127.0.0.1",
        )
    )
    listen_port = config_port(
        config,
        "listen_port",
        "local_port",
        "socks_port",
        default=23000 + item["id"] % 20000,
    )
    target_host = str(
        config_value(
            config,
            "target_host",
            default="127.0.0.1",
        )
    )
    target_port = config_port(
        config,
        "target_port",
        default=22,
    )
    pool = int(
        config_value(
            config,
            "connection_min_idle",
            default=4,
        )
    )

    if method == "WSTUNNEL_TCP":
        local_spec = (
            f"tcp://{listen_host}:{listen_port}:"
            f"{target_host}:{target_port}"
        )
        protocol = "tcp"
        restrictions = [
            f"--restrict-to {shlex.quote(target_host + ':' + str(target_port))}"
        ]
    elif method == "WSTUNNEL_UDP":
        local_spec = (
            f"udp://{listen_host}:{listen_port}:"
            f"{target_host}:{target_port}?timeout_sec=0"
        )
        protocol = "udp"
        restrictions = [
            f"--restrict-to {shlex.quote(target_host + ':' + str(target_port))}"
        ]
    elif method == "WSTUNNEL_SOCKS5":
        local_spec = (
            f"socks5://{listen_host}:{listen_port}"
        )
        protocol = "tcp"
        restrictions = []
    else:
        raise RuntimeError(
            "UNSUPPORTED_WSTUNNEL_METHOD"
        )

    server_command = (
        "/usr/local/bin/wstunnel server "
        f"--restrict-http-upgrade-path-prefix {shlex.quote(path_secret)} "
        + " ".join(restrictions)
        + f" wss://0.0.0.0:{server_port}"
    )
    client_command = (
        "/usr/local/bin/wstunnel client "
        f"--http-upgrade-path-prefix {shlex.quote(path_secret)} "
        f"--connection-min-idle {pool} "
        f"-L {shlex.quote(local_spec)} "
        f"wss://{server_host}:{server_port}"
    )

    server_service = f"{name}-server"
    client_service = f"{name}-client"

    persistent_service(
        server,
        server_service,
        server_command,
    )
    wait_service(server, server_service)
    wait_listener(server, "tcp", server_port)

    persistent_service(
        client,
        client_service,
        client_command,
    )
    wait_service(client, client_service)
    wait_listener(
        client,
        protocol,
        listen_port,
    )

    return {
        "method": method,
        "services_a": (
            [client_service]
            if sides["client_side"] == "A"
            else [server_service]
        ),
        "services_b": (
            [client_service]
            if sides["client_side"] == "B"
            else [server_service]
        ),
        "client_side": sides["client_side"],
        "server_side": sides["server_side"],
        "server_host": server_host,
        "server_port": server_port,
        "listener_side": sides["client_side"],
        "listener_host": listen_host,
        "listener_port": listen_port,
        "listener_protocol": protocol,
        "target": (
            "dynamic-socks5"
            if method == "WSTUNNEL_SOCKS5"
            else f"{target_host}:{target_port}"
        ),
        "transport": "WSS",
        "path_authentication": True,
        "certificate_validation": False,
        "warning": (
            "wstunnel embedded TLS certificate encrypts the transport "
            "but is not identity-pinned; use Chisel TLS or Rathole TLS/Noise "
            "when authenticated server identity is required."
        ),
    }


def deploy_pack4_method(
    method: str,
    run: dict,
    item: dict,
    config: dict,
    remote_a: Remote,
    remote_b: Remote,
    endpoint_a: dict,
    endpoint_b: dict,
) -> dict:
    if method in FRP_METHODS:
        return deploy_frp_method(
            method,
            run,
            item,
            config,
            remote_a,
            remote_b,
            endpoint_a,
            endpoint_b,
        )
    if method in RATHOLE_METHODS:
        return deploy_rathole_method(
            method,
            run,
            item,
            config,
            remote_a,
            remote_b,
            endpoint_a,
            endpoint_b,
        )
    if method in CHISEL_METHODS:
        return deploy_chisel_method(
            method,
            run,
            item,
            config,
            remote_a,
            remote_b,
            endpoint_a,
            endpoint_b,
        )
    if method in WSTUNNEL_METHODS:
        return deploy_wstunnel_method(
            method,
            run,
            item,
            config,
            remote_a,
            remote_b,
            endpoint_a,
            endpoint_b,
        )
    raise RuntimeError(
        "PACK4_METHOD_NOT_IMPLEMENTED"
    )




VPN_METHODS = {
    "OPENVPN",
    "IKEV2_IPSEC",
    "L2TP_IPSEC",
    "VTI",
    "VTI6",
}


def ensure_debian_ubuntu(remote: Remote):
    result = remote.run(
        "test -r /etc/os-release && . /etc/os-release; "
        "printf '%s' \"${ID:-unknown}\"",
        root=True,
        check=False,
    )
    os_id = result["stdout"].strip().lower()
    if os_id not in {"ubuntu", "debian"}:
        raise RuntimeError(
            "VPN_ENGINE_CURRENTLY_REQUIRES_DEBIAN_OR_UBUNTU_" + os_id
        )


def route_to_peer_command(peer_ip: str, interface_name: str) -> str:
    address = ipaddress.ip_address(peer_ip)
    if address.version == 6:
        return (
            f"ip -6 route replace {shlex.quote(peer_ip + '/128')} "
            f"dev {shlex.quote(interface_name)}"
        )
    return (
        f"ip route replace {shlex.quote(peer_ip + '/32')} "
        f"dev {shlex.quote(interface_name)}"
    )


def openvpn_identity(remote: Remote, base_dir: str, common_name: str, source_ip: str) -> dict:
    install_packages(remote, ["openvpn", "openssl", "ca-certificates"])
    try:
        source = ipaddress.ip_address(source_ip)
        san = f"IP:{source}"
    except ValueError:
        san = f"DNS:{source_ip}"

    script = f'''set -Eeuo pipefail
install -d -m 0700 {shlex.quote(base_dir)}
cd {shlex.quote(base_dir)}
cat > openssl.cnf <<'CNF'
[req]
prompt = no
distinguished_name = dn
x509_extensions = ext
[dn]
CN = {common_name}
[ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = {san}
CNF
if [ ! -s identity.key ] || [ ! -s identity.crt ]; then
  openssl req -x509 -newkey rsa:3072 -nodes \\
    -keyout identity.key -out identity.crt \\
    -days 825 -sha256 -config openssl.cnf
fi
chmod 0600 identity.key
chmod 0644 identity.crt
openssl x509 -in identity.crt -noout -fingerprint -sha256 | cut -d= -f2
'''
    result = remote.run(script, root=True, timeout=240)
    fingerprint = result["stdout"].strip().splitlines()[-1].strip()
    if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}", fingerprint):
        raise RuntimeError("OPENVPN_CERTIFICATE_FINGERPRINT_INVALID")
    return {
        "dir": base_dir,
        "key": f"{base_dir}/identity.key",
        "cert": f"{base_dir}/identity.crt",
        "fingerprint": fingerprint.upper(),
    }


def deploy_openvpn(
    run: dict,
    item: dict,
    config: dict,
    remote_a: Remote,
    remote_b: Remote,
    endpoint_a: dict,
    endpoint_b: dict,
) -> dict:
    addressing = parse_addressing(config)
    ensure_debian_ubuntu(remote_a)
    ensure_debian_ubuntu(remote_b)
    if addressing["source_a"].version != addressing["source_b"].version:
        raise RuntimeError("OPENVPN_OUTER_ADDRESS_FAMILY_MISMATCH")

    name = unit_name(run["id"], item["id"])
    interface_name = short_name("nov", run["id"], item["id"])
    base_a = f"/etc/netauto/openvpn/{name}"
    base_b = f"/etc/netauto/openvpn/{name}"

    identity_a = openvpn_identity(
        remote_a, base_a, f"{name}-a", str(addressing["source_a"])
    )
    identity_b = openvpn_identity(
        remote_b, base_b, f"{name}-b", str(addressing["source_b"])
    )

    preferred = int(config.get("port") or (11940 + item["id"] % 1000))
    port = free_port(remote_b, "udp", preferred)
    allow_firewall_port(remote_b, port, "udp")

    tls_key_path_b = f"{base_b}/tls-crypt.key"
    remote_b.run(
        f"if [ ! -s {shlex.quote(tls_key_path_b)} ]; then "
        f"openvpn --genkey tls-crypt {shlex.quote(tls_key_path_b)} "
        f"|| openvpn --genkey secret {shlex.quote(tls_key_path_b)}; fi; "
        f"chmod 0600 {shlex.quote(tls_key_path_b)}",
        root=True,
        timeout=120,
    )
    tls_key = remote_b.run(
        f"cat {shlex.quote(tls_key_path_b)}", root=True
    )["stdout"]
    tls_key_path_a = f"{base_a}/tls-crypt.key"
    write_remote_text(remote_a, tls_key_path_a, tls_key, "0600")

    address_a = addressing["address_a"]
    address_b = addressing["address_b"]
    if address_a.version == 6:
        inner_a = f"ifconfig-ipv6 {address_a.ip}/{address_a.network.prefixlen} {address_b.ip}"
        inner_b = f"ifconfig-ipv6 {address_b.ip}/{address_b.network.prefixlen} {address_a.ip}"
    else:
        inner_a = f"ifconfig {address_a.ip} {address_b.ip}"
        inner_b = f"ifconfig {address_b.ip} {address_a.ip}"

    common = "\n".join(
        [
            f"dev {interface_name}",
            "dev-type tun",
            "topology p2p",
            "persist-key",
            "persist-tun",
            "keepalive 10 60",
            "auth SHA256",
            "data-ciphers CHACHA20-POLY1305:AES-256-GCM:AES-128-GCM",
            "data-ciphers-fallback AES-256-GCM",
            "tls-version-min 1.2",
            "replay-window 256 30",
            "verb 3",
        ]
    )

    config_b = (
        common + "\nproto udp\n"
        + f"local {addressing['source_b']}\nport {port}\n"
        + "tls-server\ndh none\n"
        + f"cert {identity_b['cert']}\nkey {identity_b['key']}\n"
        + f"peer-fingerprint {identity_a['fingerprint']}\n"
        + f"tls-crypt {tls_key_path_b}\n" + inner_b + "\n"
    )
    config_a = (
        common + "\nproto udp\nnobind\ntls-client\n"
        + f"remote {addressing['source_b']} {port}\n"
        + f"cert {identity_a['cert']}\nkey {identity_a['key']}\n"
        + f"peer-fingerprint {identity_b['fingerprint']}\n"
        + f"tls-crypt {tls_key_path_a}\n" + inner_a + "\n"
    )

    config_path_a = f"{base_a}/openvpn.conf"
    config_path_b = f"{base_b}/openvpn.conf"
    write_remote_text(remote_a, config_path_a, config_a, "0600")
    write_remote_text(remote_b, config_path_b, config_b, "0600")

    service_a = f"{name}-a"
    service_b = f"{name}-b"
    try:
        persistent_service(remote_b, service_b, f"exec openvpn --config {shlex.quote(config_path_b)}")
        wait_listener(remote_b, "udp", port)
        persistent_service(remote_a, service_a, f"exec openvpn --config {shlex.quote(config_path_a)}")
        for _ in range(30):
            check = remote_a.run(ping_command(address_b.ip), root=True, check=False, timeout=12)
            if check["code"] == 0:
                break
            time.sleep(2)
        else:
            raise RuntimeError("OPENVPN_POST_TEST_A_TO_B_FAILED")
        remote_b.run(ping_command(address_a.ip), root=True, timeout=30)
    except Exception:
        remove_services(remote_a, [service_a], [base_a], [interface_name])
        remove_services(remote_b, [service_b], [base_b], [interface_name])
        raise

    return {
        "method": "OPENVPN",
        "interface_name": interface_name,
        "services_a": [service_a],
        "services_b": [service_b],
        "files_a": [base_a],
        "files_b": [base_b],
        "interfaces_a": [interface_name],
        "interfaces_b": [interface_name],
        "source_ip_a": str(addressing["source_a"]),
        "source_ip_b": str(addressing["source_b"]),
        "tunnel_cidr": str(addressing["network"]),
        "tunnel_ip_a": str(address_a),
        "tunnel_ip_b": str(address_b),
        "protocol": "udp",
        "port": port,
        "authentication": "mutual-self-signed-peer-fingerprint+tls-crypt",
    }


def install_strongswan(
    remote: Remote,
):
    ensure_debian_ubuntu(remote)

    install_packages(
        remote,
        [
            "strongswan-swanctl",
            "charon-systemd",
            "strongswan-pki",
            "libstrongswan-standard-plugins",
            "libstrongswan-extra-plugins",
            "iproute2",
            "iptables",
            "kmod",
        ],
    )

    remote.run(
        r"""
set -Eeuo pipefail

install -d -m 0700 \
    /etc/swanctl/conf.d

if [ ! -e /etc/swanctl/swanctl.conf ]; then
    : > /etc/swanctl/swanctl.conf
fi

if ! grep -Eq \
    '^[[:space:]]*include[[:space:]]+conf.d/\*\.conf' \
    /etc/swanctl/swanctl.conf
then
    printf '\ninclude conf.d/*.conf\n' \
        >> /etc/swanctl/swanctl.conf
fi

for plugin in \
    aes sha2 hmac kdf gmp
do
    test -e \
        "/usr/lib/ipsec/plugins/libstrongswan-${plugin}.so"
done

systemctl disable --now \
    strongswan-starter.service \
    2>/dev/null || true

systemctl enable \
    strongswan.service

systemctl restart \
    strongswan.service

for i in $(seq 1 60); do
    if systemctl is-active \
        --quiet strongswan.service \
        && {
            [ -S /run/charon.vici ] \
            || [ -S /var/run/charon.vici ]
        }
    then
        break
    fi

    sleep 0.5

    if [ "$i" = 60 ]; then
        systemctl status \
            strongswan.service \
            --no-pager -l >&2 || true

        journalctl \
            -u strongswan.service \
            -n 200 \
            --no-pager >&2 || true

        exit 52
    fi
done

swanctl --list-algs \
    | grep -Eqi \
    'AES|SHA2|HMAC|PRF'

swanctl --version
""",
        root=True,
        timeout=900,
    )

    allow_firewall_port(
        remote,
        500,
        "udp",
    )

    allow_firewall_port(
        remote,
        4500,
        "udp",
    )




def swanctl_psk_config(
    *,
    connection_name: str,
    child_name: str,
    local_address: str,
    remote_address: str,
    secret: str,
    start_action: str,
    mode: str = "tunnel",
    interface_id: int | None = None,
    mark: int | None = None,
    ike_version: int = 2,
    local_ts: str = "0.0.0.0/0,::/0",
    remote_ts: str = "0.0.0.0/0,::/0",
) -> str:
    child_lines = []
    if interface_id is not None:
        child_lines.extend([
            f"        if_id_in = {int(interface_id)}",
            f"        if_id_out = {int(interface_id)}",
        ])
    if mark is not None:
        child_lines.extend([
            f"        mark_in = {int(mark)}",
            f"        mark_out = {int(mark)}",
        ])
    extra = "\n" + "\n".join(child_lines) if child_lines else ""
    return f"""connections {{
  {connection_name} {{
    version = {int(ike_version)}
    local_addrs = {local_address}
    remote_addrs = {remote_address}
    proposals = aes256-sha256-modp2048
    mobike = no
    fragmentation = yes
    dpd_delay = 20s

    local-psk {{
      auth = psk
      id = "{local_address}"
    }}

    remote-psk {{
      auth = psk
      id = "{remote_address}"
    }}

    children {{
      {child_name} {{
        mode = {mode}
        local_ts = {local_ts}
        remote_ts = {remote_ts}
        esp_proposals = aes256-sha256-modp2048
        start_action = {start_action}
        close_action = restart
        dpd_action = restart
        rekey_time = 45m{extra}
      }}
    }}
  }}
}}

secrets {{
  ike-{connection_name} {{
    id-a = "{local_address}"
    id-b = "{remote_address}"
    secret = "{secret}"
  }}
}}
"""



def strongswan_start_script(
    *,
    connection_name: str,
    child_name: str,
    interface_create: str,
    interface_name: str,
    address: str,
    peer_inner: str,
    initiate: bool,
    vti: bool,
) -> str:
    interface_address = ipaddress.ip_interface(address)
    lowered = interface_create.lower()
    module_commands = []
    if " type xfrm " in (" " + lowered + " "):
        module_commands.append("modprobe xfrm_interface")
    if " type vti " in (" " + lowered + " "):
        module_commands.append("modprobe ip_vti")
    if " mode vti6 " in (" " + lowered + " "):
        module_commands.append("modprobe ip6_vti")
    lines = [
        "set -Eeuo pipefail",
        *module_commands,
        f"ip link del {shlex.quote(interface_name)} 2>/dev/null || true",
        interface_create,
        f"ip link set {shlex.quote(interface_name)} up",
        address_command(interface_name, interface_address),
    ]
    if vti:
        lines += [
            f"sysctl -w net.ipv4.conf.{interface_name}.disable_policy=1 >/dev/null 2>&1 || true",
            f"sysctl -w net.ipv4.conf.{interface_name}.rp_filter=0 >/dev/null 2>&1 || true",
        ]
    lines += [
        "swanctl --load-all --noprompt",
        (
            "swanctl --list-conns "
            f"--ike {shlex.quote(connection_name)} "
            "| grep -F "
            f"{shlex.quote(connection_name)}"
        ),
        route_to_peer_command(peer_inner, interface_name),
    ]
    if initiate:
        lines.append(
            "swanctl --initiate "
            f"--ike {shlex.quote(connection_name)} "
            f"--child {shlex.quote(child_name)}"
        )
    return "; ".join(lines)




def deploy_strongswan_route_based(method: str, run: dict, item: dict, config: dict, remote_a: Remote, remote_b: Remote, endpoint_a: dict, endpoint_b: dict) -> dict:
    addressing = parse_addressing(config)
    install_strongswan(remote_a)
    install_strongswan(remote_b)
    ensure_source(remote_a, addressing["source_a"])
    ensure_source(remote_b, addressing["source_b"])
    if method in {"IKEV2_IPSEC", "VTI"} and (addressing["source_a"].version != 4 or addressing["source_b"].version != 4):
        raise RuntimeError(method + "_REQUIRES_OUTER_IPV4")
    if method == "VTI6" and (addressing["source_a"].version != 6 or addressing["source_b"].version != 6):
        raise RuntimeError("VTI6_REQUIRES_OUTER_IPV6")

    connection_name = f"netauto-{run['id']}-{item['id']}"
    child_name = f"child-{item['id']}"
    service_name = unit_name(run["id"], item["id"])
    interface_id = 10000 + int(item["id"])
    mark = 20000 + int(item["id"])
    secret = stable_secret(run["id"], item["id"], method + "-psk", 48)

    if method == "IKEV2_IPSEC":
        interface_name = short_name("nxi", run["id"], item["id"])
        create_a = f"ip link add {interface_name} type xfrm if_id {interface_id}"
        create_b = create_a
        interface_option, mark_option, is_vti = interface_id, None, False
    elif method == "VTI":
        interface_name = short_name("nvt", run["id"], item["id"])
        create_a = f"ip link add {interface_name} type vti local {addressing['source_a']} remote {addressing['source_b']} key {mark}"
        create_b = f"ip link add {interface_name} type vti local {addressing['source_b']} remote {addressing['source_a']} key {mark}"
        interface_option, mark_option, is_vti = None, mark, True
    else:
        interface_name = short_name("nv6", run["id"], item["id"])
        create_a = f"ip -6 tunnel add {interface_name} mode vti6 local {addressing['source_a']} remote {addressing['source_b']} key {mark}"
        create_b = f"ip -6 tunnel add {interface_name} mode vti6 local {addressing['source_b']} remote {addressing['source_a']} key {mark}"
        interface_option, mark_option, is_vti = None, mark, True

    path_a = f"/etc/swanctl/conf.d/{connection_name}-a.conf"
    path_b = f"/etc/swanctl/conf.d/{connection_name}-b.conf"
    write_remote_text(remote_a, path_a, swanctl_psk_config(connection_name=connection_name, child_name=child_name, local_address=str(addressing["source_a"]), remote_address=str(addressing["source_b"]), secret=secret, start_action="start", interface_id=interface_option, mark=mark_option), "0600")
    write_remote_text(remote_b, path_b, swanctl_psk_config(connection_name=connection_name, child_name=child_name, local_address=str(addressing["source_b"]), remote_address=str(addressing["source_a"]), secret=secret, start_action="trap", interface_id=interface_option, mark=mark_option), "0600")

    start_b = strongswan_start_script(connection_name=connection_name, child_name=child_name, interface_create=create_b, interface_name=interface_name, address=str(addressing["address_b"]), peer_inner=str(addressing["address_a"].ip), initiate=False, vti=is_vti)
    start_a = strongswan_start_script(connection_name=connection_name, child_name=child_name, interface_create=create_a, interface_name=interface_name, address=str(addressing["address_a"]), peer_inner=str(addressing["address_b"].ip), initiate=True, vti=is_vti)
    stop_a = f"swanctl --terminate --ike {shlex.quote(connection_name)} 2>/dev/null || true; rm -f {shlex.quote(path_a)}; swanctl --load-all >/dev/null 2>&1 || true; ip link del {shlex.quote(interface_name)} 2>/dev/null || true"
    stop_b = f"swanctl --terminate --ike {shlex.quote(connection_name)} 2>/dev/null || true; rm -f {shlex.quote(path_b)}; swanctl --load-all >/dev/null 2>&1 || true; ip link del {shlex.quote(interface_name)} 2>/dev/null || true"

    try:
        oneshot_service(remote_b, service_name, start_b, stop_b)
        oneshot_service(remote_a, service_name, start_a, stop_a)
        for _ in range(30):
            sas = remote_a.run(f"swanctl --list-sas --ike {shlex.quote(connection_name)}", root=True, check=False)
            if "ESTABLISHED" in sas["stdout"]:
                break
            time.sleep(2)
        else:
            raise RuntimeError(method + "_IKE_SA_NOT_ESTABLISHED")
        remote_a.run(ping_command(addressing["address_b"].ip), root=True, timeout=30)
        remote_b.run(ping_command(addressing["address_a"].ip), root=True, timeout=30)
    except Exception:
        remove_services(remote_a, [service_name], [path_a], [interface_name])
        remove_services(remote_b, [service_name], [path_b], [interface_name])
        raise

    return {
        "method": method,
        "interface_name": interface_name,
        "services_a": [service_name],
        "services_b": [service_name],
        "files_a": [path_a],
        "files_b": [path_b],
        "interfaces_a": [interface_name],
        "interfaces_b": [interface_name],
        "source_ip_a": str(addressing["source_a"]),
        "source_ip_b": str(addressing["source_b"]),
        "tunnel_cidr": str(addressing["network"]),
        "tunnel_ip_a": str(addressing["address_a"]),
        "tunnel_ip_b": str(addressing["address_b"]),
        "ike_version": 2,
        "authentication": "high-entropy-psk",
        "xfrm_interface_id": interface_id if method == "IKEV2_IPSEC" else None,
        "vti_mark": mark if method in {"VTI", "VTI6"} else None,
    }


def append_managed_chap_secret(remote: Remote, marker: str, username: str, password: str, server_name: str, ip_value: str):
    line = f'{username} {server_name} "{password}" {ip_value} # {marker}'
    remote.run(
        "touch /etc/ppp/chap-secrets; chmod 0600 /etc/ppp/chap-secrets; "
        f"sed -i '/{re.escape(marker)}/d' /etc/ppp/chap-secrets; "
        f"printf '%s\\n' {shlex.quote(line)} >> /etc/ppp/chap-secrets",
        root=True,
    )


def deploy_l2tp_ipsec(run: dict, item: dict, config: dict, remote_a: Remote, remote_b: Remote, endpoint_a: dict, endpoint_b: dict) -> dict:
    addressing = parse_addressing(config)
    if addressing["source_a"].version != 4 or addressing["source_b"].version != 4:
        raise RuntimeError("L2TP_IPSEC_REQUIRES_OUTER_IPV4")
    if addressing["address_a"].version != 4 or addressing["address_b"].version != 4:
        raise RuntimeError("L2TP_IPSEC_REQUIRES_INNER_IPV4")

    sides = choose_sides(item, remote_a, remote_b, endpoint_a, endpoint_b)
    client, server = sides["client"], sides["server"]
    client_is_a = client is remote_a
    client_source = str(addressing["source_a"] if client_is_a else addressing["source_b"])
    server_source = str(addressing["source_b"] if client_is_a else addressing["source_a"])
    client_inner = str(addressing["address_a"].ip if client_is_a else addressing["address_b"].ip)
    server_inner = str(addressing["address_b"].ip if client_is_a else addressing["address_a"].ip)

    install_strongswan(client); install_strongswan(server)
    install_packages(client, ["xl2tpd", "ppp"]); install_packages(server, ["xl2tpd", "ppp"])
    for side in (client, server):
        side.run(
            (
                "systemctl disable --now "
                "xl2tpd.service "
                "2>/dev/null || true; "
                "pkill -x xl2tpd "
                "2>/dev/null || true; "
                "rm -f /run/xl2tpd/"
                "xl2tpd.pid "
                "/var/run/xl2tpd/"
                "xl2tpd.pid"
            ),
            root=True,
            check=False,
            timeout=60,
        )

    busy = server.run("ss -H -lun | grep -Eq '[:.]1701[[:space:]]'", root=True, check=False)
    if busy["code"] == 0:
        raise RuntimeError("L2TP_UDP_1701_ALREADY_IN_USE_ON_SERVER")

    name = f"netauto-{run['id']}-{item['id']}"
    service_name = unit_name(run["id"], item["id"])
    marker = f"NETAUTO_L2TP_{run['id']}_{item['id']}"
    username = "na" + stable_secret(run["id"], item["id"], "l2tp-user", 10)
    password = stable_secret(run["id"], item["id"], "l2tp-password", 32)
    psk = stable_secret(run["id"], item["id"], "l2tp-psk", 48)
    server_name = "netauto-l2tp"
    base_client = f"/etc/netauto/l2tp/{name}"
    base_server = f"/etc/netauto/l2tp/{name}"
    conf_ipsec_client = f"/etc/swanctl/conf.d/{name}-client.conf"
    conf_ipsec_server = f"/etc/swanctl/conf.d/{name}-server.conf"

    write_remote_text(client, conf_ipsec_client, swanctl_psk_config(connection_name=name, child_name="l2tp", local_address=client_source, remote_address=server_source, secret=psk, start_action="start", mode="transport", ike_version=1, local_ts="dynamic[udp/1701]", remote_ts="dynamic[udp/1701]"), "0600")
    write_remote_text(server, conf_ipsec_server, swanctl_psk_config(connection_name=name, child_name="l2tp", local_address=server_source, remote_address=client_source, secret=psk, start_action="trap", mode="transport", ike_version=1, local_ts="dynamic[udp/1701]", remote_ts="dynamic[udp/1701]"), "0600")

    server_ppp = f"name {server_name}\nauth\nrequire-mschap-v2\nrefuse-pap\nrefuse-chap\nrefuse-mschap\nmtu 1400\nmru 1400\nproxyarp\nlcp-echo-interval 20\nlcp-echo-failure 4\nlock\n"
    client_ppp = f"name {username}\npassword {password}\nnoauth\nrefuse-eap\nrefuse-pap\nrefuse-chap\nrefuse-mschap\nmtu 1400\nmru 1400\nipcp-accept-local\nipcp-accept-remote\nlcp-echo-interval 20\nlcp-echo-failure 4\npersist\n"
    server_xl2tp = f"[global]\nport = 1701\n\n[lns {name}]\nip range = {client_inner}-{client_inner}\nlocal ip = {server_inner}\nrequire authentication = yes\nrequire chap = yes\nrefuse pap = yes\nname = {server_name}\npppoptfile = {base_server}/ppp.options\nlength bit = yes\n"
    client_xl2tp = f"[global]\nport = 1701\n\n[lac {name}]\nlns = {server_source}\nredial = yes\nredial timeout = 5\nmax redials = 6\npppoptfile = {base_client}/ppp.options\nname = {username}\nrequire chap = yes\n"
    write_remote_text(server, f"{base_server}/ppp.options", server_ppp, "0600")
    write_remote_text(client, f"{base_client}/ppp.options", client_ppp, "0600")
    write_remote_text(server, f"{base_server}/xl2tpd.conf", server_xl2tp, "0600")
    write_remote_text(client, f"{base_client}/xl2tpd.conf", client_xl2tp, "0600")
    append_managed_chap_secret(server, marker, username, password, server_name, client_inner)
    allow_firewall_port(server, 1701, "udp")

    start_server = f"set -Eeuo pipefail; swanctl --load-all; xl2tpd -D -c {shlex.quote(base_server + '/xl2tpd.conf')} -p {shlex.quote(base_server + '/xl2tpd.pid')} -C {shlex.quote(base_server + '/control')} > {shlex.quote(base_server + '/xl2tpd.log')} 2>&1 & echo $! > {shlex.quote(base_server + '/launcher.pid')}; for i in $(seq 1 30); do [ -p {shlex.quote(base_server + '/control')} ] && exit 0; sleep 1; done; exit 42"
    start_client = f"set -Eeuo pipefail; swanctl --load-all; swanctl --initiate --ike {shlex.quote(name)} --child l2tp; xl2tpd -D -c {shlex.quote(base_client + '/xl2tpd.conf')} -p {shlex.quote(base_client + '/xl2tpd.pid')} -C {shlex.quote(base_client + '/control')} > {shlex.quote(base_client + '/xl2tpd.log')} 2>&1 & echo $! > {shlex.quote(base_client + '/launcher.pid')}; for i in $(seq 1 30); do [ -p {shlex.quote(base_client + '/control')} ] && break; sleep 1; done; printf 'c {name}\\n' > {shlex.quote(base_client + '/control')}"
    stop_server = f"[ -f {shlex.quote(base_server + '/launcher.pid')} ] && kill $(cat {shlex.quote(base_server + '/launcher.pid')}) 2>/dev/null || true; sed -i '/{marker}/d' /etc/ppp/chap-secrets; rm -f {shlex.quote(conf_ipsec_server)}; swanctl --load-all >/dev/null 2>&1 || true"
    stop_client = f"[ -f {shlex.quote(base_client + '/launcher.pid')} ] && kill $(cat {shlex.quote(base_client + '/launcher.pid')}) 2>/dev/null || true; swanctl --terminate --ike {shlex.quote(name)} 2>/dev/null || true; rm -f {shlex.quote(conf_ipsec_client)}; swanctl --load-all >/dev/null 2>&1 || true"

    try:
        oneshot_service(server, service_name, start_server, stop_server)
        oneshot_service(client, service_name, start_client, stop_client)
        for _ in range(45):
            result = client.run(f"ip -o -4 addr show | grep -F {shlex.quote(client_inner + '/')} ", root=True, check=False)
            if result["code"] == 0:
                break
            time.sleep(2)
        else:
            logs = client.run(f"tail -100 {shlex.quote(base_client + '/xl2tpd.log')}", root=True, check=False)
            raise RuntimeError("L2TP_PPP_INTERFACE_NOT_READY: " + logs["stdout"][-1200:])
        client.run(f"ping -c 3 -W 4 {shlex.quote(server_inner)}", root=True, timeout=30)
        server.run(f"ping -c 3 -W 4 {shlex.quote(client_inner)}", root=True, timeout=30)
    except Exception:
        remove_services(client, [service_name], [base_client, conf_ipsec_client], [])
        remove_services(server, [service_name], [base_server, conf_ipsec_server], [])
        server.run(f"sed -i '/{marker}/d' /etc/ppp/chap-secrets", root=True, check=False)
        raise

    return {
        "method": "L2TP_IPSEC",
        "services_a": [service_name],
        "services_b": [service_name],
        "files_a": [base_client, conf_ipsec_client] if client_is_a else [base_server, conf_ipsec_server],
        "files_b": [base_server, conf_ipsec_server] if client_is_a else [base_client, conf_ipsec_client],
        "source_ip_a": str(addressing["source_a"]),
        "source_ip_b": str(addressing["source_b"]),
        "tunnel_cidr": str(addressing["network"]),
        "tunnel_ip_a": str(addressing["address_a"]),
        "tunnel_ip_b": str(addressing["address_b"]),
        "ike_version": 1,
        "l2tp_port": 1701,
        "authentication": "IPsec high-entropy PSK + MSCHAPv2",
        "single_instance_per_endpoint": True,
        "warning": "L2TP/IPsec is a legacy compatibility method; prefer IKEv2/IPsec or WireGuard when possible.",
        "cleanup_commands_a": [f"sed -i '/{marker}/d' /etc/ppp/chap-secrets"] if not client_is_a else [],
        "cleanup_commands_b": [f"sed -i '/{marker}/d' /etc/ppp/chap-secrets"] if client_is_a else [],
    }


def deploy_vpn_method(method: str, run: dict, item: dict, config: dict, remote_a: Remote, remote_b: Remote, endpoint_a: dict, endpoint_b: dict) -> dict:
    if method == "OPENVPN":
        return deploy_openvpn(run, item, config, remote_a, remote_b, endpoint_a, endpoint_b)
    if method in {"IKEV2_IPSEC", "VTI", "VTI6"}:
        return deploy_strongswan_route_based(method, run, item, config, remote_a, remote_b, endpoint_a, endpoint_b)
    if method == "L2TP_IPSEC":
        return deploy_l2tp_ipsec(run, item, config, remote_a, remote_b, endpoint_a, endpoint_b)
    raise RuntimeError("VPN_METHOD_NOT_IMPLEMENTED")

XRAY_METHODS = {
    "VLESS_TCP", "VLESS_WS", "VLESS_GRPC", "VLESS_XHTTP",
    "VLESS_REALITY", "VLESS_VISION_REALITY", "VLESS_XHTTP_REALITY",
}
SINGBOX_METHODS = {"HYSTERIA2", "TUIC", "TROJAN_TLS", "SHADOWSOCKS", "SINGBOX_TUN"}
MODERN_PROXY_METHODS = XRAY_METHODS | SINGBOX_METHODS


def stable_uuid(run_id: int, item_id: int, label: str) -> str:
    namespace = uuid.UUID("c83ca37b-c82f-43d4-a427-491f5b4cc1c9")
    return str(uuid.uuid5(namespace, f"{APP_SECRET_KEY}:{run_id}:{item_id}:{label}"))


def stable_base64(run_id: int, item_id: int, label: str, length: int) -> str:
    raw = hashlib.sha256(f"{APP_SECRET_KEY}:{run_id}:{item_id}:{label}".encode()).digest()[:length]
    return base64.b64encode(raw).decode()


def install_xray(remote: Remote):
    script = r'''set -Eeuo pipefail
if command -v xray >/dev/null 2>&1; then xray version | head -n1; exit 0; fi
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a DEBCONF_NONINTERACTIVE_SEEN=true
apt-get update
apt-get install -y ca-certificates python3 unzip
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
python3 - "$TMP_DIR" <<'PYDL'
import json, platform, shutil, sys, urllib.request, zipfile
from pathlib import Path
out=Path(sys.argv[1]); machine=platform.machine().lower()
assets={
 "x86_64":"Xray-linux-64.zip","amd64":"Xray-linux-64.zip",
 "aarch64":"Xray-linux-arm64-v8a.zip","arm64":"Xray-linux-arm64-v8a.zip",
 "armv7l":"Xray-linux-arm32-v7a.zip","armv7":"Xray-linux-arm32-v7a.zip",
}
wanted=assets.get(machine)
if not wanted: raise SystemExit(f"XRAY_UNSUPPORTED_ARCHITECTURE: {machine}")
req=urllib.request.Request("https://api.github.com/repos/XTLS/Xray-core/releases/latest",headers={"Accept":"application/vnd.github+json","User-Agent":"TehranNetwork-Automation"})
with urllib.request.urlopen(req,timeout=30) as r: release=json.load(r)
asset=next((a for a in release.get("assets",[]) if a.get("name")==wanted),None)
if not asset: raise SystemExit(f"XRAY_ASSET_NOT_FOUND: {wanted}")
archive=out/wanted
with urllib.request.urlopen(urllib.request.Request(asset["browser_download_url"],headers={"User-Agent":"TehranNetwork-Automation"}),timeout=120) as r: archive.write_bytes(r.read())
with zipfile.ZipFile(archive) as z: z.extractall(out/"extract")
binary=out/"extract"/"xray"
if not binary.is_file(): raise SystemExit("XRAY_BINARY_NOT_FOUND")
shutil.copy2(binary,"/usr/local/bin/xray"); Path("/usr/local/bin/xray").chmod(0o755)
print(release.get("tag_name","unknown"))
PYDL
xray version | head -n1
'''
    return remote.run(script, root=True, timeout=600)["stdout"].strip()


def install_singbox(remote: Remote):
    return install_release_binary(remote, repo="SagerNet/sing-box", binaries=["sing-box"], asset_family="sing-box")


def install_ca_trust(remote: Remote, name: str, ca_path: str):
    target=f"/usr/local/share/ca-certificates/netauto-{name}.crt"
    remote.run(f"install -m 0644 {shlex.quote(ca_path)} {shlex.quote(target)}; update-ca-certificates >/dev/null",root=True,timeout=180)
    return target


def validate_json_service(remote: Remote, binary: str, config_path: str):
    command=(f"xray run -test -config {shlex.quote(config_path)}" if binary=="xray" else f"sing-box check -c {shlex.quote(config_path)}")
    remote.run(command,root=True,timeout=120)


def proxy_throughput_test(
    client: Remote,
    server: Remote,
    socks_port: int,
    name: str,
    size_mb: int,
) -> dict:
    safe_size = max(
        1,
        min(int(size_mb), 64),
    )

    seed = sum(
        ord(char)
        for char in str(name)
    )

    http_port = free_port(
        server,
        "tcp",
        38000 + seed % 12000,
    )

    safe_name = re.sub(
        r"[^a-zA-Z0-9_.-]+",
        "-",
        str(name),
    )[:48]

    unit = (
        f"netauto-proxytest-"
        f"{safe_name}-"
        f"{http_port}"
    )[:120]

    directory = (
        f"/tmp/netauto-proxy-test-"
        f"{safe_name}-{http_port}"
    )

    payload = (
        f"{directory}/payload.bin"
    )

    install_packages(
        server,
        ["python3", "coreutils"],
    )

    install_packages(
        client,
        ["curl", "ca-certificates"],
    )

    server.run(
        (
            "set -Eeuo pipefail; "
            f"systemctl stop "
            f"{shlex.quote(unit)}.service "
            "2>/dev/null || true; "
            f"rm -rf {shlex.quote(directory)}; "
            f"install -d -m 0700 "
            f"{shlex.quote(directory)}; "
            f"dd if=/dev/zero "
            f"of={shlex.quote(payload)} "
            "bs=1M "
            f"count={safe_size} "
            "status=none; "
            f"systemd-run "
            f"--unit={shlex.quote(unit)} "
            "--collect "
            "--property=Type=simple "
            "--property=Restart=no "
            "/usr/bin/python3 "
            "-m http.server "
            f"{int(http_port)} "
            "--bind 127.0.0.1 "
            f"--directory "
            f"{shlex.quote(directory)} "
            ">/dev/null"
        ),
        root=True,
        timeout=180,
    )

    server.run(
        (
            "for i in $(seq 1 50); do "
            "ss -H -ltn "
            "| awk '{print $4}' "
            f"| grep -Eq ':"
            f"{int(http_port)}$' "
            "&& exit 0; "
            "sleep 0.2; "
            "done; "
            f"systemctl status "
            f"{shlex.quote(unit)}.service "
            "--no-pager -l >&2 || true; "
            f"journalctl -u "
            f"{shlex.quote(unit)}.service "
            "-n 100 --no-pager >&2 "
            "|| true; "
            "exit 42"
        ),
        root=True,
        timeout=30,
    )

    try:
        result = client.run(
            (
                "curl "
                "--fail "
                "--silent "
                "--show-error "
                "--max-time 180 "
                "--retry 2 "
                "--retry-delay 1 "
                "--socks5-hostname "
                f"127.0.0.1:{int(socks_port)} "
                "--output /dev/null "
                "--write-out "
                "'%{http_code}\\t"
                "%{size_download}\\t"
                "%{speed_download}\\t"
                "%{time_total}' "
                f"http://127.0.0.1:"
                f"{int(http_port)}/payload.bin"
            ),
            root=True,
            timeout=210,
        )

        values = (
            result["stdout"]
            .strip()
            .split("\\t")
        )

        if len(values) != 4:
            raise RuntimeError(
                "PROXY_BENCHMARK_OUTPUT_INVALID: "
                + result["stdout"][-1000:]
            )

        http_code = int(values[0])
        downloaded = float(values[1])
        bytes_per_second = float(
            values[2]
        )
        duration = float(values[3])

        if http_code != 200:
            raise RuntimeError(
                "PROXY_BENCHMARK_HTTP_"
                + str(http_code)
            )

        if downloaded < (
            safe_size
            * 1024
            * 1024
            * 0.95
        ):
            raise RuntimeError(
                "PROXY_BENCHMARK_SHORT_DOWNLOAD"
            )

        return {
            "http_code": http_code,
            "size_mb": round(
                downloaded
                / 1024
                / 1024,
                3,
            ),
            "duration_seconds": round(
                duration,
                3,
            ),
            "throughput_mbps": round(
                bytes_per_second
                * 8
                / 1_000_000,
                3,
            ),
            "test_target": (
                "remote-loopback-http"
            ),
        }

    finally:
        server.run(
            (
                f"systemctl stop "
                f"{shlex.quote(unit)}.service "
                "2>/dev/null || true; "
                f"rm -rf "
                f"{shlex.quote(directory)}"
            ),
            root=True,
            check=False,
            timeout=60,
        )



def xray_stream_settings(
    method: str,
    tls: dict | None,
    reality: dict | None,
    path: str,
    service_name: str,
) -> dict:
    if method in {
        "VLESS_TCP",
        "VLESS_REALITY",
        "VLESS_VISION_REALITY",
    }:
        transport = "raw"
        key = "rawSettings"
        value = {}

    elif method == "VLESS_WS":
        transport = "websocket"
        key = "wsSettings"
        value = {"path": path}

    elif method == "VLESS_GRPC":
        transport = "grpc"
        key = "grpcSettings"
        value = {
            "serviceName": service_name,
        }

    else:
        transport = "xhttp"
        key = "xhttpSettings"
        value = {
            "path": path,
            "mode": "auto",
        }

    stream = {
        "network": transport,
        "security": "none",
        key: value,
    }

    if reality:
        stream.update(
            {
                "security": "reality",
                "realitySettings": reality,
            }
        )

    elif tls:
        stream.update(
            {
                "security": "tls",
                "tlsSettings": tls,
            }
        )

    return stream



def generate_xray_reality(
    server: Remote,
    target: str,
    short_id: str,
) -> tuple[dict, dict]:
    result = server.run(
        "xray x25519",
        root=True,
        timeout=60,
    )["stdout"]

    private = re.search(
        (
            r"Private(?:\s+key|Key)"
            r"\s*:\s*(\S+)"
        ),
        result,
        flags=re.IGNORECASE,
    )

    public = re.search(
        (
            r"(?:"
            r"Public(?:\s+key|Key)"
            r"|Password"
            r"(?:\s*\(\s*PublicKey\s*\))?"
            r")"
            r"\s*:\s*(\S+)"
        ),
        result,
        flags=re.IGNORECASE,
    )

    if not private or not public:
        raise RuntimeError(
            "XRAY_REALITY_KEY_GENERATION_FAILED: "
            + result[-1200:]
        )

    host = (
        target
        .rsplit(":", 1)[0]
        .strip("[]")
    )

    return (
        {
            "show": False,
            "target": target,
            "xver": 0,
            "serverNames": [host],
            "privateKey": (
                private.group(1)
            ),
            "shortIds": [short_id],
        },
        {
            "fingerprint": "chrome",
            "serverName": host,
            "password": (
                public.group(1)
            ),
            "shortId": short_id,
            "spiderX": "/",
        },
    )




def deploy_xray_method(
    method: str,
    run: dict,
    item: dict,
    config: dict,
    remote_a: Remote,
    remote_b: Remote,
    endpoint_a: dict,
    endpoint_b: dict,
) -> dict:
    sides = choose_sides(
        item,
        remote_a,
        remote_b,
        endpoint_a,
        endpoint_b,
    )

    client = sides["client"]
    server = sides["server"]
    server_endpoint = sides["server_endpoint"]

    install_xray(client)
    install_xray(server)

    name = (
        f"xray-{run['id']}-{item['id']}"
    )

    base_client = (
        f"/etc/netauto/xray/{name}"
    )
    base_server = (
        f"/etc/netauto/xray/{name}"
    )

    cpath = f"{base_client}/client.json"
    spath = f"{base_server}/server.json"

    server_host = endpoint_source(
        config,
        sides["server_side"],
        server_endpoint,
    )

    server_port = free_port(
        server,
        "tcp",
        int(
            config.get("port")
            or (
                24000
                + item["id"] % 10000
            )
        ),
    )

    socks_port = free_port(
        client,
        "tcp",
        int(
            config.get("socks_port")
            or (
                10800
                + item["id"] % 4000
            )
        ),
    )

    user_id = stable_uuid(
        run["id"],
        item["id"],
        "vless",
    )

    path = (
        "/"
        + stable_secret(
            run["id"],
            item["id"],
            "path",
            20,
        )
    )

    grpc_name = (
        "svc-"
        + stable_secret(
            run["id"],
            item["id"],
            "grpc",
            16,
        )
    )

    flow = (
        "xtls-rprx-vision"
        if method
        == "VLESS_VISION_REALITY"
        else ""
    )

    server_tls = None
    client_tls = None
    server_reality = None
    client_reality = None

    reality_methods = {
        "VLESS_REALITY",
        "VLESS_VISION_REALITY",
        "VLESS_XHTTP_REALITY",
    }

    if method in reality_methods:
        (
            server_reality,
            client_reality,
        ) = generate_xray_reality(
            server,
            str(
                config.get(
                    "reality_target"
                )
                or "www.microsoft.com:443"
            ),
            stable_secret(
                run["id"],
                item["id"],
                "short-id",
                16,
            ),
        )

    else:
        tls = prepare_tls_pair(
            server,
            client,
            name=name,
            server_host=server_host,
            pfx_password=stable_secret(
                run["id"],
                item["id"],
                "pfx",
                24,
            ),
        )

        install_ca_trust(
            client,
            name,
            tls["client_ca"],
        )

        server_tls = {
            "serverName": server_host,
            "minVersion": "1.2",
            "certificates": [
                {
                    "certificateFile": (
                        tls["server_cert"]
                    ),
                    "keyFile": (
                        tls["server_key"]
                    ),
                }
            ],
        }

        client_tls = {
            "serverName": server_host,
            "minVersion": "1.2",
            "allowInsecure": False,
        }

    server_user = {
        "id": user_id,
        "level": 0,
        "email": (
            f"{name}@netauto.local"
        ),
    }

    client_settings = {
        "address": server_host,
        "port": server_port,
        "id": user_id,
        "encryption": "none",
        "level": 0,
    }

    if flow:
        server_user["flow"] = flow
        client_settings["flow"] = flow

    version_output = server.run(
        "xray version | head -n1",
        root=True,
        timeout=60,
    )["stdout"]

    version_match = re.search(
        r"Xray\s+(\d+)\.(\d+)\.(\d+)",
        version_output,
    )

    if not version_match:
        raise RuntimeError(
            "XRAY_VERSION_PARSE_FAILED: "
            + version_output[-500:]
        )

    xray_version = tuple(
        int(value)
        for value in version_match.groups()
    )

    inbound_user_key = (
        "users"
        if xray_version >= (26, 5, 9)
        else "clients"
    )

    server_config = {
        "log": {
            "loglevel": "warning",
        },
        "inbounds": [
            {
                "listen": server_host,
                "port": server_port,
                "protocol": "vless",
                "settings": {
                    inbound_user_key: [server_user],
                    "decryption": "none",
                },
                "streamSettings": (
                    xray_stream_settings(
                        method,
                        server_tls,
                        server_reality,
                        path,
                        grpc_name,
                    )
                ),
            }
        ],
        "outbounds": [
            {
                "protocol": "freedom",
                "tag": "direct",
            }
        ],
    }

    # Xray 26.x uses the flat VLESS outbound
    # settings object.  The old vnext array is
    # no longer used here because it can result
    # in a different effective user ID.
    client_config = {
        "log": {
            "loglevel": "warning",
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                },
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": (
                    client_settings
                ),
                "streamSettings": (
                    xray_stream_settings(
                        method,
                        client_tls,
                        client_reality,
                        path,
                        grpc_name,
                    )
                ),
            }
        ],
    }

    write_remote_text(
        server,
        spath,
        json.dumps(
            server_config,
            indent=2,
        ),
        "0600",
    )

    write_remote_text(
        client,
        cpath,
        json.dumps(
            client_config,
            indent=2,
        ),
        "0600",
    )

    validate_json_service(
        server,
        "xray",
        spath,
    )

    validate_json_service(
        client,
        "xray",
        cpath,
    )

    server_hash = server.run(
        (
            "python3 - "
            + shlex.quote(spath)
            + " <<'PYID'\n"
            "import hashlib,json,sys\n"
            "data=json.load(open(sys.argv[1]))\n"
            "value=data['inbounds'][0]"
            "['settings'][inbound_user_key][0]['id']\n"
            "print(hashlib.sha256("
            "str(value).encode()).hexdigest())\n"
            "PYID"
        ),
        root=True,
        timeout=60,
    )["stdout"].strip()

    client_hash = client.run(
        (
            "python3 - "
            + shlex.quote(cpath)
            + " <<'PYID'\n"
            "import hashlib,json,sys\n"
            "data=json.load(open(sys.argv[1]))\n"
            "value=data['outbounds'][0]"
            "['settings']['id']\n"
            "print(hashlib.sha256("
            "str(value).encode()).hexdigest())\n"
            "PYID"
        ),
        root=True,
        timeout=60,
    )["stdout"].strip()

    if (
        not server_hash
        or server_hash != client_hash
    ):
        remove_services(
            client,
            [],
            [base_client],
        )
        remove_services(
            server,
            [],
            [base_server],
        )
        raise RuntimeError(
            "XRAY_USER_ID_CONFIG_MISMATCH"
        )

    server_service = (
        f"netauto-{name}-server"
    )
    client_service = (
        f"netauto-{name}-client"
    )

    try:
        allow_firewall_port(
            server,
            server_port,
            "tcp",
        )

        persistent_service(
            server,
            server_service,
            (
                "exec xray run -config "
                + shlex.quote(spath)
            ),
        )

        wait_listener(
            server,
            "tcp",
            server_port,
        )

        persistent_service(
            client,
            client_service,
            (
                "exec xray run -config "
                + shlex.quote(cpath)
            ),
        )

        wait_listener(
            client,
            "tcp",
            socks_port,
        )

        benchmark = proxy_throughput_test(
            client,
            server,
            socks_port,
            name,
            int(
                config.get(
                    "benchmark_size_mb"
                )
                or 16
            ),
        )

    except Exception:
        remove_services(
            client,
            [client_service],
            [base_client],
        )

        remove_services(
            server,
            [server_service],
            [base_server],
        )

        raise

    artifact = {
        "method": method,
        "engine": "xray",
        "client_side": (
            sides["client_side"]
        ),
        "server_side": (
            sides["server_side"]
        ),
        "server_host": server_host,
        "server_port": server_port,
        "local_socks_host": (
            "127.0.0.1"
        ),
        "local_socks_port": socks_port,
        "transport_path": (
            path
            if method
            in {
                "VLESS_WS",
                "VLESS_XHTTP",
                "VLESS_XHTTP_REALITY",
            }
            else None
        ),
        "grpc_service_name": (
            grpc_name
            if method == "VLESS_GRPC"
            else None
        ),
        "flow": flow or None,
        "services_a": (
            [client_service]
            if sides["client_side"] == "A"
            else [server_service]
        ),
        "services_b": (
            [server_service]
            if sides["server_side"] == "B"
            else [client_service]
        ),
        "files_a": (
            [base_client]
            if sides["client_side"] == "A"
            else [base_server]
        ),
        "files_b": (
            [base_server]
            if sides["server_side"] == "B"
            else [base_client]
        ),
        "proxy_benchmark": benchmark,
        "certificate_validation": (
            method not in reality_methods
        ),
        "reality": (
            method in reality_methods
        ),
        "xray_outbound_schema": (
            "flat-vless-26x"
        ),
    }

    if method == "VLESS_REALITY":
        artifact["warning"] = (
            "VLESS REALITY without Vision "
            "is retained for compatibility; "
            "Vision REALITY is preferred for "
            "new deployments."
        )

    return artifact



def singbox_tls_pair(server: Remote, client: Remote, name: str, server_host: str, run: dict, item: dict) -> dict:
    tls=prepare_tls_pair(server,client,name=name,server_host=server_host,pfx_password=stable_secret(run["id"],item["id"],"singbox-pfx",24))
    return {"server":{"enabled":True,"server_name":server_host,"min_version":"1.2","certificate_path":tls["server_cert"],"key_path":tls["server_key"]},"client":{"enabled":True,"server_name":server_host,"min_version":"1.2","certificate_path":tls["client_ca"]}}


def deploy_singbox_method(method: str, run: dict, item: dict, config: dict, remote_a: Remote, remote_b: Remote, endpoint_a: dict, endpoint_b: dict) -> dict:
    sides=choose_sides(item,remote_a,remote_b,endpoint_a,endpoint_b); client=sides["client"]; server=sides["server"]; server_endpoint=sides["server_endpoint"]
    install_singbox(client); install_singbox(server)
    name=f"singbox-{run['id']}-{item['id']}"; base_client=f"/etc/netauto/sing-box/{name}"; base_server=f"/etc/netauto/sing-box/{name}"; cpath=f"{base_client}/client.json"; spath=f"{base_server}/server.json"
    server_host=endpoint_source(config,sides["server_side"],server_endpoint); protocol="udp" if method in {"HYSTERIA2","TUIC"} else "tcp"
    server_port=free_port(server,protocol,int(config.get("port") or (26000+item["id"]%10000))); socks_port=free_port(client,"tcp",int(config.get("socks_port") or (11800+item["id"]%4000)))
    tls=singbox_tls_pair(server,client,name,server_host,run,item) if method in {"HYSTERIA2","TUIC","TROJAN_TLS"} else None; warning=None; tun_interface=None
    if method=="HYSTERIA2":
        password=stable_secret(run["id"],item["id"],"hy2-password",32); obfs=stable_secret(run["id"],item["id"],"hy2-obfs",32); up=int(config.get("up_mbps") or 200); down=int(config.get("down_mbps") or 200)
        sin={"type":"hysteria2","tag":"proxy-in","listen":server_host,"listen_port":server_port,"up_mbps":up,"down_mbps":down,"obfs":{"type":"salamander","password":obfs},"users":[{"name":name,"password":password}],"tls":tls["server"],"masquerade":{"type":"string","status_code":404,"content":"Not Found"}}
        cout={"type":"hysteria2","tag":"proxy-out","server":server_host,"server_port":server_port,"up_mbps":up,"down_mbps":down,"obfs":{"type":"salamander","password":obfs},"password":password,"tls":tls["client"]}
    elif method=="TUIC":
        uid=stable_uuid(run["id"],item["id"],"tuic"); password=stable_secret(run["id"],item["id"],"tuic-password",32); congestion=str(config.get("congestion_control") or "bbr")
        sin={"type":"tuic","tag":"proxy-in","listen":server_host,"listen_port":server_port,"users":[{"name":name,"uuid":uid,"password":password}],"congestion_control":congestion,"zero_rtt_handshake":False,"heartbeat":"10s","tls":tls["server"]}
        cout={"type":"tuic","tag":"proxy-out","server":server_host,"server_port":server_port,"uuid":uid,"password":password,"congestion_control":congestion,"udp_relay_mode":"native","zero_rtt_handshake":False,"heartbeat":"10s","tls":tls["client"]}
    elif method=="TROJAN_TLS":
        password=stable_secret(run["id"],item["id"],"trojan-password",32)
        sin={"type":"trojan","tag":"proxy-in","listen":server_host,"listen_port":server_port,"users":[{"name":name,"password":password}],"tls":tls["server"]}
        cout={"type":"trojan","tag":"proxy-out","server":server_host,"server_port":server_port,"password":password,"tls":tls["client"]}
    else:
        key=stable_base64(run["id"],item["id"],"shadowsocks-2022",16)
        sin={"type":"shadowsocks","tag":"proxy-in","listen":server_host,"listen_port":server_port,"network":"tcp","method":"2022-blake3-aes-128-gcm","password":key,"multiplex":{"enabled":True}}
        cout={"type":"shadowsocks","tag":"proxy-out","server":server_host,"server_port":server_port,"method":"2022-blake3-aes-128-gcm","password":key,"multiplex":{"enabled":True}}
        warning="Shadowsocks AEAD 2022 with TCP multiplexing is enabled; use TLS/REALITY methods when ordinary HTTPS appearance is required."
    sconfig={"log":{"level":"warn"},"inbounds":[sin],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
    if method=="SINGBOX_TUN":
        route_cidrs=config.get("route_cidrs") or config.get("route_address")
        if isinstance(route_cidrs,str): route_cidrs=[v.strip() for v in route_cidrs.split(",") if v.strip()]
        if not route_cidrs: raise RuntimeError("SINGBOX_TUN_REQUIRES_EXPLICIT_ROUTE_CIDRS")
        for value in route_cidrs: ipaddress.ip_network(value,strict=False)
        tun_interface=short_name("nsb",run["id"],item["id"]); tun_address=str(config.get("tun_address") or "172.31.255.1/30"); ipaddress.ip_interface(tun_address)
        cin={"type":"tun","tag":"tun-in","interface_name":tun_interface,"address":[tun_address],"mtu":int(config.get("mtu") or 1400),"auto_route":True,"auto_redirect":True,"strict_route":True,"route_address":route_cidrs,"stack":"system"}
    else: cin={"type":"socks","tag":"socks-in","listen":"127.0.0.1","listen_port":socks_port}
    cconfig={"log":{"level":"warn"},"inbounds":[cin],"outbounds":[cout,{"type":"direct","tag":"direct"}],"route":{"auto_detect_interface":True,"final":"proxy-out"}}
    write_remote_text(server,spath,json.dumps(sconfig,indent=2),"0600"); write_remote_text(client,cpath,json.dumps(cconfig,indent=2),"0600"); validate_json_service(server,"sing-box",spath); validate_json_service(client,"sing-box",cpath)
    ss=f"netauto-{name}-server"; cs=f"netauto-{name}-client"
    try:
        allow_firewall_port(server,server_port,protocol); persistent_service(server,ss,f"exec sing-box run -c {shlex.quote(spath)}"); wait_listener(server,protocol,server_port); persistent_service(client,cs,f"exec sing-box run -c {shlex.quote(cpath)}")
        if method=="SINGBOX_TUN": client.run(f"for i in $(seq 1 20); do ip link show {shlex.quote(tun_interface)} >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1",root=True,timeout=30); benchmark=None
        else: wait_listener(client,"tcp",socks_port); benchmark=proxy_throughput_test(client,server,socks_port,name,int(config.get("benchmark_size_mb") or 16))
    except Exception:
        remove_services(client,[cs],[base_client],[tun_interface] if tun_interface else []); remove_services(server,[ss],[base_server]); raise
    artifact={"method":method,"engine":"sing-box","client_side":sides["client_side"],"server_side":sides["server_side"],"server_host":server_host,"server_port":server_port,"transport_protocol":protocol,"local_socks_host":None if method=="SINGBOX_TUN" else "127.0.0.1","local_socks_port":None if method=="SINGBOX_TUN" else socks_port,"interface_name":tun_interface,"services_a":[cs] if sides["client_side"]=="A" else [ss],"services_b":[ss] if sides["server_side"]=="B" else [cs],"files_a":[base_client] if sides["client_side"]=="A" else [base_server],"files_b":[base_server] if sides["server_side"]=="B" else [base_client],"interfaces_a":[tun_interface] if tun_interface and sides["client_side"]=="A" else [],"interfaces_b":[tun_interface] if tun_interface and sides["client_side"]=="B" else [],"proxy_benchmark":benchmark,"certificate_validation":bool(tls)}
    if warning: artifact["warning"]=warning
    return artifact



GUARDIAN_SCRIPT = r"""#!/usr/bin/env bash
set -u

mkdir -p /run /var/lib/netauto-guardian /etc/netauto/guardian.d

if command -v flock >/dev/null 2>&1; then
    exec 9>/run/netauto-guardian.lock
    flock -n 9 || exit 0
fi

now="$(date +%s)"
cooldown=120

safe_key() {
    printf '%s' "$1" | tr -cd 'A-Za-z0-9_.@:-'
}

restart_unit() {
    unit="$1"

    case "$unit" in
        netauto-*.service|wg-quick@*.service)
            ;;
        *)
            return 0
            ;;
    esac

    key="$(safe_key "$unit")"
    stamp="/var/lib/netauto-guardian/restart-${key}"
    last=0

    if [ -r "$stamp" ]; then
        last="$(cat "$stamp" 2>/dev/null || echo 0)"
    fi

    if [ $((now - last)) -lt "$cooldown" ]; then
        return 0
    fi

    systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    systemctl restart "$unit" >/dev/null 2>&1 || true
    printf '%s\n' "$now" > "$stamp"
    logger -t netauto-guardian "restart requested for $unit" || true
}

shopt -s nullglob

for unit_path in /etc/systemd/system/netauto-*.service; do
    unit="$(basename "$unit_path")"

    case "$unit" in
        netauto-guardian.service|netauto-stack.service)
            continue
            ;;
    esac

    systemctl is-enabled --quiet "$unit" \
        || systemctl enable "$unit" >/dev/null 2>&1 \
        || true

    systemctl is-active --quiet "$unit" \
        || restart_unit "$unit"
done

for config in /etc/wireguard/*.conf; do
    interface="$(basename "$config" .conf)"
    unit="wg-quick@${interface}.service"

    systemctl is-enabled --quiet "$unit" \
        || systemctl enable "$unit" >/dev/null 2>&1 \
        || true

    if ! ip link show "$interface" >/dev/null 2>&1; then
        restart_unit "$unit"
    fi
done

for manifest in /etc/netauto/guardian.d/*.conf; do
    SERVICES=""
    INTERFACES=""
    PING_TARGETS=""

    # Manifests are generated by NetAuto with validated values.
    # shellcheck disable=SC1090
    . "$manifest"

    unhealthy=0

    old_ifs="$IFS"
    IFS=','

    for service in $SERVICES; do
        [ -n "$service" ] || continue

        systemctl is-enabled --quiet "$service" \
            || systemctl enable "$service" >/dev/null 2>&1 \
            || true

        if ! systemctl is-active --quiet "$service"; then
            unhealthy=1
        fi
    done

    for interface in $INTERFACES; do
        [ -n "$interface" ] || continue

        if ! ip link show "$interface" >/dev/null 2>&1; then
            unhealthy=1
        fi
    done

    ping_failed=0

    for target in $PING_TARGETS; do
        [ -n "$target" ] || continue

        if printf '%s' "$target" | grep -q ':'; then
            ping -6 -c 1 -W 2 "$target" >/dev/null 2>&1 \
                || ping_failed=1
        else
            ping -c 1 -W 2 "$target" >/dev/null 2>&1 \
                || ping_failed=1
        fi
    done

    IFS="$old_ifs"

    manifest_key="$(safe_key "$(basename "$manifest")")"
    failure_file="/var/lib/netauto-guardian/fail-${manifest_key}"
    failure_count=0

    if [ -r "$failure_file" ]; then
        failure_count="$(cat "$failure_file" 2>/dev/null || echo 0)"
    fi

    if [ "$ping_failed" -eq 1 ]; then
        failure_count=$((failure_count + 1))
        printf '%s\n' "$failure_count" > "$failure_file"

        if [ "$failure_count" -ge 3 ]; then
            unhealthy=1
        fi
    else
        printf '0\n' > "$failure_file"
    fi

    if [ "$unhealthy" -eq 1 ]; then
        old_ifs="$IFS"
        IFS=','

        for service in $SERVICES; do
            [ -n "$service" ] || continue
            restart_unit "$service"
        done

        IFS="$old_ifs"
    fi
done
"""


def ensure_endpoint_guardian(remote: Remote):
    guardian_service = (
        "[Unit]\n"
        "Description=TehranNetwork endpoint tunnel guardian\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "StartLimitIntervalSec=0\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/local/sbin/netauto-guardian\n"
        "TimeoutStartSec=120\n"
    )
    guardian_timer = (
        "[Unit]\n"
        "Description=Run TehranNetwork endpoint guardian periodically\n\n"
        "[Timer]\n"
        "OnBootSec=45s\n"
        "OnUnitActiveSec=30s\n"
        "AccuracySec=5s\n"
        "RandomizedDelaySec=5s\n"
        "Persistent=true\n"
        "Unit=netauto-guardian.service\n\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )

    write_remote_text(
        remote,
        "/usr/local/sbin/netauto-guardian",
        GUARDIAN_SCRIPT,
        "0755",
    )
    write_remote_text(
        remote,
        "/etc/systemd/system/netauto-guardian.service",
        guardian_service,
        "0644",
    )
    write_remote_text(
        remote,
        "/etc/systemd/system/netauto-guardian.timer",
        guardian_timer,
        "0644",
    )
    remote.run(
        "systemctl daemon-reload; "
        "systemctl enable --now netauto-guardian.timer; "
        "systemctl start netauto-guardian.service || true",
        root=True,
        timeout=120,
    )


def _guardian_service_name(value: str) -> str:
    value = str(value).strip()

    if not re.fullmatch(
        r"[A-Za-z0-9_.@:-]+(?:\.service)?",
        value,
    ):
        raise RuntimeError("INVALID_GUARDIAN_SERVICE_NAME")

    if not value.endswith(".service"):
        value += ".service"

    return value


def _guardian_interface_name(value: str) -> str:
    value = str(value).strip()

    if not re.fullmatch(
        r"[A-Za-z0-9_.:-]{1,64}",
        value,
    ):
        raise RuntimeError("INVALID_GUARDIAN_INTERFACE_NAME")

    return value


def _guardian_ip(value: str) -> str:
    value = str(value).strip()

    if "/" in value:
        return str(
            ipaddress.ip_interface(value).ip
        )

    return str(
        ipaddress.ip_address(value)
    )


def register_guardian_manifest(
    remote: Remote,
    *,
    name: str,
    services: list[str],
    interfaces: list[str],
    ping_targets: list[str],
):
    ensure_endpoint_guardian(remote)

    clean_services = sorted(
        {
            _guardian_service_name(value)
            for value in services
            if value
        }
    )
    clean_interfaces = sorted(
        {
            _guardian_interface_name(value)
            for value in interfaces
            if value
        }
    )
    clean_targets = sorted(
        {
            _guardian_ip(value)
            for value in ping_targets
            if value
        }
    )

    manifest_name = re.sub(
        r"[^A-Za-z0-9_.-]+",
        "-",
        name,
    )[:120]

    content = (
        "SERVICES="
        + shlex.quote(
            ",".join(clean_services)
        )
        + "\n"
        + "INTERFACES="
        + shlex.quote(
            ",".join(clean_interfaces)
        )
        + "\n"
        + "PING_TARGETS="
        + shlex.quote(
            ",".join(clean_targets)
        )
        + "\n"
    )

    manifest_path = (
        "/etc/netauto/guardian.d/"
        + manifest_name
        + ".conf"
    )

    write_remote_text(
        remote,
        manifest_path,
        content,
        "0600",
    )

    remote.run(
        "systemctl start netauto-guardian.service || true",
        root=True,
        check=False,
        timeout=120,
    )

    return {
        "manifest": manifest_path,
        "services": clean_services,
        "interfaces": clean_interfaces,
        "ping_targets": clean_targets,
    }


def register_artifact_guardian(
    remote_a: Remote,
    remote_b: Remote,
    artifact: dict,
    run: dict,
    item: dict,
) -> dict:
    method = str(
        artifact.get("method")
        or item.get("method_id")
        or "UNKNOWN"
    )

    service_a = list(
        artifact.get("services_a")
        or []
    )
    service_b = list(
        artifact.get("services_b")
        or []
    )

    interface_a = list(
        artifact.get("interfaces_a")
        or []
    )
    interface_b = list(
        artifact.get("interfaces_b")
        or []
    )

    common_unit = artifact.get(
        "systemd_unit"
    )
    common_interface = artifact.get(
        "interface_name"
    )

    kernel_methods = {
        "GRE",
        "GRETAP",
        "IPIP",
        "SIT_6IN4",
        "IP6GRE",
        "IP6GRETAP",
        "VXLAN",
    }

    if common_unit:
        service_a.append(
            str(common_unit)
        )
        service_b.append(
            str(common_unit)
        )

    if (
        method in kernel_methods
        and common_interface
    ):
        interface_a.append(
            str(common_interface)
        )
        interface_b.append(
            str(common_interface)
        )

    if (
        method == "WIREGUARD"
        and common_interface
    ):
        wireguard_unit = (
            "wg-quick@"
            + str(common_interface)
            + ".service"
        )
        service_a.append(
            wireguard_unit
        )
        service_b.append(
            wireguard_unit
        )
        interface_a.append(
            str(common_interface)
        )
        interface_b.append(
            str(common_interface)
        )

    ping_a = []
    ping_b = []

    if artifact.get("tunnel_ip_b"):
        ping_a.append(
            artifact["tunnel_ip_b"]
        )

    if artifact.get("tunnel_ip_a"):
        ping_b.append(
            artifact["tunnel_ip_a"]
        )

    guardian_a = register_guardian_manifest(
        remote_a,
        name=(
            f"run-{run['id']}-"
            f"item-{item['id']}-a"
        ),
        services=service_a,
        interfaces=interface_a,
        ping_targets=ping_a,
    )

    try:
        guardian_b = register_guardian_manifest(
            remote_b,
            name=(
                f"run-{run['id']}-"
                f"item-{item['id']}-b"
            ),
            services=service_b,
            interfaces=interface_b,
            ping_targets=ping_b,
        )
    except Exception:
        remote_a.run(
            "rm -f "
            + shlex.quote(
                guardian_a["manifest"]
            ),
            root=True,
            check=False,
        )
        raise

    return {
        "enabled": True,
        "check_interval_seconds": 30,
        "consecutive_ping_failures": 3,
        "restart_cooldown_seconds": 120,
        "endpoint_a": guardian_a,
        "endpoint_b": guardian_b,
    }

def rollback_artifact(remote_a: Remote, remote_b: Remote, artifact: dict):
    resilience = artifact.get("resilience") or {}

    for remote, side in (
        (remote_a, "endpoint_a"),
        (remote_b, "endpoint_b"),
    ):
        manifest = (
            resilience.get(side)
            or {}
        ).get("manifest")

        if manifest:
            remote.run(
                "rm -f "
                + shlex.quote(
                    str(manifest)
                ),
                root=True,
                check=False,
            )

    if artifact.get("method") == "WIREGUARD":
        remove_wireguard(remote_a, artifact["interface_name"])
        remove_wireguard(remote_b, artifact["interface_name"])
        return

    if any(key in artifact for key in ("services_a", "services_b", "files_a", "files_b")):
        remove_services(
            remote_a,
            list(artifact.get("services_a") or []),
            list(artifact.get("files_a") or []),
            list(artifact.get("interfaces_a") or []),
        )
        remove_services(
            remote_b,
            list(artifact.get("services_b") or []),
            list(artifact.get("files_b") or []),
            list(artifact.get("interfaces_b") or []),
        )
        if artifact.get("authorized_marker_a") and artifact.get("authorized_user_a"):
            remove_authorized_marker(
                remote_a,
                artifact["authorized_user_a"],
                artifact["authorized_marker_a"],
            )
        if artifact.get("authorized_marker_b") and artifact.get("authorized_user_b"):
            remove_authorized_marker(
                remote_b,
                artifact["authorized_user_b"],
                artifact["authorized_marker_b"],
            )
        for command in artifact.get("cleanup_commands_a") or []:
            remote_a.run(command, root=True, check=False)
        for command in artifact.get("cleanup_commands_b") or []:
            remote_b.run(command, root=True, check=False)
        return

    name = artifact.get("systemd_unit")
    interface_name = artifact.get("interface_name")
    if name and interface_name:
        remove_kernel_unit(remote_a, name, interface_name)
        remove_kernel_unit(remote_b, name, interface_name)


def claim_run(connection, run_id: int):
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM tunnel_plan_runs WHERE id=%s FOR UPDATE",
            (run_id,),
        )
        run = cursor.fetchone()
        if run is None or run["status"] != "QUEUED":
            connection.rollback()
            return None
        cursor.execute(
            """
            UPDATE tunnel_plan_runs
            SET status='RUNNING',started_at=%s
            WHERE id=%s
            """,
            (datetime.utcnow(), run_id),
        )
        cursor.execute(
            """
            UPDATE tunnel_plans
            SET status='RUNNING',updated_at=%s
            WHERE id=%s
            """,
            (datetime.utcnow(), run["plan_id"]),
        )
    connection.commit()
    return dict(run)


def next_run_id(connection):
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT id FROM tunnel_plan_runs WHERE status='QUEUED' ORDER BY id ASC LIMIT 1"
        )
        row = cursor.fetchone()
    return row["id"] if row else None


def load_run_items(connection, run_id: int):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT ri.*,pi.endpoint_a_id,pi.endpoint_b_id,
                   pi.traffic_direction,pi.initiator,
                   pi.carrier_method_id,pi.config_json
            FROM tunnel_plan_run_items ri
            JOIN tunnel_plan_items pi ON pi.id=ri.plan_item_id
            WHERE ri.run_id=%s
            ORDER BY ri.order_index ASC
            """,
            (run_id,),
        )
        return cursor.fetchall()


def cancel_requested(connection, run_id: int) -> bool:
    with connection.cursor() as cursor:
        cursor.execute("SELECT status FROM tunnel_plan_runs WHERE id=%s", (run_id,))
        row = cursor.fetchone()
    return bool(row and row["status"] == "CANCEL_REQUESTED")


def finish_cancelled(connection, run: dict):
    with connection.cursor() as cursor:
        cursor.execute(
            "UPDATE tunnel_plan_runs SET status='CANCELLED',finished_at=%s WHERE id=%s",
            (datetime.utcnow(), run["id"]),
        )
        cursor.execute(
            "UPDATE tunnel_plan_run_items SET status='SKIPPED' WHERE run_id=%s AND status='WAITING'",
            (run["id"],),
        )
        cursor.execute(
            "UPDATE tunnel_plans SET status='DRAFT',updated_at=%s WHERE id=%s",
            (datetime.utcnow(), run["plan_id"]),
        )
    connection.commit()
    add_event(connection, run["id"], "Execution cancelled between sequential items.", level="WARNING")



# ==========================================================
# PACK 7 — WATERWALL / PAQET / COMPOSITE ENGINES
# ==========================================================

WATERWALL_METHODS = {
    "WATERWALL_DIRECT",
    "WATERWALL_REVERSE",
    "WATERWALL_TLS_MUX",
}

PAQET_METHODS = {
    "PAQET_RAW_KCP",
    "PAQET_SOCKS5",
}

COMPOSITE_METHODS = {
    "SIT_OVER_GOST",
    "GRE_OVER_GOST",
    "GRETAP_OVER_GOST",
    "SIT_OVER_SSH",
    "GRE_OVER_SSH",
    "GRE_OVER_WIREGUARD",
}

WATERWALL_RELEASE_TAG = "v1.46.3"
PAQET_RELEASE_TAG = "v1.0.0-alpha.20"


def adaptive_workers(remote: Remote, *, multiplier: int = 1) -> int:
    result = remote.run(
        "getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 1",
        root=True,
        check=False,
    )
    try:
        cores = max(1, int(result["stdout"].strip().splitlines()[-1]))
    except Exception:
        cores = 1
    return max(1, min(32, cores * max(1, multiplier)))


def install_waterwall(remote: Remote) -> dict:
    script = r'''set -Eeuo pipefail
TAG="__TAG__"
RUNTIME=/opt/netauto/waterwall/runtime
META="$RUNTIME/netauto-release.json"
if [ -x "$RUNTIME/WaterWall" ] && [ -s "$META" ] && grep -q "\"tag\": \"$TAG\"" "$META"; then
  cat "$META"
  exit 0
fi
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a DEBCONF_NONINTERACTIVE_SEEN=true
if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  apt-get install -y ca-certificates python3 unzip tar gzip
fi
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
python3 - "$TMP" "$TAG" <<'PYWW'
import json, os, platform, shutil, stat, sys, tarfile, urllib.request, zipfile
from pathlib import Path
out = Path(sys.argv[1]); tag = sys.argv[2]
machine = platform.machine().lower()
arch = 'amd64' if machine in {'x86_64','amd64'} else 'arm64' if machine in {'aarch64','arm64'} else None
if not arch: raise SystemExit('WATERWALL_UNSUPPORTED_ARCH_' + machine)
req = urllib.request.Request(
    f'https://api.github.com/repos/radkesvat/WaterWall/releases/tags/{tag}',
    headers={'Accept':'application/vnd.github+json','User-Agent':'TehranNetwork-Automation'},
)
with urllib.request.urlopen(req, timeout=30) as r: release = json.load(r)
assets = release.get('assets', [])
candidates=[]
for asset in assets:
    name=asset.get('name',''); low=name.lower()
    if 'linux' not in low: continue
    if arch == 'amd64' and not any(x in low for x in ('x64','amd64','x86_64')): continue
    if arch == 'arm64' and not any(x in low for x in ('arm64','aarch64')): continue
    if any(x in low for x in ('sha256','checksum','.sig','source','debug')): continue
    score=0
    if low.endswith('.zip'): score += 20
    if low.endswith(('.tar.gz','.tgz')): score += 12
    if arch == 'amd64':
        if 'avx512' in low: score -= 50
        if 'old' in low: score -= 5
        if 'x64' in low: score += 8
    else:
        if 'old' in low: score += 12
        if 'arm64' in low: score += 8
    candidates.append((score,asset))
if not candidates:
    raise SystemExit('WATERWALL_COMPATIBLE_ASSET_NOT_FOUND: ' + ','.join(a.get('name','') for a in assets))
candidates.sort(key=lambda x:x[0], reverse=True)
asset=candidates[0][1]
archive=out/asset['name']
dreq=urllib.request.Request(asset['browser_download_url'],headers={'User-Agent':'TehranNetwork-Automation'})
with urllib.request.urlopen(dreq, timeout=120) as r: archive.write_bytes(r.read())
extract=out/'extract'; extract.mkdir()
low=archive.name.lower()
if low.endswith('.zip'):
    with zipfile.ZipFile(archive) as z: z.extractall(extract)
elif low.endswith(('.tar.gz','.tgz')):
    with tarfile.open(archive,'r:gz') as t: t.extractall(extract)
else:
    shutil.copy2(archive, extract/archive.name)
files=[p for p in extract.rglob('*') if p.is_file()]
exact=[p for p in files if p.name.lower() == 'waterwall']
if not exact:
    exact=[p for p in files if 'waterwall' in p.name.lower() and not p.suffix.lower() in {'.md','.txt','.json'}]
if not exact: raise SystemExit('WATERWALL_BINARY_NOT_FOUND_IN_' + archive.name)
binary=max(exact,key=lambda p:p.stat().st_size)
runtime=Path('/opt/netauto/waterwall/runtime')
if runtime.exists(): shutil.rmtree(runtime)
runtime.mkdir(parents=True)
shutil.copy2(binary, runtime/'WaterWall'); (runtime/'WaterWall').chmod(0o755)
libs_dirs=[p for p in extract.rglob('*') if p.is_dir() and p.name.lower()=='libs']
if libs_dirs: shutil.copytree(libs_dirs[0], runtime/'libs', dirs_exist_ok=True)
else: (runtime/'libs').mkdir()
metadata={'repo':'radkesvat/WaterWall','tag':tag,'asset':asset['name'],'machine':machine,'arch':arch}
(runtime/'netauto-release.json').write_text(json.dumps(metadata,indent=2),encoding='utf-8')
print(json.dumps(metadata))
PYWW
cat "$META"
'''.replace('__TAG__', WATERWALL_RELEASE_TAG)
    result = remote.run(script, root=True, timeout=900)
    lines = [line for line in result["stdout"].splitlines() if line.strip().startswith("{")]
    try:
        return json.loads(lines[-1]) if lines else {"tag": WATERWALL_RELEASE_TAG}
    except Exception:
        return {"tag": WATERWALL_RELEASE_TAG, "raw": result["stdout"][-1000:]}


def waterwall_core(workers: int, *, mtu: int = 1500) -> dict:
    return {
        "log": {
            "path": "logs/",
            "internal": {"loglevel": "WARN", "file": "internal.log", "console": True},
            "core": {"loglevel": "INFO", "file": "core.log", "console": True},
            "network": {"loglevel": "INFO", "file": "network.log", "console": True},
            "dns": {"loglevel": "WARN", "file": "dns.log", "console": False},
        },
        "misc": {
            "workers": workers,
            "ram-profile": "server",
            "mtu": mtu,
            "try-enabling-bbr": False,
            "libs-path": "/opt/netauto/waterwall/runtime/libs/",
        },
        "dns": {
            "domain-strategy": "prefer-ipv4",
            "timeout-ms": 1500,
            "max-timeout-ms": 5000,
            "tries": 2,
        },
        "configs": ["config.json"],
    }


def write_waterwall_instance(remote: Remote, name: str, config_doc: dict, workers: int) -> tuple[str, list[str]]:
    base = f"/etc/netauto/waterwall/{name}"
    core_path = f"{base}/core.json"
    config_path = f"{base}/config.json"
    write_remote_text(remote, core_path, json.dumps(waterwall_core(workers), indent=2), mode="0600")
    write_remote_text(remote, config_path, json.dumps(config_doc, indent=2), mode="0600")
    remote.run(f"install -d -m 0700 {shlex.quote(base + '/logs')}", root=True)
    persistent_service(
        remote,
        name,
        f"cd {shlex.quote(base)} && exec /opt/netauto/waterwall/runtime/WaterWall",
    )
    wait_service(remote, name)
    return base, [base]


def ww_listener(name: str, address: str, port: int, nxt: str) -> dict:
    return {
        "name": name,
        "type": "TcpListener",
        "settings": {
            "address": address,
            "port": port,
            "nodelay": True,
            "large-send-buffer": True,
            "large-recv-buffer": True,
            "initial-idle-timeout-ms": 10000,
            "active-idle-timeout-ms": 600000,
        },
        "next": nxt,
    }


def ww_connector(name: str, address: str, port: int) -> dict:
    return {
        "name": name,
        "type": "TcpConnector",
        "settings": {
            "address": address,
            "port": port,
            "nodelay": True,
            "fastopen": False,
            "large-send-buffer": True,
            "large-recv-buffer": True,
            "domain-strategy": "prefer-ipv4",
        },
    }


def ww_encryption(name: str, node_type: str, secret: str, salt: str, nxt: str) -> dict:
    return {
        "name": name,
        "type": node_type,
        "settings": {
            "algorithm": "chacha20-poly1305",
            "password": secret,
            "salt": salt,
            "kdf-iterations": 12000,
        },
        "next": nxt,
    }


def waterwall_bind(source: str) -> str:
    try:
        return str(ipaddress.ip_address(source))
    except Exception:
        return "0.0.0.0"


def deploy_waterwall_method(method: str, run: dict, item: dict, config: dict, remote_a: Remote, remote_b: Remote, endpoint_a: dict, endpoint_b: dict) -> dict:
    sides = choose_sides(item, remote_a, remote_b, endpoint_a, endpoint_b)
    client = sides["client"]
    server = sides["server"]
    client_side = sides["client_side"]
    server_side = sides["server_side"]
    server_host = endpoint_source(config, server_side, sides["server_endpoint"])
    server_bind = waterwall_bind(server_host)
    target_host = str(config.get("target_host") or "127.0.0.1")
    target_port = config_port(config, "target_port", default=int(sides["client_endpoint"].get("port") or 22) if method == "WATERWALL_REVERSE" else int(sides["server_endpoint"].get("port") or 22))
    local_bind = str(config.get("bind_address") or "127.0.0.1")
    local_port_remote = server if method == "WATERWALL_REVERSE" else client
    local_port = free_port(local_port_remote, "tcp", int(config.get("listen_port") or (25000 + item["id"] % 12000)))
    transport_port = free_port(server, "tcp", int(config.get("transport_port") or (38000 + item["id"] % 12000)))
    secret = stable_secret(run["id"], item["id"], "waterwall-encryption", 32)
    salt = stable_secret(run["id"], item["id"], "waterwall-salt", 24)
    name_base = f"netauto-ww-{run['id']}-{item['id']}"
    client_name = name_base + "-c"
    server_name = name_base + "-s"
    metadata_client = install_waterwall(client)
    metadata_server = install_waterwall(server)
    allow_firewall_port(server, transport_port, "tcp")
    files_client: list[str] = []
    files_server: list[str] = []
    tls_info = None

    if method == "WATERWALL_DIRECT":
        client_doc = {
            "name": client_name,
            "nodes": [
                ww_listener("local-in", local_bind, local_port, "enc-client"),
                ww_encryption("enc-client", "EncryptionClient", secret, salt, "transport-out"),
                ww_connector("transport-out", server_host, transport_port),
            ],
        }
        server_doc = {
            "name": server_name,
            "nodes": [
                ww_listener("transport-in", server_bind, transport_port, "enc-server"),
                ww_encryption("enc-server", "EncryptionServer", secret, salt, "target-out"),
                ww_connector("target-out", target_host, target_port),
            ],
        }
    elif method == "WATERWALL_TLS_MUX":
        tls_name = f"ww-{run['id']}-{item['id']}"
        tls_info = prepare_tls_pair(
            server,
            client,
            name=tls_name,
            server_host=server_host,
            pfx_password=stable_secret(run["id"], item["id"], "ww-pfx", 24),
        )
        sni = str(config.get("sni") or server_host)
        client_doc = {
            "name": client_name,
            "nodes": [
                ww_listener("local-in", local_bind, local_port, "mux-client"),
                {"name":"mux-client","type":"MuxClient","settings":{"mode":"fixed-connections-count","per-worker-connections-count":max(1,min(4,int(config.get("mux_connections") or 2))),"child-buffer-limit":8388608},"next":"enc-client"},
                ww_encryption("enc-client", "EncryptionClient", secret, salt, "tls-client"),
                {"name":"tls-client","type":"TlsClient","settings":{"sni":sni,"alpns":["http/1.1"],"verify":False,"x25519mlkem768":True},"next":"transport-out"},
                ww_connector("transport-out", server_host, transport_port),
            ],
        }
        server_doc = {
            "name": server_name,
            "nodes": [
                ww_listener("transport-in", server_bind, transport_port, "tls-server"),
                {"name":"tls-server","type":"TlsServer","settings":{"cert-file":tls_info["server_cert"],"key-file":tls_info["server_key"],"min-version":"TLSv1.2","max-version":"TLSv1.3","select-alpns":["http/1.1"],"session-tickets":True},"next":"enc-server"},
                ww_encryption("enc-server", "EncryptionServer", secret, salt, "mux-server"),
                {"name":"mux-server","type":"MuxServer","settings":{"child-buffer-limit":8388608},"next":"target-out"},
                ww_connector("target-out", target_host, target_port),
            ],
        }
    else:
        reverse_secret = stable_secret(run["id"], item["id"], "ww-reverse", 40)
        min_unused = max(1, min(64, int(config.get("minimum_unused") or 8)))
        # Initiating side connects outward and reaches its local target through a bridge pair.
        client_doc = {
            "name": client_name,
            "nodes": [
                ww_connector("outbound-to-target", target_host, target_port),
                {"name":"bridge-target","type":"Bridge","settings":{"pair":"bridge-reverse"},"next":"outbound-to-target"},
                {"name":"bridge-reverse","type":"Bridge","settings":{"pair":"bridge-target"},"next":"reverse-client"},
                {"name":"reverse-client","type":"ReverseClient","settings":{"minimum-unused":min_unused,"reverse-secret-length":64,"reverse-secret":reverse_secret},"next":"enc-client"},
                ww_encryption("enc-client", "EncryptionClient", secret, salt, "transport-out"),
                ww_connector("transport-out", server_host, transport_port),
            ],
        }
        server_doc = {
            "name": server_name,
            "nodes": [
                ww_listener("users-inbound", local_bind, local_port, "bridge-public"),
                {"name":"bridge-public","type":"Bridge","settings":{"pair":"bridge-reverse"}},
                {"name":"bridge-reverse","type":"Bridge","settings":{"pair":"bridge-public"}},
                {"name":"reverse-server","type":"ReverseServer","settings":{"reverse-secret-length":64,"reverse-secret":reverse_secret},"next":"bridge-reverse"},
                ww_encryption("enc-server", "EncryptionServer", secret, salt, "reverse-server"),
                ww_listener("transport-in", server_bind, transport_port, "enc-server"),
            ],
        }

    try:
        server_base, files_server = write_waterwall_instance(
            server, server_name, server_doc,
            adaptive_workers(server, multiplier=4 if method == "WATERWALL_REVERSE" else 1),
        )
        wait_listener(server, "tcp", transport_port)
        client_base, files_client = write_waterwall_instance(
            client, client_name, client_doc,
            adaptive_workers(client),
        )
        wait_listener(local_port_remote, "tcp", local_port)
    except Exception:
        remove_services(client, [client_name], files_client)
        remove_services(server, [server_name], files_server)
        raise

    artifact = {
        "method": method,
        "services_a": [client_name] if client_side == "A" else [server_name],
        "services_b": [client_name] if client_side == "B" else [server_name],
        "files_a": files_client if client_side == "A" else files_server,
        "files_b": files_client if client_side == "B" else files_server,
        "client_side": client_side,
        "server_side": server_side,
        "listen_side": server_side if method == "WATERWALL_REVERSE" else client_side,
        "listen_address": local_bind,
        "listen_port": local_port,
        "transport_port": transport_port,
        "target_host": target_host,
        "target_port": target_port,
        "encrypted": True,
        "multiplexed": method == "WATERWALL_TLS_MUX",
        "reverse": method == "WATERWALL_REVERSE",
        "waterwall_client": metadata_client,
        "waterwall_server": metadata_server,
    }
    if tls_info:
        artifact["files_a"].append(tls_info["client_dir"] if client_side == "A" else tls_info["server_dir"])
        artifact["files_b"].append(tls_info["client_dir"] if client_side == "B" else tls_info["server_dir"])
    return artifact


def install_paqet(remote: Remote) -> dict:
    script = r'''set -Eeuo pipefail
TAG="__TAG__"
BIN=/usr/local/bin/paqet
META=/opt/netauto/paqet/netauto-release.json
if [ -x "$BIN" ] && [ -s "$META" ] && grep -q "\"tag\": \"$TAG\"" "$META"; then cat "$META"; exit 0; fi
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a DEBCONF_NONINTERACTIVE_SEEN=true
if command -v apt-get >/dev/null 2>&1; then apt-get update; apt-get install -y ca-certificates python3 tar gzip unzip iproute2 iputils-ping iptables; fi
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
python3 - "$TMP" "$TAG" <<'PYPQ'
import json, platform, shutil, sys, tarfile, urllib.request, zipfile
from pathlib import Path
out=Path(sys.argv[1]); tag=sys.argv[2]; machine=platform.machine().lower()
tokens={'x86_64':['linux','amd64'],'amd64':['linux','amd64'],'aarch64':['linux','arm64'],'arm64':['linux','arm64'],'armv7l':['linux','armv7'],'armv7':['linux','armv7'],'mips':['linux','mips'],'mipsel':['linux','mipsle']}.get(machine)
if not tokens: raise SystemExit('PAQET_UNSUPPORTED_ARCH_'+machine)
req=urllib.request.Request(f'https://api.github.com/repos/hanselime/paqet/releases/tags/{tag}',headers={'Accept':'application/vnd.github+json','User-Agent':'TehranNetwork-Automation'})
with urllib.request.urlopen(req,timeout=30) as r: release=json.load(r)
c=[]
for a in release.get('assets',[]):
 n=a.get('name',''); low=n.lower()
 if all(t in low for t in tokens) and not any(x in low for x in ('sha256','checksum','.sig','source')): c.append(a)
if not c: raise SystemExit('PAQET_ASSET_NOT_FOUND:'+','.join(a.get('name','') for a in release.get('assets',[])))
a=c[0]; archive=out/a['name']
with urllib.request.urlopen(urllib.request.Request(a['browser_download_url'],headers={'User-Agent':'TehranNetwork-Automation'}),timeout=120) as r: archive.write_bytes(r.read())
extract=out/'extract'; extract.mkdir(); low=archive.name.lower()
if low.endswith('.zip'):
 with zipfile.ZipFile(archive) as z:z.extractall(extract)
elif low.endswith(('.tar.gz','.tgz')):
 with tarfile.open(archive,'r:gz') as t:t.extractall(extract)
else: shutil.copy2(archive,extract/archive.name)
files=[p for p in extract.rglob('*') if p.is_file() and not p.name.lower().endswith(('.txt','.md','.yaml','.yml','.json'))]
exact=[p for p in files if p.name.lower()=='paqet' or p.name.lower().startswith('paqet_')]
if not exact: raise SystemExit('PAQET_BINARY_NOT_FOUND')
b=max(exact,key=lambda p:p.stat().st_size); Path('/usr/local/bin').mkdir(exist_ok=True); shutil.copy2(b,'/usr/local/bin/paqet'); Path('/usr/local/bin/paqet').chmod(0o755)
meta=Path('/opt/netauto/paqet'); meta.mkdir(parents=True,exist_ok=True); data={'repo':'hanselime/paqet','tag':tag,'asset':a['name'],'machine':machine}; (meta/'netauto-release.json').write_text(json.dumps(data,indent=2),encoding='utf-8'); print(json.dumps(data))
PYPQ
cat "$META"
'''.replace('__TAG__', PAQET_RELEASE_TAG)
    result = remote.run(script, root=True, timeout=900)
    lines=[line for line in result["stdout"].splitlines() if line.strip().startswith("{")]
    try: return json.loads(lines[-1]) if lines else {"tag": PAQET_RELEASE_TAG}
    except Exception: return {"tag": PAQET_RELEASE_TAG}


def paqet_network_profile(remote: Remote, preferred_ip: str | None = None) -> dict:
    preferred = str(preferred_ip or "")
    script = r'''set -Eeuo pipefail
PREFERRED=__PREFERRED__
if [ -n "$PREFERRED" ]; then
  line=$(ip -4 route get 1.1.1.1 from "$PREFERRED" 2>/dev/null | head -n1 || true)
else
  line=$(ip -4 route get 1.1.1.1 2>/dev/null | head -n1 || true)
fi
iface=$(printf '%s\n' "$line" | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
src=$(printf '%s\n' "$line" | awk '{for(i=1;i<=NF;i++)if($i=="src"){print $(i+1);exit}}')
[ -n "$iface" ] || iface=$(ip -4 route show default | awk 'NR==1{print $5}')
[ -n "$src" ] || src=$(ip -4 -o addr show dev "$iface" scope global | awk 'NR==1{split($4,a,"/");print a[1]}')
gw=$(ip -4 route show default dev "$iface" | awk 'NR==1{for(i=1;i<=NF;i++)if($i=="via"){print $(i+1);exit}}')
if [ -z "$gw" ]; then gw=$(printf '%s\n' "$line" | awk '{for(i=1;i<=NF;i++)if($i=="via"){print $(i+1);exit}}'); fi
[ -n "$gw" ] || { echo PAQET_DEFAULT_GATEWAY_NOT_FOUND >&2; exit 51; }
ping -c 1 -W 2 "$gw" >/dev/null 2>&1 || true
mac=$(ip neigh show "$gw" dev "$iface" | awk 'NR==1{for(i=1;i<=NF;i++)if($i=="lladdr"){print $(i+1);exit}}')
[ -n "$mac" ] || { echo PAQET_GATEWAY_MAC_NOT_FOUND >&2; exit 52; }
printf 'interface=%s\nip=%s\ngateway=%s\nrouter_mac=%s\n' "$iface" "$src" "$gw" "$mac"
'''.replace('__PREFERRED__', shlex.quote(preferred))
    result=remote.run(script,root=True,timeout=60)
    profile={}
    for line in result["stdout"].splitlines():
        if "=" in line:
            k,v=line.split("=",1); profile[k]=v
    if not all(profile.get(k) for k in ("interface","ip","gateway","router_mac")):
        raise RuntimeError("PAQET_NETWORK_PROFILE_INCOMPLETE")
    ipaddress.ip_address(profile["ip"])
    return profile


def paqet_yaml(role: str, net: dict, key: str, profile: dict, *, server_addr: str | None = None, server_port: int | None = None, mode: str, listen: str | None = None, target: str | None = None, username: str = "", password: str = "") -> str:
    lines=[f'role: "{role}"','log:','  level: "info"']
    if role == "server":
        lines += ['listen:', f'  addr: ":{server_port}"']
    elif mode == "socks":
        lines += ['socks5:', f'  - listen: "{listen}"', f'    username: "{username}"', f'    password: "{password}"']
    else:
        lines += ['forward:', f'  - listen: "{listen}"', f'    target: "{target}"', '    protocol: "tcp"']
    lines += ['network:', f'  interface: "{net["interface"]}"','  ipv4:', f'    addr: "{net["ip"]}:{server_port if role == "server" else 0}"', f'    router_mac: "{net["router_mac"]}"','  tcp:','    local_flag: ["PA"]','    remote_flag: ["PA"]']
    if role == "client": lines += ['server:', f'  addr: "{server_addr}:{server_port}"']
    lines += ['transport:','  protocol: "kcp"',f'  conn: {int(profile.get("connections") or 1)}','  kcp:',f'    mode: "{profile["mode"]}"',f'    mtu: {profile["mtu"]}',f'    rcvwnd: {profile["rcvwnd"]}',f'    sndwnd: {profile["sndwnd"]}','    block: "aes-128-gcm"',f'    key: "{key}"','    smuxkalive: 2','    smuxktimeout: 8']
    return "\n".join(lines)+"\n"


def deploy_paqet_method(method: str, run: dict, item: dict, config: dict, remote_a: Remote, remote_b: Remote, endpoint_a: dict, endpoint_b: dict) -> dict:
    sides=choose_sides(item,remote_a,remote_b,endpoint_a,endpoint_b)
    client=sides["client"]; server=sides["server"]
    client_side=sides["client_side"]; server_side=sides["server_side"]
    server_host=endpoint_source(config,server_side,sides["server_endpoint"])
    try: ipaddress.ip_address(server_host)
    except Exception: raise RuntimeError("PAQET_REQUIRES_SERVER_IPV4_ADDRESS")
    if ipaddress.ip_address(server_host).version != 4: raise RuntimeError("PAQET_REQUIRES_SERVER_IPV4_ADDRESS")
    preferred_client=endpoint_source(config,client_side,sides["client_endpoint"])
    meta_client=install_paqet(client); meta_server=install_paqet(server)
    net_client=paqet_network_profile(client,preferred_client)
    net_server=paqet_network_profile(server,server_host)
    port=free_port(server,"tcp",int(config.get("transport_port") or (41000+item["id"]%15000)))
    while port in {80,443,22,25,53}: port += 1
    baseline=path_probe(client,server_host)
    profile=choose_kcp_profile(baseline,config)
    profile["connections"]=max(1,min(16,int(config.get("connections") or (2 if profile["mode"] in {"fast2","fast3"} else 1))))
    key=stable_secret(run["id"],item["id"],"paqet-key",48)
    local_bind=str(config.get("bind_address") or "127.0.0.1")
    local_port=free_port(client,"tcp",int(config.get("listen_port") or (27000+item["id"]%12000)))
    target_host=str(config.get("target_host") or "127.0.0.1")
    target_port=config_port(config,"target_port",default=int(sides["server_endpoint"].get("port") or 22))
    username="na"+stable_secret(run["id"],item["id"],"paqet-user",10)
    password=stable_secret(run["id"],item["id"],"paqet-pass",24)
    base=f"/etc/netauto/paqet/{run['id']}-{item['id']}"
    client_file=base+"/client.yaml"; server_file=base+"/server.yaml"
    client_yaml=paqet_yaml("client",net_client,key,profile,server_addr=server_host,server_port=port,mode="socks" if method=="PAQET_SOCKS5" else "forward",listen=f"{local_bind}:{local_port}",target=f"{target_host}:{target_port}",username=username,password=password)
    server_yaml=paqet_yaml("server",net_server,key,profile,server_port=port,mode="server")
    write_remote_text(client,client_file,client_yaml,"0600"); write_remote_text(server,server_file,server_yaml,"0600")
    server_name=f"netauto-paqet-{run['id']}-{item['id']}-s"; client_name=f"netauto-paqet-{run['id']}-{item['id']}-c"
    rule_add=(f"iptables -t raw -C PREROUTING -p tcp --dport {port} -j NOTRACK 2>/dev/null || iptables -t raw -A PREROUTING -p tcp --dport {port} -j NOTRACK; " f"iptables -t raw -C OUTPUT -p tcp --sport {port} -j NOTRACK 2>/dev/null || iptables -t raw -A OUTPUT -p tcp --sport {port} -j NOTRACK; " f"iptables -t mangle -C OUTPUT -p tcp --sport {port} --tcp-flags RST RST -j DROP 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --sport {port} --tcp-flags RST RST -j DROP; " f"iptables -C INPUT -p tcp --dport {port} -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport {port} -j ACCEPT")
    cleanup=(f"iptables -t raw -D PREROUTING -p tcp --dport {port} -j NOTRACK 2>/dev/null || true; " f"iptables -t raw -D OUTPUT -p tcp --sport {port} -j NOTRACK 2>/dev/null || true; " f"iptables -t mangle -D OUTPUT -p tcp --sport {port} --tcp-flags RST RST -j DROP 2>/dev/null || true; " f"iptables -D INPUT -p tcp --dport {port} -j ACCEPT 2>/dev/null || true")
    try:
        persistent_service(server,server_name,f"{rule_add}; exec /usr/local/bin/paqet run -c {shlex.quote(server_file)}")
        wait_service(server,server_name)
        time.sleep(3)
        ping_result=client.run(f"/usr/local/bin/paqet ping -c {shlex.quote(client_file)}",root=True,timeout=45,check=False)
        if ping_result["code"] != 0:
            raise RuntimeError("PAQET_PING_FAILED: "+(ping_result["stderr"] or ping_result["stdout"])[-1000:])
        persistent_service(client,client_name,f"exec /usr/local/bin/paqet run -c {shlex.quote(client_file)}")
        wait_service(client,client_name)
        wait_listener(client,"tcp",local_port)
    except Exception:
        remove_services(client,[client_name],[base]); remove_services(server,[server_name],[base]); server.run(cleanup,root=True,check=False)
        raise
    return {"method":method,"services_a":[client_name] if client_side=="A" else [server_name],"services_b":[client_name] if client_side=="B" else [server_name],"files_a":[base],"files_b":[base],"cleanup_commands_a":[cleanup] if server_side=="A" else [],"cleanup_commands_b":[cleanup] if server_side=="B" else [],"client_side":client_side,"server_side":server_side,"listen_address":local_bind,"listen_port":local_port,"transport_port":port,"target_host":target_host,"target_port":target_port,"socks_username":username if method=="PAQET_SOCKS5" else None,"socks_password":password if method=="PAQET_SOCKS5" else None,"kcp_profile":profile,"baseline":baseline,"network_client":net_client,"network_server":net_server,"paqet_client":meta_client,"paqet_server":meta_server,"encrypted":True,"warning":"Paqet is an alpha raw-packet engine; platform and gateway-MAC checks passed for this deployment."}


def candidate_carrier_networks(run_id: int, item_id: int):
    base=ipaddress.ip_network("100.64.0.0/10")
    total=base.num_addresses//4
    start=(run_id*4099+item_id*131)%total
    for offset in range(2048):
        index=(start+offset)%total
        yield ipaddress.ip_network((int(base.network_address)+index*4,30))


def network_conflicts(remote: Remote, network: ipaddress.IPv4Network) -> bool:
    result=remote.run("ip -4 -o addr show; ip -4 route show table all",root=True,check=False)
    for token in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?",result["stdout"]):
        try:
            other=ipaddress.ip_network(token if "/" in token else token+"/32",strict=False)
            if network.overlaps(other): return True
        except Exception: pass
    return False


def allocate_carrier_addressing(remote_a: Remote, remote_b: Remote, run: dict, item: dict) -> dict:
    for network in candidate_carrier_networks(run["id"],item["id"]):
        if not network_conflicts(remote_a,network) and not network_conflicts(remote_b,network):
            hosts=list(network.hosts())
            return {"tunnel_cidr":str(network),"tunnel_ip_a":f"{hosts[0]}/30","tunnel_ip_b":f"{hosts[1]}/30"}
    raise RuntimeError("NO_FREE_RFC6598_CARRIER_SUBNET")


def deploy_secure_gost_tun_carrier(run: dict, item: dict, config: dict, remote_a: Remote, remote_b: Remote, endpoint_a: dict, endpoint_b: dict, carrier: dict) -> dict:
    sides=choose_sides(item,remote_a,remote_b,endpoint_a,endpoint_b)
    client=sides["client"]; server=sides["server"]
    server_host=endpoint_source(config,sides["server_side"],sides["server_endpoint"])
    server_ip=str(ipaddress.ip_interface(carrier["tunnel_ip_b"] if sides["server_side"]=="B" else carrier["tunnel_ip_a"]).ip)
    client_ip=str(ipaddress.ip_interface(carrier["tunnel_ip_a"] if sides["client_side"]=="A" else carrier["tunnel_ip_b"]).ip)
    server_cidr=server_ip+"/30"; client_cidr=client_ip+"/30"
    interface=short_name("ngc",run["id"],item["id"])
    relay_port=free_port(server,"tcp",int(config.get("carrier_port") or (43000+item["id"]%12000)))
    logical_port=8421+(item["id"]%1000)
    username="na"+stable_secret(run["id"],item["id"],"gost-carrier-user",10)
    password=stable_secret(run["id"],item["id"],"gost-carrier-pass",28)
    server_name=f"netauto-gostc-{run['id']}-{item['id']}-s"; client_name=f"netauto-gostc-{run['id']}-{item['id']}-c"
    server_tun=f"tun://:{logical_port}?net={server_cidr}&name={interface}&mtu=1360"
    relay=f"relay+wss://{username}:{password}@{waterwall_bind(server_host)}:{relay_port}?bind=true"
    client_tun=f"tun://:0/:{logical_port}?net={client_cidr}&name={interface}&mtu=1360&keepalive=true&ttl=10s"
    chain=f"relay+wss://{username}:{password}@{server_host}:{relay_port}"
    try:
        install_gost(client); install_gost(server); allow_firewall_port(server,relay_port,"tcp")
        persistent_service(server,server_name,f"exec /usr/local/bin/gost -L {shlex.quote(server_tun)} -L {shlex.quote(relay)}")
        wait_service(server,server_name); wait_listener(server,"tcp",relay_port)
        persistent_service(client,client_name,f"exec /usr/local/bin/gost -L {shlex.quote(client_tun)} -F {shlex.quote(chain)}")
        wait_service(client,client_name); time.sleep(5)
        client.run(ping_command(ipaddress.ip_address(server_ip)),root=True,timeout=35)
        server.run(ping_command(ipaddress.ip_address(client_ip)),root=True,timeout=35)
    except Exception:
        remove_services(client,[client_name],[],[interface]); remove_services(server,[server_name],[],[interface]); raise
    return {"method":"SECURE_GOST_TUN_CARRIER","services_a":[client_name] if sides["client_side"]=="A" else [server_name],"services_b":[client_name] if sides["client_side"]=="B" else [server_name],"interfaces_a":[interface],"interfaces_b":[interface],"client_side":sides["client_side"],"server_side":sides["server_side"],"relay_port":relay_port,"transport":"relay+wss","encrypted":True,"tunnel_cidr":carrier["tunnel_cidr"],"tunnel_ip_a":carrier["tunnel_ip_a"],"tunnel_ip_b":carrier["tunnel_ip_b"]}


def merge_component_artifacts(method: str, components: list[dict], inner: dict) -> dict:
    result={"method":method,"components":components,"tunnel_cidr":inner.get("tunnel_cidr"),"tunnel_ip_a":inner.get("tunnel_ip_a"),"tunnel_ip_b":inner.get("tunnel_ip_b"),"encrypted_carrier":True}
    for key in ("services_a","services_b","interfaces_a","interfaces_b","files_a","files_b","cleanup_commands_a","cleanup_commands_b"):
        values=[]
        for art in components:
            values.extend(list(art.get(key) or []))
        result[key]=list(dict.fromkeys(str(v) for v in values if v))
    if inner.get("systemd_unit"):
        result["services_a"].append(inner["systemd_unit"]); result["services_b"].append(inner["systemd_unit"])
    if inner.get("interface_name"):
        result["interfaces_a"].append(inner["interface_name"]); result["interfaces_b"].append(inner["interface_name"])
    for side in ("a","b"):
        for field in ("authorized_marker","authorized_user"):
            key=f"{field}_{side}"
            for art in components:
                if art.get(key): result[key]=art[key]
    return result


def deploy_composite_method(method: str, run: dict, item: dict, config: dict, remote_a: Remote, remote_b: Remote, endpoint_a: dict, endpoint_b: dict) -> dict:
    carrier_addr=allocate_carrier_addressing(remote_a,remote_b,run,item)
    public_config=dict(config)
    public_config.setdefault("source_ip_a",endpoint_a["host"])
    public_config.setdefault("source_ip_b",endpoint_b["host"])
    carrier_config={**public_config,**carrier_addr}
    carrier_artifact=None
    if method.endswith("_OVER_GOST"):
        carrier_artifact=deploy_secure_gost_tun_carrier(run,item,public_config,remote_a,remote_b,endpoint_a,endpoint_b,carrier_addr)
    elif method.endswith("_OVER_SSH"):
        carrier_artifact=deploy_ssh_tunnel("SSH_TUN_L3",run,item,carrier_config,remote_a,remote_b,endpoint_a,endpoint_b)
    elif method == "GRE_OVER_WIREGUARD":
        carrier_artifact=deploy_wireguard(run,item,carrier_config,remote_a,remote_b)
        iface=carrier_artifact["interface_name"]
        carrier_artifact.update({"services_a":[f"wg-quick@{iface}.service"],"services_b":[f"wg-quick@{iface}.service"],"interfaces_a":[iface],"interfaces_b":[iface],"files_a":[f"/etc/wireguard/{iface}.conf"],"files_b":[f"/etc/wireguard/{iface}.conf"]})
    else: raise RuntimeError("UNSUPPORTED_COMPOSITE_CARRIER")
    inner_method="SIT_6IN4" if method.startswith("SIT_") else "GRETAP" if method.startswith("GRETAP_") else "GRE"
    inner_config=dict(config)
    inner_config["source_ip_a"]=str(ipaddress.ip_interface(carrier_addr["tunnel_ip_a"]).ip)
    inner_config["source_ip_b"]=str(ipaddress.ip_interface(carrier_addr["tunnel_ip_b"]).ip)
    try:
        inner=deploy_kernel(inner_method,run,item,inner_config,remote_a,remote_b)
    except Exception:
        rollback_artifact(remote_a,remote_b,carrier_artifact)
        raise
    return merge_component_artifacts(method,[carrier_artifact,inner],inner)

BENCHMARK_L3_METHODS = {
    "GRE", "GRETAP", "IPIP", "SIT_6IN4", "IP6GRE", "IP6GRETAP",
    "VXLAN", "WIREGUARD", "SSH_TUN_L3", "SSH_TAP_L2", "GOST_TUN", "GOST_TAP",
    "OPENVPN", "IKEV2_IPSEC", "L2TP_IPSEC", "VTI", "VTI6",
    "SIT_OVER_GOST",
    "GRE_OVER_GOST",
    "GRETAP_OVER_GOST",
    "SIT_OVER_SSH",
    "GRE_OVER_SSH",
    "GRE_OVER_WIREGUARD",
}

PLATFORM_RULES = {
    "OPENVPN": {"os": {"linux"}},
    "IKEV2_IPSEC": {"os": {"linux"}},
    "L2TP_IPSEC": {"os": {"linux"}},
    "VTI": {"os": {"linux"}},
    "VTI6": {"os": {"linux"}},
    "WATERWALL_DIRECT": {"os": {"linux"}, "arch": {"amd64", "arm64"}},
    "WATERWALL_REVERSE": {"os": {"linux"}, "arch": {"amd64", "arm64"}},
    "WATERWALL_TLS_MUX": {"os": {"linux"}, "arch": {"amd64", "arm64"}},
    "PAQET_RAW_KCP": {"os": {"linux"}, "arch": {"amd64", "arm64", "armv7", "mips", "mipsle"}, "raw_socket": True},
    "PAQET_SOCKS5": {"os": {"linux"}, "arch": {"amd64", "arm64", "armv7", "mips", "mipsle"}, "raw_socket": True},
}

PLATFORM_RULES.update(
    {
        method: {
            "os": {"linux"},
            "arch": {"amd64", "arm64", "armv7"},
        }
        for method in MODERN_PROXY_METHODS
    }
)



def platform_profile(remote: Remote) -> dict:
    script = r'''set -Eeuo pipefail
os_name=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  armv7l|armv7) arch=armv7 ;;
  mips64el|mipsel) arch=mipsle ;;
  mips64|mips) arch=mips ;;
esac
os_id=unknown
os_version=unknown
if [ -r /etc/os-release ]; then
  . /etc/os-release
  os_id=${ID:-unknown}
  os_version=${VERSION_ID:-unknown}
fi
pkg=unknown
for candidate in apt-get dnf yum apk pacman; do
  if command -v "$candidate" >/dev/null 2>&1; then pkg=$candidate; break; fi
done
raw_socket=no
if [ "$(id -u)" = 0 ]; then raw_socket=yes; fi
printf 'os=%s\narch=%s\nos_id=%s\nos_version=%s\nkernel=%s\ncpu_count=%s\npackage_manager=%s\nraw_socket=%s\ntun=%s\n' \
  "$os_name" "$arch" "$os_id" "$os_version" "$(uname -r)" "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)" "$pkg" "$raw_socket" "$([ -c /dev/net/tun ] && echo yes || echo no)"
'''
    result = remote.run(script, root=True, check=False)
    profile = {}
    for line in result["stdout"].splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            profile[key] = value
    return profile


def validate_platform(method: str, profile_a: dict, profile_b: dict):
    rule = PLATFORM_RULES.get(method)
    if not rule:
        return
    for side, profile in (("A", profile_a), ("B", profile_b)):
        if profile.get("os") not in rule.get("os", {profile.get("os")}):
            raise RuntimeError(f"{method}_UNSUPPORTED_OS_{side}_{profile.get('os')}")
        if profile.get("arch") not in rule.get("arch", {profile.get("arch")}):
            raise RuntimeError(f"{method}_UNSUPPORTED_ARCH_{side}_{profile.get('arch')}")
        if rule.get("raw_socket") and profile.get("raw_socket") != "yes":
            raise RuntimeError(f"{method}_RAW_SOCKET_REQUIRED_{side}")


def install_benchmark_tools(remote: Remote):
    remote.run(
        r'''set -Eeuo pipefail
if command -v iperf3 >/dev/null 2>&1 && command -v ping >/dev/null 2>&1; then exit 0; fi
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a DEBCONF_NONINTERACTIVE_SEEN=true
if command -v apt-get >/dev/null 2>&1; then
  apt-get update && apt-get install -y iperf3 iputils-ping
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y iperf3 iputils
elif command -v yum >/dev/null 2>&1; then
  yum install -y iperf3 iputils
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache iperf3 iputils
elif command -v pacman >/dev/null 2>&1; then
  pacman -Sy --noconfirm iperf3 iputils
else
  echo NO_SUPPORTED_PACKAGE_MANAGER >&2
  exit 41
fi
''',
        root=True,
        timeout=360,
    )


def parse_iperf_json(raw: str, udp: bool = False) -> dict:
    data = json.loads(raw)
    end = data.get("end", {})
    if udp:
        summary = end.get("sum") or end.get("sum_received") or {}
        return {
            "mbps": round(float(summary.get("bits_per_second", 0)) / 1_000_000, 2),
            "jitter_ms": round(float(summary.get("jitter_ms", 0)), 3),
            "loss_percent": round(float(summary.get("lost_percent", 0)), 3),
            "packets": int(summary.get("packets", 0) or 0),
        }
    summary = end.get("sum_received") or end.get("sum_sent") or {}
    return {
        "mbps": round(float(summary.get("bits_per_second", 0)) / 1_000_000, 2),
        "retransmits": int((end.get("sum_sent") or {}).get("retransmits", 0) or 0),
        "seconds": round(float(summary.get("seconds", 0)), 2),
    }


def start_iperf_server(remote: Remote, bind_ip: str, port: int):
    family = "-6" if ":" in bind_ip else "-4"
    remote.run(
        f"pkill -f 'iperf3 -s -1 .* -p {port}' 2>/dev/null || true; "
        f"nohup iperf3 {family} -s -1 -B {shlex.quote(bind_ip)} -p {port} "
        f">/tmp/netauto-iperf-{port}.log 2>&1 &",
        root=True,
        check=False,
    )
    time.sleep(1)


def iperf_once(server: Remote, client: Remote, server_ip: str, port: int, *, duration: int, streams: int = 1, udp_mbps: int | None = None) -> dict:
    start_iperf_server(server, server_ip, port)
    family = "-6" if ":" in server_ip else "-4"
    if udp_mbps is None:
        command = (
            f"iperf3 {family} -c {shlex.quote(server_ip)} -p {port} "
            f"-t {duration} -P {streams} -J --connect-timeout 5000"
        )
        result = client.run(command, root=True, timeout=duration + 25)
        return parse_iperf_json(result["stdout"], udp=False)
    command = (
        f"iperf3 {family} -c {shlex.quote(server_ip)} -p {port} "
        f"-u -b {int(udp_mbps)}M -t {duration} -J --connect-timeout 5000"
    )
    result = client.run(command, root=True, timeout=duration + 25)
    return parse_iperf_json(result["stdout"], udp=True)


def benchmark_tunnel(remote_a: Remote, remote_b: Remote, artifact: dict, config: dict) -> dict | None:
    ip_a_value = artifact.get("tunnel_ip_a") or config.get("tunnel_ip_a")
    ip_b_value = artifact.get("tunnel_ip_b") or config.get("tunnel_ip_b")
    if not ip_a_value or not ip_b_value:
        return None
    ip_a = str(ipaddress.ip_interface(ip_a_value).ip)
    ip_b = str(ipaddress.ip_interface(ip_b_value).ip)
    install_benchmark_tools(remote_a)
    install_benchmark_tools(remote_b)
    duration = max(3, min(int(config.get("benchmark_duration") or 6), 30))
    max_udp_mbps = max(10, min(int(config.get("benchmark_max_mbps") or 200), 2000))
    port_base = int(config.get("benchmark_port") or (5201 + int(time.time()) % 1000))

    ping_a_b = path_probe(remote_a, ip_b)
    ping_b_a = path_probe(remote_b, ip_a)

    tcp_candidates = []
    for streams in (1, 4):
        tcp_candidates.append(
            {
                "streams": streams,
                "a_to_b": iperf_once(remote_b, remote_a, ip_b, port_base + streams, duration=duration, streams=streams),
                "b_to_a": iperf_once(remote_a, remote_b, ip_a, port_base + 20 + streams, duration=duration, streams=streams),
            }
        )
    best = max(
        tcp_candidates,
        key=lambda row: min(row["a_to_b"]["mbps"], row["b_to_a"]["mbps"]),
    )

    udp_rates = sorted({min(max_udp_mbps, rate) for rate in (25, 50, 100, 200, max_udp_mbps)})
    udp_results = []
    for index, rate in enumerate(udp_rates):
        sample = iperf_once(remote_b, remote_a, ip_b, port_base + 100 + index, duration=max(3, duration - 1), udp_mbps=rate)
        sample["requested_mbps"] = rate
        udp_results.append(sample)
        if sample["loss_percent"] > 2.0:
            break
    stable_udp = [row for row in udp_results if row["loss_percent"] <= 1.0]
    best_udp = max(stable_udp or udp_results, key=lambda row: row["mbps"], default=None)

    min_tcp = min(best["a_to_b"]["mbps"], best["b_to_a"]["mbps"])
    max_loss = max(ping_a_b["loss_percent"], ping_b_a["loss_percent"])
    avg_rtt_values = [value for value in (ping_a_b.get("rtt_avg_ms"), ping_b_a.get("rtt_avg_ms")) if value is not None]
    avg_rtt = sum(avg_rtt_values) / len(avg_rtt_values) if avg_rtt_values else 999
    stability_score = round(max(0.0, 100.0 - max_loss * 12.0 - avg_rtt / 8.0 - ((best_udp or {}).get("loss_percent", 0) * 5.0)), 1)

    recommendation = "WIREGUARD_OR_MTCP"
    if max_loss >= 1.0 or avg_rtt >= 120:
        recommendation = "KCP_OR_QUIC"
    elif min_tcp < 20:
        recommendation = "KCP_BALANCED_OR_REVERSE_PATH"

    return {
        "ping": {"a_to_b": ping_a_b, "b_to_a": ping_b_a},
        "tcp": {"candidates": tcp_candidates, "best": best, "minimum_bidirectional_mbps": round(min_tcp, 2)},
        "udp": {"samples": udp_results, "best_stable": best_udp},
        "stability_score": stability_score,
        "recommended_transport": recommendation,
        "benchmark_profile": {
            "duration_seconds": duration,
            "max_udp_mbps": max_udp_mbps,
            "runs_sequentially": True,
        },
    }


def execute_item(connection, run: dict, item: dict) -> dict:
    method = item["method_id"]
    if method not in SUPPORTED:
        raise RuntimeError("EXECUTOR_NOT_READY_FOR_" + method)
    config = json.loads(item["config_json"] or "{}")

    with remote_pair(connection, item["endpoint_a_id"], item["endpoint_b_id"]) as (
        remote_a,
        remote_b,
        endpoint_a,
        endpoint_b,
    ):
        profile_a = platform_profile(remote_a)
        profile_b = platform_profile(remote_b)
        validate_platform(method, profile_a, profile_b)
        add_event(
            connection,
            run["id"],
            "Secure SSH sessions and platform compatibility checks completed.",
            run_item_id=item["id"],
            details={
                "endpoint_a": {"id": endpoint_a["id"], "name": endpoint_a["name"], "platform": profile_a},
                "endpoint_b": {"id": endpoint_b["id"], "name": endpoint_b["name"], "platform": profile_b},
            },
        )
        if method == "WIREGUARD":
            artifact = deploy_wireguard(run, item, config, remote_a, remote_b)
        elif method in SSH_METHODS:
            artifact = deploy_ssh_method(method, run, item, config, remote_a, remote_b, endpoint_a, endpoint_b)
        elif method in GOST_METHODS:
            if method in {"GOST_TUN", "GOST_TAP"}:
                add_event(
                    connection,
                    run["id"],
                    "Warning: direct GOST TUN/TAP uses unencrypted UDP transport unless wrapped by a secure carrier.",
                    run_item_id=item["id"],
                    level="WARNING",
                )
            artifact = deploy_gost_method(method, run, item, config, remote_a, remote_b, endpoint_a, endpoint_b)
        elif method in WATERWALL_METHODS:
            artifact = deploy_waterwall_method(method, run, item, config, remote_a, remote_b, endpoint_a, endpoint_b)
        elif method in PAQET_METHODS:
            artifact = deploy_paqet_method(method, run, item, config, remote_a, remote_b, endpoint_a, endpoint_b)
            if artifact.get("warning"):
                add_event(connection, run["id"], artifact["warning"], run_item_id=item["id"], level="WARNING")
        elif method in COMPOSITE_METHODS:
            artifact = deploy_composite_method(method, run, item, config, remote_a, remote_b, endpoint_a, endpoint_b)
        elif method in VPN_METHODS:
            artifact = deploy_vpn_method(
                method, run, item, config, remote_a, remote_b, endpoint_a, endpoint_b
            )
            if artifact.get("warning"):
                add_event(
                    connection, run["id"], artifact["warning"],
                    run_item_id=item["id"], level="WARNING",
                )
        elif method in XRAY_METHODS:
            artifact = deploy_xray_method(method, run, item, config, remote_a, remote_b, endpoint_a, endpoint_b)
            if artifact.get("warning"):
                add_event(connection, run["id"], artifact["warning"], run_item_id=item["id"], level="WARNING")
        elif method in SINGBOX_METHODS:
            artifact = deploy_singbox_method(method, run, item, config, remote_a, remote_b, endpoint_a, endpoint_b)
            if artifact.get("warning"):
                add_event(connection, run["id"], artifact["warning"], run_item_id=item["id"], level="WARNING")
        elif method in (
            FRP_METHODS
            | RATHOLE_METHODS
            | CHISEL_METHODS
            | WSTUNNEL_METHODS
        ):
            artifact = deploy_pack4_method(
                method,
                run,
                item,
                config,
                remote_a,
                remote_b,
                endpoint_a,
                endpoint_b,
            )
            if artifact.get("warning"):
                add_event(
                    connection,
                    run["id"],
                    artifact["warning"],
                    run_item_id=item["id"],
                    level="WARNING",
                )
        else:
            artifact = deploy_kernel(method, run, item, config, remote_a, remote_b)

        artifact["platform_a"] = profile_a
        artifact["platform_b"] = profile_b

        if config.get("benchmark_enabled", True) and method in BENCHMARK_L3_METHODS:
            add_event(
                connection,
                run["id"],
                "Starting sequential bidirectional tunnel benchmark.",
                run_item_id=item["id"],
            )
            benchmark = benchmark_tunnel(remote_a, remote_b, artifact, config)
            artifact["benchmark"] = benchmark
            if benchmark:
                add_event(
                    connection,
                    run["id"],
                    (
                        "Benchmark completed: "
                        f"minimum TCP {benchmark['tcp']['minimum_bidirectional_mbps']} Mbps, "
                        f"stability score {benchmark['stability_score']}/100, "
                        f"recommendation {benchmark['recommended_transport']}."
                    ),
                    run_item_id=item["id"],
                    level="SUCCESS",
                    details=benchmark,
                )
        try:
            resilience = register_artifact_guardian(
                remote_a,
                remote_b,
                artifact,
                run,
                item,
            )
            artifact["resilience"] = resilience
            add_event(
                connection,
                run["id"],
                (
                    "Automatic boot recovery and "
                    "30-second tunnel guardian enabled "
                    "on both endpoints."
                ),
                run_item_id=item["id"],
                level="SUCCESS",
                details=resilience,
            )
        except Exception as exc:
            try:
                rollback_artifact(
                    remote_a,
                    remote_b,
                    artifact,
                )
            except Exception:
                log.exception(
                    "Rollback after guardian failure "
                    "also failed."
                )

            raise RuntimeError(
                "TUNNEL_GUARDIAN_SETUP_FAILED: "
                + str(exc)[:800]
            ) from exc

        return artifact


def rollback_successful(connection, run: dict):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT ri.artifact_json,pi.endpoint_a_id,pi.endpoint_b_id
            FROM tunnel_plan_run_items ri
            JOIN tunnel_plan_items pi ON pi.id=ri.plan_item_id
            WHERE ri.run_id=%s AND ri.status='SUCCESS'
            ORDER BY ri.order_index DESC
            """,
            (run["id"],),
        )
        rows = cursor.fetchall()

    for row in rows:
        artifact = json.loads(row["artifact_json"] or "{}")
        try:
            with remote_pair(connection, row["endpoint_a_id"], row["endpoint_b_id"]) as (
                remote_a,
                remote_b,
                _,
                __,
            ):
                rollback_artifact(remote_a, remote_b, artifact)
        except Exception as exc:
            add_event(
                connection,
                run["id"],
                f"Whole-plan rollback warning: {type(exc).__name__}: {str(exc)[:500]}",
                level="WARNING",
            )


def process_run(connection, run: dict):
    items = load_run_items(connection, run["id"])
    failures = 0

    for item in items:
        if cancel_requested(connection, run["id"]):
            finish_cancelled(connection, run)
            return

        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE tunnel_plan_runs SET current_order=%s WHERE id=%s",
                (item["order_index"], run["id"]),
            )
            cursor.execute(
                "UPDATE tunnel_plans SET current_order=%s,updated_at=%s WHERE id=%s",
                (item["order_index"], datetime.utcnow(), run["plan_id"]),
            )
            cursor.execute(
                "UPDATE tunnel_plan_run_items SET status='RUNNING',started_at=%s WHERE id=%s",
                (datetime.utcnow(), item["id"]),
            )
            cursor.execute(
                "UPDATE tunnel_plan_items SET status='RUNNING',last_error=NULL,updated_at=%s WHERE id=%s",
                (datetime.utcnow(), item["plan_item_id"]),
            )
        connection.commit()

        add_event(
            connection,
            run["id"],
            f"Starting item {item['order_index']}: {item['item_name']} ({item['method_id']}).",
            run_item_id=item["id"],
        )

        try:
            artifact = execute_item(connection, run, item)
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE tunnel_plan_run_items
                    SET status='SUCCESS',artifact_json=%s,error_message=NULL,finished_at=%s
                    WHERE id=%s
                    """,
                    (json.dumps(artifact, ensure_ascii=False), datetime.utcnow(), item["id"]),
                )
                cursor.execute(
                    "UPDATE tunnel_plan_items SET status='SUCCESS',last_error=NULL,updated_at=%s WHERE id=%s",
                    (datetime.utcnow(), item["plan_item_id"]),
                )
            connection.commit()
            add_event(
                connection,
                run["id"],
                f"Item {item['order_index']} completed and passed bidirectional post-tests.",
                run_item_id=item["id"],
                level="SUCCESS",
                details=artifact,
            )
        except Exception as exc:
            failures += 1
            error = f"{type(exc).__name__}: {str(exc)}"[:4000]
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE tunnel_plan_run_items
                    SET status='FAILED',error_message=%s,finished_at=%s
                    WHERE id=%s
                    """,
                    (error, datetime.utcnow(), item["id"]),
                )
                cursor.execute(
                    "UPDATE tunnel_plan_items SET status='FAILED',last_error=%s,updated_at=%s WHERE id=%s",
                    (error, datetime.utcnow(), item["plan_item_id"]),
                )
            connection.commit()
            add_event(
                connection,
                run["id"],
                f"Item {item['order_index']} failed: {error}",
                run_item_id=item["id"],
                level="ERROR",
            )

            if run["rollback_policy"] == "WHOLE_PLAN":
                rollback_successful(connection, run)

            if run["stop_policy"] == "STOP_ON_ERROR":
                with connection.cursor() as cursor:
                    cursor.execute(
                        "UPDATE tunnel_plan_run_items SET status='SKIPPED' WHERE run_id=%s AND status='WAITING'",
                        (run["id"],),
                    )
                    cursor.execute(
                        "UPDATE tunnel_plan_runs SET status='FAILED',error_message=%s,finished_at=%s WHERE id=%s",
                        (error, datetime.utcnow(), run["id"]),
                    )
                    cursor.execute(
                        "UPDATE tunnel_plans SET status='FAILED',updated_at=%s WHERE id=%s",
                        (datetime.utcnow(), run["plan_id"]),
                    )
                connection.commit()
                return

    final_run_status = "PARTIAL" if failures else "SUCCESS"
    final_plan_status = "PARTIAL" if failures else "ACTIVE"
    with connection.cursor() as cursor:
        cursor.execute(
            """
            UPDATE tunnel_plan_runs
            SET status=%s,current_order=total_items,finished_at=%s
            WHERE id=%s
            """,
            (final_run_status, datetime.utcnow(), run["id"]),
        )
        cursor.execute(
            """
            UPDATE tunnel_plans
            SET status=%s,current_order=total_items,updated_at=%s
            WHERE id=%s
            """,
            (final_plan_status, datetime.utcnow(), run["plan_id"]),
        )
    connection.commit()
    add_event(
        connection,
        run["id"],
        f"Sequential execution finished with status {final_run_status}.",
        level="SUCCESS" if final_run_status == "SUCCESS" else "WARNING",
    )


def fail_run(connection, run: dict, exc: Exception):
    error = f"{type(exc).__name__}: {str(exc)}"[:4000]
    with connection.cursor() as cursor:
        cursor.execute(
            "UPDATE tunnel_plan_runs SET status='FAILED',error_message=%s,finished_at=%s WHERE id=%s",
            (error, datetime.utcnow(), run["id"]),
        )
        cursor.execute(
            "UPDATE tunnel_plans SET status='FAILED',updated_at=%s WHERE id=%s",
            (datetime.utcnow(), run["plan_id"]),
        )
    connection.commit()
    add_event(connection, run["id"], "Execution engine failed: " + error, level="ERROR")


def get_run_id():
    item = redis_client.blpop("netauto:tunnel-runs", timeout=5)
    if item:
        try:
            return int(item[1])
        except ValueError:
            return None
    with db_connect() as connection:
        return next_run_id(connection)


def main():
    log.info("Plan executor started; supported=%s", ",".join(sorted(SUPPORTED)))
    while True:
        try:
            run_id = get_run_id()
            if run_id is None:
                continue
            with db_connect() as connection:
                run = claim_run(connection, run_id)
                if run is None:
                    continue
                add_event(
                    connection,
                    run["id"],
                    "Sequential execution started. Only one item is processed at a time.",
                    details={"supported_methods": sorted(SUPPORTED)},
                )
                try:
                    process_run(connection, run)
                except Exception as exc:
                    log.exception("Run %s failed", run["id"])
                    fail_run(connection, run, exc)
        except KeyboardInterrupt:
            break
        except Exception:
            log.exception("Executor loop failure")
            time.sleep(5)

# NETAUTO_VALIDATION_COMMON_FIX_BEGIN

def free_udp_port(
    remote: Remote,
    preferred: int,
) -> int:
    result = remote.run(
        (
            "ss -H -lun "
            "| awk '{print $4}' "
            "| sed 's/.*://' "
            "| sort -n -u"
        ),
        root=True,
        check=False,
    )

    used = {
        int(line.strip())
        for line in result["stdout"].splitlines()
        if line.strip().isdigit()
    }

    for port in range(
        max(1025, preferred),
        min(
            max(1025, preferred) + 2000,
            65535,
        ),
    ):
        if port not in used:
            return port

    raise RuntimeError("NO_FREE_UDP_PORT")


def free_port(
    remote: Remote,
    protocol: str,
    preferred: int,
) -> int:
    flag = (
        "-lun"
        if protocol.lower() == "udp"
        else "-ltn"
    )

    result = remote.run(
        (
            "ss -H "
            + flag
            + " | awk '{print $4}' "
            + "| sed 's/.*://' "
            + "| sort -n -u"
        ),
        root=True,
        check=False,
    )

    used = {
        int(line.strip())
        for line in result["stdout"].splitlines()
        if line.strip().isdigit()
    }

    for port in range(
        max(1025, preferred),
        65000,
    ):
        if port not in used:
            return port

    raise RuntimeError("NO_FREE_PORT")


def wait_service(
    remote: Remote,
    name: str,
):
    unit = shlex.quote(
        name + ".service"
    )

    remote.run(
        (
            "for i in $(seq 1 20); do "
            f"systemctl is-active --quiet {unit} "
            "&& exit 0; "
            "sleep 1; "
            "done; "
            "echo SERVICE_START_FAILED >&2; "
            f"systemctl status {unit} "
            "--no-pager -l >&2 || true; "
            f"journalctl -u {unit} "
            "-n 160 --no-pager >&2 || true; "
            "exit 1"
        ),
        root=True,
        timeout=40,
    )


def wait_listener(
    remote: Remote,
    protocol: str,
    port: int,
):
    flag = (
        "-lun"
        if protocol.lower() == "udp"
        else "-ltn"
    )

    remote.run(
        (
            "for i in $(seq 1 30); do "
            "ss -H "
            + flag
            + " | awk '{print $4}' "
            + f"| grep -Eq ':{int(port)}$' "
            + "&& exit 0; "
            + "sleep 1; "
            + "done; "
            + (
                "echo LISTENER_NOT_FOUND_"
                f"{protocol.upper()}_{int(port)} >&2; "
            )
            + "ss -H "
            + flag
            + " >&2 || true; "
            + (
                "systemctl --failed "
                "--no-pager -l >&2 || true; "
            )
            + (
                "journalctl -u 'netauto-*' "
                "-n 160 --no-pager >&2 || true; "
            )
            + "exit 1"
        ),
        root=True,
        timeout=45,
    )


def start_iperf_server(
    remote: Remote,
    bind_ip: str,
    port: int,
):
    family = (
        "-6"
        if ":" in bind_ip
        else "-4"
    )

    log_path = (
        f"/tmp/netauto-iperf-{int(port)}.log"
    )

    pattern = shlex.quote(
        (
            "[i]perf3 .* -p "
            f"{int(port)}( |$)"
        )
    )

    command = (
        "set -Eeuo pipefail\n"
        f"pkill -f {pattern} "
        "2>/dev/null || true\n"
        f"rm -f {shlex.quote(log_path)}\n"
        f"nohup iperf3 {family} "
        "-s -1 "
        f"-B {shlex.quote(bind_ip)} "
        f"-p {int(port)} "
        f">{shlex.quote(log_path)} "
        "2>&1 </dev/null &\n"
        "pid=$!\n"
        "for i in $(seq 1 40); do\n"
        "  if ! kill -0 \"$pid\" "
        "2>/dev/null; then\n"
        f"    cat {shlex.quote(log_path)} "
        ">&2 || true\n"
        "    exit 41\n"
        "  fi\n"
        "  if ss -H -ltn "
        "| awk '{print $4}' "
        f"| grep -Eq ':{int(port)}$'; then\n"
        "    exit 0\n"
        "  fi\n"
        "  sleep 0.25\n"
        "done\n"
        f"cat {shlex.quote(log_path)} "
        ">&2 || true\n"
        "ss -H -ltnp >&2 || true\n"
        "exit 42\n"
    )

    remote.run(
        command,
        root=True,
        timeout=25,
    )


# NETAUTO_VALIDATION_COMMON_FIX_END

# NETAUTO_IPERF_SYSTEMD_FIX_BEGIN

def start_iperf_server(
    remote: Remote,
    bind_ip: str,
    port: int,
):
    family = (
        "-6"
        if ":" in bind_ip
        else "-4"
    )

    unit = (
        "netauto-iperf-"
        + str(int(port))
    )

    command = (
        "set -Eeuo pipefail\n"
        f"systemctl stop {shlex.quote(unit)}.service "
        "2>/dev/null || true\n"
        f"systemctl reset-failed "
        f"{shlex.quote(unit)}.service "
        "2>/dev/null || true\n"
        f"systemd-run "
        f"--unit={shlex.quote(unit)} "
        "--collect "
        "--property=Type=simple "
        "--property=Restart=no "
        "--property=KillMode=mixed "
        "/usr/bin/iperf3 "
        f"{family} "
        "-s -1 "
        f"-B {shlex.quote(bind_ip)} "
        f"-p {int(port)} "
        ">/dev/null\n"
        "for i in $(seq 1 50); do\n"
        "  if ss -H -ltn "
        "| awk '{print $4}' "
        f"| grep -Eq ':{int(port)}$'; then\n"
        "    exit 0\n"
        "  fi\n"
        f"  if systemctl is-failed "
        f"{shlex.quote(unit)}.service "
        ">/dev/null 2>&1; then\n"
        f"    systemctl status "
        f"{shlex.quote(unit)}.service "
        "--no-pager -l >&2 || true\n"
        f"    journalctl -u "
        f"{shlex.quote(unit)}.service "
        "-n 120 --no-pager >&2 || true\n"
        "    exit 41\n"
        "  fi\n"
        "  sleep 0.2\n"
        "done\n"
        f"systemctl status "
        f"{shlex.quote(unit)}.service "
        "--no-pager -l >&2 || true\n"
        f"journalctl -u "
        f"{shlex.quote(unit)}.service "
        "-n 120 --no-pager >&2 || true\n"
        "ss -H -ltnp >&2 || true\n"
        "exit 42\n"
    )

    remote.run(
        command,
        root=True,
        timeout=30,
    )


# NETAUTO_IPERF_SYSTEMD_FIX_END

if __name__ == "__main__":
    main()
