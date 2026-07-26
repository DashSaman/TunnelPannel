import base64
import hashlib
import io
import json
import os
import shlex
import socket
import time
from datetime import datetime

import paramiko
import psycopg
from cryptography.fernet import Fernet
from psycopg.rows import dict_row
from redis import Redis


DATABASE_URL = os.environ["DATABASE_URL"].replace(
    "postgresql+psycopg://",
    "postgresql://",
)

REDIS_URL = os.environ["REDIS_URL"]
APP_SECRET_KEY = os.environ["APP_SECRET_KEY"]

redis_client = Redis.from_url(
    REDIS_URL,
    decode_responses=True,
)


def db_connect():
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
    )


def fernet():
    digest = hashlib.sha256(
        APP_SECRET_KEY.encode("utf-8")
    ).digest()

    return Fernet(
        base64.urlsafe_b64encode(digest)
    )


def decrypt_secret(value: str) -> str:
    return fernet().decrypt(
        value.encode("utf-8")
    ).decode("utf-8")


def emit(
    connection,
    job_id,
    step,
    message,
    level="INFO",
    command=None,
    output=None,
    progress=None,
):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO job_events (
                job_id,
                level,
                step,
                public_message,
                command,
                output,
                created_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                job_id,
                level,
                step,
                message,
                command,
                output,
                datetime.utcnow(),
            ),
        )

        if progress is not None:
            cursor.execute(
                """
                UPDATE jobs
                SET progress = %s,
                    current_step = %s
                WHERE id = %s
                """,
                (
                    progress,
                    step,
                    job_id,
                ),
            )

    connection.commit()


def load_private_key(raw_key: str):
    loaders = [
        paramiko.RSAKey,
        paramiko.ECDSAKey,
        paramiko.Ed25519Key,
    ]

    for loader in loaders:
        try:
            return loader.from_private_key(
                io.StringIO(raw_key)
            )
        except Exception:
            continue

    raise ValueError(
        "PRIVATE_KEY_FORMAT_UNSUPPORTED"
    )


def ssh_fingerprint(key) -> str:
    return ":".join(f"{byte:02x}" for byte in key.get_fingerprint()).lower()


class EndpointHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Accept the first key, then enforce the stored endpoint fingerprint."""

    def __init__(self, expected: str | None):
        self.expected = (expected or "").strip().lower()

    def missing_host_key(self, client, hostname, key):
        actual = ssh_fingerprint(key)
        if self.expected and actual != self.expected:
            raise paramiko.SSHException("SSH_HOST_KEY_MISMATCH")
        client._host_keys.add(hostname, key.get_name(), key)


def run_command(client, command: str):
    stdin, stdout, stderr = client.exec_command(
        command,
        timeout=25,
    )

    output = stdout.read().decode(
        "utf-8",
        errors="replace",
    )

    error = stderr.read().decode(
        "utf-8",
        errors="replace",
    )

    return (
        output.strip(),
        error.strip(),
        stdout.channel.recv_exit_status(),
    )


def parse_os_release(value: str):
    result = {}

    for line in value.splitlines():
        if "=" not in line:
            continue

        key, raw = line.split("=", 1)
        result[key] = raw.strip().strip('"')

    return result



def queue_inventory_job(
    connection,
    owner_user_id,
    endpoint_id,
):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT id
            FROM jobs
            WHERE endpoint_id = %s
              AND job_type = 'ENDPOINT_INVENTORY'
              AND status IN (
                'QUEUED',
                'RUNNING',
                'RETRY'
              )
            LIMIT 1
            """,
            (endpoint_id,),
        )

        if cursor.fetchone():
            return

        cursor.execute(
            """
            INSERT INTO jobs (
                owner_user_id,
                endpoint_id,
                job_type,
                status,
                progress,
                current_step,
                created_at
            )
            VALUES (
                %s,
                %s,
                'ENDPOINT_INVENTORY',
                'QUEUED',
                0,
                'inventory_queue',
                %s
            )
            RETURNING id
            """,
            (
                owner_user_id,
                endpoint_id,
                datetime.utcnow(),
            ),
        )

        job_id = cursor.fetchone()["id"]

        cursor.execute(
            """
            INSERT INTO job_events (
                job_id,
                level,
                step,
                public_message,
                created_at
            )
            VALUES (
                %s,
                'INFO',
                'inventory_queue',
                'Network inventory scan queued.',
                %s
            )
            """,
            (
                job_id,
                datetime.utcnow(),
            ),
        )

        cursor.execute(
            """
            INSERT INTO network_inventories (
                endpoint_id,
                status,
                summary_json,
                inventory_json,
                updated_at
            )
            VALUES (
                %s,
                'QUEUED',
                '{}',
                '{}',
                %s
            )
            ON CONFLICT (endpoint_id)
            DO UPDATE SET
                status = 'QUEUED',
                last_error = NULL,
                updated_at = EXCLUDED.updated_at
            """,
            (
                endpoint_id,
                datetime.utcnow(),
            ),
        )

    connection.commit()

    try:
        redis_client.rpush(
            "netauto:jobs",
            json.dumps(
                {
                    "id": job_id,
                    "type": "ENDPOINT_INVENTORY",
                }
            ),
        )
    except Exception as exc:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE jobs
                SET status = 'FAILED',
                    error_message = %s,
                    finished_at = %s
                WHERE id = %s
                """,
                (
                    f"QUEUE_ERROR: {type(exc).__name__}",
                    datetime.utcnow(),
                    job_id,
                ),
            )

            cursor.execute(
                """
                UPDATE network_inventories
                SET status = 'ERROR',
                    last_error = 'QUEUE_ERROR',
                    updated_at = %s
                WHERE endpoint_id = %s
                """,
                (
                    datetime.utcnow(),
                    endpoint_id,
                ),
            )

        connection.commit()


def process_endpoint_discovery(
    connection,
    job,
):
    job_id = job["id"]
    endpoint_id = job["endpoint_id"]

    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT
                e.*,
                c.encrypted_blob
            FROM endpoints e
            JOIN endpoint_credentials c
              ON c.endpoint_id = e.id
            WHERE e.id = %s
            """,
            (endpoint_id,),
        )

        endpoint = cursor.fetchone()

    if not endpoint:
        raise RuntimeError(
            "ENDPOINT_NOT_FOUND"
        )

    credentials = json.loads(
        decrypt_secret(
            endpoint["encrypted_blob"]
        )
    )

    emit(
        connection,
        job_id,
        "validate",
        "در حال بررسی مشخصات Endpoint...",
        progress=5,
    )

    host = endpoint["host"]
    port = endpoint["port"]

    emit(
        connection,
        job_id,
        "tcp",
        "در حال بررسی دسترسی به پورت SSH...",
        command=f"TCP connect {host}:{port}",
        progress=15,
    )

    with socket.create_connection(
        (host, port),
        timeout=12,
    ):
        pass

    emit(
        connection,
        job_id,
        "tcp",
        "پورت SSH در دسترس است.",
        level="SUCCESS",
        output="TCP connection established",
        progress=25,
    )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(
        EndpointHostKeyPolicy(
            endpoint.get("host_key_fingerprint")
        )
    )

    connect_kwargs = {
        "hostname": host,
        "port": port,
        "username": endpoint["ssh_username"],
        "timeout": 18,
        "banner_timeout": 18,
        "auth_timeout": 18,
        "allow_agent": False,
        "look_for_keys": False,
    }

    if credentials["auth_method"] == "PASSWORD":
        connect_kwargs["password"] = (
            credentials["secret"]
        )
    else:
        connect_kwargs["pkey"] = load_private_key(
            credentials["secret"]
        )

    emit(
        connection,
        job_id,
        "ssh",
        "در حال ایجاد نشست امن SSH...",
        progress=35,
    )

    client.connect(**connect_kwargs)

    transport = client.get_transport()

    fingerprint = None

    if transport:
        server_key = transport.get_remote_server_key()
        fingerprint = ssh_fingerprint(server_key)

    emit(
        connection,
        job_id,
        "ssh",
        "ورود SSH با موفقیت انجام شد.",
        level="SUCCESS",
        output=(
            f"Host key fingerprint: {fingerprint}"
            if fingerprint
            else "SSH authenticated"
        ),
        progress=45,
    )

    commands = [
        (
            "os",
            "در حال شناسایی سیستم‌عامل...",
            "cat /etc/os-release",
            55,
        ),
        (
            "arch",
            "در حال شناسایی معماری پردازنده...",
            "uname -m",
            63,
        ),
        (
            "hostname",
            "در حال دریافت نام میزبان...",
            "hostname",
            70,
        ),
        (
            "interfaces",
            "در حال بررسی Interfaceهای شبکه...",
            "ip -br address",
            78,
        ),
        (
            "route",
            "در حال بررسی مسیر پیش‌فرض...",
            "ip route show default",
            85,
        ),
        (
            "privilege",
            "در حال بررسی دسترسی مدیریتی...",
            "id -u",
            90,
        ),
    ]

    results = {}

    for step, message, command, progress in commands:
        emit(
            connection,
            job_id,
            step,
            message,
            command=command,
            progress=progress,
        )

        output, error, exit_code = run_command(
            client,
            command,
        )

        combined = output

        if error:
            combined = (
                f"{output}\n{error}"
            ).strip()

        results[step] = output

        emit(
            connection,
            job_id,
            step,
            "مرحله با موفقیت انجام شد."
            if exit_code == 0
            else "مرحله با هشدار پایان یافت.",
            level="SUCCESS"
            if exit_code == 0
            else "WARNING",
            command=command,
            output=combined[:20000],
            progress=progress,
        )

    sudo_mode = credentials.get(
        "sudo_mode",
        "NONE",
    )

    if sudo_mode == "PASSWORDLESS":
        command = "sudo -n true"
        output, error, code = run_command(
            client,
            command,
        )

        emit(
            connection,
            job_id,
            "sudo",
            "دسترسی sudo بدون رمز بررسی شد.",
            level="SUCCESS"
            if code == 0
            else "WARNING",
            command=command,
            output=(output or error)[:10000],
            progress=94,
        )

    elif sudo_mode == "PASSWORD":
        command = "sudo -S -p '' true"
        stdin, stdout, stderr = client.exec_command(
            command,
            timeout=20,
        )

        stdin.write(
            (
                credentials.get(
                    "sudo_password",
                    "",
                )
                + "\n"
            )
        )
        stdin.flush()

        output = stdout.read().decode(
            "utf-8",
            errors="replace",
        )

        error = stderr.read().decode(
            "utf-8",
            errors="replace",
        )

        code = stdout.channel.recv_exit_status()

        emit(
            connection,
            job_id,
            "sudo",
            "دسترسی sudo بررسی شد.",
            level="SUCCESS"
            if code == 0
            else "WARNING",
            command="sudo [REDACTED] true",
            output=(output or error)[:10000],
            progress=94,
        )

    client.close()

    os_info = parse_os_release(
        results.get("os", "")
    )

    default_route = results.get(
        "route",
        "",
    ).split()

    interface = None

    if "dev" in default_route:
        index = default_route.index("dev")

        if index + 1 < len(default_route):
            interface = default_route[index + 1]

    with connection.cursor() as cursor:
        cursor.execute(
            """
            UPDATE endpoints
            SET status = 'READY',
                detected_os = %s,
                detected_version = %s,
                detected_hostname = %s,
                detected_arch = %s,
                primary_interface = %s,
                public_ip = %s,
                host_key_fingerprint = %s,
                last_error = NULL,
                updated_at = %s
            WHERE id = %s
            """,
            (
                os_info.get(
                    "NAME",
                    "Linux",
                ),
                os_info.get(
                    "VERSION_ID",
                ),
                results.get(
                    "hostname",
                    "",
                ).strip() or None,
                results.get(
                    "arch",
                    "",
                ).strip() or None,
                interface,
                host
                if not any(
                    character.isalpha()
                    for character in host
                )
                else None,
                fingerprint,
                datetime.utcnow(),
                endpoint_id,
            ),
        )

        cursor.execute(
            """
            UPDATE jobs
            SET status = 'SUCCESS',
                progress = 100,
                current_step = 'complete',
                finished_at = %s
            WHERE id = %s
            """,
            (
                datetime.utcnow(),
                job_id,
            ),
        )

    connection.commit()

    emit(
        connection,
        job_id,
        "complete",
        "Endpoint با موفقیت ثبت و آماده استفاده شد.",
        level="SUCCESS",
        progress=100,
    )





    try:
        queue_inventory_job(
            connection,
            job["owner_user_id"],
            endpoint_id,
        )
    except Exception as exc:
        print(
            "Unable to queue automatic inventory: "
            f"{type(exc).__name__}: {exc}",
            flush=True,
        )

def load_endpoint_bundle(
    connection,
    endpoint_id,
):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT
                e.*,
                c.encrypted_blob
            FROM endpoints e
            JOIN endpoint_credentials c
              ON c.endpoint_id = e.id
            WHERE e.id = %s
            """,
            (endpoint_id,),
        )
        endpoint = cursor.fetchone()

    if not endpoint:
        raise RuntimeError("ENDPOINT_NOT_FOUND")

    credentials = json.loads(
        decrypt_secret(
            endpoint["encrypted_blob"]
        )
    )

    return endpoint, credentials


def connect_endpoint(
    endpoint,
    credentials,
):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(
        EndpointHostKeyPolicy(
            endpoint.get("host_key_fingerprint")
        )
    )

    kwargs = {
        "hostname": endpoint["host"],
        "port": endpoint["port"],
        "username": endpoint["ssh_username"],
        "timeout": 18,
        "banner_timeout": 18,
        "auth_timeout": 18,
        "allow_agent": False,
        "look_for_keys": False,
    }

    if credentials["auth_method"] == "PASSWORD":
        kwargs["password"] = credentials["secret"]
    else:
        kwargs["pkey"] = load_private_key(
            credentials["secret"]
        )

    client.connect(**kwargs)
    return client


def resolve_peer(host):
    results = socket.getaddrinfo(
        host,
        None,
        type=socket.SOCK_STREAM,
    )

    if not results:
        raise RuntimeError("PEER_DNS_RESOLUTION_FAILED")

    return results[0][4][0]


def execute_probe(
    connection,
    job_id,
    client,
    step,
    message,
    command,
    progress,
    failure_is_error=False,
):
    emit(
        connection,
        job_id,
        step,
        message,
        command=command,
        progress=progress,
    )

    output, error, code = run_command(
        client,
        command,
    )

    combined = (
        output
        if not error
        else f"{output}\n{error}".strip()
    )

    emit(
        connection,
        job_id,
        step,
        (
            "Probe completed successfully."
            if code == 0
            else "Probe did not receive a successful response."
        ),
        level=(
            "SUCCESS"
            if code == 0
            else (
                "ERROR"
                if failure_is_error
                else "WARNING"
            )
        ),
        command=command,
        output=combined[:20000],
        progress=progress,
    )

    return {
        "success": code == 0,
        "exit_code": code,
        "output": combined[:20000],
    }



def safe_json_load(
    value,
    default,
):
    try:
        return json.loads(value)
    except Exception:
        return default


def parse_listening_ports(value):
    items = []

    for line in value.splitlines():
        parts = line.split()

        if len(parts) < 5:
            continue

        protocol = parts[0].lower()
        local = parts[4]

        if protocol not in {
            "tcp",
            "udp",
        }:
            continue

        try:
            address, port = local.rsplit(
                ":",
                1,
            )

            port_number = int(
                port.replace("*", "0")
            )
        except Exception:
            continue

        items.append(
            {
                "protocol": protocol,
                "address": address,
                "port": port_number,
            }
        )

    unique = {}

    for item in items:
        key = (
            item["protocol"],
            item["address"],
            item["port"],
        )
        unique[key] = item

    return list(unique.values())


def parse_wireguard(value):
    interfaces = []
    current = None

    for line in value.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.startswith("interface="):
            if current:
                interfaces.append(current)

            current = {
                "interface": line.split(
                    "=",
                    1,
                )[1],
                "peers": [],
                "allowed_ips": [],
                "endpoints": [],
            }

        elif current and "=" in line:
            key, raw = line.split(
                "=",
                1,
            )

            if key == "public_key":
                current["public_key"] = raw
            elif key == "listen_port":
                try:
                    current["listen_port"] = int(raw)
                except ValueError:
                    current["listen_port"] = 0
            elif key == "peer":
                current["peers"].append(raw)
            elif key == "allowed_ips":
                current["allowed_ips"].append(raw)
            elif key == "endpoint":
                current["endpoints"].append(raw)

    if current:
        interfaces.append(current)

    return interfaces


def process_endpoint_inventory(
    connection,
    job,
):
    job_id = job["id"]
    endpoint_id = job["endpoint_id"]
    client = None

    try:
        endpoint, credentials = load_endpoint_bundle(
            connection,
            endpoint_id,
        )

        emit(
            connection,
            job_id,
            "inventory_connect",
            "Connecting to endpoint for a read-only inventory scan...",
            progress=5,
        )

        client = connect_endpoint(
            endpoint,
            credentials,
        )

        emit(
            connection,
            job_id,
            "inventory_connect",
            "Secure endpoint session established.",
            level="SUCCESS",
            progress=10,
        )

        commands = [
            (
                "addresses",
                "inventory_addresses",
                "Collecting network addresses...",
                "ip -j address show",
                18,
            ),
            (
                "links",
                "inventory_links",
                "Collecting interface and tunnel details...",
                "ip -d -j link show",
                28,
            ),
            (
                "routes4",
                "inventory_routes",
                "Collecting IPv4 routes...",
                "ip -j route show table all",
                38,
            ),
            (
                "routes6",
                "inventory_routes",
                "Collecting IPv6 routes...",
                "ip -j -6 route show table all",
                47,
            ),
            (
                "ports",
                "inventory_ports",
                "Collecting listening TCP and UDP ports...",
                "ss -H -lntup 2>/dev/null || ss -H -lntu",
                57,
            ),
            (
                "wireguard",
                "inventory_wireguard",
                "Collecting WireGuard metadata...",
                (
                    "if command -v wg >/dev/null 2>&1; then "
                    "for i in $(wg show interfaces); do "
                    "echo interface=$i; "
                    "echo public_key=$(wg show $i public-key); "
                    "echo listen_port=$(wg show $i listen-port); "
                    "wg show $i peers | sed 's/^/peer=/'; "
                    "wg show $i allowed-ips | sed 's/^/allowed_ips=/'; "
                    "wg show $i endpoints | sed 's/^/endpoint=/'; "
                    "done; fi"
                ),
                65,
            ),
            (
                "docker",
                "inventory_docker",
                "Collecting Docker network information...",
                (
                    "if command -v docker >/dev/null 2>&1; then "
                    "ids=$(docker network ls -q 2>/dev/null); "
                    "if [ -n \"$ids\" ]; then "
                    "docker network inspect $ids 2>/dev/null; "
                    "else echo '[]'; fi; "
                    "else echo '[]'; fi"
                ),
                74,
            ),
            (
                "namespaces",
                "inventory_namespaces",
                "Collecting network namespaces...",
                "ip netns list 2>/dev/null || true",
                81,
            ),
            (
                "xfrm",
                "inventory_xfrm",
                "Collecting IPsec/XFRM metadata...",
                (
                    "echo '[states]'; "
                    "ip xfrm state list 2>/dev/null "
                    "| awk '/^src /{print}'; "
                    "echo '[policies]'; "
                    "ip xfrm policy list 2>/dev/null || true"
                ),
                88,
            ),
        ]

        outputs = {}
        scan_errors = []

        for (
            key,
            step,
            message,
            command,
            progress,
        ) in commands:
            emit(
                connection,
                job_id,
                step,
                message,
                command=command,
                progress=progress,
            )

            output, error, code = run_command(
                client,
                command,
            )

            outputs[key] = output

            if code != 0:
                scan_errors.append(
                    {
                        "section": key,
                        "error": error[:1000],
                    }
                )

            emit(
                connection,
                job_id,
                step,
                (
                    "Inventory section collected."
                    if code == 0
                    else "Inventory section completed with a warning."
                ),
                level=(
                    "SUCCESS"
                    if code == 0
                    else "WARNING"
                ),
                command=command,
                output=(
                    output
                    if output
                    else error
                )[:20000],
                progress=progress,
            )

        addresses_json = safe_json_load(
            outputs.get(
                "addresses",
                "[]",
            ),
            [],
        )

        links_json = safe_json_load(
            outputs.get(
                "links",
                "[]",
            ),
            [],
        )

        routes4 = safe_json_load(
            outputs.get(
                "routes4",
                "[]",
            ),
            [],
        )

        routes6 = safe_json_load(
            outputs.get(
                "routes6",
                "[]",
            ),
            [],
        )

        docker_json = safe_json_load(
            outputs.get(
                "docker",
                "[]",
            ),
            [],
        )

        interfaces = []
        addresses = []
        cidrs = set()

        for interface in addresses_json:
            interface_name = interface.get(
                "ifname",
                "",
            )

            interfaces.append(
                {
                    "name": interface_name,
                    "state": interface.get(
                        "operstate"
                    ),
                    "mtu": interface.get(
                        "mtu"
                    ),
                    "mac": interface.get(
                        "address"
                    ),
                }
            )

            for address in interface.get(
                "addr_info",
                [],
            ):
                local = address.get("local")
                prefix = address.get(
                    "prefixlen"
                )

                if (
                    not local
                    or prefix is None
                ):
                    continue

                cidr = f"{local}/{prefix}"
                cidrs.add(cidr)

                addresses.append(
                    {
                        "interface": interface_name,
                        "family": address.get(
                            "family"
                        ),
                        "address": local,
                        "prefix": prefix,
                        "cidr": cidr,
                        "scope": address.get(
                            "scope"
                        ),
                    }
                )

        routes = []

        for route in routes4 + routes6:
            destination = route.get(
                "dst",
                "default",
            )

            item = {
                "family": (
                    "ipv6"
                    if ":" in str(destination)
                    or ":" in str(
                        route.get("gateway", "")
                    )
                    else "ipv4"
                ),
                "destination": destination,
                "gateway": route.get(
                    "gateway"
                ),
                "interface": route.get(
                    "dev"
                ),
                "table": route.get(
                    "table"
                ),
                "protocol": route.get(
                    "protocol"
                ),
                "metric": route.get(
                    "metric"
                ),
            }

            routes.append(item)

            if destination != "default":
                cidrs.add(str(destination))

        tunnel_kinds = {
            "wireguard",
            "gre",
            "gretap",
            "ip6gre",
            "ip6gretap",
            "ipip",
            "sit",
            "vxlan",
            "vti",
            "vti6",
            "tun",
            "tap",
            "xfrm",
        }

        tunnels = []
        vxlan_vnis = set()
        tunnel_keys = []
        tunnel_pairs = []

        for link in links_json:
            linkinfo = link.get(
                "linkinfo",
                {},
            ) or {}

            kind = linkinfo.get(
                "info_kind"
            )

            if kind not in tunnel_kinds:
                continue

            info_data = linkinfo.get(
                "info_data",
                {},
            ) or {}

            interface_name = link.get(
                "ifname",
                "",
            )

            tunnel = {
                "interface": interface_name,
                "kind": kind,
                "state": link.get(
                    "operstate"
                ),
                "mtu": link.get(
                    "mtu"
                ),
                "local": info_data.get(
                    "local"
                ),
                "remote": info_data.get(
                    "remote"
                ),
                "link": info_data.get(
                    "link"
                ),
                "details": info_data,
            }

            tunnels.append(tunnel)

            if kind == "vxlan":
                vni = info_data.get("id")

                if isinstance(vni, int):
                    vxlan_vnis.add(vni)

            for key_name in (
                "key",
                "ikey",
                "okey",
            ):
                value = info_data.get(
                    key_name
                )

                if value is not None:
                    tunnel_keys.append(
                        {
                            "interface": (
                                interface_name
                            ),
                            "kind": kind,
                            "direction": key_name,
                            "key": str(value),
                        }
                    )

            if (
                info_data.get("local")
                or info_data.get("remote")
            ):
                tunnel_pairs.append(
                    {
                        "interface": (
                            interface_name
                        ),
                        "kind": kind,
                        "local": info_data.get(
                            "local"
                        ),
                        "remote": info_data.get(
                            "remote"
                        ),
                    }
                )

        listening_ports = parse_listening_ports(
            outputs.get(
                "ports",
                "",
            )
        )

        wireguard = parse_wireguard(
            outputs.get(
                "wireguard",
                "",
            )
        )

        for wg_interface in wireguard:
            port = wg_interface.get(
                "listen_port"
            )

            if port:
                listening_ports.append(
                    {
                        "protocol": "udp",
                        "address": "*",
                        "port": port,
                        "source": "wireguard",
                    }
                )

        docker_networks = []

        for network in docker_json:
            subnets = []

            for item in (
                network.get(
                    "IPAM",
                    {},
                )
                .get(
                    "Config",
                    [],
                )
                or []
            ):
                subnet = item.get(
                    "Subnet"
                )

                if subnet:
                    subnets.append(subnet)
                    cidrs.add(subnet)

            docker_networks.append(
                {
                    "id": network.get("Id"),
                    "name": network.get(
                        "Name"
                    ),
                    "driver": network.get(
                        "Driver"
                    ),
                    "scope": network.get(
                        "Scope"
                    ),
                    "subnets": subnets,
                }
            )

        namespaces = [
            line.split()[0]
            for line in outputs.get(
                "namespaces",
                "",
            ).splitlines()
            if line.strip()
        ]

        interface_names = sorted(
            {
                item.get("name")
                for item in interfaces
                if item.get("name")
            }
        )

        unique_ports = {}

        for item in listening_ports:
            key = (
                item.get("protocol"),
                item.get("address"),
                item.get("port"),
            )
            unique_ports[key] = item

        listening_ports = list(
            unique_ports.values()
        )

        resources = {
            "cidrs": sorted(cidrs),
            "interface_names": (
                interface_names
            ),
            "ports": listening_ports,
            "vxlan_vnis": sorted(
                vxlan_vnis
            ),
            "tunnel_keys": tunnel_keys,
            "tunnel_pairs": tunnel_pairs,
        }

        summary = {
            "interfaces": len(interfaces),
            "addresses": len(addresses),
            "routes": len(routes),
            "tunnels": len(tunnels),
            "listening_ports": len(
                listening_ports
            ),
            "wireguard_interfaces": len(
                wireguard
            ),
            "docker_networks": len(
                docker_networks
            ),
            "namespaces": len(
                namespaces
            ),
            "scan_warnings": len(
                scan_errors
            ),
        }

        inventory = {
            "interfaces": interfaces,
            "addresses": addresses,
            "routes": routes,
            "tunnels": tunnels,
            "listening_ports": (
                listening_ports
            ),
            "wireguard": wireguard,
            "docker_networks": (
                docker_networks
            ),
            "namespaces": namespaces,
            "xfrm": outputs.get(
                "xfrm",
                "",
            ).splitlines(),
            "resources": resources,
            "scan_errors": scan_errors,
            "raw": outputs,
        }

        now = datetime.utcnow()

        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO network_inventories (
                    endpoint_id,
                    status,
                    summary_json,
                    inventory_json,
                    last_error,
                    scanned_at,
                    updated_at
                )
                VALUES (
                    %s,
                    'READY',
                    %s,
                    %s,
                    NULL,
                    %s,
                    %s
                )
                ON CONFLICT (endpoint_id)
                DO UPDATE SET
                    status = 'READY',
                    summary_json = EXCLUDED.summary_json,
                    inventory_json = EXCLUDED.inventory_json,
                    last_error = NULL,
                    scanned_at = EXCLUDED.scanned_at,
                    updated_at = EXCLUDED.updated_at
                """,
                (
                    endpoint_id,
                    json.dumps(
                        summary,
                        ensure_ascii=False,
                    ),
                    json.dumps(
                        inventory,
                        ensure_ascii=False,
                    ),
                    now,
                    now,
                ),
            )

            cursor.execute(
                """
                UPDATE jobs
                SET status = 'SUCCESS',
                    progress = 100,
                    current_step = 'inventory_complete',
                    error_message = NULL,
                    finished_at = %s
                WHERE id = %s
                """,
                (
                    now,
                    job_id,
                ),
            )

        connection.commit()

        emit(
            connection,
            job_id,
            "inventory_complete",
            "Network inventory completed successfully.",
            level="SUCCESS",
            output=json.dumps(
                summary,
                indent=2,
            ),
            progress=100,
        )

    except Exception as exc:
        safe_error = (
            f"{type(exc).__name__}: {exc}"
        )[:2000]

        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO network_inventories (
                    endpoint_id,
                    status,
                    summary_json,
                    inventory_json,
                    last_error,
                    updated_at
                )
                VALUES (
                    %s,
                    'ERROR',
                    '{}',
                    '{}',
                    %s,
                    %s
                )
                ON CONFLICT (endpoint_id)
                DO UPDATE SET
                    status = 'ERROR',
                    last_error = EXCLUDED.last_error,
                    updated_at = EXCLUDED.updated_at
                """,
                (
                    endpoint_id,
                    safe_error,
                    datetime.utcnow(),
                ),
            )

        connection.commit()
        raise

    finally:
        if client:
            client.close()


def process_pair_precheck(
    connection,
    job,
):
    job_id = job["id"]

    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT *
            FROM pair_prechecks
            WHERE job_id = %s
            """,
            (job_id,),
        )
        precheck = cursor.fetchone()

    if not precheck:
        raise RuntimeError("PAIR_PRECHECK_NOT_FOUND")

    endpoint_a, credentials_a = load_endpoint_bundle(
        connection,
        precheck["endpoint_a_id"],
    )
    endpoint_b, credentials_b = load_endpoint_bundle(
        connection,
        precheck["endpoint_b_id"],
    )

    emit(
        connection,
        job_id,
        "connect_a",
        "Connecting securely to endpoint A...",
        progress=8,
    )
    client_a = connect_endpoint(
        endpoint_a,
        credentials_a,
    )

    emit(
        connection,
        job_id,
        "connect_a",
        "Endpoint A SSH session established.",
        level="SUCCESS",
        progress=15,
    )

    emit(
        connection,
        job_id,
        "connect_b",
        "Connecting securely to endpoint B...",
        progress=20,
    )
    client_b = connect_endpoint(
        endpoint_b,
        credentials_b,
    )

    emit(
        connection,
        job_id,
        "connect_b",
        "Endpoint B SSH session established.",
        level="SUCCESS",
        progress=27,
    )

    try:
        peer_a = resolve_peer(endpoint_a["host"])
        peer_b = resolve_peer(endpoint_b["host"])

        ping_ab = execute_probe(
            connection,
            job_id,
            client_a,
            "ping_ab",
            "Testing ICMP from endpoint A to endpoint B...",
            f"ping -c 3 -W 2 {shlex.quote(peer_b)}",
            35,
        )

        route_ab_command = (
            "ip -6 route get"
            if ":" in peer_b
            else "ip route get"
        ) + f" {shlex.quote(peer_b)}"

        route_ab = execute_probe(
            connection,
            job_id,
            client_a,
            "route_ab",
            "Inspecting route from endpoint A to endpoint B...",
            route_ab_command,
            43,
        )

        tcp_ab_python = (
            "import socket; "
            f"s=socket.create_connection(({peer_b!r},"
            f"{int(endpoint_b['port'])}),6); "
            "print('TCP_OK'); s.close()"
        )

        tcp_ab = execute_probe(
            connection,
            job_id,
            client_a,
            "tcp_ab",
            "Testing TCP from endpoint A to endpoint B...",
            "python3 -c "
            + shlex.quote(tcp_ab_python),
            52,
            failure_is_error=True,
        )

        ping_ba = execute_probe(
            connection,
            job_id,
            client_b,
            "ping_ba",
            "Testing ICMP from endpoint B to endpoint A...",
            f"ping -c 3 -W 2 {shlex.quote(peer_a)}",
            62,
        )

        route_ba_command = (
            "ip -6 route get"
            if ":" in peer_a
            else "ip route get"
        ) + f" {shlex.quote(peer_a)}"

        route_ba = execute_probe(
            connection,
            job_id,
            client_b,
            "route_ba",
            "Inspecting route from endpoint B to endpoint A...",
            route_ba_command,
            71,
        )

        tcp_ba_python = (
            "import socket; "
            f"s=socket.create_connection(({peer_a!r},"
            f"{int(endpoint_a['port'])}),6); "
            "print('TCP_OK'); s.close()"
        )

        tcp_ba = execute_probe(
            connection,
            job_id,
            client_b,
            "tcp_ba",
            "Testing TCP from endpoint B to endpoint A...",
            "python3 -c "
            + shlex.quote(tcp_ba_python),
            82,
            failure_is_error=True,
        )

        if tcp_ab["success"] and tcp_ba["success"]:
            connectivity = "BIDIRECTIONAL"
            final_status = "SUCCESS"
            precheck_status = "READY"
            final_level = "SUCCESS"
            final_message = (
                "Bidirectional TCP connectivity is available."
            )
            error_message = None

        elif tcp_ab["success"]:
            connectivity = "A_TO_B_ONLY"
            final_status = "FAILED"
            precheck_status = "BLOCKED"
            final_level = "ERROR"
            final_message = (
                "Only endpoint A can reach endpoint B."
            )
            error_message = "A_TO_B_ONLY"

        elif tcp_ba["success"]:
            connectivity = "B_TO_A_ONLY"
            final_status = "FAILED"
            precheck_status = "BLOCKED"
            final_level = "ERROR"
            final_message = (
                "Only endpoint B can reach endpoint A."
            )
            error_message = "B_TO_A_ONLY"

        else:
            connectivity = "BLOCKED"
            final_status = "FAILED"
            precheck_status = "BLOCKED"
            final_level = "ERROR"
            final_message = (
                "TCP connectivity is unavailable in both directions."
            )
            error_message = "BIDIRECTIONAL_TCP_BLOCKED"

        result = {
            "connectivity": connectivity,
            "endpoint_a": {
                "id": endpoint_a["id"],
                "name": endpoint_a["name"],
                "resolved_ip": peer_a,
            },
            "endpoint_b": {
                "id": endpoint_b["id"],
                "name": endpoint_b["name"],
                "resolved_ip": peer_b,
            },
            "a_to_b": {
                "ping": ping_ab,
                "route": route_ab,
                "tcp": tcp_ab,
            },
            "b_to_a": {
                "ping": ping_ba,
                "route": route_ba,
                "tcp": tcp_ba,
            },
        }

        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE pair_prechecks
                SET status = %s,
                    result_json = %s,
                    finished_at = %s
                WHERE id = %s
                """,
                (
                    precheck_status,
                    json.dumps(result),
                    datetime.utcnow(),
                    precheck["id"],
                ),
            )

            cursor.execute(
                """
                UPDATE jobs
                SET status = %s,
                    progress = 100,
                    current_step = %s,
                    error_message = %s,
                    finished_at = %s
                WHERE id = %s
                """,
                (
                    final_status,
                    (
                        "complete"
                        if final_status == "SUCCESS"
                        else "failed"
                    ),
                    error_message,
                    datetime.utcnow(),
                    job_id,
                ),
            )

        connection.commit()

        emit(
            connection,
            job_id,
            "summary",
            final_message,
            level=final_level,
            output=json.dumps(
                {
                    "connectivity": connectivity,
                    "ping_a_to_b": ping_ab["success"],
                    "tcp_a_to_b": tcp_ab["success"],
                    "ping_b_to_a": ping_ba["success"],
                    "tcp_b_to_a": tcp_ba["success"],
                },
                indent=2,
            ),
            progress=100,
        )

    finally:
        client_a.close()
        client_b.close()


def process_job(job_id: int):
    with db_connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT *
                FROM jobs
                WHERE id = %s
                FOR UPDATE
                """,
                (job_id,),
            )

            job = cursor.fetchone()

            if not job:
                return

            if job["status"] not in {
                "QUEUED",
                "RETRY",
            }:
                return

            cursor.execute(
                """
                UPDATE jobs
                SET status = 'RUNNING',
                    started_at = %s,
                    current_step = 'starting'
                WHERE id = %s
                """,
                (
                    datetime.utcnow(),
                    job_id,
                ),
            )

        connection.commit()

        try:
            if job["job_type"] == "ENDPOINT_DISCOVERY":
                process_endpoint_discovery(
                    connection,
                    job,
                )
            elif job["job_type"] == "ENDPOINT_INVENTORY":
                process_endpoint_inventory(
                    connection,
                    job,
                )
            elif job["job_type"] == "ENDPOINT_PAIR_PRECHECK":
                process_pair_precheck(
                    connection,
                    job,
                )
            else:
                raise RuntimeError(
                    "UNSUPPORTED_JOB_TYPE"
                )

        except Exception as exc:
            safe_error = (
                f"{type(exc).__name__}: {str(exc)}"
            )[:2000]

            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE jobs
                    SET status = 'FAILED',
                        current_step = 'failed',
                        error_message = %s,
                        finished_at = %s
                    WHERE id = %s
                    """,
                    (
                        safe_error,
                        datetime.utcnow(),
                        job_id,
                    ),
                )

                if (
                    job.get("endpoint_id")
                    and job.get("job_type")
                    == "ENDPOINT_DISCOVERY"
                ):
                    cursor.execute(
                        """
                        UPDATE endpoints
                        SET status = 'ERROR',
                            last_error = %s,
                            updated_at = %s
                        WHERE id = %s
                        """,
                        (
                            safe_error,
                            datetime.utcnow(),
                            job["endpoint_id"],
                        ),
                    )

            connection.commit()

            emit(
                connection,
                job_id,
                "failed",
                "عملیات متوقف شد. جزئیات خطا برای مدیر ثبت شد.",
                level="ERROR",
                output=safe_error,
            )


print("netauto-worker started")

while True:
    item = redis_client.blpop(
        "netauto:jobs",
        timeout=10,
    )

    if item is None:
        continue

    _, raw_job = item

    try:
        payload = json.loads(raw_job)
        process_job(int(payload["id"]))
    except Exception as exc:
        print(
            f"Invalid job payload: "
            f"{type(exc).__name__}: {exc}",
            flush=True,
        )
        time.sleep(1)
