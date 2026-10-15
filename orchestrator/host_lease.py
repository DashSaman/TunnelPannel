"""Process-safe leases for physical SSH hosts, plus conflict-free inner prefixes."""
import hashlib
import base64
import ipaddress
import json
import os
from pathlib import Path
import secrets
import tempfile
import time


class HostLease:
    def __init__(self, endpoint, directory=None):
        identity = endpoint.get("host_key_fingerprint") or endpoint["host"]
        if identity.startswith('SHA256:'):
            encoded = identity[7:]
            identity = base64.b64decode(encoded + '=' * (-len(encoded) % 4)).hex()
        self.key = hashlib.sha256(identity.lower().encode()).hexdigest()
        self.directory = Path(directory or os.environ.get("TP_LOCK_DIR") or
                              Path(tempfile.gettempdir()) / "tunnelpannel-leases")
        self.file = None

    def acquire(self, timeout=0):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        file = open(self.directory / (self.key + ".lock"), "a+b")
        file.seek(0, 2)
        if file.tell() == 0:
            file.write(b"0")
            file.flush()
        deadline = time.monotonic() + timeout
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    file.seek(0)
                    msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.file = file
                return True
            except OSError:
                if time.monotonic() >= deadline:
                    file.close()
                    return False
                time.sleep(min(.1, max(0, deadline - time.monotonic())))

    def release(self):
        if self.file:
            if os.name == "nt":
                import msvcrt
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
            self.file.close()
            self.file = None


def choose_prefix(occupied, version=4):
    networks = [ipaddress.ip_network(n, strict=False) for n in occupied]
    if version not in {4, 6}:
        raise ValueError('unsupported address family')
    pools = [ipaddress.ip_network(n) for n in
             (["10.246.0.0/15", "172.30.0.0/16"] if version == 4 else
              ["fd45:246::/48", "fd45:5a1::/48"])]
    prefixlen = 30 if version == 4 else 64
    size = 2 ** (pools[0].max_prefixlen - prefixlen)
    for pool in pools:
        slots = pool.num_addresses // size
        offset = secrets.randbelow(slots)
        for index in range(slots):
            cls = ipaddress.IPv4Network if version == 4 else ipaddress.IPv6Network
            prefix = cls((int(pool.network_address) + ((index + offset) % slots) * size, prefixlen))
            if not any(prefix.version == n.version and prefix.overlaps(n) for n in networks):
                return str(prefix)
    raise RuntimeError("no conflict-free inner prefix in the dedicated pools")


def unused_prefix(remotes, version=4, exclude=()):
    occupied = list(exclude)
    for remote in remotes:
        for family in ("-4", "-6"):
            for row in json.loads(remote.run(f"ip -j {family} address show")["stdout"]):
                occupied.extend(str(ipaddress.ip_network(f"{a['local']}/{a['prefixlen']}", strict=False))
                                for a in row.get("addr_info", []) if a.get("local"))
        for family in ('-4', '-6'):
            for row in json.loads(remote.run(f"ip -j {family} route show table all")["stdout"]):
                if row.get("dst") and row["dst"] != "default":
                    occupied.append(row["dst"])
    return choose_prefix(occupied, version)
