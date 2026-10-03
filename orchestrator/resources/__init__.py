"""Canonical Resource Manager (P4) — single allocation authority.

Every shared host resource TunnelPannel creates is allocated HERE and
recorded in the ``resource_allocations`` ledger (core.models) with
``owner = TunnelPannel`` and full deployment/chain/component provenance.
Collisions are impossible by construction: an allocation either finds a
free key or raises :class:`ResourceConflict` — engines never invent
shared resources on their own.

Portable by design: real-world "what is currently in use on node X" comes
from an :class:`InUseProvider` (SSH scan in production — Gen2 ``portmgr``
logic; fake in tests). The manager itself is pure ledger + policy.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.models import ResourceAllocation

OWNER = "TunnelPannel"

# allocation ranges (conventions inherited from Gen2 portmgr)
TCP_RANGE = range(21000, 26000)
UDP_RANGE = range(26000, 30000)
NEVER_PORTS = frozenset({
    22, 53, 80, 443, 3306, 5432, 6379, 8080, 8443, 9443,  # services
    111, 123, 161, 389, 445, 514, 873, 1080, 1900, 2049,   # rpc/ntp/snmp/ldap/smb/syslog/rsync/socks/upnp/nfs
    3128, 4444, 4848, 5000, 51820, 51821, 5900, 6000, 6443,  # squid/metasploit/etc + wireguard defaults
    11211, 27017, 9000, 9001, 10000, 18080,                 # memcache/mongo/supervisor/xxxx
})
INTERFACE_PREFIX = "tp"
TABLE_RANGE = range(51000, 51100)
FWMARK_RANGE = range(5100, 5200)
SUBNET_V4_POOL = ipaddress.ip_network("10.174.0.0/16")
SUBNET_V6_POOL = ipaddress.ip_network("fd00:174::/32")
SUBNET_V4_PREFIX, SUBNET_V6_PREFIX = 24, 64


class ResourceConflict(RuntimeError):
    """Raised when a requested resource is not free or not owned by us."""


class InUseProvider(Protocol):
    """What is currently in use on a node (production: SSH scan; tests: fake)."""

    def in_use(self, node_id: str, kind: str) -> set[str]:
        """Return occupied keys of ``kind`` on ``node_id`` (ports as str ints)."""


@dataclass
class _NothingInUse:
    def in_use(self, node_id: str, kind: str) -> set[str]:
        return set()


class ResourceManager:
    def __init__(self, session: Session, provider: InUseProvider | None = None):
        self.session = session
        self.provider = provider or _NothingInUse()

    # ── ledger helpers ──
    def _live(self, kind: str, node_id: str | None) -> dict[str, ResourceAllocation]:
        stmt = select(ResourceAllocation).where(
            ResourceAllocation.kind == kind,
            ResourceAllocation.released_at.is_(None),
        )
        rows = self.session.scalars(stmt).all()
        return {r.key: r for r in rows if node_id is None or r.node_id in (node_id, None)}

    def _record(self, *, kind: str, key: str, deployment_id: str,
                node_id: str | None = None, chain_id: str | None = None,
                component_id: str | None = None, meta: dict | None = None) -> ResourceAllocation:
        alloc = ResourceAllocation(
            deployment_id=deployment_id, chain_id=chain_id, component_id=component_id,
            node_id=node_id, owner=OWNER, kind=kind, key=key, meta=meta or {})
        self.session.add(alloc)
        self.session.flush()
        return alloc

    def _check_external(self, kind: str, key: str, node_id: str | None) -> None:
        if node_id is None:
            return
        if key in self.provider.in_use(node_id, kind):
            raise ResourceConflict(f"{kind} {key!r} is in use on node {node_id} (external)")

    # ── generic idempotent reservation ──
    def reserve(self, *, kind: str, key: str, deployment_id: str,
                node_id: str | None = None, chain_id: str | None = None,
                component_id: str | None = None, meta: dict | None = None) -> ResourceAllocation:
        """Idempotent: re-reserving the same (deployment, kind, key, node) returns
        the existing row instead of duplicating; a key held by another
        deployment raises ResourceConflict."""
        live = self._live(kind, node_id)
        existing = live.get(key)
        if existing is not None:
            if existing.deployment_id == deployment_id:
                return existing
            raise ResourceConflict(
                f"{kind} {key!r} already allocated to deployment {existing.deployment_id}")
        self._check_external(kind, key, node_id)
        return self._record(kind=kind, key=key, deployment_id=deployment_id,
                            node_id=node_id, chain_id=chain_id,
                            component_id=component_id, meta=meta)

    # ── typed allocations ──
    def allocate_port(self, *, kind: str, deployment_id: str, node_id: str,
                      preferred: int | None = None, **kw) -> ResourceAllocation:
        assert kind in ("tcp_port", "udp_port")
        span = TCP_RANGE if kind == "tcp_port" else UDP_RANGE
        if preferred is not None:
            if preferred in NEVER_PORTS:
                raise ResourceConflict(f"port {preferred} is in the NEVER list (system port)")
            if preferred not in span:
                raise ResourceConflict(f"preferred port {preferred} outside {kind} range {span}")
            return self.reserve(kind=kind, key=str(preferred), deployment_id=deployment_id,
                                node_id=node_id, **kw)
        return self._scan_allocate(kind=kind, span=span, deployment_id=deployment_id,
                                   node_id=node_id, **kw)

    def _scan_allocate(self, *, kind: str, span: range, deployment_id: str,
                       node_id: str, **kw) -> ResourceAllocation:
        live = self._live(kind, node_id)
        external = self.provider.in_use(node_id, kind)
        for candidate in span:
            if candidate in NEVER_PORTS:
                continue
            key = str(candidate)
            if key in live or key in external:
                continue
            return self._record(kind=kind, key=key, deployment_id=deployment_id,
                                node_id=node_id, **kw)
        raise ResourceConflict(f"{kind} range exhausted on node {node_id}")

    def allocate_interface(self, *, deployment_id: str, node_id: str,
                           prefix: str = INTERFACE_PREFIX, **kw) -> ResourceAllocation:
        kind = "interface"
        live = self._live(kind, node_id)
        external = self.provider.in_use(node_id, kind)
        idx = 0
        while True:
            name = f"{prefix}{idx}"
            if name not in live and name not in external:
                return self.reserve(kind=kind, key=name, deployment_id=deployment_id,
                                    node_id=node_id, **kw)
            idx += 1
            if idx > 4096:
                raise ResourceConflict("interface namespace exhausted")

    def allocate_subnet(self, *, version: int, deployment_id: str,
                        pool: str | None = None, **kw) -> ResourceAllocation:
        kind = f"subnet_v{version}"
        prefixlen = SUBNET_V4_PREFIX if version == 4 else SUBNET_V6_PREFIX
        base = ipaddress.ip_network(pool or (SUBNET_V4_POOL if version == 4 else SUBNET_V6_POOL))
        live = self._live(kind, None)
        for sub in base.subnets(new_prefix=prefixlen):
            key = str(sub)
            if key not in live:
                return self.reserve(kind=kind, key=key, deployment_id=deployment_id, **kw)
        raise ResourceConflict(f"subnet pool {base} exhausted")

    def allocate_table(self, *, deployment_id: str, node_id: str, **kw) -> ResourceAllocation:
        return self._scan_allocate(kind="route_table", span=TABLE_RANGE,
                                   deployment_id=deployment_id, node_id=node_id, **kw)

    def allocate_fwmark(self, *, deployment_id: str, node_id: str, **kw) -> ResourceAllocation:
        return self._scan_allocate(kind="fwmark", span=FWMARK_RANGE,
                                   deployment_id=deployment_id, node_id=node_id, **kw)

    def allocate_nft_chain(self, *, name: str, deployment_id: str, **kw) -> ResourceAllocation:
        return self.reserve(kind="nft_chain", key=name, deployment_id=deployment_id, **kw)

    def allocate_systemd_unit(self, *, name: str, deployment_id: str, **kw) -> ResourceAllocation:
        if not name.endswith(".service"):
            name += ".service"
        return self.reserve(kind="systemd_unit", key=name, deployment_id=deployment_id, **kw)

    def allocate_namespace(self, *, deployment_id: str, node_id: str,
                           prefix: str = "tpns", **kw) -> ResourceAllocation:
        kind = "namespace"
        live = self._live(kind, node_id)
        idx = 0
        while f"{prefix}{idx}" in live:
            idx += 1
        return self.reserve(kind=kind, key=f"{prefix}{idx}", deployment_id=deployment_id,
                            node_id=node_id, **kw)

    def allocate_temp(self, *, key: str, deployment_id: str, **kw) -> ResourceAllocation:
        """Benchmark/scratch resources — same ledger, same ownership rules."""
        return self.reserve(kind="temp", key=key, deployment_id=deployment_id, **kw)

    # ── release / ownership ──
    def release(self, allocation_id: str) -> None:
        alloc = self.session.get(ResourceAllocation, allocation_id)
        if alloc is None or alloc.released_at is not None:
            return
        self._assert_owned(alloc)
        import datetime as dt
        alloc.released_at = dt.datetime.now(dt.timezone.utc)
        self.session.flush()

    def release_deployment(self, deployment_id: str) -> int:
        stmt = select(ResourceAllocation).where(
            ResourceAllocation.deployment_id == deployment_id,
            ResourceAllocation.released_at.is_(None))
        n = 0
        for alloc in self.session.scalars(stmt).all():
            self._assert_owned(alloc)
            self.release(alloc.id)
            n += 1
        return n

    @staticmethod
    def _assert_owned(alloc: ResourceAllocation) -> None:
        if alloc.owner != OWNER:
            raise ResourceConflict(
                f"refusing to release {alloc.kind} {alloc.key!r}: owner is {alloc.owner!r}, "
                "not TunnelPannel")

    def owned_keys(self, kind: str, node_id: str | None = None) -> set[str]:
        return set(self._live(kind, node_id))
