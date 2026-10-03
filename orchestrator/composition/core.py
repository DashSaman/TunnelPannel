"""Composition engine core (P8 §1-§17).

Canonical semantics everywhere: ``A over B`` means **A uses B as its
UNDERLAY/CARRIER**. Validation is capability-driven from manifests —
never a hard-coded pair list. Protocol conversion happens only through
EXPLICIT registered adapters; otherwise INVALID with a reason code.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field

from engines.manifests import load_all

# ── reason codes (§21) ────────────────────────────────────────────────

VALID = "VALID"
MISSING_CAPABILITY = "MISSING_CAPABILITY_{}"
RAW_IP_NOT_AVAILABLE = "RAW_IP_NOT_AVAILABLE"
CYCLE_DETECTED = "CYCLE_DETECTED"
SELF_PARENT = "SELF_PARENT"
MTU_TOO_LOW = "MTU_TOO_LOW"
ENDPOINT_ROUTE_LOOP = "ENDPOINT_ROUTE_LOOP"
UNSUPPORTED_NESTING = "UNSUPPORTED_NESTING"
NON_REPEATABLE_ENGINE = "NON_REPEATABLE_ENGINE"
DEPTH_EXCEEDED = "DEPTH_EXCEEDED"
INVALID_PLACEMENT = "INVALID_PLACEMENT"
RESOURCE_CONFLICT = "RESOURCE_CONFLICT"
UNKNOWN_ENGINE = "UNKNOWN_ENGINE_{}"
TCP_OVER_TCP_WARNING = "HEAD_OF_LINE_RISK"

# ── explicit capability adapters (§4) — conversion is NEVER assumed ───


@dataclass(frozen=True)
class CapabilityAdapter:
    key: str
    synthesizes: str                    # capability it provides
    requires: str                       # capability it consumes from parent
    notes: str
    implemented: bool = False           # a declared-but-unbuilt adapter does
                                        # NOT satisfy requirements (§4: real only)


EXPLICIT_ADAPTERS: dict[str, CapabilityAdapter] = {
    "UDP_OVER_STREAM": CapabilityAdapter(
        "UDP_OVER_STREAM", "UDP_DATAGRAM", "TCP_STREAM",
        "encapsulates UDP datagrams inside a TCP stream (adds HOL risk)"),
    "SOCKS_TO_TUN": CapabilityAdapter(
        "SOCKS_TO_TUN", "TUN_INTERFACE", "SOCKS5_PROXY",
        "userspace TUN device backed by a SOCKS upstream (e.g. tun2socks)"),
    "L2_BRIDGE": CapabilityAdapter(
        "L2_BRIDGE", "L2_INTERFACE", "TAP_INTERFACE",
        "bridges a TAP onto an L2 segment"),
}


# ── component/chain specs ─────────────────────────────────────────────

@dataclass
class CompSpec:
    component_id: str
    engine_id: str
    profile_id: str = "default"
    parent_id: str | None = None        # None = rides the physical network
    node: str = "both"                  # "a" | "b" | "both"
    endpoint: str | None = None         # outer endpoint address (if any)
    endpoint_via: str = "physical"      # "physical" | parent component_id


@dataclass
class ChainSpec:
    name: str
    components: list[CompSpec]

    def by_id(self) -> dict[str, CompSpec]:
        return {c.component_id: c for c in self.components}


@dataclass
class Validation:
    valid: bool
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    adapters_used: list[str] = field(default_factory=list)

    def explain(self) -> str:
        return "; ".join(self.reasons) if self.reasons else VALID


# ── DAG machinery (§2) ────────────────────────────────────────────────

def detect_cycle(spec: ChainSpec) -> str | None:
    """Return the component_id where a cycle is closed, or None."""
    comps = spec.by_id()
    state: dict[str, int] = {}          # 0=unvisited 1=in-stack 2=done

    def dfs(cid: str, stack: list[str]) -> str | None:
        state[cid] = 1
        parent = comps[cid].parent_id
        if parent is not None:
            if parent == cid:
                return cid                                   # self-cycle
            if parent not in comps:
                return None                                  # dangling handled elsewhere
            if state.get(parent) == 1:
                return parent                                # cycle closed
            if state.get(parent, 0) == 0:
                found = dfs(parent, stack + [parent])
                if found:
                    return found
        state[cid] = 2
        return None

    for cid in comps:
        if state.get(cid, 0) == 0:
            found = dfs(cid, [cid])
            if found:
                return found
    return None


def descendants(spec: ChainSpec, cid: str) -> set[str]:
    """All components that (transitively) ride ON cid (cid is their underlay)."""
    comps = spec.by_id()
    out: set[str] = set()
    changed = True
    while changed:
        changed = False
        for c in comps.values():
            if c.component_id in out:
                continue
            if c.parent_id == cid or (c.parent_id in out and c.component_id != cid):
                out.add(c.component_id)
                changed = True
    return out


def topological_order(spec: ChainSpec) -> list[str]:
    """Underlay → overlay (parents before children); deterministic."""
    comps = spec.by_id()

    def depth(cid: str, seen: frozenset[str] = frozenset()) -> int:
        if cid in seen:
            return 0                        # cycle-guard; cycle check reports it
        p = comps[cid].parent_id
        if p is None or p not in comps:
            return 0
        return 1 + depth(p, seen | {cid})

    return sorted(comps, key=lambda c: (depth(c), c))


# ── capability resolver (§3, §4, §8) ──────────────────────────────────

# What a provided capability SATISFIES beyond itself. A full IP interface
# (L3/TUN) carries any IP-based requirement; a UDP forwarder carries
# datagram consumers; a TCP stream carries TLS; a TAP carries L2.
# Application-proxy semantics (SOCKS/HTTP) subsume nothing — that is why
# GRE directly over SOCKS stays invalid (§3).
SUBSUMES: dict[str, frozenset[str]] = {
    "L3_INTERFACE": frozenset({"TCP_STREAM", "UDP_DATAGRAM", "RAW_IP",
                               "IP_PROTOCOL_41", "IP_PROTOCOL_47", "QUIC", "TLS"}),
    "TUN_INTERFACE": frozenset({"TCP_STREAM", "UDP_DATAGRAM", "RAW_IP",
                                "IP_PROTOCOL_41", "IP_PROTOCOL_47", "QUIC", "TLS"}),
    "TAP_INTERFACE": frozenset({"L2_INTERFACE", "TCP_STREAM", "UDP_DATAGRAM",
                                "RAW_IP", "IP_PROTOCOL_41", "IP_PROTOCOL_47", "QUIC"}),
    "L2_INTERFACE": frozenset({"L2_INTERFACE"}),
    "UDP_DATAGRAM": frozenset({"UDP_DATAGRAM", "QUIC"}),
    "TCP_STREAM": frozenset({"TCP_STREAM", "TLS"}),
    "SOCKS5_PROXY": frozenset({"SOCKS5_PROXY"}),
    "HTTP_PROXY": frozenset({"HTTP_PROXY"}),
}


def effective_provides(provided: set[str]) -> set[str]:
    out = set(provided)
    for cap in provided:
        out |= SUBSUMES.get(cap, frozenset({cap}))
    return out


# ── profile-level capability narrowing (honesty for app-layer engines) ─
# Engine manifests aggregate all profiles; an underlay candidate must be
# judged by what THAT profile really provides. GRE over ssh/dynamic_socks
# is INVALID even though the ssh engine (with its tun profile) lists TUN.
PROFILE_PROVIDES: dict[tuple[str, str], frozenset[str]] = {
    # ssh
    ("ssh", "local_forward"): frozenset({"TCP_STREAM"}),
    ("ssh", "remote_forward"): frozenset({"TCP_STREAM", "REVERSE_TCP"}),
    ("ssh", "dynamic_socks"): frozenset({"TCP_STREAM", "SOCKS5_PROXY"}),
    ("ssh", "tun_l3"): frozenset({"TUN_INTERFACE"}),
    ("ssh", "tap_l2"): frozenset({"TAP_INTERFACE"}),
    ("ssh", "reverse"): frozenset({"TCP_STREAM", "REVERSE_TCP"}),
    # gost
    ("gost", "socks5"): frozenset({"TCP_STREAM", "SOCKS5_PROXY"}),
    ("gost", "http"): frozenset({"TCP_STREAM", "HTTP_PROXY"}),
    ("gost", "ws"): frozenset({"TCP_STREAM"}),
    ("gost", "grpc"): frozenset({"TCP_STREAM"}),
    ("gost", "http2"): frozenset({"TCP_STREAM"}),
    ("gost", "quic"): frozenset({"UDP_DATAGRAM", "QUIC"}),
    ("gost", "kcp_forward"): frozenset({"UDP_DATAGRAM"}),
    ("gost", "socks5_kcp"): frozenset({"TCP_STREAM", "SOCKS5_PROXY", "UDP_DATAGRAM"}),
    ("gost", "remote_tcp"): frozenset({"TCP_STREAM", "REVERSE_TCP"}),
    ("gost", "remote_udp"): frozenset({"UDP_DATAGRAM", "REVERSE_UDP"}),
    ("gost", "ssh"): frozenset({"TCP_STREAM"}),
    ("gost", "tun"): frozenset({"TUN_INTERFACE"}),
    ("gost", "tap"): frozenset({"TAP_INTERFACE"}),
    ("gost", "tcp_forward"): frozenset({"TCP_STREAM"}),
    ("gost", "udp_forward"): frozenset({"UDP_DATAGRAM"}),
    # frp
    ("frp", "tcp"): frozenset({"TCP_STREAM", "REVERSE_TCP"}),
    ("frp", "udp"): frozenset({"UDP_DATAGRAM", "REVERSE_UDP"}),
    ("frp", "kcp"): frozenset({"UDP_DATAGRAM", "REVERSE_TCP"}),
    ("frp", "quic"): frozenset({"UDP_DATAGRAM", "QUIC", "REVERSE_TCP"}),
    ("frp", "stcp"): frozenset({"TCP_STREAM"}),
    ("frp", "xtcp"): frozenset({"UDP_DATAGRAM"}),
    # singbox
    ("singbox", "tun"): frozenset({"TUN_INTERFACE"}),
    ("singbox", "shadowsocks"): frozenset({"TCP_STREAM", "UDP_DATAGRAM", "SOCKS5_PROXY"}),
    ("singbox", "trojan_tls"): frozenset({"TCP_STREAM", "TLS", "SOCKS5_PROXY"}),
    ("singbox", "tuic"): frozenset({"UDP_DATAGRAM", "QUIC", "SOCKS5_PROXY"}),
    ("singbox", "hysteria2"): frozenset({"UDP_DATAGRAM", "SOCKS5_PROXY"}),
    # hedioum
    ("hedioum", "tun"): frozenset({"TUN_INTERFACE"}),
    ("hedioum", "pool_socks"): frozenset({"SOCKS5_PROXY", "TCP_STREAM"}),
    # wstunnel
    ("wstunnel", "tcp"): frozenset({"TCP_STREAM"}),
    ("wstunnel", "udp"): frozenset({"UDP_DATAGRAM"}),
    ("wstunnel", "socks5"): frozenset({"TCP_STREAM", "SOCKS5_PROXY"}),
    # chisel
    ("chisel", "tcp"): frozenset({"TCP_STREAM"}),
    ("chisel", "udp"): frozenset({"UDP_DATAGRAM"}),
    ("chisel", "socks5"): frozenset({"TCP_STREAM", "SOCKS5_PROXY"}),
    ("chisel", "reverse_tcp"): frozenset({"TCP_STREAM", "REVERSE_TCP"}),
    ("chisel", "reverse_udp"): frozenset({"UDP_DATAGRAM", "REVERSE_UDP"}),
    ("chisel", "reverse_socks5"): frozenset({"TCP_STREAM", "SOCKS5_PROXY", "REVERSE_TCP"}),
    # rathole
    ("rathole", "tcp"): frozenset({"TCP_STREAM", "REVERSE_TCP"}),
    ("rathole", "udp"): frozenset({"UDP_DATAGRAM", "REVERSE_UDP"}),
    ("rathole", "tls"): frozenset({"TCP_STREAM", "TLS", "REVERSE_TCP"}),
    ("rathole", "noise"): frozenset({"TCP_STREAM", "REVERSE_TCP"}),
    ("rathole", "websocket"): frozenset({"TCP_STREAM", "REVERSE_TCP"}),
    # xray (vless variants all expose a socks/forward path over their wire)
    ("xray", "vless_tcp"): frozenset({"TCP_STREAM", "SOCKS5_PROXY"}),
    ("xray", "vless_ws"): frozenset({"TCP_STREAM", "SOCKS5_PROXY"}),
    ("xray", "vless_grpc"): frozenset({"TCP_STREAM", "SOCKS5_PROXY"}),
    ("xray", "vless_reality"): frozenset({"TCP_STREAM", "TLS", "SOCKS5_PROXY"}),
    ("xray", "vless_vision_reality"): frozenset({"TCP_STREAM", "TLS", "SOCKS5_PROXY"}),
    ("xray", "vless_xhttp"): frozenset({"TCP_STREAM", "SOCKS5_PROXY"}),
    ("xray", "vless_xhttp_reality"): frozenset({"TCP_STREAM", "TLS", "SOCKS5_PROXY"}),
    # paqet / waterwall
    ("paqet", "socks5"): frozenset({"TCP_STREAM", "SOCKS5_PROXY"}),
    ("paqet", "raw_kcp"): frozenset({"UDP_DATAGRAM"}),
    ("waterwall", "direct"): frozenset({"TCP_STREAM"}),
    ("waterwall", "reverse"): frozenset({"TCP_STREAM", "REVERSE_TCP"}),
    ("waterwall", "tls_mux"): frozenset({"TCP_STREAM", "TLS"}),
}


def get_provides(engine_id: str, profile_id: str, manifests: dict | None = None) -> set[str]:
    manifests = manifests or load_all()
    narrowed = PROFILE_PROVIDES.get((engine_id, profile_id))
    if narrowed is not None:
        return set(narrowed)
    m = manifests.get(engine_id)
    return set(m["provides"]) if m else set()


def resolve_pair(child_engine: str, parent_engine: str | None,
                 parent_profile: str = "default",
                 manifests: dict | None = None) -> tuple[bool, list[str], list[str]]:
    """Validate 'child over parent'. parent None = physical network
    (implicitly provides everything). The parent is judged by what ITS
    PROFILE really provides (§3: GRE directly over SOCKS is invalid).
    Returns (valid, reasons, adapters_used)."""
    manifests = manifests or load_all()
    if child_engine not in manifests:
        return False, [UNKNOWN_ENGINE.format(child_engine)], []
    child = manifests[child_engine]
    required = set(child["requires"])
    if parent_engine is None:
        return True, [], []                 # physical root satisfies all
    if parent_engine not in manifests:
        return False, [UNKNOWN_ENGINE.format(parent_engine)], []
    parent = manifests[parent_engine]
    provided = effective_provides(get_provides(parent_engine, parent_profile, manifests))

    # nesting semantics (§8)
    if not parent["can_be_underlay"]:
        return False, [UNSUPPORTED_NESTING], []

    missing = required - provided
    adapters: list[str] = []
    reasons: list[str] = []
    for cap in sorted(missing):
        adapter = next((a for a in EXPLICIT_ADAPTERS.values()
                        if a.synthesizes == cap and a.requires in provided), None)
        if adapter is not None and adapter.implemented:
            adapters.append(adapter.key)
        elif adapter is not None:
            reasons.append(f"{MISSING_CAPABILITY.format(cap)} "
                           f"(explicit adapter {adapter.key} declared but NOT implemented)")
        elif cap == "RAW_IP":
            reasons.append(RAW_IP_NOT_AVAILABLE)
        else:
            reasons.append(MISSING_CAPABILITY.format(cap))
    return (not reasons), reasons, adapters


# ── repeatability (§8) ────────────────────────────────────────────────

def check_repeatability(spec: ChainSpec, manifests: dict | None = None) -> list[str]:
    manifests = manifests or load_all()
    reasons: list[str] = []
    seen: dict[str, int] = {}
    for c in spec.components:
        m = manifests.get(c.engine_id)
        if m is None:
            continue
        seen[c.engine_id] = seen.get(c.engine_id, 0) + 1
        if seen[c.engine_id] > 1 and not m["repeatable"]:
            reasons.append(f"{NON_REPEATABLE_ENGINE}: {c.engine_id}")
    return reasons


# ── MTU / MSS planner (§11, §12) ──────────────────────────────────────

PHYSICAL_MTU_V4 = 1500
IPv6_MIN_MTU = 1280
IPv4_FLOOR = 1000                          # safe practical floor for reject


@dataclass
class MtuPlan:
    effective_mtu: int
    overhead_total: int
    mss_clamp_required: bool
    ipv6_ok: bool

    def as_actions(self) -> list[str]:
        return ([f"MSS-CLAMP on TCP egress (effective MTU {self.effective_mtu})"]
                if self.mss_clamp_required else [])


def plan_mtu(spec: ChainSpec, physical_mtu: int = PHYSICAL_MTU_V4,
             manifests: dict | None = None) -> tuple[MtuPlan | None, list[str]]:
    manifests = manifests or load_all()
    overhead = 0
    has_tcp = False
    for cid in topological_order(spec):
        m = manifests.get(spec.by_id()[cid].engine_id)
        if m is None:
            return None, [UNKNOWN_ENGINE.format(spec.by_id()[cid].engine_id)]
        overhead += int(m["mtu_overhead"])
        if "tcp" in m["transport"] or "L3_INTERFACE" in m["provides"]                 or "TUN_INTERFACE" in m["provides"]:
            has_tcp = True
    effective = physical_mtu - overhead
    reasons: list[str] = []
    if effective < IPv4_FLOOR:
        reasons.append(f"{MTU_TOO_LOW}: effective {effective} < {IPv4_FLOOR}")
    if effective < IPv6_MIN_MTU:
        reasons.append(f"{MTU_TOO_LOW}: IPv6 minimum {IPv6_MIN_MTU} unreachable")
    clamp = has_tcp and effective < physical_mtu - 40
    return MtuPlan(effective, overhead, clamp, effective >= IPv6_MIN_MTU), reasons


# ── endpoint route guard (§13) ────────────────────────────────────────

def check_endpoint_routes(spec: ChainSpec) -> tuple[list[str], list[str]]:
    """reasons + guard actions. An overlay's outer endpoint must be reached
    via the physical underlay or an ancestor — never itself or a descendant
    (its own riders)."""
    reasons: list[str] = []
    actions: list[str] = []
    comps = spec.by_id()
    for c in spec.components:
        if not c.endpoint:
            continue
        via = c.endpoint_via
        if via == c.component_id:
            reasons.append(f"{ENDPOINT_ROUTE_LOOP}: {c.component_id} routes its own endpoint")
            continue
        if via != "physical":
            if via in descendants(spec, c.component_id):
                reasons.append(
                    f"{ENDPOINT_ROUTE_LOOP}: {c.component_id} endpoint via its own rider {via}")
                continue
            if via not in comps:
                reasons.append(f"{ENDPOINT_ROUTE_LOOP}: unknown via component {via}")
                continue
        via_desc = "physical gateway" if via == "physical" else f"underlay {via}"
        actions.append(f"PIN {c.endpoint}/32 via {via_desc} "
                       f"(before any route/rule mutation for {c.component_id})")
    return reasons, actions


# ── node placement (§14) ──────────────────────────────────────────────

def check_placement(spec: ChainSpec) -> list[str]:
    comps = spec.by_id()
    reasons: list[str] = []
    for c in spec.components:
        if c.node not in ("a", "b", "both"):
            reasons.append(f"{INVALID_PLACEMENT}: {c.component_id} node={c.node!r}")
            continue
        p = comps.get(c.parent_id) if c.parent_id else None
        if p is not None:
            shared = {"a", "b"} if c.node == "both" or p.node == "both" else \
                     ({c.node} & {p.node})
            if not shared:
                reasons.append(
                    f"{INVALID_PLACEMENT}: {c.component_id}({c.node}) has no common node "
                    f"with parent {p.component_id}({p.node})")
    return reasons


# ── maturity + warnings (§9, §10) ─────────────────────────────────────

def classify_maturity(spec: ChainSpec, adapters_used: list[str] | None = None,
                      manifests: dict | None = None) -> tuple[str, list[str]]:
    adapters_used = adapters_used or []
    manifests = manifests or load_all()
    warnings: list[str] = []
    tcp_over_tcp = False
    comps = spec.by_id()
    for c in spec.components:
        p = comps.get(c.parent_id) if c.parent_id else None
        if p is None:
            continue
        cm, pm = manifests.get(c.engine_id), manifests.get(p.engine_id)
        if cm and pm and "tcp" in cm["transport"] and "tcp" in pm["transport"] \
                and cm is not pm:
            tcp_over_tcp = True
            warnings.append(f"{TCP_OVER_TCP_WARNING}: {c.component_id} over "
                            f"{p.component_id} nests TCP reliability layers")
    depth = chain_depth(spec)
    all_standard = all(manifests.get(c.engine_id, {}).get("maturity") == "STANDARD"
                       for c in spec.components)
    all_realpair = all(manifests.get(c.engine_id, {}).get("verification")
                       in ("REAL_PAIR_VERIFIED", "PRODUCTION_VERIFIED")
                       for c in spec.components)

    if depth <= 2 and not adapters_used and not tcp_over_tcp \
            and all_standard and all_realpair:
        maturity = "STANDARD"
    elif depth <= 3 and len(adapters_used) <= 1:
        maturity = "ADVANCED"
    else:
        maturity = "EXPERIMENTAL"
    if tcp_over_tcp and maturity == "STANDARD":
        maturity = "ADVANCED"
    return maturity, warnings


def chain_depth(spec: ChainSpec) -> int:
    comps = spec.by_id()

    def depth(cid: str, seen: frozenset[str] = frozenset()) -> int:
        if cid in seen:
            return 0
        p = comps[cid].parent_id
        if p is None or p not in comps:
            return 1
        return 1 + depth(p, seen | {cid})

    return max((depth(c) for c in comps), default=0)


# ── depth limits (§19) ────────────────────────────────────────────────

RECOMMENDED_DEPTH = 3
HARD_AUTO_LIMIT = 5
ABSOLUTE_CEILING = 8


def check_depth(spec: ChainSpec, override: bool = False) -> list[str]:
    n = len(spec.components)
    depth = chain_depth(spec)
    reasons: list[str] = []
    if n > ABSOLUTE_CEILING or depth > ABSOLUTE_CEILING:
        reasons.append(f"{DEPTH_EXCEEDED}: absolute ceiling {ABSOLUTE_CEILING}")
    elif depth > HARD_AUTO_LIMIT and not override:
        reasons.append(f"{DEPTH_EXCEEDED}: {depth} > automatic limit {HARD_AUTO_LIMIT} "
                       f"(operator override required)")
    return reasons


# ── full validation ───────────────────────────────────────────────────

def validate_chain(spec: ChainSpec, manifests: dict | None = None) -> Validation:
    manifests = manifests or load_all()
    v = Validation(valid=True)
    ids = spec.by_id()

    # unknown engines
    for c in spec.components:
        if c.engine_id not in manifests:
            v.reasons.append(UNKNOWN_ENGINE.format(c.engine_id))
    if v.reasons:
        v.valid = False
        return v

    # DAG
    if not spec.components:
        v.reasons.append("EMPTY_CHAIN")
        v.valid = False
        return v
    cycle = detect_cycle(spec)
    if cycle:
        v.reasons.append(f"{CYCLE_DETECTED}: closed at {cycle}")
        v.valid = False
        return v
    for c in spec.components:
        if c.parent_id is not None and c.parent_id not in ids:
            v.reasons.append(f"UNKNOWN_PARENT: {c.component_id} -> {c.parent_id}")
    if v.reasons:
        v.valid = False
        return v

    # capability resolution per edge (bottom-up: each child over its parent)
    comps = ids
    for c in spec.components:
        parent = comps.get(c.parent_id) if c.parent_id else None
        parent_engine = parent.engine_id if parent else None
        parent_profile = (parent.profile_id if parent else "default") or "default"
        ok, reasons, adapters = resolve_pair(c.engine_id, parent_engine,
                                             parent_profile, manifests)
        v.reasons.extend(reasons)
        v.adapters_used.extend(a for a in adapters if a not in v.adapters_used)
    if v.reasons:
        v.valid = False

    # repeatability / depth / placement / routes / mtu
    v.reasons.extend(check_repeatability(spec, manifests))
    v.reasons.extend(check_depth(spec))
    v.reasons.extend(check_placement(spec))
    route_reasons, _guard_actions = check_endpoint_routes(spec)
    v.reasons.extend(route_reasons)
    mtu, mtu_reasons = plan_mtu(spec, manifests=manifests)
    v.reasons.extend(mtu_reasons)
    if any(r.startswith(MTU_TOO_LOW) for r in v.reasons):
        v.valid = False
    if v.reasons:
        v.valid = False

    # maturity + warnings only for valid chains
    if v.valid:
        _maturity, warnings = classify_maturity(spec, v.adapters_used, manifests)
        v.warnings = warnings
        if chain_depth(spec) > RECOMMENDED_DEPTH:
            v.warnings.append(f"DEPTH_ABOVE_RECOMMENDED: {chain_depth(spec)} > {RECOMMENDED_DEPTH}")
        for a in v.adapters_used:
            v.warnings.append(f"EXPLICIT_ADAPTER: {a}")
    return v


# ── composition plan (§16, §17) ───────────────────────────────────────

@dataclass
class CompositionPlan:
    chain_name: str
    install_order: list[str]
    rollback_order: list[str]
    probe_order: list[str]
    mtu: MtuPlan | None
    guard_actions: list[str]
    warnings: list[str]
    maturity: str
    verification: dict[str, str]
    components: list[dict]

    def as_dict(self) -> dict:
        return {
            "chain_name": self.chain_name,
            "install_order": self.install_order,
            "rollback_order": self.rollback_order,
            "probe_order": self.probe_order,
            "effective_mtu": self.mtu.effective_mtu if self.mtu else None,
            "overhead_total": self.mtu.overhead_total if self.mtu else None,
            "mss_clamp_required": self.mtu.mss_clamp_required if self.mtu else None,
            "guard_actions": self.guard_actions,
            "warnings": self.warnings,
            "maturity": self.maturity,
            "verification": self.verification,
            "components": self.components,
        }


def build_plan(spec: ChainSpec, manifests: dict | None = None) -> CompositionPlan | None:
    v = validate_chain(spec, manifests)
    if not v.valid:
        return None
    manifests = manifests or load_all()
    order = topological_order(spec)                 # underlay → overlay
    mtu, _ = plan_mtu(spec, manifests=manifests)
    _r, guard_actions = check_endpoint_routes(spec)
    maturity, warnings = classify_maturity(spec, v.adapters_used, manifests)
    warnings = warnings + [w for w in v.warnings if w not in warnings]
    return CompositionPlan(
        chain_name=spec.name,
        install_order=order,
        rollback_order=list(reversed(order)),
        probe_order=order,
        mtu=mtu,
        guard_actions=guard_actions,
        warnings=warnings,
        maturity=maturity,
        verification={c.component_id: manifests[c.engine_id]["verification"]
                      for c in spec.components},
        components=[dataclasses.asdict(c) for c in
                    sorted(spec.components, key=lambda c: order.index(c.component_id))],
    )
