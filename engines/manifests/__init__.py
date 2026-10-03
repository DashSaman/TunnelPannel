"""Engine manifest schema + validation (P3).

A manifest is a JSON document per engine declaring identity, layer, transport
semantics, requires/provides capabilities, OS/arch support, packages/binaries,
kernel modules, privileges, ports/protocols, address-family + interface
capabilities, MTU overhead and nesting semantics.

Validation is strict: an incomplete or contradictory manifest FAILS (tests
enforce this). Zero external dependencies.
"""
from __future__ import annotations

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
MANIFESTS_DIR = pathlib.Path(__file__).resolve().parent

CAPABILITY_VOCABULARY = frozenset({
    "L3_INTERFACE", "L2_INTERFACE", "TUN_INTERFACE", "TAP_INTERFACE",
    "TCP_STREAM", "UDP_DATAGRAM", "SOCKS5_PROXY", "HTTP_PROXY",
    "RAW_IP", "IP_PROTOCOL_41", "IP_PROTOCOL_47", "IPSEC",
    "REVERSE_TCP", "REVERSE_UDP", "QUIC", "TLS",
})

LAYERS = frozenset({"L2", "L3", "L4", "PROXY", "APPLICATION"})
MATURITIES = frozenset({"STANDARD", "ADVANCED", "EXPERIMENTAL"})
VERIFICATION_LEVELS = frozenset({
    "UNTESTED", "LAB_VERIFIED", "REAL_PAIR_VERIFIED", "PRODUCTION_VERIFIED"})
IMPLEMENTATION_STATUSES = frozenset({
    "IMPLEMENTED", "PARTIAL", "UNSUPPORTED", "DEPRECATED"})

REQUIRED_TOP = ("id", "name", "family", "version", "maturity", "layer",
                "transport", "requires", "provides", "supported_os",
                "supported_arch", "required_binaries", "required_kernel_modules",
                "required_privileges", "ports", "ip_protocols", "ipv4", "ipv6",
                "tun", "tap", "socks", "http_proxy", "reverse", "raw_ip",
                "encryption", "mtu_overhead", "can_be_overlay", "can_be_underlay",
                "can_be_nested", "repeatable", "known_limitations", "verification")


class ManifestError(ValueError):
    """Raised when a manifest is incomplete or contradictory."""


def validate(manifest: dict) -> dict:
    """Validate one manifest document; raises ManifestError with a reason."""
    def need(key: str):
        if key not in manifest:
            raise ManifestError(f"missing required field: {key}")

    for key in REQUIRED_TOP:
        need(key)

    # ── identity ──
    if manifest["id"] != manifest["id"].lower() or " " in manifest["id"]:
        raise ManifestError("id must be a stable lowercase identifier without spaces")
    if manifest["layer"] not in LAYERS:
        raise ManifestError(f"layer must be one of {sorted(LAYERS)}")
    if manifest["maturity"] not in MATURITIES:
        raise ManifestError(f"maturity must be one of {sorted(MATURITIES)}")
    if manifest["verification"] not in VERIFICATION_LEVELS:
        raise ManifestError(f"verification must be one of {sorted(VERIFICATION_LEVELS)}")
    if manifest.get("implementation_status", "IMPLEMENTED") not in IMPLEMENTATION_STATUSES:
        raise ManifestError("implementation_status must be one of "
                            f"{sorted(IMPLEMENTATION_STATUSES)}")

    # ── capabilities ──
    for field in ("requires", "provides"):
        caps = manifest[field]
        if not isinstance(caps, list) or not caps:
            raise ManifestError(f"{field} must be a non-empty list")
        unknown = set(caps) - CAPABILITY_VOCABULARY
        if unknown:
            raise ManifestError(f"{field} has unknown capabilities: {sorted(unknown)}")

    # ── transport semantics ──
    transport = manifest["transport"]
    if not isinstance(transport, list) or not transport:
        raise ManifestError("transport must be a non-empty list")
    unknown_t = set(transport) - {"tcp", "udp", "ip", "ethernet", "quic", "ws", "grpc"}
    if unknown_t:
        raise ManifestError(f"transport has unknown semantics: {sorted(unknown_t)}")

    # ── booleans / numbers ──
    for flag in ("ipv4", "ipv6", "tun", "tap", "socks", "http_proxy", "reverse", "raw_ip",
                 "can_be_overlay", "can_be_underlay", "can_be_nested", "repeatable"):
        if not isinstance(manifest[flag], bool):
            raise ManifestError(f"{flag} must be a boolean")
    mtu = manifest["mtu_overhead"]
    if not isinstance(mtu, int) or isinstance(mtu, bool) or mtu < 0:
        raise ManifestError("mtu_overhead must be a non-negative integer")

    # ── contradictions (capability ↔ declared flags) ──
    provides = set(manifest["provides"])
    requires = set(manifest["requires"])

    if manifest["tun"] and "TUN_INTERFACE" not in provides:
        raise ManifestError("tun=true but TUN_INTERFACE not provided")
    if manifest["tap"] and "TAP_INTERFACE" not in provides:
        raise ManifestError("tap=true but TAP_INTERFACE not provided")
    if manifest["socks"] and "SOCKS5_PROXY" not in provides:
        raise ManifestError("socks=true but SOCKS5_PROXY not provided")
    if manifest["http_proxy"] and "HTTP_PROXY" not in provides:
        raise ManifestError("http_proxy=true but HTTP_PROXY not provided")
    if manifest["raw_ip"] and "RAW_IP" not in provides:
        raise ManifestError("raw_ip=true but RAW_IP not provided")
    if manifest["layer"] == "L3" and "L3_INTERFACE" not in provides:
        raise ManifestError("layer=L3 but L3_INTERFACE not provided")
    if manifest["layer"] == "L2" and "L2_INTERFACE" not in provides:
        raise ManifestError("layer=L2 but L2_INTERFACE not provided")
    # wire transport ⇒ what the engine needs from ITS underlay
    # (provides-side is a service statement: e.g. wstunnel may provide
    #  UDP_DATAGRAM as a service while riding a TCP wire)
    if "udp" in transport and "UDP_DATAGRAM" not in requires:
        raise ManifestError("transport includes udp but UDP_DATAGRAM not required")
    if "tcp" in transport and "TCP_STREAM" not in requires:
        raise ManifestError("transport includes tcp but TCP_STREAM not required")
    if manifest["reverse"]:
        if "REVERSE_TCP" not in provides and "REVERSE_UDP" not in provides:
            raise ManifestError("reverse=true but neither REVERSE_TCP nor REVERSE_UDP provided")
    if not manifest["can_be_underlay"] and manifest["can_be_nested"]:
        raise ManifestError("can_be_nested=true requires can_be_underlay=true")
    if requires - CAPABILITY_VOCABULARY:
        raise ManifestError("requires outside vocabulary")

    # ── lists sanity ──
    for key in ("supported_os", "required_binaries", "known_limitations"):
        if not isinstance(manifest[key], list):
            raise ManifestError(f"{key} must be a list")
    if not isinstance(manifest["ports"], dict):
        raise ManifestError("ports must be a dict (e.g. {'udp': 'any' | 51820})")
    if not isinstance(manifest["ip_protocols"], list):
        raise ManifestError("ip_protocols must be a list")

    return manifest


def load_all(directory: pathlib.Path | None = None) -> dict[str, dict]:
    """Load + validate every manifest JSON in the directory."""
    d = pathlib.Path(directory or MANIFESTS_DIR)
    out: dict[str, dict] = {}
    for path in sorted(d.glob("*.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        validate(manifest)
        if manifest["id"] != path.stem:
            raise ManifestError(f"{path.name}: id {manifest['id']!r} must match filename")
        if manifest["id"] in out:
            raise ManifestError(f"duplicate manifest id: {manifest['id']}")
        out[manifest["id"]] = manifest
    return out
