"""Canonical engine/profile identity + legacy method-ID aliases (P1.7 / P2).

Rules (ADR-001):
- ENGINE  = the technology      : wireguard, gre, gost, xray, frp, …
- PROFILE = a transport variant : gost/grpc, xray/vless_xhttp, ssh/tun_l3, …
- Legacy registry IDs (GOST_GRPC, VLESS_XHTTP_REALITY, …) remain valid
  addressable aliases forever — nothing existing breaks.
- ``X_OVER_Y`` IDs describe composites: X uses Y as underlay/carrier.
  They are kept as chain templates, not standalone engines.

Source of truth for the split: deploy/methods_registry.json (Gen2 registry,
the 82-entry superset — see docs/development/CATALOG_INVENTORY.md).
"""
from __future__ import annotations

import json
import pathlib
import re
from dataclasses import dataclass, field

ROOT = pathlib.Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "deploy" / "methods_registry.json"

# legacy-prefix → engine. Order matters (longest first).
_ENGINE_PREFIXES: list[tuple[str, str]] = [
    ("AUTOSSH_", "ssh"),
    ("GOST_", "gost"),
    ("VLESS_", "xray"),
    ("CHISEL_", "chisel"),
    ("RATHOLE_", "rathole"),
    ("WSTUNNEL_", "wstunnel"),
    ("WATERWALL_", "waterwall"),
    ("PAQET_", "paqet"),
    ("HEDIOUM_", "hedioum"),
    ("HAJSAMAN_", "hajsaman"),
    ("SINGBOX_", "singbox"),
    ("FRP_", "frp"),
    ("SSH_", "ssh"),
]

# exact legacy IDs → (engine, profile); entries not matched by prefix rules
_EXACT: dict[str, tuple[str, str]] = {
    "WIREGUARD": ("wireguard", "default"),
    "GRE": ("gre", "default"),
    "IP6GRE": ("gre", "ip6"),
    "GRETAP": ("gretap", "default"),
    "IP6GRETAP": ("gretap", "ip6"),
    "IPIP": ("ipip", "default"),
    "SIT_6IN4": ("sit", "6in4"),
    "VTI": ("vti", "default"),
    "VTI6": ("vti", "v6"),
    "VXLAN": ("vxlan", "default"),
    "OPENVPN": ("openvpn", "default"),
    "IKEV2_IPSEC": ("ipsec", "ikev2"),
    "L2TP_IPSEC": ("ipsec", "l2tp"),
    # sing-box protocol entries (registry carries them without SINGBOX_ prefix)
    "SHADOWSOCKS": ("singbox", "shadowsocks"),
    "TROJAN_TLS": ("singbox", "trojan_tls"),
    "TUIC": ("singbox", "tuic"),
    "HYSTERIA2": ("singbox", "hysteria2"),
}

# Gen3 bare adapter names → canonical registry IDs (alias resolution)
_LEGACY_ALIASES: dict[str, str] = {
    "HEDIOUM": "HEDIOUM_TUN",
    "HAJSAMAN": "HAJSAMAN_FULL",
    "PAQET": "PAQET_SOCKS5",
    "IKEV2": "IKEV2_IPSEC",
    "L2TP": "L2TP_IPSEC",
    "SIT": "SIT_6IN4",
}

_OVER_RE = re.compile(r"^(?P<overlay>[A-Z0-9]+)_OVER_(?P<underlay>[A-Z0-9]+)$")

# canonical overlay/underlay tokens → engine ids for composite templates
_TOKEN_ENGINE = {
    "WIREGUARD": "wireguard", "GRE": "gre", "GRETAP": "gretap", "SIT": "sit",
    "SSH": "ssh", "GOST": "gost", "FRP": "frp",
}


@dataclass(frozen=True)
class MethodIdentity:
    legacy_id: str
    engine: str
    profile: str
    family: str
    display_name: str = ""
    is_composite: bool = False
    overlay: str | None = None       # engine id of overlay component (composites)
    underlay: str | None = None      # engine id of underlay component (composites)


@dataclass
class Catalog:
    identities: dict[str, MethodIdentity] = field(default_factory=dict)
    composite_templates: dict[str, MethodIdentity] = field(default_factory=dict)

    # ── queries ──
    def by_legacy(self, legacy_id: str) -> MethodIdentity:
        """Resolve a legacy method ID, following Gen3 bare-name aliases."""
        legacy_id = _LEGACY_ALIASES.get(legacy_id, legacy_id)
        try:
            return self.identities[legacy_id]
        except KeyError:
            raise KeyError(f"unknown legacy method id: {legacy_id}") from None

    def engines(self) -> list[str]:
        return sorted({m.engine for m in self.identities.values()
                       if not m.engine.startswith("_") and m.engine != "composite"})

    def profiles_of(self, engine: str) -> list[str]:
        return sorted(m.profile for m in self.identities.values() if m.engine == engine)

    def resolve(self, engine: str, profile: str) -> MethodIdentity | None:
        for m in self.identities.values():
            if m.engine == engine and m.profile == profile:
                return m
        return None


def _split(legacy_id: str, family: str, display: str) -> MethodIdentity:
    m = _OVER_RE.match(legacy_id)
    if m:  # composite template: overlay uses underlay as carrier
        ov, un = m.group("overlay"), m.group("underlay")
        return MethodIdentity(legacy_id, "composite", legacy_id.lower(), family, display,
                              is_composite=True,
                              overlay=_TOKEN_ENGINE.get(ov, ov.lower()),
                              underlay=_TOKEN_ENGINE.get(un, un.lower()))

    if legacy_id in _EXACT:
        eng, prof = _EXACT[legacy_id]
        return MethodIdentity(legacy_id, eng, prof, family, display)

    for prefix, engine in _ENGINE_PREFIXES:
        if legacy_id.startswith(prefix):
            profile = legacy_id[len(prefix):].lower() or "default"
            return MethodIdentity(legacy_id, engine, profile, family, display)

    raise ValueError(f"cannot derive engine/profile identity for {legacy_id!r}")


def load_catalog(path: pathlib.Path | None = None) -> Catalog:
    """Build the canonical catalog from the Gen2 registry (superset)."""
    src = pathlib.Path(path or REGISTRY_PATH)
    reg = json.loads(src.read_text(encoding="utf-8"))
    methods = reg["methods"] if isinstance(reg, dict) else reg

    cat = Catalog()
    for m in methods:
        mid = m["id"]
        fam = str(m.get("set") or m.get("family") or "?").replace("_METHODS", "")
        ident = _split(mid, fam, str(m.get("name") or mid))
        if ident.is_composite:
            cat.composite_templates[mid] = ident
        cat.identities[mid] = ident
    return cat


# module-level singleton (registry file is static data in-repo)
CATALOG = load_catalog()
