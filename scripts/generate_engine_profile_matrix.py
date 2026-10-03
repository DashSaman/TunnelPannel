#!/usr/bin/env python3
"""Generate the authoritative engine/profile matrix (P5 §1).

docs/development/ENGINE_PROFILE_MATRIX.json — machine-readable, generated
from catalog + manifests + adapter registry + test evidence. Do not edit
by hand; regenerate after adapter changes.

Run: python scripts/generate_engine_profile_matrix.py
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.catalog import CATALOG                       # noqa: E402
from engines.manifests import load_all                 # noqa: E402

PROBE_BY_FAMILY = {
    "kernel": "ICMP", "vpn": "ICMP", "custom": "MULTI_SIGNAL",
    "proxy": "SOCKS5", "forwarder": "TCP",
}

# engine-specific probe types where the family default is wrong
PROBE_OVERRIDE = {
    ("gost", "http"): "HTTP",
    ("gost", "http2"): "HTTP",
    ("gost", "tcp_forward"): "TCP",
    ("gost", "udp_forward"): "UDP",
    ("gost", "kcp_forward"): "TCP",
    ("gost", "remote_tcp"): "TCP",
    ("gost", "remote_udp"): "UDP",
    ("gost", "tun"): "TUN",
    ("gost", "tap"): "TAP",
    ("frp", "udp"): "UDP",
    ("frp", "stcp"): "TCP",
    ("frp", "xtcp"): "UDP",
    ("frp", "quic"): "QUIC",
    ("frp", "kcp"): "UDP",
    ("chisel", "udp"): "UDP",
    ("chisel", "reverse_udp"): "UDP",
    ("wstunnel", "udp"): "UDP",
    ("wstunnel", "socks5"): "SOCKS5",
    ("rathole", "udp"): "UDP",
    ("singbox", "tun"): "TUN",
    ("ssh", "dynamic_socks"): "SOCKS5",
    ("ssh", "local_forward"): "TCP",
    ("ssh", "remote_forward"): "TCP",
    ("ssh", "tun_l3"): "TUN",
    ("ssh", "tap_l2"): "TAP",
    ("ssh", "reverse"): "TCP",
    ("hedioum", "tun"): "TUN",
    ("hedioum", "pool_socks"): "SOCKS5",
    ("paqet", "raw_kcp"): "UDP",
}


def parse_test_report() -> dict[str, set[str]]:
    src = (ROOT / "docs" / "TEST-REPORT.md").read_text(encoding="utf-8")
    known = set(CATALOG.identities) | set(CATALOG.composite_templates)
    sections: dict[str, set[str]] = {"PASS": set(), "PARTIAL": set(), "FAIL": set()}
    kind = None
    for line in src.splitlines():
        header = re.match(r"^##\s+.*(✅ PASS|🟡 PARTIAL|❌ FAIL)", line)
        if header:
            kind = header.group(1).split()[1]
            continue
        if re.match(r"^##\s", line):
            kind = None
            continue
        if kind:
            sections[kind].update(t for t in re.findall(r"\b[A-Z][A-Z0-9_]{1,}\b", line)
                                  if t in known)
    return sections


def main() -> int:
    # import adapters lazily so generation sees current registry
    import engines.adapters.kernel          # noqa: F401
    import engines.adapters.kernel_extra    # noqa: F401
    import engines.adapters.ssh_family      # noqa: F401
    import engines.adapters.userspace       # noqa: F401
    from engines.adapters import registered

    manifests = load_all()
    evidence = parse_test_report()
    adapter_keys = set(registered())

    matrix = []
    for legacy_id, ident in sorted(CATALOG.identities.items()):
        if ident.is_composite:
            continue
        m = manifests.get(ident.engine, {})
        has_adapter = (ident.engine, ident.profile) in adapter_keys or \
                      any(e == ident.engine for e, _p in adapter_keys)
        ev = ("PASS" if legacy_id in evidence["PASS"] else
              "PARTIAL" if legacy_id in evidence["PARTIAL"] else
              "FAIL" if legacy_id in evidence["FAIL"] else "NONE")
        matrix.append({
            "engine_id": ident.engine,
            "profile_id": ident.profile,
            "legacy_method_ids": [legacy_id],
            "family": ident.family,
            "implementation_status": m.get("implementation_status", "PARTIAL"),
            "verification_status": {
                "PASS": "REAL_PAIR_VERIFIED", "PARTIAL": "LAB_VERIFIED",
                "FAIL": "UNTESTED", "NONE": "UNTESTED",
            }[ev],
            "implementation_source": {
                "PASS": "combination", "PARTIAL": "gen2",
                "FAIL": "gen1", "NONE": "gen2",
            }[ev],
            "adapter_status": "COMPLETE" if has_adapter else "MISSING",
            "adapter_class": "canonical (command-plan)",
            "probe_type": PROBE_OVERRIDE.get((ident.engine, ident.profile),
                                             PROBE_BY_FAMILY.get(m.get("family", ""), "MULTI_SIGNAL")),
            "requirements": {
                "binaries": m.get("required_binaries", []),
                "kernel_modules": m.get("required_kernel_modules", []),
                "privileges": m.get("required_privileges", "none"),
            },
            "known_limitations": m.get("known_limitations", []),
            "existing_test_evidence": ev,
            "real_verification": "REAL_VERIFICATION_BLOCKED until P14 (Windows dev host)",
        })

    composites = [
        {"legacy_method_id": lid,
         "overlay_engine": ident.overlay,
         "underlay_engine": ident.underlay,
         "canonical_home": "P8 composition engine (compatibility template until then)"}
        for lid, ident in sorted(CATALOG.composite_templates.items())
    ]

    doc = {
        "generated_by": "scripts/generate_engine_profile_matrix.py",
        "engines": sorted({e["engine_id"] for e in matrix}),
        "engine_count": len({e["engine_id"] for e in matrix}),
        "profile_count": len(matrix),
        "adapter_coverage": f"{sum(1 for e in matrix if e['adapter_status'] == 'COMPLETE')}/{len(matrix)}",
        "composites": composites,
        "matrix": matrix,
    }
    out = ROOT / "docs" / "development" / "ENGINE_PROFILE_MATRIX.json"
    out.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n",
                   encoding="utf-8", newline="\n")
    print(f"wrote {out.relative_to(ROOT)}: {doc['engine_count']} engines, "
          f"{doc['profile_count']} profiles, adapter coverage {doc['adapter_coverage']}, "
          f"{len(composites)} composite templates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
