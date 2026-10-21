"""Directed mesh planning and evidence-gated, diversity-aware recommendations."""
from __future__ import annotations

import math

from fastapi import HTTPException

from orchestrator.benchmarking.scoring import rank, score_sample
from orchestrator.mesh_quality import OBJECTIVES, encryption


def directed_routes(nodes):
    if len(nodes) < 2 or len(set(nodes)) != len(nodes):
        raise ValueError("select at least two distinct nodes")
    return [(a, b) for a in nodes for b in nodes if a != b]


def failure_domain(method):
    if method == 'IP4IN6':
        return 'ipv6:4'
    # Describe the OUTER carrier: overlays cannot survive their carrier's loss.
    if method.startswith("HAJSAMAN_") or method in {"SIT_6IN4", "SIT_OVER_SSH"}:
        return "ip:41" if method != "SIT_OVER_SSH" else "tcp:ssh"
    if "OVER_" in method:
        return failure_domain(method.split("_OVER_", 1)[1])
    if method in {"GRE", "GRETAP", "IP6GRE", "IP6GRETAP"}:
        return "ip:47"
    if method == "IPIP":
        return "ip:4"
    if method in {"VTI", "VTI6", "IKEV2_IPSEC", "L2TP_IPSEC"}:
        return "udp:ipsec"
    if method in {"WIREGUARD", "AMNEZIAWG", "VXLAN", "OPENVPN"}:
        return "udp:" + method.lower()
    if method.startswith("PAQET_"):
        return "raw:tcp"
    if any(k in method for k in ("QUIC", "HYSTERIA", "TUIC", "KCP")):
        return "udp:" + ("kcp" if "KCP" in method else "quic")
    if method.startswith(("SSH_", "AUTOSSH_")) or method == "GOST_SSH":
        return "tcp:ssh"
    if method.startswith("HEDIOUM_"):
        return "tcp:hedioum"
    if "UDP" in method:
        return "udp:forward"
    if method.startswith(("VLESS_", "VMESS_", "TROJAN_", "ANYTLS", "SHADOWTLS", "NAIVE_")):
        return "tcp:tls"
    return "tcp:" + method.split("_", 1)[0].lower()


def capability(method):
    if method in {"WIREGUARD", "AMNEZIAWG", "IP4IN6", "GRE", "GRETAP", "IPIP", "IP6GRE", "IP6GRETAP", "SIT_6IN4",
                  "VXLAN", "VTI", "VTI6", "IKEV2_IPSEC", "L2TP_IPSEC", "OPENVPN",
                  "SSH_TUN_L3", "SSH_TAP_L2", "GOST_TUN", "GOST_TAP", "HEDIOUM_TUN",
                  "SINGBOX_TUN", "HAJSAMAN_SIT", "HAJSAMAN_WG", "HAJSAMAN_FULL"} or "_OVER_" in method:
        return "ip"
    if "UDP" in method:
        return "udp_forward"
    if (method.startswith(("VLESS_", "VMESS_", "HEDIOUM_POOL", "ANYTLS", "SHADOWTLS", "NAIVE_")) or
            method in {"HYSTERIA2", "TUIC", "TROJAN_TLS", "SHADOWSOCKS"} or
            "SOCKS" in method or method in {"GOST_WS", "GOST_HTTP2", "GOST_GRPC", "GOST_QUIC", "GOST_SSH"}):
        return "socks"
    return "tcp_forward"


def qualification(row):
    m = row.get("metrics") or {}
    if row.get("status") != "PASS" or not row.get("receipt"):
        return "a successful real-pair receipt is required"
    if not all(m.get(k) is True for k in ("setup_ok", "data_plane_ok", "recovery_ok")):
        return "setup, data plane and restart recovery must pass"
    if not str(m.get("cleanup", "")).startswith("released "):
        return "verified cleanup is required"
    for key in ("rtt_avg", "jitter", "loss_pct", "throughput_mbps", "reconnect_s"):
        value = m.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            return "missing or invalid measured " + key
    if m["throughput_mbps"] <= 0 or m["loss_pct"] > 20:
        return "insufficient throughput or excessive request loss"
    if m.get("rtt_basis") not in {"http_request", "udp_echo"}:
        return "comparable on-node latency measurement is required"
    return None


def recommendations(rows, count=5, purpose="any", objective="balanced", encrypted_only=False):
    if not 1 <= count <= 1000:
        raise ValueError("recommendation count out of range")
    if objective not in OBJECTIVES:
        raise ValueError('unknown quality objective')
    eligible, excluded = [], []
    for row in rows:
        method = row["candidate"]
        why = qualification(row)
        if not why and encrypted_only and encryption(method) != 'protocol_encrypted':
            why = 'the template does not establish protocol encryption'
        if not why and purpose == 'tcp_egress':
            from orchestrator.mesh_persistent import egress_supported
            if not egress_supported(method):
                why = 'this profile has no persistent TCP egress adapter'
        elif not why and purpose != "any" and capability(method) != purpose:
            why = "different data-plane capability"
        if why:
            excluded.append({"candidate": method, "reason": why})
        else:
            eligible.append(score_sample(method, row["metrics"], "PASS", OBJECTIVES[objective]))
    ranked = rank(eligible)
    selected, seen, deferred = [], set(), []
    for item in ranked:
        domain = failure_domain(item.candidate)
        if domain in seen:
            deferred.append(item.candidate)
        else:
            selected.append(item.candidate)
            seen.add(domain)
    selected = (selected + deferred)[:count]
    return {"selected": selected, "requested": count, "qualified": len(ranked),
            "shortfall": max(0, count - len(selected)), "excluded": excluded,
            "ranked": [{"candidate": r.candidate, "score": r.score,
                        "metrics": r.metrics, "failure_domain": failure_domain(r.candidate),
                        "capability": capability(r.candidate), 'reasons': r.reasons,
                        'encryption': encryption(r.candidate)} for r in ranked],
            'objective': objective, 'weights': OBJECTIVES[objective], 'encrypted_only': encrypted_only,
            "policy": "quality rank, distinct outer carriers first, then remaining quality rank",
            "endpoint_redundancy": False}


def quality_weights(rows):
    """Normalize measured capacity with request-loss and jitter penalties."""
    values = {}
    for row in rows:
        metrics = row.get('metrics') or {}
        speed, jitter, loss = (metrics.get(key, 0) for key in ('throughput_mbps', 'jitter', 'loss_pct'))
        valid = all(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
                    for v in (speed, jitter, loss))
        values[row['candidate']] = (speed * (1 - loss / 100) / (1 + jitter / 10)
            if valid and speed > 0 and jitter >= 0 and 0 <= loss < 100 else 0)
    best = max(values.values(), default=0)
    return {key: max(1, min(100, round(value / best * 100, 3))) if best else 1
            for key, value in values.items()}


def select_methods(rows, ordered, limit):
    if not ordered or len(ordered) != len(set(ordered)) or len(ordered) > limit:
        raise HTTPException(400, "selection must be nonempty, unique and within workspace limits")
    qualified = {row['candidate'] for row in rows if qualification(row) is None}
    if not set(ordered) <= qualified:
        raise HTTPException(400, "select only qualified methods from this route's measured results")
    return list(ordered)
