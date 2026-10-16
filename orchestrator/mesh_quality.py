"""Transparent priorities; encryption labels describe known templates, not measurements."""
from orchestrator.benchmarking.scoring import DEFAULT_WEIGHTS

OBJECTIVES = {'balanced': DEFAULT_WEIGHTS,
    'latency': dict(zip(DEFAULT_WEIGHTS, [10, 15, 35, 20, 8, 2, 5, 2, 3])),
    'throughput': dict(zip(DEFAULT_WEIGHTS, [10, 15, 5, 5, 8, 45, 5, 4, 3])),
    'stability': dict(zip(DEFAULT_WEIGHTS, [20, 20, 5, 10, 20, 2, 15, 5, 3]))}


def encryption(method):
    if '_OVER_' in method:
        parts = method.split('_OVER_', 1)
        return ('protocol_encrypted' if any(encryption(p) == 'protocol_encrypted' for p in parts)
                else 'configuration_dependent')
    if method in {'GRE', 'GRETAP', 'IP6GRE', 'IP6GRETAP', 'IPIP', 'SIT_6IN4', 'VXLAN', 'VTI', 'VTI6', 'HAJSAMAN_SIT'}:
        return 'none'
    if (method in {'WIREGUARD', 'OPENVPN', 'IKEV2_IPSEC', 'L2TP_IPSEC', 'GOST_SSH',
                   'HYSTERIA2', 'TUIC', 'SHADOWSOCKS', 'HAJSAMAN_WG', 'HAJSAMAN_FULL'}
            or method.startswith(('SSH_', 'AUTOSSH_', 'TROJAN_', 'VMESS_', 'ANYTLS', 'SHADOWTLS', 'NAIVE_'))
            or 'TLS' in method or 'REALITY' in method):
        return 'protocol_encrypted'
    return 'configuration_dependent'
