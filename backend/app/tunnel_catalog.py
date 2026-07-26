def m(i,n,c,l,d='A_TO_B,B_TO_A,BIDIRECTIONAL',car=''):
 return {'id':i,'name':n,'category':c,'layer':l,'directions':d.split(','),'initiators':['AUTO','A','B'],'carriers':[x for x in car.split(',') if x]}

CATALOG=[
 m('GRE','GRE','KERNEL','L3',car='GOST_TCP_FORWARD,GOST_GRPC,GOST_QUIC,SSH_REMOTE_FORWARD,WIREGUARD'),
 m('GRETAP','GRETAP','KERNEL','L2',car='GOST_TCP_FORWARD,GOST_GRPC,SSH_REMOTE_FORWARD,WIREGUARD'),
 m('IPIP','IPIP','KERNEL','L3',car='GOST_TCP_FORWARD,SSH_REMOTE_FORWARD,WIREGUARD'),
 m('SIT_6IN4','SIT / 6in4','KERNEL','L3',car='GOST_TCP_FORWARD,GOST_GRPC,GOST_QUIC,SSH_REMOTE_FORWARD,WIREGUARD'),
 m('IP6GRE','IP6GRE','KERNEL','L3',car='GOST_TCP_FORWARD,SSH_REMOTE_FORWARD,WIREGUARD'),
 m('IP6GRETAP','IP6GRETAP','KERNEL','L2',car='GOST_TCP_FORWARD,SSH_REMOTE_FORWARD,WIREGUARD'),
 m('VXLAN','VXLAN','KERNEL','L2',car='GOST_UDP_FORWARD,GOST_QUIC,WIREGUARD'),
 m('VTI','VTI','KERNEL','L3'),m('VTI6','VTI6','KERNEL','L3'),
 m('WIREGUARD','WireGuard','VPN','L3'),m('OPENVPN','OpenVPN','VPN','L3'),
 m('IKEV2_IPSEC','IKEv2 / IPsec','VPN','L3'),m('L2TP_IPSEC','L2TP / IPsec','VPN','L3'),
 m('SSH_LOCAL_FORWARD','SSH Local Forward','SSH','STREAM','A_TO_B,B_TO_A'),
 m('SSH_REMOTE_FORWARD','Reverse SSH / Remote Forward','SSH','STREAM','A_TO_B,B_TO_A'),
 m('SSH_DYNAMIC_SOCKS','SSH Dynamic SOCKS','SSH','PROXY','A_TO_B,B_TO_A'),
 m('AUTOSSH_REVERSE','Persistent Reverse SSH (autossh)','SSH','STREAM','A_TO_B,B_TO_A'),
 m('SSH_TUN_L3','SSH TUN Layer 3','SSH','L3'),m('SSH_TAP_L2','SSH TAP Layer 2','SSH','L2'),
 m('GOST_TCP_FORWARD','GOST TCP Forward','GOST','STREAM','A_TO_B,B_TO_A'),
 m('GOST_UDP_FORWARD','GOST UDP Forward','GOST','DATAGRAM','A_TO_B,B_TO_A'),
 m('GOST_REMOTE_TCP','GOST Remote TCP','GOST','STREAM','A_TO_B,B_TO_A'),
 m('GOST_REMOTE_UDP','GOST Remote UDP','GOST','DATAGRAM','A_TO_B,B_TO_A'),
 m('GOST_SOCKS5','GOST SOCKS5','GOST','PROXY'),m('GOST_HTTP','GOST HTTP','GOST','CARRIER'),
 m('GOST_WS','GOST WebSocket','GOST','CARRIER'),m('GOST_HTTP2','GOST HTTP/2','GOST','CARRIER'),
 m('GOST_GRPC','GOST gRPC','GOST','CARRIER'),m('GOST_QUIC','GOST QUIC','GOST','CARRIER'),
 m('GOST_SSH','GOST SSH','GOST','CARRIER'),m('GOST_TUN','GOST TUN','GOST','L3'),m('GOST_TAP','GOST TAP','GOST','L2'),
 m('VLESS_TCP','VLESS TCP','XRAY','PROXY'),m('VLESS_WS','VLESS WebSocket','XRAY','PROXY'),
 m('VLESS_GRPC','VLESS gRPC','XRAY','PROXY'),m('VLESS_XHTTP','VLESS XHTTP','XRAY','PROXY'),
 m('VLESS_REALITY','VLESS REALITY','XRAY','PROXY'),m('VLESS_VISION_REALITY','VLESS Vision REALITY','XRAY','PROXY'),
 m('VLESS_XHTTP_REALITY','VLESS XHTTP REALITY','XRAY','PROXY'),
 m('SIT_OVER_GOST','6in4 / SIT over GOST','COMPOSITE','L3',car='GOST_TCP_FORWARD,GOST_GRPC,GOST_QUIC,GOST_SSH'),
 m('GRE_OVER_GOST','GRE over GOST','COMPOSITE','L3',car='GOST_TCP_FORWARD,GOST_GRPC,GOST_QUIC,GOST_SSH'),
 m('GRETAP_OVER_GOST','GRETAP over GOST','COMPOSITE','L2',car='GOST_TCP_FORWARD,GOST_GRPC,GOST_QUIC,GOST_SSH'),
 m('SIT_OVER_SSH','6in4 / SIT over SSH','COMPOSITE','L3',car='SSH_REMOTE_FORWARD,AUTOSSH_REVERSE,SSH_TUN_L3'),
 m('GRE_OVER_SSH','GRE over SSH','COMPOSITE','L3',car='SSH_REMOTE_FORWARD,AUTOSSH_REVERSE,SSH_TUN_L3'),
 m('GRE_OVER_WIREGUARD','GRE over WireGuard','COMPOSITE','L3',car='WIREGUARD'),
]


# NETAUTO_EXPANDED_CATALOG_BEGIN

def em(
    method_id,
    name,
    category,
    layer,
    description,
    directions="A_TO_B,B_TO_A,BIDIRECTIONAL",
    carriers="",
    flags="MULTI_INSTANCE",
    default_direction=None,
    default_initiator="AUTO",
):
    item = m(
        method_id,
        name,
        category,
        layer,
        directions,
        carriers,
    )

    item["description"] = description
    item["flags"] = [
        value
        for value in flags.split(",")
        if value
    ]
    item["simple_supported"] = True
    item["advanced_supported"] = True

    if default_direction is None:
        default_direction = (
            "BIDIRECTIONAL"
            if "BIDIRECTIONAL"
            in item["directions"]
            else item["directions"][0]
        )

    item["simple_defaults"] = {
        "traffic_direction": default_direction,
        "initiator": default_initiator,
        "carrier_method_id": None,
        "config": {
            "mode": "SIMPLE",
            "auto_allocate": True,
            "auto_install": True,
            "auto_precheck": True,
            "auto_inventory_refresh": True,
        },
    }

    return item


EXTRA_METHODS = [
    em(
        "WATERWALL_DIRECT",
        "WaterWall Direct",
        "WATERWALL",
        "STREAM",
        "Direct WaterWall node-based TCP tunnel.",
        flags="MULTI_INSTANCE,TCP,MUX,AUTO_RECONNECT",
    ),
    em(
        "WATERWALL_REVERSE",
        "WaterWall Reverse",
        "WATERWALL",
        "STREAM",
        "Reverse WaterWall tunnel initiated from the selected side.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,TCP,REVERSE,MUX,AUTO_RECONNECT",
        default_direction="B_TO_A",
        default_initiator="B",
    ),
    em(
        "WATERWALL_TLS_MUX",
        "WaterWall TLS + MUX",
        "WATERWALL",
        "STREAM",
        "Encrypted multiplexed WaterWall profile.",
        flags="MULTI_INSTANCE,TCP,TLS,MUX,ENCRYPTED",
    ),
    em(
        "PAQET_RAW_KCP",
        "Paqet Raw KCP",
        "PAQET",
        "PROXY",
        "Raw-packet Paqet profile using KCP.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,RAW_SOCKET,KCP,PCAP,ENCRYPTED",
    ),
    em(
        "PAQET_SOCKS5",
        "Paqet SOCKS5",
        "PAQET",
        "PROXY",
        "Paqet profile exposing a local SOCKS5 endpoint.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,RAW_SOCKET,KCP,SOCKS5",
    ),
    em(
        "RATHOLE_TCP",
        "Rathole TCP",
        "RATHOLE",
        "STREAM",
        "Reverse TCP service exposure using Rathole.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,TCP,REVERSE,TOKEN",
    ),
    em(
        "RATHOLE_UDP",
        "Rathole UDP",
        "RATHOLE",
        "DATAGRAM",
        "Reverse UDP service exposure using Rathole.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,UDP,REVERSE,TOKEN",
    ),
    em(
        "RATHOLE_TLS",
        "Rathole TLS",
        "RATHOLE",
        "STREAM",
        "Rathole reverse tunnel protected by TLS.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,TCP,REVERSE,TLS,TOKEN",
    ),
    em(
        "RATHOLE_NOISE",
        "Rathole Noise",
        "RATHOLE",
        "STREAM",
        "Rathole reverse tunnel protected by Noise.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,TCP,REVERSE,NOISE,TOKEN",
    ),
    em(
        "RATHOLE_WEBSOCKET",
        "Rathole WebSocket",
        "RATHOLE",
        "STREAM",
        "Rathole reverse tunnel over WebSocket.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,TCP,REVERSE,WEBSOCKET",
    ),
    em(
        "CHISEL_TCP",
        "Chisel TCP",
        "CHISEL",
        "STREAM",
        "TCP forwarding through Chisel.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,TCP,HTTP,SSH_SECURITY",
    ),
    em(
        "CHISEL_UDP",
        "Chisel UDP",
        "CHISEL",
        "DATAGRAM",
        "UDP forwarding through Chisel.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,UDP,HTTP,SSH_SECURITY",
    ),
    em(
        "CHISEL_REVERSE_TCP",
        "Chisel Reverse TCP",
        "CHISEL",
        "STREAM",
        "Reverse TCP forwarding through Chisel.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,TCP,REVERSE,HTTP,SSH_SECURITY",
        default_direction="B_TO_A",
        default_initiator="B",
    ),
    em(
        "CHISEL_REVERSE_UDP",
        "Chisel Reverse UDP",
        "CHISEL",
        "DATAGRAM",
        "Reverse UDP forwarding through Chisel.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,UDP,REVERSE,HTTP,SSH_SECURITY",
    ),
    em(
        "CHISEL_SOCKS5",
        "Chisel SOCKS5",
        "CHISEL",
        "PROXY",
        "SOCKS5 proxy through Chisel.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,SOCKS5,HTTP,SSH_SECURITY",
    ),
    em(
        "CHISEL_REVERSE_SOCKS5",
        "Chisel Reverse SOCKS5",
        "CHISEL",
        "PROXY",
        "Reverse SOCKS5 proxy through Chisel.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,SOCKS5,REVERSE,HTTP,SSH_SECURITY",
    ),
    em(
        "FRP_TCP",
        "FRP TCP",
        "FRP",
        "STREAM",
        "FRP TCP reverse proxy.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,TCP,REVERSE",
    ),
    em(
        "FRP_UDP",
        "FRP UDP",
        "FRP",
        "DATAGRAM",
        "FRP UDP reverse proxy.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,UDP,REVERSE",
    ),
    em(
        "FRP_STCP",
        "FRP STCP",
        "FRP",
        "STREAM",
        "FRP secret TCP service.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,TCP,SECRET",
    ),
    em(
        "FRP_XTCP",
        "FRP XTCP",
        "FRP",
        "P2P",
        "FRP peer-to-peer TCP mode.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,TCP,P2P",
    ),
    em(
        "FRP_KCP",
        "FRP KCP",
        "FRP",
        "CARRIER",
        "FRP forwarding using KCP transport.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,KCP,UDP",
    ),
    em(
        "FRP_QUIC",
        "FRP QUIC",
        "FRP",
        "CARRIER",
        "FRP forwarding using QUIC transport.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,QUIC,UDP",
    ),
    em(
        "WSTUNNEL_TCP",
        "wstunnel TCP",
        "WSTUNNEL",
        "STREAM",
        "TCP tunnel transported over WebSocket.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,TCP,WEBSOCKET",
    ),
    em(
        "WSTUNNEL_UDP",
        "wstunnel UDP",
        "WSTUNNEL",
        "DATAGRAM",
        "UDP tunnel transported over WebSocket.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,UDP,WEBSOCKET",
    ),
    em(
        "WSTUNNEL_SOCKS5",
        "wstunnel SOCKS5",
        "WSTUNNEL",
        "PROXY",
        "SOCKS5 tunnel transported over WebSocket.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,SOCKS5,WEBSOCKET",
    ),
    em(
        "HYSTERIA2",
        "Hysteria 2",
        "MODERN_PROXY",
        "PROXY",
        "Hysteria 2 client/server profile.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,QUIC,UDP,TLS",
    ),
    em(
        "TUIC",
        "TUIC",
        "MODERN_PROXY",
        "PROXY",
        "TUIC client/server profile.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,QUIC,UDP,TLS",
    ),
    em(
        "TROJAN_TLS",
        "Trojan TLS",
        "MODERN_PROXY",
        "PROXY",
        "Trojan proxy protected by TLS.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,TCP,TLS",
    ),
    em(
        "SHADOWSOCKS",
        "Shadowsocks",
        "MODERN_PROXY",
        "PROXY",
        "Shadowsocks TCP and UDP proxy profile.",
        directions="A_TO_B,B_TO_A",
        flags="MULTI_INSTANCE,TCP_UDP,ENCRYPTED",
    ),
    em(
        "SINGBOX_TUN",
        "sing-box TUN",
        "MODERN_PROXY",
        "L3",
        "sing-box TUN routing profile.",
        flags="MULTI_INSTANCE,TUN,ROUTING",
    ),
]


EXISTING_IDS = {
    item["id"]
    for item in CATALOG
}

for item in EXTRA_METHODS:
    if item["id"] not in EXISTING_IDS:
        CATALOG.append(item)
        EXISTING_IDS.add(item["id"])


REVERSE_IDS = {
    "SSH_REMOTE_FORWARD",
    "AUTOSSH_REVERSE",
    "GOST_REMOTE_TCP",
    "GOST_REMOTE_UDP",
}

for item in CATALOG:
    item.setdefault(
        "description",
        item["name"],
    )

    item.setdefault(
        "flags",
        ["MULTI_INSTANCE"],
    )

    item.setdefault(
        "simple_supported",
        True,
    )

    item.setdefault(
        "advanced_supported",
        True,
    )

    reverse = item["id"] in REVERSE_IDS

    default_direction = (
        "B_TO_A"
        if (
            reverse
            and "B_TO_A"
            in item["directions"]
        )
        else (
            "BIDIRECTIONAL"
            if "BIDIRECTIONAL"
            in item["directions"]
            else item["directions"][0]
        )
    )

    item.setdefault(
        "simple_defaults",
        {
            "traffic_direction": (
                default_direction
            ),
            "initiator": (
                "B"
                if default_direction
                == "B_TO_A"
                else "AUTO"
            ),
            "carrier_method_id": None,
            "config": {
                "mode": "SIMPLE",
                "auto_allocate": True,
                "auto_install": True,
                "auto_precheck": True,
                "auto_inventory_refresh": True,
            },
        },
    )

# NETAUTO_EXPANDED_CATALOG_END

METHODS = {
    item["id"]: item
    for item in CATALOG
}


# NETAUTO_PACK3_KCP_CATALOG_BEGIN

PACK3_METHODS = [
    {
        "id": "GOST_KCP_FORWARD",
        "name": "GOST TCP over KCP",
        "category": "GOST",
        "layer": "STREAM",
        "directions": ["A_TO_B", "B_TO_A"],
        "initiators": ["AUTO", "A", "B"],
        "carriers": [],
        "description": (
            "TCP forwarding between two endpoints "
            "using an authenticated KCP data channel."
        ),
        "flags": [
            "MULTI_INSTANCE",
            "TCP",
            "KCP",
            "UDP_CARRIER",
            "AUTO_TUNE",
        ],
        "simple_supported": True,
        "advanced_supported": True,
        "simple_defaults": {
            "traffic_direction": "A_TO_B",
            "initiator": "AUTO",
            "carrier_method_id": None,
            "config": {
                "mode": "SIMPLE",
                "auto_install": True,
                "auto_precheck": True,
                "auto_inventory_refresh": True,
                "benchmark_enabled": True,
                "benchmark_duration": 6,
                "benchmark_max_mbps": 200,
            },
        },
    },
    {
        "id": "GOST_SOCKS5_KCP",
        "name": "GOST SOCKS5 over KCP",
        "category": "GOST",
        "layer": "PROXY",
        "directions": ["A_TO_B", "B_TO_A"],
        "initiators": ["AUTO", "A", "B"],
        "carriers": [],
        "description": (
            "Authenticated SOCKS5 service "
            "transported by a tuned KCP channel."
        ),
        "flags": [
            "MULTI_INSTANCE",
            "SOCKS5",
            "KCP",
            "UDP_CARRIER",
            "AUTO_TUNE",
        ],
        "simple_supported": True,
        "advanced_supported": True,
        "simple_defaults": {
            "traffic_direction": "A_TO_B",
            "initiator": "AUTO",
            "carrier_method_id": None,
            "config": {
                "mode": "SIMPLE",
                "auto_install": True,
                "auto_precheck": True,
                "auto_inventory_refresh": True,
            },
        },
    },
]

_existing_method_ids = {
    item["id"]
    for item in CATALOG
}

for _item in PACK3_METHODS:
    if _item["id"] not in _existing_method_ids:
        CATALOG.append(_item)
        _existing_method_ids.add(_item["id"])

METHODS = {
    item["id"]: item
    for item in CATALOG
}

# NETAUTO_PACK3_KCP_CATALOG_END


# NETAUTO_PACK4_SAFE_DEFAULTS_BEGIN

PACK4_EXECUTABLE_METHODS = {
    "FRP_TCP",
    "FRP_UDP",
    "FRP_STCP",
    "FRP_XTCP",
    "FRP_KCP",
    "FRP_QUIC",
    "RATHOLE_TCP",
    "RATHOLE_UDP",
    "RATHOLE_TLS",
    "RATHOLE_NOISE",
    "RATHOLE_WEBSOCKET",
    "CHISEL_TCP",
    "CHISEL_UDP",
    "CHISEL_REVERSE_TCP",
    "CHISEL_REVERSE_UDP",
    "CHISEL_SOCKS5",
    "CHISEL_REVERSE_SOCKS5",
    "WSTUNNEL_TCP",
    "WSTUNNEL_UDP",
    "WSTUNNEL_SOCKS5",
}

PACK4_PARAMETERS = {
    "FRP_TCP": [
        "control_port",
        "remote_port",
        "local_host",
        "local_port",
        "remote_bind_host",
    ],
    "FRP_UDP": [
        "control_port",
        "remote_port",
        "local_host",
        "local_port",
        "remote_bind_host",
    ],
    "FRP_STCP": [
        "control_port",
        "remote_port",
        "local_host",
        "local_port",
        "remote_bind_host",
    ],
    "FRP_XTCP": [
        "control_port",
        "remote_port",
        "local_host",
        "local_port",
        "remote_bind_host",
    ],
    "FRP_KCP": [
        "control_port",
        "remote_port",
        "local_host",
        "local_port",
        "remote_bind_host",
    ],
    "FRP_QUIC": [
        "control_port",
        "remote_port",
        "local_host",
        "local_port",
        "remote_bind_host",
    ],
    "RATHOLE_TCP": [
        "control_port",
        "remote_port",
        "local_host",
        "local_port",
        "remote_bind_host",
    ],
    "RATHOLE_UDP": [
        "control_port",
        "remote_port",
        "local_host",
        "local_port",
        "remote_bind_host",
    ],
    "RATHOLE_TLS": [
        "control_port",
        "remote_port",
        "local_host",
        "local_port",
        "remote_bind_host",
    ],
    "RATHOLE_NOISE": [
        "control_port",
        "remote_port",
        "local_host",
        "local_port",
        "remote_bind_host",
    ],
    "RATHOLE_WEBSOCKET": [
        "control_port",
        "remote_port",
        "local_host",
        "local_port",
        "remote_bind_host",
    ],
    "CHISEL_TCP": [
        "server_port",
        "listen_host",
        "listen_port",
        "target_host",
        "target_port",
    ],
    "CHISEL_UDP": [
        "server_port",
        "listen_host",
        "listen_port",
        "target_host",
        "target_port",
    ],
    "CHISEL_REVERSE_TCP": [
        "server_port",
        "listen_host",
        "listen_port",
        "target_host",
        "target_port",
    ],
    "CHISEL_REVERSE_UDP": [
        "server_port",
        "listen_host",
        "listen_port",
        "target_host",
        "target_port",
    ],
    "CHISEL_SOCKS5": [
        "server_port",
        "listen_host",
        "socks_port",
    ],
    "CHISEL_REVERSE_SOCKS5": [
        "server_port",
        "listen_host",
        "socks_port",
    ],
    "WSTUNNEL_TCP": [
        "server_port",
        "listen_host",
        "listen_port",
        "target_host",
        "target_port",
        "connection_min_idle",
    ],
    "WSTUNNEL_UDP": [
        "server_port",
        "listen_host",
        "listen_port",
        "target_host",
        "target_port",
        "connection_min_idle",
    ],
    "WSTUNNEL_SOCKS5": [
        "server_port",
        "listen_host",
        "socks_port",
        "connection_min_idle",
    ],
}

for _method in CATALOG:
    _method_id = _method.get("id")

    if _method_id not in (
        PACK4_EXECUTABLE_METHODS
    ):
        continue

    _method["parameters"] = (
        PACK4_PARAMETERS.get(
            _method_id,
            [],
        )
    )

    _method["simple_supported"] = True
    _method["advanced_supported"] = True

    _defaults = dict(
        _method.get(
            "simple_defaults",
            {},
        )
    )

    _config = dict(
        _defaults.get(
            "config",
            {},
        )
    )

    _config.update(
        {
            "auto_install": True,
            "auto_precheck": True,
            "auto_inventory_refresh": True,
            "local_host": "127.0.0.1",
            "target_host": "127.0.0.1",
            "target_port": 22,
            "listen_host": "127.0.0.1",
            "remote_bind_host": (
                "127.0.0.1"
            ),
            "benchmark_enabled": False,
        }
    )

    _defaults["config"] = _config

    _method["simple_defaults"] = (
        _defaults
    )

METHODS = {
    item["id"]: item
    for item in CATALOG
}

# NETAUTO_PACK4_SAFE_DEFAULTS_END


# NETAUTO_PACK5_VPN_DEFAULTS_BEGIN
PACK5_VPN_METHODS = {"OPENVPN", "IKEV2_IPSEC", "L2TP_IPSEC", "VTI", "VTI6"}
for _method in CATALOG:
    if _method.get("id") not in PACK5_VPN_METHODS:
        continue
    _method["simple_supported"] = True
    _method["advanced_supported"] = True
    _defaults = dict(_method.get("simple_defaults", {}))
    _config = dict(_defaults.get("config", {}))
    _config.update({"auto_install": True, "auto_precheck": True, "auto_inventory_refresh": True, "benchmark_enabled": True, "benchmark_duration": 6, "benchmark_max_mbps": 200})
    _defaults["config"] = _config
    _method["simple_defaults"] = _defaults
    if _method["id"] == "L2TP_IPSEC":
        _method["flags"] = ["SINGLE_INSTANCE", "LEGACY", "IPSEC", "PPP"]
        _method["description"] = "Legacy L2TP over IPsec compatibility tunnel; prefer IKEv2 or WireGuard."
    elif _method["id"] == "OPENVPN":
        _method["flags"] = ["MULTI_INSTANCE", "TLS", "UDP", "PEER_FINGERPRINT", "TLS_CRYPT"]
    elif _method["id"] == "IKEV2_IPSEC":
        _method["flags"] = ["MULTI_INSTANCE", "IKEV2", "IPSEC", "XFRM_INTERFACE"]
    else:
        _method["flags"] = ["MULTI_INSTANCE", "IKEV2", "IPSEC", "ROUTE_BASED"]
METHODS = {item["id"]: item for item in CATALOG}
# NETAUTO_PACK5_VPN_DEFAULTS_END


# NETAUTO_PACK6_MODERN_DEFAULTS_BEGIN
PACK6_METHODS = {
    "VLESS_TCP", "VLESS_WS", "VLESS_GRPC", "VLESS_XHTTP",
    "VLESS_REALITY", "VLESS_VISION_REALITY", "VLESS_XHTTP_REALITY",
    "HYSTERIA2", "TUIC", "TROJAN_TLS", "SHADOWSOCKS", "SINGBOX_TUN",
}
PACK6_PARAMETERS = {
    "VLESS_TCP": ["port", "socks_port", "benchmark_size_mb"],
    "VLESS_WS": ["port", "socks_port", "benchmark_size_mb"],
    "VLESS_GRPC": ["port", "socks_port", "benchmark_size_mb"],
    "VLESS_XHTTP": ["port", "socks_port", "benchmark_size_mb"],
    "VLESS_REALITY": ["port", "socks_port", "reality_target", "benchmark_size_mb"],
    "VLESS_VISION_REALITY": ["port", "socks_port", "reality_target", "benchmark_size_mb"],
    "VLESS_XHTTP_REALITY": ["port", "socks_port", "reality_target", "benchmark_size_mb"],
    "HYSTERIA2": ["port", "socks_port", "up_mbps", "down_mbps", "benchmark_size_mb"],
    "TUIC": ["port", "socks_port", "congestion_control", "benchmark_size_mb"],
    "TROJAN_TLS": ["port", "socks_port", "benchmark_size_mb"],
    "SHADOWSOCKS": ["port", "socks_port", "benchmark_size_mb"],
    "SINGBOX_TUN": ["port", "route_cidrs", "tun_address", "mtu"],
}
for _method in CATALOG:
    _id=_method.get("id")
    if _id not in PACK6_METHODS:
        continue
    _method["parameters"]=PACK6_PARAMETERS[_id]
    _method["advanced_supported"]=True
    _method["simple_supported"]=_id != "SINGBOX_TUN"
    _defaults=dict(_method.get("simple_defaults",{}))
    _config=dict(_defaults.get("config",{}))
    _config.update({
        "auto_install": True,
        "auto_precheck": True,
        "auto_inventory_refresh": True,
        "benchmark_enabled": True,
        "benchmark_size_mb": 16,
        "socks_bind": "127.0.0.1",
    })
    if _id in {"VLESS_REALITY","VLESS_VISION_REALITY","VLESS_XHTTP_REALITY"}:
        _config.setdefault("reality_target","www.microsoft.com:443")
    if _id == "HYSTERIA2":
        _config.setdefault("up_mbps",200)
        _config.setdefault("down_mbps",200)
    if _id == "TUIC":
        _config.setdefault("congestion_control","bbr")
    if _id == "SINGBOX_TUN":
        _config["benchmark_enabled"]=False
        _config["requires_explicit_route_cidrs"]=True
    _defaults["config"]=_config
    _method["simple_defaults"]=_defaults
METHODS={item["id"]:item for item in CATALOG}
# NETAUTO_PACK6_MODERN_DEFAULTS_END

# NETAUTO_PACK7_FINAL_DEFAULTS_BEGIN
PACK7_PARAMETERS = {
 "WATERWALL_DIRECT": ["listen_port","transport_port","target_host","target_port","bind_address"],
 "WATERWALL_REVERSE": ["listen_port","transport_port","target_host","target_port","bind_address","minimum_unused"],
 "WATERWALL_TLS_MUX": ["listen_port","transport_port","target_host","target_port","bind_address","sni","mux_connections"],
 "PAQET_RAW_KCP": ["listen_port","transport_port","target_host","target_port","bind_address","kcp_mode","connections"],
 "PAQET_SOCKS5": ["listen_port","transport_port","bind_address","kcp_mode","connections"],
 "SIT_OVER_GOST": ["tunnel_cidr","tunnel_ip_a","tunnel_ip_b","carrier_port","mtu"],
 "GRE_OVER_GOST": ["tunnel_cidr","tunnel_ip_a","tunnel_ip_b","carrier_port","mtu"],
 "GRETAP_OVER_GOST": ["tunnel_cidr","tunnel_ip_a","tunnel_ip_b","carrier_port","mtu"],
 "SIT_OVER_SSH": ["tunnel_cidr","tunnel_ip_a","tunnel_ip_b","ssh_tunnel_id","mtu"],
 "GRE_OVER_SSH": ["tunnel_cidr","tunnel_ip_a","tunnel_ip_b","ssh_tunnel_id","mtu"],
 "GRE_OVER_WIREGUARD": ["tunnel_cidr","tunnel_ip_a","tunnel_ip_b","mtu"],
}
for _item in CATALOG:
    _id=_item.get('id')
    if _id not in PACK7_PARAMETERS:
        continue
    _item['parameters']=PACK7_PARAMETERS[_id]
    _item['simple_supported']=True
    _item['advanced_supported']=True
    _defaults=dict(_item.get('simple_defaults') or {})
    _cfg=dict(_defaults.get('config') or {})
    _cfg.update({
        'auto_install':True,
        'auto_precheck':True,
        'auto_inventory_refresh':True,
        'benchmark_enabled':True,
        'benchmark_duration':6,
        'benchmark_max_mbps':200,
    })
    if _id.startswith('WATERWALL_') or _id.startswith('PAQET_'):
        _cfg.setdefault('bind_address','127.0.0.1')
    if _id == 'WATERWALL_REVERSE':
        _cfg.setdefault('minimum_unused',8)
    _defaults['config']=_cfg
    _item['simple_defaults']=_defaults
METHODS={item['id']:item for item in CATALOG}
# NETAUTO_PACK7_FINAL_DEFAULTS_END


# NETAUTO_FINAL_XHTTP_PROFILES_BEGIN
for _method in CATALOG:
    _id = _method.get("id")

    if _id == "VLESS_XHTTP":
        _method["name"] = "VLESS XHTTP Direct"
        _method["description"] = (
            "Direct endpoint-to-endpoint XHTTP transport using an internal "
            "TLS certificate. No CDN or public domain is required."
        )
        _method["deployment_mode"] = "DIRECT"
        _method["requires_domain"] = False
        _method["requires_cdn"] = False
        _method["cdn_compatible"] = False
        _method["flags"] = sorted(
            set(_method.get("flags", []))
            | {"MULTI_INSTANCE", "XHTTP", "DIRECT", "TLS"}
        )

    elif _id == "VLESS_XHTTP_REALITY":
        _method["name"] = "VLESS XHTTP REALITY Direct"
        _method["description"] = (
            "Direct XHTTP transport protected by REALITY. It connects to the "
            "server IP and does not pass through a CDN."
        )
        _method["deployment_mode"] = "DIRECT_REALITY"
        _method["requires_domain"] = False
        _method["requires_cdn"] = False
        _method["cdn_compatible"] = False
        _method["flags"] = sorted(
            set(_method.get("flags", []))
            | {"MULTI_INSTANCE", "XHTTP", "DIRECT", "REALITY"}
        )

METHODS = {item["id"]: item for item in CATALOG}
# NETAUTO_FINAL_XHTTP_PROFILES_END
