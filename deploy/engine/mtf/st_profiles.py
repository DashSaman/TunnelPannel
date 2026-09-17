#!/usr/bin/env python3
"""MTF persistent-install profiles — real tunnels between two real servers.

kernel_plan(mid, ctx) -> {"A": plan, "B": plan}
user_plan(mid, ctx)   -> {"A": plan, "B": plan, "origin": "A"|"B"|None,
                          "verify": [(side, cmd, expect)], "bins": [names]}

plan = {"script": str(bash), "files": {abs_path: content},
        "unit_name": str, "unit_kind": "oneshot"|"simple", "exec": str}

Token style: templates use @TOKENS@ replaced by concrete values (bash-safe).
"""
import secrets

# ---------------------------------------------------------------- allocations
# runtime port overrides filled by portmgr (conflict-safe auto-assign)
PORT_OVERRIDES = {}

def idx_of(mid: str) -> int:
    return PERSIST_ORDER.index(mid) if mid in PERSIST_ORDER else 99

def ports_of(mid: str):
    """(server_port, client_port, exposed_port); portmgr override wins."""
    if mid in PORT_OVERRIDES:
        ps, pc, pr = PORT_OVERRIDES[mid]
        return int(ps), int(pc), int(pr)
    i = idx_of(mid)
    ps = 15810 + i * 4
    return ps, ps + 2, ps + 1

def tun4(mid: str):
    """(a_tun_ip, b_tun_ip) from 10.173.<idx>.0/30"""
    i = idx_of(mid)
    return f"10.173.{i}.1", f"10.173.{i}.2"

def tun6(mid: str):
    i = idx_of(mid)
    return f"fd00:173:{i}::1", f"fd00:173:{i}::2"

PERSIST_ORDER = [
    # kernel
    "WIREGUARD", "GRE", "GRETAP", "SIT_6IN4", "IPIP", "VXLAN", "VTI", "VTI6",
    "IP6GRE", "IP6GRETAP", "HAJSAMAN_SIT", "HAJSAMAN_WG", "HAJSAMAN_FULL",
    "OPENVPN",
    # gost
    "GOST_SOCKS5", "GOST_HTTP", "GOST_WS", "GOST_GRPC",
    # chisel
    "CHISEL_SOCKS5", "CHISEL_TCP",
    # wstunnel
    "WSTUNNEL_SOCKS5", "WSTUNNEL_TCP",
    # rathole
    "RATHOLE_TCP", "RATHOLE_TLS",
    # frp
    "FRP_TCP", "FRP_KCP", "FRP_QUIC",
    # xray
    "VLESS_TCP", "VLESS_WS", "VLESS_GRPC", "VLESS_XHTTP",
    "VLESS_REALITY", "VLESS_VISION_REALITY", "VLESS_XHTTP_REALITY",
    # sing-box
    "HYSTERIA2", "TUIC", "TROJAN_TLS", "SHADOWSOCKS",
    # ssh
    "SSH_LOCAL_FORWARD", "SSH_DYNAMIC_SOCKS", "SSH_REMOTE_FORWARD",
]

KERNEL_MAP = {
    "GRE": "gre", "GRETAP": "gretap", "SIT_6IN4": "sit", "IPIP": "ipip",
    "VXLAN": "vxlan", "WIREGUARD": "wg", "HAJSAMAN_SIT": "sit",
    "HAJSAMAN_WG": "wg", "HAJSAMAN_FULL": "wg", "VTI": "vti", "VTI6": "vti6",
    "IP6GRE": "ip6gre", "IP6GRETAP": "ip6gretap", "OPENVPN": "ovpn",
}

BIN = "/opt/multitunnel/bin"
PDIR = "/opt/mtf-inst"

PARTIAL_NOTES = {
    "AUTOSSH_REVERSE": ("نصب ماندگار نیاز به باینری autossh دارد؛ از تب Deploy استفاده کنید",
                        "persistent install needs autossh binary; use the Deploy tab"),
    "SSH_TUN_L3": ("نیاز به sshd با PermitTunnel و دسترسی root روی هر دو سرور دارد",
                    "needs sshd PermitTunnel + root on both ends"),
    "SSH_TAP_L2": ("نیاز به sshd با PermitTunnel=ethernet دارد",
                    "needs sshd PermitTunnel=ethernet"),
    "IKEV2_IPSEC": ("نیاز به strongswan + swanctl روی هر دو سرور؛ بعد از نصب دستی پنل آن را مانیتور می‌کند",
                     "needs strongswan+swanctl on both ends; panel monitors after manual setup"),
    "L2TP_IPSEC": ("نیاز به strongswan + xl2tpd؛ پروفایل دستی در مستندات",
                    "needs strongswan + xl2tpd; manual profile in docs"),
    "SINGBOX_TUN": ("حالت TUN نیازمند اینترفیس و روتینگ اختصاصی روی هر دو سرور است",
                     "TUN mode needs dedicated iface+routing on both ends"),
    "CHISEL_UDP": ("حالت UDP برای نصب ماندگار هنوز پروفایل ندارد",
                    "UDP mode has no persistent profile yet"),
    "CHISEL_REVERSE_SOCKS5": ("حالت معکوس: کلاینت باید سمت ایران باشد؛ با جابه‌جایی نقش‌ها نصب کنید",
                              "reverse mode: run on the client side with swapped roles"),
    "CHISEL_REVERSE_TCP": ("حالت معکوس: کلاینت باید سمت ایران باشد؛ با جابه‌جایی نقش‌ها نصب کنید",
                           "reverse mode: run on the client side with swapped roles"),
    "CHISEL_REVERSE_UDP": ("حالت معکوس UDP هنوز پروفایل ماندگار ندارد",
                           "reverse UDP has no persistent profile yet"),
    "WSTUNNEL_UDP": ("حالت UDP برای نصب ماندگار هنوز پروفایل ندارد",
                     "UDP mode has no persistent profile yet"),
    "RATHOLE_NOISE": ("ترنسپورت noise به کلیدسرور دستی نیاز دارد",
                      "noise transport needs manual server key"),
    "RATHOLE_WEBSOCKET": ("ترنسپورت websocket به گواهی TLS معتبر نیاز دارد",
                          "websocket transport needs a valid TLS cert"),
    "RATHOLE_UDP": ("rathole آپاستریم UDP را پشتیبانی نمی‌کند",
                    "upstream rathole does not support UDP"),
    "FRP_UDP": ("پروکسی UDP برای نصب ماندگار هنوز پروفایل ندارد",
                "UDP proxy has no persistent profile yet"),
    "FRP_STCP": ("STCP به visitor با secretKey دستی نیاز دارد",
                 "STCP needs a manual secretKey visitor"),
    "FRP_XTCP": ("XTCP به visitor با secretKey دستی نیاز دارد",
                 "XTCP needs a manual secretKey visitor"),
    "WATERWALL_DIRECT": ("WaterWall اسکیمای کانفیگ اختصاصی دارد؛ پروفایل نمونه در /root/.mtf-profiles نوشته می‌شود",
                         "WaterWall has its own config schema; sample profile written to /root/.mtf-profiles"),
    "WATERWALL_REVERSE": ("WaterWall اسکیمای کانفیگ اختصاصی دارد؛ پروفایل نمونه نوشته می‌شود",
                          "WaterWall has its own config schema; sample profile written"),
    "WATERWALL_TLS_MUX": ("WaterWall TLS-mux به گواهی معتبر نیاز دارد",
                          "WaterWall TLS-mux needs a valid cert"),
    "PAQET_SOCKS5": ("paqet نیازمند جفت سرور/کلاینت روی لینک واقعی است؛ پروفایل نوشته می‌شود",
                     "paqet needs a real server/client pair; profile written"),
    "PAQET_RAW_KCP": ("raw-packet KCP به لینک اختصاصی نیاز دارد",
                      "raw-packet KCP needs a dedicated link"),
    "HEDIOUM_POOL_SOCKS": ("هدیوم با setup-foreign/setup-iran جفت‌می‌شود؛ پروفایل جفت در /root/.mtf-profiles",
                           "Hedioum pairs via setup-foreign/setup-iran; pair profile written"),
    "HEDIOUM_TUN": ("هدیوم TUN/gateway حالت اختصاصی دارد؛ پروفایل نوشته می‌شود",
                    "Hedioum TUN/gateway is a dedicated mode; profile written"),
}

# make every composite & remaining gost variants honest-PARTIAL too
for _m in ("GRE_OVER_GOST", "GRETAP_OVER_GOST", "SIT_OVER_GOST", "GRE_OVER_SSH",
           "SIT_OVER_SSH", "GRE_OVER_WIREGUARD"):
    PARTIAL_NOTES[_m] = ("پروفایل ترکیبی؛ ابتدا تانل پایه را نصب کنید سپس لایه دوم را",
                         "composite profile; install the base tunnel first, then the overlay")
for _m in ("GOST_KCP_FORWARD", "GOST_QUIC", "GOST_REMOTE_TCP", "GOST_REMOTE_UDP",
           "GOST_SOCKS5_KCP", "GOST_SSH", "GOST_TAP", "GOST_TCP_FORWARD",
           "GOST_TUN", "GOST_UDP_FORWARD", "GOST_HTTP2"):
    PARTIAL_NOTES[_m] = ("واریانت پیشرفته GOST برای نصب ماندگار هنوز پروفایل ندارد؛ از تب Deploy تست می‌شود",
                         "advanced GOST variant has no persistent profile yet; covered by Deploy tab")


def _unit_oneshot(name: str, script_path: str) -> str:
    return (f"[Unit]\nDescription=MTF persistent tunnel {name}\n"
            "After=network-online.target\nWants=network-online.target\n\n"
            "[Service]\nType=oneshot\n"
            f"ExecStart={script_path}\nRemainAfterExit=yes\n\n"
            "[Install]\nWantedBy=multi-user.target\n")


def _unit_simple(name: str, execs: str) -> str:
    return (f"[Unit]\nDescription=MTF persistent tunnel {name}\n"
            "After=network-online.target\nWants=network-online.target\n\n"
            "[Service]\nType=simple\nExecStart=" + execs + "\n"
            "Restart=always\nRestartSec=4\n\n"
            "[Install]\nWantedBy=multi-user.target\n")


KERNEL_ONESHOT = """#!/bin/bash
# MTF persistent tunnel @MID@ (@ROLE@ side) — idempotent
set -u
IF=@IF@
MYIP=@MYIP@ ; PEERIP=@PEERIP@
MY6=@MY6@ ; PEER6=@PEER6@
MYTUN=@MYTUN@ ; PEERTUN=@PEERTUN@
MYTUN6=@MYTUN6@ ; PEERTUN6=@PEERTUN6@
PORT=@PORT@ ; VNI=@VNI@ ; MARK=@MARK@

ip link del "$IF" 2>/dev/null || true
@CREATE@

@ADDRS@
ip link set "$IF" up 2>/dev/null || true
"""


def kernel_plan(mid: str, ctx: dict) -> dict:
    """ctx: {a_ip,b_ip,a6,b6, wg:{a_priv,a_pub,b_priv,b_pub}, keys:{auth1,enc1,auth2,enc2}}"""
    kind = KERNEL_MAP[mid]
    ps, pc, pr = ports_of(mid)
    a4, b4 = tun4(mid)
    a6, b6 = tun6(mid)
    mk = hex(0x200 + idx_of(mid))
    plans = {}
    for role, my, peer, mytun, peertun, my6, peer6 in (
            ("a", ctx["a_ip"], ctx["b_ip"], a4, b4, a6, b6),
            ("b", ctx["b_ip"], ctx["a_ip"], b4, a4, b6, a6)):
        ifname = ("mtf-" + mid.lower().replace("_", ""))[:15]
        create, addrs, files = "", "", {}
        if kind == "gre":
            create = f'ip tunnel add "$IF" mode gre local "$MYIP" remote "$PEERIP" ttl 64'
            addrs = (f'ip addr add "$MYTUN"/30 dev "$IF" 2>/dev/null || true\n'
                     f'ip -6 addr add "$MYTUN6"/126 dev "$IF" 2>/dev/null || true')
        elif kind == "gretap":
            create = f'ip link add "$IF" type gretap local "$MYIP" remote "$PEERIP"'
            addrs = (f'ip addr add "$MYTUN"/30 dev "$IF" 2>/dev/null || true\n'
                     f'ip -6 addr add "$MYTUN6"/126 dev "$IF" 2>/dev/null || true')
        elif kind == "sit":
            create = f'ip tunnel add "$IF" mode sit local "$MYIP" remote "$PEERIP" ttl 64'
            addrs = f'ip -6 addr add "$MYTUN6"/126 dev "$IF" 2>/dev/null || true'
        elif kind == "ipip":
            create = f'ip tunnel add "$IF" mode ipip local "$MYIP" remote "$PEERIP" ttl 64'
            addrs = (f'ip addr add "$MYTUN"/30 dev "$IF" 2>/dev/null || true\n'
                     f'ip -6 addr add "$MYTUN6"/126 dev "$IF" 2>/dev/null || true')
        elif kind == "vxlan":
            # dstport from allocation (@PORT@=server port) instead of fixed 4789
            create = f'ip link add "$IF" type vxlan id {200 + idx_of(mid)} local "$MYIP" remote "$PEERIP" dstport "$PORT"'
            addrs = (f'ip addr add "$MYTUN"/30 dev "$IF" 2>/dev/null || true\n'
                     f'ip -6 addr add "$MYTUN6"/126 dev "$IF" 2>/dev/null || true')
        elif kind == "wg":
            priv = ctx["wg"][role]["priv"]
            mypub = ctx["wg"]["a" if role == "b" else "b"]["pub"]
            peer_pub = ctx["wg"][("b" if role == "a" else "a")]["pub"]
            listen = ps if role == "b" else pc  # B=server listens ps, A=client
            files[f"/etc/wireguard/{ifname}.data"] = (
                f"{priv}\n{mypub}\n{peer_pub}\n")
            create = (f'ip link add "$IF" type wireguard && '
                      f'wg set "$IF" listen-port {listen} private-key <(head -1 /etc/wireguard/{ifname}.data) && '
                      f'wg set "$IF" peer {peer_pub} endpoint "$PEERIP":{ps if role == "a" else pc} '
                      f'allowed-ips "$PEERTUN"/32,"$PEERTUN6"/128 persistent-keepalive 25')
            addrs = (f'ip addr add "$MYTUN"/30 dev "$IF" 2>/dev/null || true\n'
                     f'ip -6 addr add "$MYTUN6"/126 dev "$IF" 2>/dev/null || true')
        elif kind == "vti":
            create = (f'ip tunnel add "$IF" mode vti local "$MYIP" remote "$PEERIP" mark {mk} && '
                      f'ip xfrm state add src "$MYIP" dst "$PEERIP" proto esp spi {hex(0x1000 + idx_of(mid) * 2)} mode tunnel '
                      f"auth-trunc 'hmac(sha256)' {ctx['keys']['auth1']} 128 enc 'cbc(aes)' {ctx['keys']['enc1']} && "
                      f'ip xfrm state add src "$PEERIP" dst "$MYIP" proto esp spi {hex(0x1000 + idx_of(mid) * 2 + 1)} mode tunnel '
                      f"auth-trunc 'hmac(sha256)' {ctx['keys']['auth2']} 128 enc 'cbc(aes)' {ctx['keys']['enc2']} && "
                      f'ip xfrm policy add dir out mark {mk} tmpl src "$MYIP" dst "$PEERIP" proto esp mode tunnel mark {mk} && '
                      f'ip xfrm policy add dir in mark {mk} tmpl src "$PEERIP" dst "$MYIP" proto esp mode tunnel mark {mk}')
            addrs = (f'ip addr add "$MYTUN"/30 dev "$IF" 2>/dev/null || true\n'
                     f'ip -6 addr add "$MYTUN6"/126 dev "$IF" 2>/dev/null || true')
        elif kind == "vti6":
            create = (f'ip -6 tunnel add "$IF" mode vti6 local "$MY6" remote "$PEER6" mark {mk} && '
                      f'ip xfrm state add src "$MY6" dst "$PEER6" proto esp spi {hex(0x3000 + idx_of(mid) * 2)} mode tunnel '
                      f"auth-trunc 'hmac(sha256)' {ctx['keys']['auth1']} 128 enc 'cbc(aes)' {ctx['keys']['enc1']} && "
                      f'ip xfrm state add src "$PEER6" dst "$MY6" proto esp spi {hex(0x3000 + idx_of(mid) * 2 + 1)} mode tunnel '
                      f"auth-trunc 'hmac(sha256)' {ctx['keys']['auth2']} 128 enc 'cbc(aes)' {ctx['keys']['enc2']}")
            addrs = f'ip addr add "$MYTUN"/30 dev "$IF" 2>/dev/null || true'
        elif kind == "ip6gre":
            create = f'ip -6 tunnel add "$IF" mode ip6gre local "$MY6" remote "$PEER6"'
            addrs = f'ip -6 addr add "$MYTUN6"/126 dev "$IF" 2>/dev/null || true'
        elif kind == "ip6gretap":
            create = f'ip link add "$IF" type ip6gretap local "$MY6" remote "$PEER6"'
            addrs = f'ip -6 addr add "$MYTUN6"/126 dev "$IF" 2>/dev/null || true'
        elif kind == "ovpn":
            port = ps if role == "b" else pc
            files[f"/etc/openvpn/mtf-{ifname}.key"] = ctx["keys"]["ovpn"]
            files[f"/etc/openvpn/mtf-{ifname}.conf"] = (
                f"dev {ifname}\nproto udp\nport {port}\n"
                + (f"remote {peer} {port}\n" if role == "a" else "")
                + f"ifconfig {mytun} {peertun}\nsecret /etc/openvpn/mtf-{ifname}.key\n"
                "keepalive 10 60\npersist-key\npersist-tun\nverb 3\n")
            create = "echo openvpn-configured"
            addrs = "echo openvpn-addr-via-conf"
        script = (KERNEL_ONESHOT
                  .replace("@MID@", mid).replace("@ROLE@", role)
                  .replace("@IF@", ifname).replace("@MYIP@", my).replace("@PEERIP@", peer)
                  .replace("@MY6@", ctx["a6"] if role == "a" else ctx["b6"])
                  .replace("@PEER6@", ctx["b6"] if role == "a" else ctx["a6"])
                  .replace("@MYTUN@", mytun).replace("@PEERTUN@", peertun)
                  .replace("@MYTUN6@", my6).replace("@PEERTUN6@", peer6)
                  .replace("@PORT@", str(ps)).replace("@VNI@", str(200 + idx_of(mid)))
                  .replace("@MARK@", mk)
                  .replace("@CREATE@", create).replace("@ADDRS@", addrs))
        spath = f"/usr/local/bin/{ifname}.sh"
        files[spath] = script
        files[f"/etc/systemd/system/{ifname}.service"] = _unit_oneshot(ifname, spath)
        plans[role] = {"script": script, "files": files, "unit_name": ifname,
                       "unit_kind": "oneshot", "exec": spath, "iface": ifname}
    return plans


def _origin_unit(side_dir: str) -> dict:
    return {f"{side_dir}/origin/index.html": "MTF origin OK\n",
            f"/etc/systemd/system/mtf-origin.service": _unit_simple(
                "mtf-origin", f"/usr/bin/python3 -m http.server 5201 --bind 0.0.0.0 --directory {side_dir}/origin")}


V204 = "curl -s -o /dev/null -w '%{http_code}' --socks5-hostname 127.0.0.1:@PC@ --max-time 12 http://cp.cloudflare.com/generate_204"


def user_plan(mid: str, ctx: dict) -> dict:
    """ctx: {a_ip,b_ip,uuid,pw,ss22, real:{priv,pub} (reality), cert:{crt,key}}"""
    ps, pc, pr = ports_of(mid)
    a_ip, b_ip = ctx["a_ip"], ctx["b_ip"]
    uuid, pw = ctx["uuid"], ctx["pw"]
    plans = {"A": {"files": {}, "unit_kind": "simple"}, "B": {"files": {}, "unit_kind": "simple"}}
    out = {"A": plans["A"], "B": plans["B"], "origin": None, "verify": [], "bins": [],
           "ports": [ps, pc, pr]}

    def verify_socks(side, port):
        out["verify"].append((side, V204.replace("@PC@", str(port)), "204"))

    if mid in ("GOST_SOCKS5", "GOST_HTTP", "GOST_WS", "GOST_GRPC"):
        scheme = {"GOST_SOCKS5": "socks5", "GOST_HTTP": "http", "GOST_WS": "ws",
                  "GOST_GRPC": "grpc"}[mid]
        out["bins"] = ["gost"]
        # empty host binds dual-stack (:: + v4-mapped) on Go listeners
        out["B"]["exec"] = f"{BIN}/gost -L '{scheme}://:{ps}'"
        out["A"]["exec"] = f"{BIN}/gost -L 'socks5://:{pc}' -F '{scheme}://{b_ip}:{ps}'"
        verify_socks("A", pc)
        out["origin"] = None
        return out

    if mid in ("CHISEL_SOCKS5", "CHISEL_TCP"):
        out["bins"] = ["chisel"]
        auth = f"mtf:{pw}"
        # --host :: = dual-stack listener (v4-mapped + v6)
        out["B"]["exec"] = f"{BIN}/chisel server --host :: --port {ps} --auth '{auth}' --reverse"
        out["origin"] = "B"
        out["A"]["exec"] = (
            f"{BIN}/chisel client --auth '{auth}' http://{b_ip}:{ps} "
            + (f"socks5://127.0.0.1:{pc}" if mid == "CHISEL_SOCKS5"
               else f"{pc}:127.0.0.1:5201"))
        if mid == "CHISEL_SOCKS5":
            verify_socks("A", pc)
        else:
            out["verify"].append(("A", f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 12 http://127.0.0.1:{pc}/", "200"))
        return out

    if mid in ("WSTUNNEL_SOCKS5", "WSTUNNEL_TCP"):
        out["bins"] = ["wstunnel"]
        out["B"]["exec"] = f"{BIN}/wstunnel server ws://[::]:{ps}"
        out["origin"] = "B"
        out["A"]["exec"] = (
            f"{BIN}/wstunnel client ws://{b_ip}:{ps} -L "
            + (f"socks5://127.0.0.1:{pc}" if mid == "WSTUNNEL_SOCKS5"
               else f"tcp://127.0.0.1:{pc}:127.0.0.1:5201"))
        if mid == "WSTUNNEL_SOCKS5":
            verify_socks("A", pc)
        else:
            out["verify"].append(("A", f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 12 http://127.0.0.1:{pc}/", "200"))
        return out

    if mid in ("RATHOLE_TCP", "RATHOLE_TLS"):
        out["bins"] = ["rathole"]
        tok = pw
        tls = ""
        if mid == "RATHOLE_TLS":
            tls = (f'\n[tls]\nhostname = "mtf.local"\n'
                   f'certificate = "{PDIR}/tls/cert.pem"\nprivate_key = "{PDIR}/tls/key.pem"\n')
            out["bins"] = ["rathole"]
            out["B"]["files"][f"{PDIR}/tls/cert.pem"] = ctx["cert"]["crt"]
            out["B"]["files"][f"{PDIR}/tls/key.pem"] = ctx["cert"]["key"]
            out["A"]["files"][f"{PDIR}/tls/cert.pem"] = ctx["cert"]["crt"]
            out["A"]["files"][f"{PDIR}/tls/key.pem"] = ctx["cert"]["key"]
        out["B"]["files"][f"{PDIR}/rathole/server.toml"] = (
            f'[server]\nbind_addr = "[::]:{ps}"\n{tls}\n'
            f'[server.services.mtf]\ntoken = "{tok}"\nbind_addr = "[::]:{pr}"\n')
        out["A"]["files"][f"{PDIR}/rathole/client.toml"] = (
            f'[client]\nremote_addr = "{b_ip}:{ps}"\n{tls}\n'
            f'[client.services.mtf]\ntoken = "{tok}"\nlocal_addr = "127.0.0.1:5201"\n')
        out["B"]["exec"] = f"{BIN}/rathole --server {PDIR}/rathole/server.toml"
        out["A"]["exec"] = f"{BIN}/rathole --client {PDIR}/rathole/client.toml"
        out["origin"] = "A"
        out["verify"].append(("A", f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 12 http://{b_ip}:{pr}/", "200"))
        return out

    if mid in ("FRP_TCP", "FRP_KCP", "FRP_QUIC"):
        out["bins"] = ["frps", "frpc"]
        proto = mid.replace("FRP_", "").lower()
        binds = f'bindAddr = "::"\nbindPort = {ps}\n'
        if proto == "kcp":
            binds += f"kcpBindPort = {ps}\n"
        if proto == "quic":
            binds += f"quicBindPort = {ps}\n"
        out["B"]["files"][f"{PDIR}/frp/frps.toml"] = binds
        out["A"]["files"][f"{PDIR}/frp/frpc.toml"] = (
            f'serverAddr = "{b_ip}"\nserverPort = {ps}\n'
            f'transport.protocol = "{proto}"\n\n'
            f'[[proxies]]\nname = "mtf"\ntype = "tcp"\n'
            f'localIP = "127.0.0.1"\nlocalPort = 5201\nremotePort = {pr}\n')
        out["B"]["exec"] = f"{BIN}/frps -c {PDIR}/frp/frps.toml"
        out["A"]["exec"] = f"{BIN}/frpc -c {PDIR}/frp/frpc.toml"
        out["origin"] = "A"
        out["verify"].append(("A", f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 14 http://{b_ip}:{pr}/", "200"))
        return out

    if mid.startswith("VLESS_"):
        out["bins"] = ["xray"]
        transport = mid.replace("VLESS_", "").lower()
        vuser = {"id": uuid}
        stream = {"network": "tcp"}
        reality = "reality" in transport
        if "xhttp" in transport:
            stream["network"] = "xhttp"
            stream["xhttpSettings"] = {"path": "/mtf"}
        elif transport == "ws":
            stream = {"network": "ws", "wsSettings": {"path": "/mtf"}}
        elif transport == "grpc":
            stream = {"network": "grpc", "grpcSettings": {"serviceName": "mtf"}}
        if reality:
            stream["realitySettings"] = {
                "dest": "www.microsoft.com:443", "serverNames": ["www.microsoft.com"],
                "privateKey": ctx["real"]["priv"], "shortIds": [""]}
            if "vision" in transport:
                vuser["flow"] = "xtls-rprx-vision"
            cstream = {"network": stream["network"], "realitySettings": {
                "serverName": "www.microsoft.com", "publicKey": ctx["real"]["pub"],
                "shortId": "", "fingerprint": "chrome"}}
            if "xhttpSettings" in stream:
                cstream["xhttpSettings"] = stream["xhttpSettings"]
        else:
            cstream = stream
        srv_cfg = {"log": {"loglevel": "warning"},
                   "inbounds": [{"listen": "::", "port": ps, "protocol": "vless",
                                 "settings": {"clients": [vuser], "decryption": "none"},
                                 "streamSettings": stream}],
                   "outbounds": [{"protocol": "freedom"}]}
        cli_cfg = {"log": {"loglevel": "warning"},
                   "inbounds": [{"listen": "127.0.0.1", "port": pc, "protocol": "socks",
                                 "settings": {"auth": "noauth", "udp": False}}],
                   "outbounds": [{"protocol": "vless",
                                  "settings": {"vnext": [{"address": b_ip, "port": ps,
                                                          "users": [vuser]}]},
                                  "streamSettings": cstream}]}
        out["B"]["files"][f"{PDIR}/xray/server.json"] = __import__("json").dumps(srv_cfg, indent=1)
        out["A"]["files"][f"{PDIR}/xray/client.json"] = __import__("json").dumps(cli_cfg, indent=1)
        out["B"]["exec"] = f"{BIN}/xray run -c {PDIR}/xray/server.json"
        out["A"]["exec"] = f"{BIN}/xray run -c {PDIR}/xray/client.json"
        verify_socks("A", pc)
        return out

    if mid in ("HYSTERIA2", "TUIC", "TROJAN_TLS", "SHADOWSOCKS"):
        out["bins"] = ["sing-box"]
        import json as _j
        if mid == "HYSTERIA2":
            srv = [{"type": "hysteria2", "listen": f"[::]:{ps}",
                    "users": [{"password": pw}],
                    "tls": {"enabled": True, "certificate_path": f"{PDIR}/tls/cert.pem",
                            "key_path": f"{PDIR}/tls/key.pem"}}]
            cli = [{"type": "hysteria2", "server": b_ip, "server_port": ps, "password": pw,
                    "tls": {"enabled": True, "insecure": True}}]
        elif mid == "TUIC":
            srv = [{"type": "tuic", "listen": f"[::]:{ps}",
                    "users": [{"uuid": uuid, "password": pw}],
                    "tls": {"enabled": True, "certificate_path": f"{PDIR}/tls/cert.pem",
                            "key_path": f"{PDIR}/tls/key.pem"}}]
            cli = [{"type": "tuic", "server": b_ip, "server_port": ps,
                    "uuid": uuid, "password": pw,
                    "tls": {"enabled": True, "insecure": True}}]
        elif mid == "TROJAN_TLS":
            srv = [{"type": "trojan", "listen": "::", "listen_port": ps,
                    "users": [{"password": pw}],
                    "tls": {"enabled": True, "certificate_path": f"{PDIR}/tls/cert.pem",
                            "key_path": f"{PDIR}/tls/key.pem"}}]
            cli = [{"type": "trojan", "server": b_ip, "server_port": ps, "password": pw,
                    "tls": {"enabled": True, "insecure": True}}]
        else:
            srv = [{"type": "shadowsocks", "listen": "::", "listen_port": ps,
                    "method": "2022-blake3-aes-128-gcm", "password": ctx["ss22"]}]
            cli = [{"type": "shadowsocks", "server": b_ip, "server_port": ps,
                    "method": "2022-blake3-aes-128-gcm", "password": ctx["ss22"]}]
        out["B"]["files"][f"{PDIR}/tls/cert.pem"] = ctx["cert"]["crt"]
        out["B"]["files"][f"{PDIR}/tls/key.pem"] = ctx["cert"]["key"]
        out["B"]["files"][f"{PDIR}/singbox/server.json"] = _j.dumps(
            {"log": {"level": "warn"}, "inbounds": srv, "outbounds": [{"type": "direct"}]}, indent=1)
        out["A"]["files"][f"{PDIR}/singbox/client.json"] = _j.dumps(
            {"log": {"level": "warn"},
             "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": pc}],
             "outbounds": cli}, indent=1)
        out["B"]["exec"] = f"{BIN}/sing-box run -c {PDIR}/singbox/server.json"
        out["A"]["exec"] = f"{BIN}/sing-box run -c {PDIR}/singbox/client.json"
        verify_socks("A", pc)
        return out

    if mid in ("SSH_LOCAL_FORWARD", "SSH_DYNAMIC_SOCKS", "SSH_REMOTE_FORWARD"):
        out["bins"] = []
        keyarg = f"-i {PDIR}/ssh/mtf_key -o StrictHostKeyChecking=no -o ServerAliveInterval=30 -o ExitOnForwardFailure=yes"
        base = f"/usr/bin/ssh -N {keyarg} -p {ctx.get('b_ssh_port', 22)} root@{b_ip}"
        if mid == "SSH_LOCAL_FORWARD":
            out["origin"] = "B"
            out["A"]["exec"] = f"{base} -L 127.0.0.1:{pc}:127.0.0.1:5201"
            out["verify"].append(("A", f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 12 http://127.0.0.1:{pc}/", "200"))
        elif mid == "SSH_DYNAMIC_SOCKS":
            out["A"]["exec"] = f"{base} -D 127.0.0.1:{pc}"
            verify_socks("A", pc)
        else:
            out["origin"] = "A"
            out["A"]["exec"] = f"{base} -R 127.0.0.1:{pr}:127.0.0.1:5201"
            out["verify"].append(("B", f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 12 http://127.0.0.1:{pr}/", "200"))
        return out

    raise ValueError(f"no persistent profile for {mid}")
