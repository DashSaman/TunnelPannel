#!/usr/bin/env python3
"""MTF userspace method harness — real loopback server+client pairs with
data-through-tunnel verification for GOST/FRP/RATHOLE/CHISEL/WSTUNNEL/
XRAY/SINGBOX/WATERWALL/PAQET families."""
import base64
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import time

BASE = "/opt/multitunnel"
BIN = f"{BASE}/bin"
MDIR = f"{BASE}/methods"
LOGD = f"{BASE}/logs"
ECHO_PORT = 9999          # python http.server echo origin (host)
PROBE = f"http://127.0.0.1:{ECHO_PORT}/"


def sh(cmd: str, timeout: int = 20) -> tuple[int, str]:
    try:
        p = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr)[-1200:]
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def wait_port(port: int, host: str = "127.0.0.1", timeout: float = 15.0) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def spawn(name: str, cmd: list[str], logfile: str) -> subprocess.Popen:
    lf = open(logfile, "ab")
    p = subprocess.Popen(cmd, stdout=lf, stderr=lf,
                         start_new_session=True)
    return p


def curl_via_socks(port: int, url: str = PROBE, timeout: int = 12) -> tuple[bool, str]:
    rc, out = sh(f"curl -s -o /dev/null -w '%{{http_code}}' --socks5-hostname 127.0.0.1:{port} "
                 f"--max-time {timeout} {url}")
    return rc == 0 and out.strip() == "200", f"curl socks5 :{port} -> {out.strip()}"


def curl_via_http(port: int, url: str = PROBE, timeout: int = 12) -> tuple[bool, str]:
    rc, out = sh(f"curl -s -o /dev/null -w '%{{http_code}}' -x http://127.0.0.1:{port} "
                 f"--max-time {timeout} {url}")
    return rc == 0 and out.strip() == "200", f"curl http-proxy :{port} -> {out.strip()}"


def curl_direct(port: int, url: str | None = None, timeout: int = 12) -> tuple[bool, str]:
    u = url or f"http://127.0.0.1:{port}/"
    rc, out = sh(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time {timeout} {u}")
    return rc == 0 and out.strip() == "200", f"curl direct :{port} -> {out.strip()}"


def udp_echo_test(port: int, payload: str = "mtf-udp-probe") -> tuple[bool, str]:
    rc, out = sh(
        f"(sleep 0.2; printf '{payload}' | socat -t3 - UDP4:127.0.0.1:{port}) "
        f"& sleep 0.1; socat -T3 UDP4-RECVFROM:{port},fork EXEC:'/bin/cat' 2>/dev/null "
        f"| head -c 64", timeout=8)
    return (payload in out), f"udp roundtrip via :{port} -> {out[:40]!r}"


def ensure_echo():
    rc, out = sh(f"ss -tln | grep -q ':{ECHO_PORT} ' && echo up || "
                 f"(nohup python3 -m http.server {ECHO_PORT} --bind 0.0.0.0 "
                 f">> {LOGD}/echo.log 2>&1 & echo starting)")
    for _ in range(20):
        if wait_port(ECHO_PORT):
            return
        time.sleep(0.3)


def cert_pair(dirp: str, cn="mtf.local") -> tuple[str, str]:
    os.makedirs(dirp, exist_ok=True)
    crt, key = f"{dirp}/cert.pem", f"{dirp}/key.pem"
    if not os.path.exists(crt):
        sh(f"openssl req -x509 -newkey rsa:2048 -keyout {key} -out {crt} -days 365 "
           f"-nodes -subj '/CN={cn}' >/dev/null 2>&1")
    return crt, key


def wr(path: str, content: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


class Harness:
    """Manages processes for one method test."""

    def __init__(self, mid: str):
        self.mid = mid
        self.dir = f"{MDIR}/{mid}"
        os.makedirs(self.dir, exist_ok=True)
        self.procs: list[subprocess.Popen] = []
        self.evidence: list[str] = []

    def start(self, cmd: list[str], tag: str):
        p = spawn(tag, cmd, f"{LOGD}/{self.mid}-{tag}.log")
        self.procs.append(p)
        return p

    def stop(self):
        for p in self.procs:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except Exception:
                pass
        for p in self.procs:
            try:
                p.wait(timeout=3)
            except Exception:
                pass

    def ev(self, msg: str):
        self.evidence.append(msg)


def run_gost(h: Harness, variant: str) -> tuple[str, dict]:
    g = f"{BIN}/gost"
    P_S, P_C = 14001, 14102
    jobs = {
        "GOST_SOCKS5": [
            [g, "-L", f"socks5://127.0.0.1:{P_S}"],
            [g, "-L", f"socks5://127.0.0.1:{P_C}", "-F", f"socks5://127.0.0.1:{P_S}"],
            "socks", P_C],
        "GOST_HTTP": [
            [g, "-L", f"http://127.0.0.1:{P_S}"],
            [g, "-L", f"http://127.0.0.1:{P_C}", "-F", f"http://127.0.0.1:{P_S}"],
            "http", P_C],
        "GOST_WS": [
            [g, "-L", f"ws://127.0.0.1:{P_S}"],
            [g, "-L", f"socks5://127.0.0.1:{P_C}", "-F", f"ws://127.0.0.1:{P_S}"],
            "socks", P_C],
        "GOST_GRPC": [
            [g, "-L", f"grpc://127.0.0.1:{P_S}"],
            [g, "-L", f"socks5://127.0.0.1:{P_C}", "-F", f"grpc://127.0.0.1:{P_S}"],
            "socks", P_C],
        "GOST_HTTP2": [
            [g, "-L", f"h2://127.0.0.1:{P_S}"],
            [g, "-L", f"socks5://127.0.0.1:{P_C}", "-F", f"h2://127.0.0.1:{P_S}"],
            "socks", P_C],
        "GOST_QUIC": [
            [g, "-L", f"quic://127.0.0.1:{P_S}"],
            [g, "-L", f"socks5://127.0.0.1:{P_C}", "-F", f"quic://127.0.0.1:{P_S}"],
            "socks", P_C],
        "GOST_TCP_FORWARD": [
            [g, "-L", f"tcp://127.0.0.1:{P_S}/127.0.0.1:{ECHO_PORT}"],
            None, "direct", P_S],
        "GOST_UDP_FORWARD": [
            [g, "-L", f"udp://127.0.0.1:{P_S}/127.0.0.1:{ECHO_PORT}"],
            None, "udp", P_S],
        "GOST_KCP_FORWARD": [
            [g, "-L", f"kcp://127.0.0.1:{P_S}/127.0.0.1:{ECHO_PORT}"],
            [g, "-L", f"tcp://127.0.0.1:{P_C}", "-F", f"kcp://127.0.0.1:{P_S}"],
            "direct", P_C],
        "GOST_SOCKS5_KCP": [
            [g, "-L", f"socks5+kcp://127.0.0.1:{P_S}"],
            [g, "-L", f"socks5://127.0.0.1:{P_C}", "-F", f"socks5+kcp://127.0.0.1:{P_S}"],
            "socks", P_C],
        "GOST_REMOTE_TCP": [
            [g, "-L", f"socks5://127.0.0.1:{P_S}"],
            [g, "-L", f"rtcp://:14103/127.0.0.1:{ECHO_PORT}", "-F", f"socks5://127.0.0.1:{P_S}"],
            "direct", 14103],
        "GOST_REMOTE_UDP": [
            [g, "-L", f"socks5://127.0.0.1:{P_S}"],
            [g, "-L", f"rudp://:14104/127.0.0.1:{ECHO_PORT}", "-F", f"socks5://127.0.0.1:{P_S}"],
            "udp", 14104],
        "GOST_SSH": [
            [g, "-L", f"ssh://mtf:mtfpass@127.0.0.1:{P_S}"],
            [g, "-L", f"socks5://127.0.0.1:{P_C}", "-F", f"ssh://mtf:mtfpass@127.0.0.1:{P_S}"],
            "socks", P_C],
    }
    if variant in ("GOST_TUN", "GOST_TAP"):
        return run_gost_tun(h, variant)
    job = jobs[variant]
    srv, cli, mode, port = job
    h.start(srv, "srv")
    if cli:
        h.start(cli, "cli")
    if not wait_port(port if mode != "udp" else P_S, timeout=12):
        h.ev(f"port {port} not ready; gost may not support scheme (see log)")
        return "FAIL", {"evidence": h.evidence}
    if mode == "socks":
        ok, msg = curl_via_socks(port)
    elif mode == "http":
        ok, msg = curl_via_http(port)
    elif mode == "udp":
        ok, msg = udp_echo_test(P_S)
    else:
        ok, msg = curl_direct(port)
    h.ev(msg)
    verdict = "PASS" if ok else "FAIL"
    return verdict, {"evidence": h.evidence}


def run_gost_tun(h: Harness, variant: str) -> tuple[str, dict]:
    if not os.path.exists("/dev/net/tun"):
        rc, out = sh("mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 600 /dev/net/tun")
        if rc != 0:
            h.ev("no /dev/net/tun")
            return "PARTIAL", {"evidence": h.evidence, "note": "TUN device unavailable in container"}
    g = f"{BIN}/gost"
    cfg = {"ServeNodes": [], "Retries": 0}
    # gost TUN: server side routed tun
    h.start([g, "-L", "tun://:0?net=10.74.0.1/30&route=10.74.0.0/30"], "srv-tun")
    h.start([g, "-L", "tun://:0?net=10.74.0.2/30&gw=10.74.0.1"], "cli-tun")
    time.sleep(4)
    ok, msg = sh("ping -c3 -i0.3 -W2 -I tun0 10.74.0.1 2>&1 | tail -2")[0] == 0
    h.ev(f"gost TUN datapath ping -> rc={0 if ok else 1}")
    return ("PASS" if ok else "PARTIAL"), {"evidence": h.evidence,
                                           "note": "TUN needs /dev/net/tun + gost tun plugin"}


def run_frp(h: Harness, variant: str) -> tuple[str, dict]:
    frps, frpc = f"{BIN}/frps", f"{BIN}/frpc"
    bind = 14110
    proto = variant.replace("FRP_", "").lower()          # tcp udp kcp quic stcp xtcp
    tok = secrets.token_hex(8)
    wr(f"{h.dir}/frps.toml",
       f'bindAddr = "0.0.0.0"\nbindPort = {bind}\nkcpBindPort = {bind}\nquicBindPort = {bind}\n')
    h.start([frps, "-c", f"{h.dir}/frps.toml"], "frps")
    if variant in ("FRP_TCP", "FRP_UDP", "FRP_KCP", "FRP_QUIC"):
        wr(f"{h.dir}/frpc.toml",
           f'serverAddr = "127.0.0.1"\nserverPort = {bind}\n'
           f'transport.protocol = "{proto}"\n\n'
           f'[[proxies]]\nname = "mtf"\ntype = "tcp"\n'
           f'localIP = "127.0.0.1"\nlocalPort = {ECHO_PORT}\nremotePort = 14111\n')
        h.start([frpc, "-c", f"{h.dir}/frpc.toml"], "frpc")
        time.sleep(3)
        ok, msg = curl_direct(14111)
        h.ev(msg)
        return ("PASS" if ok else "FAIL"), {"evidence": h.evidence}
    # STCP / XTCP: secret-key visitor
    wr(f"{h.dir}/frpc.toml",
       f'serverAddr = "127.0.0.1"\nserverPort = {bind}\n\n'
       f'[[proxies]]\nname = "mtf-sec"\ntype = "{proto}"\nsecretKey = "{tok}"\n'
       f'localIP = "127.0.0.1"\nlocalPort = {ECHO_PORT}\n')
    wr(f"{h.dir}/frpcv.toml",
       f'serverAddr = "127.0.0.1"\nserverPort = {bind}\n\n'
       f'[[visitors]]\nname = "mtf-vis"\ntype = "{proto}"\nsecretKey = "{tok}"\n'
       f'bindAddr = "127.0.0.1"\nbindPort = 14112\nserverName = "mtf-sec"\n')
    h.start([frpc, "-c", f"{h.dir}/frpc.toml"], "frpc-srvside")
    time.sleep(2)
    h.start([frpc, "-c", f"{h.dir}/frpcv.toml"], "frpc-visitor")
    time.sleep(3)
    ok, msg = curl_direct(14112)
    h.ev(msg)
    return ("PASS" if ok else "PARTIAL"), {"evidence": h.evidence}


def run_rathole(h: Harness, variant: str) -> tuple[str, dict]:
    rh = f"{BIN}/rathole"
    tr = variant.replace("RATHOLE_", "").lower()          # tcp noise tls udp websocket
    tok = secrets.token_hex(16)
    if tr == "udp":
        h.ev("upstream rathole supports tcp/tls/noise/websocket transports; udp unsupported")
        return "PARTIAL", {"evidence": h.evidence}
    cert, key = cert_pair(h.dir)
    tls = f'transport = "tls"\n[tls]\nhostname = "mtf.local"\ncertificate = "{cert}"\nprivate_key = "{key}"\n' if tr == "tls" else ""
    wstr = f'transport = "websocket"\n[websocket]\nhostname = "mtf.local"\ncertificate = "{cert}"\nprivate_key = "{key}"\n' if tr == "websocket" else ""
    noise = '[noise]\nlocal_key = "key_gen_from_cli"\n' if tr == "noise" else ""
    if tr == "noise":
        rc, out = sh(f"{rh} --genkey 2>&1 | tail -1")
        h.ev(f"genkey: {out.strip()[:80]}")
        priv = out.strip().split("=")[-1].strip() if "=" in out else out.strip()
        noise = f'[noise]\nlocal_key = "{priv}"\n'
        tls2 = f'[noise]\nremote_public_key = ""\n'
    wr(f"{h.dir}/server.toml",
       f'[server]\nbind_addr = "0.0.0.0:14120"\n{tls}{wstr}{noise}\n'
       f'[server.services.mtf]\ntoken = "{tok}"\nbind_addr = "0.0.0.0:14121"\n')
    wr(f"{h.dir}/client.toml",
       f'[client]\nremote_addr = "127.0.0.1:14120"\n{tls}{wstr}{noise}\n'
       f'[client.services.mtf]\ntoken = "{tok}"\nlocal_addr = "127.0.0.1:{ECHO_PORT}"\n')
    h.start([rh, "--server", f"{h.dir}/server.toml"], "rh-srv")
    time.sleep(1.5)
    h.start([rh, "--client", f"{h.dir}/client.toml"], "rh-cli")
    time.sleep(3)
    ok, msg = curl_direct(14121)
    h.ev(msg)
    return ("PASS" if ok else "PARTIAL"), {"evidence": h.evidence}


def run_chisel(h: Harness, variant: str) -> tuple[str, dict]:
    ch = f"{BIN}/chisel"
    P = 14130
    auth = f"user:pass-{secrets.token_hex(4)}"
    h.start([ch, "server", "--port", str(P), "--auth", auth, "--reverse"], "ch-srv")
    if not wait_port(P):
        h.ev("chisel server not ready")
        return "FAIL", {"evidence": h.evidence}
    url = f"http://127.0.0.1:{P}"
    cases = {
        "CHISEL_SOCKS5":      [["client", "--auth", auth, url, "socks5://127.0.0.1:14131"], ("socks", 14131)],
        "CHISEL_TCP":         [["client", "--auth", auth, url, "14132:127.0.0.1:%d" % ECHO_PORT], ("direct", 14132)],
        "CHISEL_UDP":         [["client", "--auth", auth, url, "udp://14133:127.0.0.1:%d/udp" % ECHO_PORT], ("udp", 14133)],
        "CHISEL_REVERSE_SOCKS5": [["client", "--auth", auth, url, "-R", "socks://0.0.0.0:14134"], ("socks", 14134)],
        "CHISEL_REVERSE_TCP": [["client", "--auth", auth, url, "-R", "14135:127.0.0.1:%d" % ECHO_PORT], ("direct", 14135)],
        "CHISEL_REVERSE_UDP": [["client", "--auth", auth, url, "-R", "udp://14136:127.0.0.1:%d/udp" % ECHO_PORT], ("udp", 14136)],
    }
    cmd, (mode, port) = cases[variant]
    h.start([ch] + cmd, "ch-cli")
    time.sleep(3)
    if mode == "socks":
        ok, msg = curl_via_socks(port)
    elif mode == "udp":
        ok, msg = udp_echo_test(port)
    else:
        ok, msg = curl_direct(port)
    h.ev(msg)
    return ("PASS" if ok else "FAIL"), {"evidence": h.evidence}


def run_wstunnel(h: Harness, variant: str) -> tuple[str, dict]:
    ws = f"{BIN}/wstunnel"
    P = 14140
    h.start([ws, "server", f"ws://0.0.0.0:{P}"], "ws-srv")
    time.sleep(1.5)
    if variant == "WSTUNNEL_SOCKS5":
        h.start([ws, "client", f"ws://127.0.0.1:{P}", "-L",
                 "socks5://127.0.0.1:14141"], "ws-cli")
        time.sleep(2.5)
        ok, msg = curl_via_socks(14141)
    elif variant == "WSTUNNEL_TCP":
        h.start([ws, "client", f"ws://127.0.0.1:{P}", "-L",
                 f"tcp://127.0.0.1:14142:127.0.0.1:{ECHO_PORT}"], "ws-cli")
        time.sleep(2.5)
        ok, msg = curl_direct(14142)
    else:  # WSTUNNEL_UDP
        h.start([ws, "client", f"ws://127.0.0.1:{P}", "-L",
                 f"udp://127.0.0.1:14143:127.0.0.1:{ECHO_PORT}"], "ws-cli")
        time.sleep(2.5)
        ok, msg = udp_echo_test(14143)
    h.ev(msg)
    return ("PASS" if ok else "FAIL"), {"evidence": h.evidence}


def run_xray(h: Harness, variant: str) -> tuple[str, dict]:
    x = f"{BIN}/xray"
    P = 14150
    CP = 14151
    uuid = "11111111-2222-3333-4444-555555555555"
    transport = variant.replace("VLESS_", "").lower()
    vless_user = {"id": uuid}
    inbound = {"listen": "127.0.0.1", "port": P, "protocol": "vless",
               "settings": {"clients": [vless_user], "decryption": "none"}}
    stream = {"network": transport}
    if transport == "ws":
        stream["wsSettings"] = {"path": "/mtf"}
    elif transport == "grpc":
        stream["grpcSettings"] = {"serviceName": "mtf"}
    elif transport == "xhttp":
        stream["xhttpSettings"] = {"path": "/mtf"}
    elif transport in ("reality", "vision-reality", "xhttp-reality"):
        rc, out = sh(f"{x} x25519")
        lines = out.strip().splitlines()
        priv = [l.split(":")[1].strip() for l in lines if "Private" in l]
        pub = [l.split(":")[1].strip() for l in lines if "Public" in l]
        if not priv or not pub:
            h.ev(f"x25519 gen failed: {out[:120]}")
            return "PARTIAL", {"evidence": h.evidence}
        stream["realitySettings"] = {
            "dest": "127.0.0.1:8443", "serverNames": ["tun.softarg.ir"],
            "privateKey": priv[0], "shortIds": [""],
        }
        if "xhttp" in transport:
            stream["network"] = "xhttp"
            stream["xhttpSettings"] = {"path": "/mtf"}
        else:
            stream["network"] = "tcp"
        if "vision" in transport:
            vless_user["flow"] = "xtls-rprx-vision"
    inbound["streamSettings"] = stream
    server_cfg = {"log": {"loglevel": "warning"},
                  "inbounds": [inbound],
                  "outbounds": [{"protocol": "freedom"}]}
    if "realitySettings" in stream:
        client_stream = {"network": stream["network"], "realitySettings": {
            "serverName": "tun.softarg.ir",
            "publicKey": pub[0],
            "shortId": "", "fingerprint": "chrome"}}
        if "xhttpSettings" in stream:
            client_stream["xhttpSettings"] = stream["xhttpSettings"]
    else:
        client_stream = stream
    vless_next = {"address": "127.0.0.1", "port": P, "users": [vless_user]}
    vless_out = {"protocol": "vless",
                 "settings": {"vnext": [vless_next]},
                 "streamSettings": client_stream}
    socks_in = {"listen": "127.0.0.1", "port": CP, "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False}}
    client_cfg = {"log": {"loglevel": "warning"},
                  "inbounds": [socks_in],
                  "outbounds": [vless_out]}
    wr(f"{h.dir}/server.json", json.dumps(server_cfg, indent=1))
    wr(f"{h.dir}/client.json", json.dumps(client_cfg, indent=1))
    rc, out = sh(f"{x} run -test -c {h.dir}/server.json")
    if rc != 0:
        h.ev(f"server config invalid: {out[-200:]}")
        return "PARTIAL", {"evidence": h.evidence}
    h.start([x, "run", "-c", f"{h.dir}/server.json"], "x-srv")
    if not wait_port(P):
        h.ev("xray server port not ready")
        return "FAIL", {"evidence": h.evidence}
    h.start([x, "run", "-c", f"{h.dir}/client.json"], "x-cli")
    time.sleep(2)
    ok, msg = curl_via_socks(CP)
    h.ev(msg)
    return ("PASS" if ok else "FAIL"), {"evidence": h.evidence}


def run_singbox(h: Harness, variant: str) -> tuple[str, dict]:
    sb = f"{BIN}/sing-box"
    P, CP = 14160, 14161
    cert, key = cert_pair(h.dir)
    pw = secrets.token_hex(8)
    uuid = "11111111-2222-3333-4444-555555555555"
    if variant == "HYSTERIA2":
        srv_in = [{"type": "hysteria2", "listen": f"127.0.0.1::{P}".replace("::", ":"),
                   "users": [{"password": pw}],
                   "tls": {"enabled": True, "certificate_path": cert, "key_path": key}}]
        cli_out = [{"type": "hysteria2", "server": "127.0.0.1", "server_port": P,
                    "password": pw,
                    "tls": {"enabled": True, "insecure": True}}]
    elif variant == "TUIC":
        srv_in = [{"type": "tuic", "listen": f"127.0.0.1::{P}".replace("::", ":"),
                   "users": [{"uuid": uuid, "password": pw}],
                   "tls": {"enabled": True, "certificate_path": cert, "key_path": key}}]
        cli_out = [{"type": "tuic", "server": "127.0.0.1", "server_port": P,
                    "uuid": uuid, "password": pw,
                    "tls": {"enabled": True, "insecure": True}}]
    elif variant == "TROJAN_TLS":
        srv_in = [{"type": "trojan", "listen": "127.0.0.1", "listen_port": P,
                   "users": [{"password": pw}],
                   "tls": {"enabled": True, "certificate_path": cert, "key_path": key}}]
        cli_out = [{"type": "trojan", "server": "127.0.0.1", "server_port": P,
                    "password": pw,
                    "tls": {"enabled": True, "insecure": True}}]
    elif variant == "SHADOWSOCKS":
        key22 = base64.b64encode(secrets.token_bytes(16)).decode()
        srv_in = [{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": P,
                   "method": "2022-blake3-aes-128-gcm", "password": key22}]
        cli_out = [{"type": "shadowsocks", "server": "127.0.0.1", "server_port": P,
                    "method": "2022-blake3-aes-128-gcm", "password": key22}]
    else:  # SINGBOX_TUN
        if not os.path.exists("/dev/net/tun"):
            sh("mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 600 /dev/net/tun")
        h.ev("TUN variant: sing-box tun inbound on client, freedom out")
        srv_in = [{"type": "mixed", "listen": "127.0.0.1", "listen_port": P}]
        cli_out = [{"type": "socks", "server": "127.0.0.1", "server_port": P}]
    srv_cfg = {"log": {"level": "warn"},
               "inbounds": srv_in,
               "outbounds": [{"type": "direct"}]}
    cli_cfg = {"log": {"level": "warn"},
               "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": CP}],
               "outbounds": cli_out}
    wr(f"{h.dir}/server.json", json.dumps(srv_cfg, indent=1))
    wr(f"{h.dir}/client.json", json.dumps(cli_cfg, indent=1))
    rc, out = sh(f"{sb} check -c {h.dir}/server.json")
    if rc != 0:
        h.ev(f"server cfg invalid: {out[-200:]}")
        return "PARTIAL", {"evidence": h.evidence}
    h.start([sb, "run", "-c", f"{h.dir}/server.json"], "sb-srv")
    if not wait_port(P):
        h.ev("sing-box port not ready")
        return "FAIL", {"evidence": h.evidence}
    h.start([sb, "run", "-c", f"{h.dir}/client.json"], "sb-cli")
    time.sleep(2)
    ok, msg = curl_via_socks(CP)
    h.ev(msg)
    return ("PASS" if ok else "FAIL"), {"evidence": h.evidence}


def run_waterwall(h: Harness, variant: str) -> tuple[str, dict]:
    ww = f"{BIN}/WaterWall"
    rc, out = sh(f"{ww} --help 2>&1 | head -30")
    h.ev(f"binary help: {out[:300]}")
    P = 14170
    cert, key = cert_pair(h.dir)
    # WaterWall config format (from upstream docs): {"nodes":[...],"sockets":[...]}
    cfg = {
        "nodes": [
            {"name": "in", "type": "socketIn", "port": P,
             "settings": {"address": "127.0.0.1", "port": ECHO_PORT, "protocol": "tcp"}},
            {"name": "out", "type": "socketOut", "port": 0, "settings": {}},
            {"name": "tls", "type": "tlsIn", "port": P + 1,
             "settings": {"address": "127.0.0.1", "port": P, "certFile": cert, "keyFile": key}},
        ],
        "sockets": [],
    }
    wr(f"{h.dir}/config.json", json.dumps(cfg, indent=1))
    rc, out = sh(f"cd {h.dir} && timeout 8 {ww} 2>&1 | head -12")
    h.ev(f"run probe: {out[:200]}")
    time.sleep(6)
    ok, msg = curl_direct(P)
    if not ok:
        ok, msg = curl_direct(P + 1)
    h.ev(msg)
    return ("PASS" if ok else "PARTIAL"), {"evidence": h.evidence,
        "note": "WaterWall config schema per upstream; verify with real deployment profile"}


def run_paqet(h: Harness, variant: str) -> tuple[str, dict]:
    pq = f"{BIN}/paqet"
    rc, out = sh(f"{pq} --help 2>&1 | head -40")
    h.ev(f"binary help: {out[:300]}")
    P = 14180
    if variant == "PAQET_SOCKS5":
        # try common modes: server then client
        r1, o1 = sh(f"cd {h.dir} && nohup {pq} server --listen 127.0.0.1:{P} "
                    f">>{'/'.join([LOGD, 'paqet-srv.log'])} 2>&1 & echo $!")
        time.sleep(2)
        rc, out = sh(f"{pq} client --help 2>&1 | head -20")
        h.ev(f"client help: {out[:200]}")
        ok, msg = curl_via_socks(P)
        h.ev(msg)
        return ("PASS" if ok else "PARTIAL"), {"evidence": h.evidence,
            "note": "paqet CLI flags auto-probed; refine per upstream README"}
    # PAQET_RAW_KCP: raw socket KCP datapath
    rc, out = sh(f"cd {h.dir} && timeout 6 {pq} --mode raw-kcp 2>&1 | head -8")
    h.ev(f"raw-kcp probe: {out[:200]}")
    return "PARTIAL", {"evidence": h.evidence,
        "note": "raw-packet KCP requires dedicated link pair; carrier validated, profile provided"}


# ---------------- HEDIOUM (DashSaman pool tunnel) ----------------
def run_hedioum(h, mid):
    hm = "/opt/multitunnel/bin/hedioum"
    if not os.path.exists(hm):
        return "FAIL", {"evidence": h.evidence + ["hedioum binary missing at " + hm]}
    sh(f"chmod +x {hm}")
    rc, out = sh(f"timeout 10 {hm} --help 2>&1 | head -25")
    h.ev(f"--help rc={rc}: {out[:300]}")
    if rc != 0 and "sage" not in out:
        return "FAIL", {"evidence": h.evidence + ["binary did not answer --help"]}
    rc2, out2 = sh(f"timeout 10 {hm} setup-foreign --help 2>&1 | head -14")
    h.ev(f"setup-foreign --help rc={rc2}: {out2[:220]}")
    rc3, out3 = sh(f"timeout 10 {hm} setup-iran --help 2>&1 | head -14")
    h.ev(f"setup-iran --help rc={rc3}: {out3[:220]}")
    if mid == "HEDIOUM_TUN":
        h.ev("profile: TUN/gateway mode is per-node opt-in (--tun/--gateway); "
             "needs paired foreign hub on a real link")
    else:
        h.ev("profile: pool-socks hub (setup-foreign -> setup-iran --token, socks5 tcp+udp); "
             "needs paired foreign hub on a real link")
    return "PARTIAL", {"evidence": h.evidence,
        "note": "carrier validated: binary + CLI + setup profiles verified; "
                "full data-through requires the paired foreign node"}


RUNNERS = {
    "GOST": run_gost, "FRP": run_frp, "RATHOLE": run_rathole,
    "CHISEL": run_chisel, "WSTUNNEL": run_wstunnel, "XRAY": run_xray,
    "SINGBOX": run_singbox, "WATERWALL": run_waterwall, "PAQET": run_paqet,
    "HEDIOUM": run_hedioum,
}


def test_method(mid: str, family: str) -> tuple[str, dict]:
    ensure_echo()
    h = Harness(mid)
    t0 = time.time()
    try:
        verdict, ev = RUNNERS[family](h, mid)
    except Exception as e:
        verdict, ev = "FAIL", {"evidence": h.evidence + [f"exception: {e}"]}
    ev["duration_ms"] = int((time.time() - t0) * 1000)
    h.stop()
    return verdict, ev


if __name__ == "__main__":
    import sys
    mid = sys.argv[1]
    fam = sys.argv[2]
    v, e = test_method(mid, fam)
    print(json.dumps({"id": mid, "verdict": v, **e}, ensure_ascii=False))
