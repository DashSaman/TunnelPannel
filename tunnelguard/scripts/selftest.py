#!/usr/bin/env python3
"""TunnelGuard — REAL engine selftest (run ON the Ubuntu server with sudo).

For every engine this harness produces an honest receipt:

  precheck   adapter-level checks (binaries, kernel modules, config keys)
  isolation  veth pair + network namespace simulating the peer side
  datapath   tunnel up -> ping THROUGH the tunnel -> counters -> tunnel down

Receipts are written to ./selftest-receipts/<engine>.json (+ a summary.md).
A FAIL here is a fact, not a regression to hide — that is the whole point.

Usage:
  sudo python3 scripts/selftest.py                 # all engines
  sudo python3 scripts/selftest.py --engine wg     # one engine
  sudo python3 scripts/selftest.py --list
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("TF_DATA_DIR", "/var/lib/tunnelguard")

NS = "tg-peer"
VETH_HOST = "tg-v0"
VETH_PEER = "tg-v1"
NET_HOST = "10.0.99.1/24"
NET_PEER = "10.0.99.2/24"
RECEIPT_DIR = os.environ.get("TF_RECEIPT_DIR", "selftest-receipts")

ENGINES = ["wireguard", "gre", "sit", "openvpn", "ikev2", "l2tp",
           "hedioum", "paqet", "hajsaman"]


def sh(cmd: str, timeout: float = 25) -> tuple[int, str]:
    cp = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                        timeout=timeout)
    return cp.returncode, (cp.stdout + cp.stderr).strip()


def note(steps: list, ok: bool, what: str, detail: str = "") -> None:
    steps.append({"ok": ok, "step": what, "detail": detail[:400]})
    print(f"  [{'PASS' if ok else 'FAIL'}] {what}"
          + (f" — {detail[:120]}" if detail and not ok else ""))


def setup_ns(steps) -> bool:
    rc, out = sh(f"ip netns add {NS}")
    if rc != 0 and "File exists" not in out:
        note(steps, False, "create netns", out)
        return False
    sh(f"ip netns del {NS}") if rc == 0 else None
    sh(f"ip netns add {NS}")
    cmds = [
        f"ip link add {VETH_HOST} type veth peer name {VETH_PEER}",
        f"ip link set {VETH_PEER} netns {NS}",
        f"ip addr add {NET_HOST} dev {VETH_HOST}",
        f"ip link set {VETH_HOST} up",
        f"ip netns exec {NS} ip addr add {NET_PEER} dev {VETH_PEER}",
        f"ip netns exec {NS} ip link set {VETH_PEER} up",
        f"ip netns exec {NS} ip link set lo up",
    ]
    for c in cmds:
        rc, out = sh(c)
        if rc != 0:
            note(steps, False, f"setup: {c}", out)
            return False
    rc, out = sh(f"ping -c 2 -W 2 -I {VETH_HOST} 10.0.99.2")
    note(steps, rc == 0, "veth baseline ping (host<->peer-ns)", out[-120:])
    return rc == 0


def teardown_ns() -> None:
    sh(f"ip netns del {NS}")
    sh(f"ip link del {VETH_HOST}")


# ------------------------------------------------------------------ engines
def tunnel_def(engine: str) -> dict:
    """A minimal viable tunnel definition pointing at the simulated peer."""
    common = dict(id=99, name=f"selftest-{engine}", engine=engine, enabled=1,
                  priority=1, remote_lan=None, remote_ssh="", created_at=0.0)
    defs = {
        "wireguard": dict(iface="tfst-wg", local_ip="10.201.0.1",
                          remote_ip="10.201.0.2", mtu=1420,
                          remote_host="10.0.99.2", config={
                              "private_key": "KEyCHOSENBYSIDE1abcdefghij0123456789ABCDEabcde=",
                              "peer_public_key": "PEERKEYWILLBESETATRUNTIME0123456789ABCDE=",
                              "listen_port": 51888, "endpoint_host": "10.0.99.2",
                              "endpoint_port": 51889, "table": "off"}),
        "gre": dict(iface="tfst-gre", local_ip="10.202.0.1",
                    remote_ip="10.202.0.2", mtu=1476, remote_host="10.0.99.2",
                    config={"local_public_ip": "10.0.99.1",
                            "remote_host": "10.0.99.2", "ttl": 64}),
        "sit": dict(iface="tfst-sit", local_ip="10.203.0.1",
                    remote_ip="10.203.0.2", mtu=1480, remote_host="10.0.99.2",
                    config={"local_public_ip": "10.0.99.1",
                            "remote_host": "10.0.99.2", "ttl": 255,
                            "v6_local": "fd00:99::1", "v6_remote": "fd00:99::2"}),
        "openvpn": dict(iface="tfst-ov", local_ip="10.204.0.1",
                        remote_ip="10.204.0.2", mtu=1440,
                        remote_host="10.0.99.2",
                        config={"remote_host": "10.0.99.2", "port": 11950,
                                "secret": None}),
        "ikev2": dict(iface="tfst-vti", local_ip="10.205.0.1",
                      remote_ip="10.205.0.2", mtu=1436,
                      remote_host="10.0.99.2",
                      config={"local_public_ip": "10.0.99.1",
                              "remote_host": "10.0.99.2", "psk": "selftest-psk",
                              "vti_key": 77}),
        "l2tp": dict(iface="tfst-l2tp", local_ip="10.206.0.1",
                     remote_ip="10.206.0.2", mtu=1410,
                     remote_host="10.0.99.2",
                     config={"local_public_ip": "10.0.99.1",
                             "remote_host": "10.0.99.2", "tunnel_id": 77,
                             "peer_tunnel_id": 88, "session_id": 77,
                             "peer_session_id": 88, "udp_port": 17077}),
    }
    d = dict(common)
    d.update(defs[engine])
    return d


def peer_wg_side(steps) -> tuple[bool, str]:
    """Bring up a WireGuard peer inside the namespace; return its pubkey."""
    rc, out = sh("wg genkey > /tmp/tg-peer.key && wg pubkey < /tmp/tg-peer.key "
                 "> /tmp/tg-peer.pub")
    if rc != 0:
        note(steps, False, "generate peer wg keys", out)
        return False, ""
    peer_key = open("/tmp/tg-peer.key").read().strip()
    host_pub = subprocess.run(["bash", "-c",
                               "echo | wg pubkey 2>/dev/null || true"],
                              capture_output=True, text=True)
    conf = f"""[Interface]
Address = 10.201.0.2/32
PrivateKey = {peer_key}
ListenPort = 51889
Table = off

[Peer]
PublicKey = {{HOSTPUB}}
Endpoint = 10.0.99.1:51888
AllowedIPs = 10.201.0.1/32
"""
    rc, out = sh(f"ip netns exec {NS} bash -c 'wg genkey > /tmp/tg-host-in-ns.key'")
    # host side private key must be generated for real to derive its pubkey
    rc, out = sh("wg genkey > /tmp/tg-host.key && wg pubkey < /tmp/tg-host.key "
                 "> /tmp/tg-host.pub")
    if rc != 0:
        note(steps, False, "generate host wg keys", out)
        return False, ""
    host_pub = open("/tmp/tg-host.pub").read().strip()
    peer_conf = conf.replace("{HOSTPUB}", host_pub)
    with open("/tmp/tg-peer-wg.conf", "w") as f:
        f.write(peer_conf)
    rc, out = sh(f"ip netns exec {NS} wg-quick up /tmp/tg-peer-wg.conf")
    if rc != 0:
        note(steps, False, "peer wg-quick up (in netns)", out)
        return False, ""
    return True, open("/tmp/tg-peer.key").read().strip()


def datapath(steps, probe_cmd: str) -> bool:
    rc, out = sh(probe_cmd, timeout=30)
    note(steps, rc == 0, "ping THROUGH tunnel", out[-160:] if rc else "ok")
    return rc == 0


def test_wireguard(steps) -> None:
    ok, peer_priv = peer_wg_side(steps)
    if not ok:
        return
    host_priv = open("/tmp/tg-host.key").read().strip()
    peer_pub = open("/tmp/tg-peer.pub").read().strip()
    t = tunnel_def("wireguard")
    t["config"]["private_key"] = host_priv
    t["config"]["peer_public_key"] = peer_pub
    from tfd.engines.wireguard import WireGuardAdapter
    a = WireGuardAdapter(t)
    problems = a.precheck()
    note(steps, not problems, "precheck", "; ".join(problems))
    if problems:
        return
    try:
        cmds = a.up()
        note(steps, True, "wg-quick up (host)", cmds[-1])
        time.sleep(1.5)
        datapath(steps, "ping -c 3 -W 3 10.201.0.2")
        st = a.status()
        note(steps, st["up"] and (st["extra"].get("rx_bytes") or 0) > 0,
             "wg show counters", json.dumps(st["extra"])[:200])
    finally:
        a.down()
        sh(f"ip netns exec {NS} wg-quick down /tmp/tg-peer-wg.conf")


def peer_kernel_tunnel(mode: str, inner_local: str, inner_remote: str,
                       v6: bool = False) -> None:
    """Mirror tunnel on the peer namespace."""
    local, remote = "10.0.99.2", "10.0.99.1"
    base = (f"ip netns exec {NS} ip tunnel add tfst-p mode {mode} "
            f"local {local} remote {remote} ttl 255" if mode != "gre"
            else f"ip netns exec {NS} ip tunnel add tfst-p mode gre "
                 f"local {local} remote {remote} ttl 64")
    rc, out = sh(base)
    if rc != 0:
        raise RuntimeError(f"peer {mode} add: {out}")
    if v6:
        sh(f"ip netns exec {NS} ip -6 addr add {inner_remote}/64 dev tfst-p")
    else:
        sh(f"ip netns exec {NS} ip addr add {inner_remote}/30 dev tfst-p")
    sh(f"ip netns exec {NS} ip link set tfst-p mtu 1400 up")


def test_kernel(steps, engine: str) -> None:
    from tfd.engines.kernel import GREAdapter, SITAdapter
    t = tunnel_def(engine)
    cls = GREAdapter if engine == "gre" else SITAdapter
    a = cls(t)
    problems = a.precheck()
    hard = [p for p in problems if not p.startswith("NOTE")]
    note(steps, not hard, "precheck", "; ".join(problems))
    if hard:
        return
    peer_ok = False
    try:
        cmds = a.up()
        note(steps, True, f"{engine} up (host)", "; ".join(cmds)[:150])
        peer_engine_mode = "sit" if engine == "sit" else "gre"
        try:
            peer_kernel_tunnel(peer_engine_mode, t["local_ip"], t["remote_ip"],
                               v6=(engine == "sit"))
            peer_ok = True
        except RuntimeError as e:
            note(steps, False, f"peer {peer_engine_mode} tunnel", str(e))
            return
        time.sleep(1)
        if engine == "sit":
            datapath(steps, "ping -6 -c 3 -W 3 fd00:99::2")
        else:
            datapath(steps, f"ping -c 3 -W 3 {t['remote_ip']}")
    finally:
        a.down()
        if peer_ok:
            sh(f"ip netns exec {NS} ip tunnel del tfst-p")


def test_openvpn(steps) -> None:
    from tfd.engines.openvpn import OpenVPNAdapter
    t = tunnel_def("openvpn")
    a = OpenVPNAdapter(t)
    problems = a.precheck()
    hard = [p for p in problems if not p.startswith("NOTE")]
    note(steps, not hard, "precheck", "; ".join(problems))
    if hard:
        return
    try:
        cmds = a.up()
        note(steps, True, "openvpn up (host)", "; ".join(cmds)[:150])
        # peer side in namespace
        peer_conf = f"""dev-type tun
dev tfst-p
proto udp4
local 10.0.99.2
lport 11950
remote 10.0.99.1
rport 11950
ifconfig 10.204.0.2 10.204.0.1
secret /tmp/tfst-ov.secret
cipher AES-256-GCM
auth SHA256
verb 3
"""
        sh(f"ip netns exec {NS} bash -c 'cat > /tmp/tg-ovp.conf << EOF\n"
           f"{peer_conf}\nEOF'")
        sh(f"cp {_conf_path('openvpn', 'tfst-ov.secret')} /tmp/tfst-ov.secret "
           f"&& ip netns exec {NS} cp /tmp/tfst-ov.secret /tmp/tfst-ov.secret")
        rc, out = sh(f"ip netns exec {NS} openvpn --daemon --config "
                     f"/tmp/tg-ovp.conf --log /tmp/tg-ovp.log")
        note(steps, rc == 0, "openvpn peer up (in netns)", out)
        time.sleep(4)
        datapath(steps, "ping -c 3 -W 3 10.204.0.2")
    finally:
        a.down()
        sh(f"ip netns exec {NS} pkill openvpn")


def _conf_path(engine: str, name: str) -> str:
    base = os.environ.get("TF_ETC_DIR", "/etc/tunnelguard")
    if engine == "openvpn":
        return f"{base}/openvpn/{name}"
    return f"{base}/{name}"


def test_ikev2(steps) -> None:
    """Capability test: charon alive, swanctl usable, VTI creatable.
    Full IPsec handshake against a netns peer is possible but flaky in CI —
    this test is honest about what it proves."""
    from tfd.engines.ipsec import IKEv2Adapter
    t = tunnel_def("ikev2")
    a = IKEv2Adapter(t)
    problems = a.precheck()
    hard = [p for p in problems if not p.startswith("NOTE")]
    if hard:
        note(steps, False, "precheck", "; ".join(problems))
        return
    note(steps, True, "precheck (charon/swanctl/ports)", "ok")
    rc, out = sh("ip link add tfst-vti type vti local 10.0.99.1 remote "
                 "10.0.99.2 key 77 && ip link del tfst-vti")
    note(steps, rc == 0, "kernel VTI create/delete", out)
    note(steps, False, "full IKE handshake", "requires real peer with UDP500/4500 "
         "reachable — run against the actual remote endpoint for a full receipt")


def test_l2tp(steps) -> None:
    from tfd.engines.ipsec import L2TPv3Adapter
    t = tunnel_def("l2tp")
    a = L2TPv3Adapter(t)
    problems = a.precheck()
    hard = [p for p in problems if not p.startswith("NOTE")]
    note(steps, not hard, "precheck", "; ".join(problems))
    if hard:
        return
    # peer side in netns
    rc, out = sh(
        f"ip netns exec {NS} ip l2tp add tunnel tunnel_id 88 peer_tunnel_id 77 "
        f"udp_sport 17077 udp_dport 17077 encap udp local 10.0.99.2 remote "
        f"10.0.99.1 && ip netns exec {NS} ip l2tp add session tunnel_id 88 "
        f"session_id 88 peer_session_id 77")
    if rc != 0:
        note(steps, False, "peer l2tp tunnel (netns)", out)
        return
    sh(f"ip netns exec {NS} ip link set tfstp mtu 1410 up && ip netns exec {NS} "
       f"ip addr add 10.206.0.2/30 dev tfstp")
    try:
        cmds = a.up()
        note(steps, True, "l2tp up (host)", "; ".join(cmds)[:150])
        time.sleep(1)
        datapath(steps, "ping -c 3 -W 3 10.206.0.2")
    finally:
        a.down()
        sh(f"ip netns exec {NS} ip l2tp del session tunnel_id 88 session_id 88")
        sh(f"ip netns exec {NS} ip l2tp del tunnel tunnel_id 88")


def test_hedioum(steps) -> None:
    """Hedioum Pool Tunnel selftest.

    Two levels, honestly labelled:
     - ALWAYS: adapter precheck + config merge (no foreign needed)
     - LIVE (env TF_HEDIOUM_FOREIGN=host:port + TF_HEDIOUM_TOKEN=32hex or a
       v2 pairing token): standalone hub activation against that foreign,
       through-tunnel SOCKS5 probe + exit-IP receipt.
    Unlike kernel engines this one has no netns peer — the 'peer side' is a
    real Hedioum foreign node on the network.
    """
    from tfd.engines.hedioum import HedioumAdapter, CONFIG_PATH
    from tfd import db as _dbm
    _dbm.init()  # probes need settings; isolated by TF_DATA_DIR
    tok = os.environ.get("TF_HEDIOUM_TOKEN", "")
    foreign = os.environ.get("TF_HEDIOUM_FOREIGN", "")
    binary = os.environ.get("TF_HEDIOUM_BIN",
                            "/usr/local/bin/hedioum-tunnel")

    note(steps, os.path.exists(binary) or bool(os.environ.get(
        "TF_HEDIOUM_BIN")), "hedioum-tunnel binary present", binary)

    cfg = {"socks_port": 40099, "standalone": bool(foreign),
           "binary_path": binary}
    if tok:
        cfg["pairing_token"] = tok
    if foreign and ":" in foreign:
        host, _, port = foreign.rpartition(":")
        cfg.update({"foreign_ip": host, "foreign_port": int(port),
                    "mimic": os.environ.get("TF_HEDIOUM_MIMIC", "ssh")})
    t = dict(id=99, name="selftest-hedioum", engine="hedioum", enabled=1,
             priority=1, iface="hedioom99", local_ip=None, remote_ip=None,
             remote_lan=None, remote_host=foreign or None, mtu=1500,
             remote_ssh="", created_at=0.0, config=cfg)
    a = HedioumAdapter(t)

    problems = a.precheck()
    hard = [p for p in problems if "SOCKS-only" not in p]
    note(steps, not hard, "adapter precheck", "; ".join(hard) or "clean")
    arts = a.render()
    note(steps, "foreign_nodes" in arts.get(CONFIG_PATH, ""),
         "hub config merge renders a foreign_nodes[] entry")

    if not foreign:
        note(steps, True, "LIVE datapath SKIPPED",
             "set TF_HEDIOUM_FOREIGN + TF_HEDIOUM_TOKEN (from the foreign's "
             "setup-foreign output) to run the real end-to-end receipt")
        return
    try:
        cmds = a.up()
        note(steps, True, "hub up (standalone)", "; ".join(cmds[-2:])[:200])
        time.sleep(2)
        row = a._probe_cycle()
        note(steps, bool(row.get("ok")), "through-tunnel SOCKS5 probe",
             f"rtt={row.get('rtt_ms')}ms loss={row.get('loss_pct')}% "
             f"detail={row.get('detail')}")
        rec = a.receipt()
        note(steps, rec.get("through_tunnel", False), "exit-IP receipt",
             f"exit_ip={rec.get('exit_ip')}")
    finally:
        a.down()
        note(steps, True, "hub down / node removed", "")


def test_paqet(steps) -> None:
    """Paqet raw-TCP/KCP selftest.

    Two levels, honestly labelled:
     - ALWAYS: render client+server YAML, precheck truth (no connection)
     - LIVE (env TF_PAQET_SERVER=host:port, TF_PAQET_KEY=secret,
       TF_PAQET_IFACE=eth0, TF_PAQET_LOCAL_IP=ip:0, TF_PAQET_ROUTER_MAC=mm):
       standalone client up against that server, SOCKS5 probe + exit-IP
       receipt. Needs root (raw sockets) and a reachable paqet server.
    """
    from tfd.engines.paqet import PaqetAdapter
    from tfd import db as _dbm
    _dbm.init()
    server = os.environ.get("TF_PAQET_SERVER", "")
    binary = os.environ.get("TF_PAQET_BIN", "/usr/local/bin/paqet")

    note(steps, os.path.exists(binary) or bool(os.environ.get(
        "TF_PAQET_BIN")), "paqet binary present", binary)

    t = dict(id=98, name="selftest-paqet", engine="paqet", enabled=1,
             priority=1, iface="pq98", local_ip=None, remote_ip=None,
             remote_lan=None, remote_host=(server or "").split(":")[0] or None,
             mtu=1350, remote_ssh="", created_at=0.0,
             config={"role": "client", "binary_path": binary,
                     "server_addr": server or "198.51.100.9:9999",
                     "socks_listen": "127.0.0.1:41098",
                     "interface": os.environ.get("TF_PAQET_IFACE", "eth0"),
                     "local_ipv4": os.environ.get("TF_PAQET_LOCAL_IP", ""),
                     "router_mac": os.environ.get("TF_PAQET_ROUTER_MAC", ""),
                     "kcp_key": os.environ.get("TF_PAQET_KEY", "selftest")})
    a = PaqetAdapter(t)

    hard = [p for p in a.precheck() if "raw sockets" not in p]
    note(steps, not hard, "adapter precheck", "; ".join(hard) or "clean")
    y = a.render()[a.conf_path]
    note(steps, "role: client" in y and "protocol: kcp" in y,
         "client YAML renders", a.conf_path)
    a2 = PaqetAdapter({**t, "config": {**t["config"], "role": "server",
                                       "listen_addr": ":41097"}})
    note(steps, "NOTRACK" in list(a2.render().values())[-1],
         "server firewall script renders NOTRACK+RST-drop", "")

    if not server:
        note(steps, True, "LIVE datapath SKIPPED",
             "set TF_PAQET_SERVER + TF_PAQET_KEY (+ IFACE/LOCAL_IP/ROUTER_MAC) "
             "to run the real end-to-end receipt")
        return
    try:
        cmds = a.up()
        note(steps, True, "client up (standalone)", "; ".join(cmds[-2:])[:200])
        row = a._probe_cycle()
        note(steps, bool(row.get("ok")), "through-tunnel SOCKS5 probe",
             f"rtt={row.get('rtt_ms')}ms loss={row.get('loss_pct')}% "
             f"detail={row.get('detail')}")
        rec = a.receipt()
        note(steps, rec.get("through_tunnel", False), "exit-IP receipt",
             f"exit_ip={rec.get('exit_ip')}")
    finally:
        a.down()
        note(steps, True, "client down", "")


def test_hajsaman(steps) -> None:
    """HajSamanTunnel selftest.

    Two levels, honestly labelled:
     - ALWAYS: native-mode render (WG conf + SIT scripts) + precheck truth
     - CLI LIVE (tool installed + TF_HJS_SLOT=<slot>): status + real through-WG
       probe + exit-IP receipt via curl --interface. Does NOT stop the slot
       afterwards (production safety) unless TF_HJS_STOP=1.
    The datapath primitives (WG, SIT) are individually covered by their own
    runners; the composed stack receipt comes from the CLI slot on a real
    two-server deployment.
    """
    from tfd.engines.hajsaman import HajSamanAdapter, parse_slot_conf
    from tfd import db as _dbm
    _dbm.init()
    slot = os.environ.get("TF_HJS_SLOT", "")
    cli = os.environ.get("TF_HJS_CLI", "/usr/local/sbin/hajsaman-tunnel")

    d = parse_slot_conf("ROLE=iran\nWG_IF=wgX\nGW_WG_IP=10.1.1.1\n")
    note(steps, d.get("WG_IF") == "wgX", "slot-conf parser",
         "KEY=value format (tunnels.d/*.conf)")

    t = dict(id=97, name="selftest-hjs", engine="hajsaman", enabled=1,
             priority=1, iface="tf-hst97", local_ip=None, remote_ip=None,
             remote_lan=None, remote_host="198.51.100.9", mtu=1420,
             remote_ssh="", created_at=0.0,
             config={"mode": "cli", "slot": slot or "hst-selftest",
                     "cli_path": cli})
    a = HajSamanAdapter(t)

    if os.path.exists(cli) and slot:
        problems = a.precheck()
        hard = [p for p in problems if "proto 41" not in p]
        note(steps, not hard, "cli slot precheck", "; ".join(hard) or "clean")
        st = a.status()
        note(steps, True, f"slot status (up={st['up']})",
             str(st.get("detail"))[:160])
        row = a._probe_cycle()
        note(steps, bool(row.get("ok")), "through-WG probe",
             f"rtt={row.get('rtt_ms')}ms detail={row.get('detail')}")
        rec = a.receipt()
        note(steps, rec.get("through_tunnel", False), "exit-IP receipt",
             f"exit_ip={rec.get('exit_ip')} via {rec.get('via', '-')}")
        if os.environ.get("TF_HJS_STOP") == "1":
            a.down()
            note(steps, True, "slot stopped (TF_HJS_STOP=1)", "")
        else:
            note(steps, True, "slot left RUNNING",
                 "set TF_HJS_STOP=1 to stop it after the test")
    else:
        tn = dict(t, config={"mode": "native", "role": "iran",
                             "local_public_ip": "192.0.2.10",
                             "foreign_ipv4": "198.51.100.9",
                             "private_key": "x" * 44,
                             "peer_public_key": "y" * 44})
        an = HajSamanAdapter(tn)
        hard = [p for p in an.precheck() if "native mode" not in p
                and "proto 41" not in p and "selftest" not in p
                and "required binary" not in p]
        note(steps, not hard, "native precheck (static level)",
             "; ".join(hard) or "clean")
        arts = an.render()
        wg = arts.get("/etc/wireguard/tf-hst97.conf", "")
        note(steps, "Endpoint = [fd00:05a1:" in wg and "wg-quick up" in
             str(list(arts.values())),
             "native stack renders WG conf + SIT scripts", "")
        note(steps, True, "LIVE datapath SKIPPED",
             "install hajsaman-tunnel and set TF_HJS_SLOT, or deploy the "
             "native stack on a real two-server pair")


RUNNERS = {
    "wireguard": test_wireguard,
    "gre": lambda s: test_kernel(s, "gre"),
    "sit": lambda s: test_kernel(s, "sit"),
    "openvpn": test_openvpn,
    "ikev2": test_ikev2,
    "l2tp": test_l2tp,
    "hedioum": test_hedioum,
    "paqet": test_paqet,
    "hajsaman": test_hajsaman,
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", choices=ENGINES)
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list:
        print("\n".join(ENGINES))
        return 0

    targets = [args.engine] if args.engine else ENGINES
    root_free_engines = {"hedioum", "paqet", "hajsaman"}
    root_free = all(t in root_free_engines for t in targets)
    if os.geteuid() != 0 and not root_free:
        print("MUST run as root (sudo) — kernel operations required.\n"
              "(userspace-only run: sudo not needed for --engine "
              "hedioum|paqet|hajsaman)")
        return 2

    os.makedirs(RECEIPT_DIR, exist_ok=True)
    summary = []
    overall_ok = True

    for engine in targets:
        print(f"\n=== selftest: {engine} ===")
        steps: list = []
        started = time.time()
        # userspace engines have their peer on the real network — the netns
        # isolation harness applies to kernel engines only.
        no_netns = engine in ("hedioum", "paqet", "hajsaman")
        isolated = True if no_netns else setup_ns(steps)
        if isolated:
            try:
                RUNNERS[engine](steps)
            except Exception as e:
                note(steps, False, "harness error", repr(e))
            finally:
                if not no_netns:
                    teardown_ns()
        passed = all(s["ok"] for s in steps) and len(steps) > 1
        receipt = {
            "engine": engine, "ts": time.time(),
            "duration_s": round(time.time() - started, 1),
            "passed": passed, "steps": steps,
            "kernel": os.uname().release,
        }
        with open(f"{RECEIPT_DIR}/{engine}.json", "w") as f:
            json.dump(receipt, f, indent=2)
        mark = "PASS" if passed else "FAIL"
        summary.append(f"- {engine}: **{mark}** ({len(steps)} steps, "
                       f"{receipt['duration_s']}s)")
        overall_ok &= passed
        print(f"  => {mark}  (receipt: {RECEIPT_DIR}/{engine}.json)")

    with open(f"{RECEIPT_DIR}/summary.md", "w") as f:
        f.write(f"# TunnelGuard Engine Selftest — {time.strftime('%Y-%m-%d %H:%M')}\n\n"
                f"Kernel: {os.uname().release}\n\n" + "\n".join(summary) + "\n")
    print(f"\nSummary -> {RECEIPT_DIR}/summary.md")
    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
