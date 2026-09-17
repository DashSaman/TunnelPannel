"""Engine adapter tests with a RECORDING executor — no kernel needed.

These verify the exact system commands and rendered artifacts for every
real engine, which is the honest maximum testable without CAP_NET_ADMIN.
Real end-to-end receipts: scripts/selftest.py on the actual Ubuntu server.
"""
import json

from tfd.engines import get_adapter
from tfd.engines.base import AdapterError


class Recorder:
    """Records commands; rc/outs programmable per command substring."""

    def __init__(self, fail_on=()):
        self.commands = []
        self.fail_on = fail_on

    def __call__(self, cmd, timeout=30.0):
        self.commands.append(cmd if isinstance(cmd, list) else [cmd])
        joined = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
        rc = 1 if any(f in joined for f in self.fail_on) else 0
        class CP:
            returncode = rc
            stdout = ""
            stderr = "simulated failure" if rc else ""
        return CP()


def make_tunnel(engine, **kw):
    base = dict(id=7, name="test", engine=engine, iface="tfW",
                local_ip="10.10.10.1", remote_ip="10.10.10.2",
                remote_host="198.51.100.9", remote_lan=None,
                mtu=None, config="{}", enabled=1, priority=1,
                remote_ssh="", created_at=1.0)
    base.update(kw)
    return base


class TestWireGuard:
    def test_render_conf(self):
        t = make_tunnel("wireguard", config=json.dumps({
            "private_key": "A" * 44, "peer_public_key": "B" * 44,
            "listen_port": 51820, "endpoint_host": "198.51.100.9"}))
        art = get_adapter(t, force_sim=False).render()
        conf = art[next(k for k in art if k.endswith("tfW.conf"))]
        assert "PrivateKey = " + "A" * 44 in conf
        assert "AllowedIPs = 10.10.10.2/32" in conf
        assert "MTU = 1420" in conf
        assert "Table = off" in conf
        assert "PersistentKeepalive = 25" in conf

    def test_up_commands(self):
        rec = Recorder()
        t = make_tunnel("wireguard", config=json.dumps({
            "private_key": "A" * 44, "peer_public_key": "B" * 44}))
        a = get_adapter(t, executor=rec, force_sim=False)
        out = a.up()
        assert any("wg-quick up tfW" in " ".join(c) for c in rec.commands)
        assert any("wg-quick" in c for c in out)

    def test_precheck_reports_missing_module(self):
        rec = Recorder(fail_on=("tf-wg-precheck",))
        t = make_tunnel("wireguard")
        problems = get_adapter(t, executor=rec, force_sim=False).precheck()
        assert any("kernel WireGuard" in p for p in problems)

    def test_precheck_bad_key_length(self):
        rec = Recorder()
        t = make_tunnel("wireguard", config=json.dumps({"private_key": "short"}))
        problems = get_adapter(t, executor=rec, force_sim=False).precheck()
        assert any("private_key" in p for p in problems)


class TestGRE:
    def test_up_command_shape(self):
        rec = Recorder()
        t = make_tunnel("gre", mtu=1476,
                        config=json.dumps({"local_public_ip": "1.2.3.4",
                                           "remote_host": "5.6.7.8", "ttl": 64}))
        out = get_adapter(t, executor=rec, force_sim=False).up()
        joined = [" ".join(c) for c in rec.commands]
        assert any("ip tunnel add tfW mode gre local 1.2.3.4 remote 5.6.7.8" in j
                   for j in joined)
        assert any("ip link set tfW mtu 1476 up" in j for j in joined)
        assert any("ip addr replace 10.10.10.1/30 dev tfW" in j for j in joined)

    def test_precheck_missing_local_public(self):
        rec = Recorder()
        problems = get_adapter(make_tunnel("gre"), executor=rec, force_sim=False).precheck()
        assert any("local_public_ip" in p for p in problems)

    def test_honest_gre_crypto_note(self):
        rec = Recorder()
        t = make_tunnel("gre", config=json.dumps({"local_public_ip": "1.2.3.4"}))
        problems = get_adapter(t, executor=rec, force_sim=False).precheck()
        assert any("NOT encrypted" in p for p in problems)


class TestSIT:
    def test_needs_v6(self):
        rec = Recorder()
        t = make_tunnel("sit", config=json.dumps({"local_public_ip": "1.2.3.4"}))
        problems = get_adapter(t, executor=rec, force_sim=False).precheck()
        assert any("v6_local" in p for p in problems)
        assert any("proto 41" in p for p in problems)  # honest upstream note

    def test_up_with_v6(self):
        rec = Recorder()
        t = make_tunnel("sit", mtu=1480, config=json.dumps({
            "local_public_ip": "1.2.3.4", "remote_host": "5.6.7.8",
            "v6_local": "2001:db8::1", "v6_remote": "2001:db8::2"}))
        get_adapter(t, executor=rec, force_sim=False).up()
        joined = [" ".join(c) for c in rec.commands]
        assert any("mode sit" in j for j in joined)
        assert any("ip -6 addr replace 2001:db8::1/64 dev tfW" in j for j in joined)


class TestOpenVPN:
    def test_render(self):
        t = make_tunnel("openvpn", config=json.dumps({
            "remote_host": "198.51.100.9", "port": 1194, "secret": "x" * 30}))
        art = get_adapter(t, force_sim=False).render()
        conf = art[next(k for k in art if k.endswith("tfW.conf"))]
        assert "dev tfW" in conf and "ifconfig 10.10.10.1 10.10.10.2" in conf
        assert "cipher AES-256-GCM" in conf
        assert any(k.endswith("tfW.secret") for k in art)

    def test_precheck_reports_missing_binary(self):
        rec = Recorder(fail_on=("openvpn",))
        problems = get_adapter(make_tunnel("openvpn"), executor=rec, force_sim=False).precheck()
        assert any("openvpn binary" in p or "/dev/net/tun" in p for p in problems)


class TestIKEv2:
    def test_render_swanctl(self):
        t = make_tunnel("ikev2", config=json.dumps({
            "local_public_ip": "1.2.3.4", "remote_host": "5.6.7.8", "psk": "s3cret"}))
        art = get_adapter(t, force_sim=False).render()
        conf = art[next(k for k in art if k.endswith("tg-tfW.conf"))]
        assert "version = 2" in conf and "start_action = start" in conf

    def test_precheck_honest_udp_note(self):
        rec = Recorder(fail_on=("swanctl",))
        t = make_tunnel("ikev2", config=json.dumps({
            "local_public_ip": "1.2.3.4", "remote_host": "5.6.7.8", "psk": "x"}))
        problems = get_adapter(t, executor=rec, force_sim=False).precheck()
        assert any("UDP500/4500" in p for p in problems)


class TestL2TPv3:
    def test_up_command_shape(self):
        rec = Recorder()
        t = make_tunnel("l2tp", mtu=1410, config=json.dumps({
            "local_public_ip": "1.2.3.4", "remote_host": "5.6.7.8"}))
        get_adapter(t, executor=rec, force_sim=False).up()
        joined = [" ".join(c) for c in rec.commands]
        assert any("ip l2tp add tunnel" in j and "encap udp" in j for j in joined)
        assert any("ip l2tp add session" in j for j in joined)

    def test_render_script(self):
        t = make_tunnel("l2tp", config=json.dumps({
            "local_public_ip": "1.2.3.4", "remote_host": "5.6.7.8"}))
        art = get_adapter(t, force_sim=False).render()
        assert "commands/tfW_up.sh" in art


class TestSimRouting:
    def test_sim_mode_routing_noop(self, fresh_db):
        from tfd import routing
        fresh_db.set_settings({"sim_mode": True})
        t = make_tunnel("wireguard")
        sim = routing.SimulatedSystem()
        out = routing.activate_tunnel_routes(t, sim=sim)
        assert any("(sim)" in o for o in out)
        assert sim.log  # mutations recorded, not executed

    def test_nft_script_contains_clamp_and_snat(self, fresh_db):
        from tfd import routing
        s = {"virtual_ip": "10.10.10.5", "mss_clamp_enabled": True,
             "dnat_rules": [{"proto": "tcp", "port": 443, "to_port": 8443}]}
        script = routing.build_nft_script("tfA", s)
        assert 'oifname "tf*" tcp flags syn tcp option maxseg size set rt mtu' in script
        assert 'oifname "tfA" snat ip to 10.10.10.5' in script
        assert "tcp dport 443 dnat ip to 10.10.10.5:8443" in script
