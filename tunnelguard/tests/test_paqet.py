"""Tests for the Paqet raw-TCP/KCP engine adapter (v1.2).

paqet is exercised on the same honest levels as Hedioum:
 1. YAML render for both roles (client SOCKS5 / server listen) — must be a
    valid paqet config subset,
 2. precheck truth-telling (binary, root, MAC, keys, weak blocks, standard
    ports, missing NOTRACK),
 3. up/down lifecycle with a recording executor and a patched Popen,
 4. probe/receipt via the SOCKS5 helpers (monkeypatched).
"""
import json

import pytest

from tfd.engines.paqet import PaqetAdapter, _dump_yaml


# ------------------------------------------------------------------ yaml
def test_dump_yaml_scalars_and_nesting():
    doc = {"role": "client", "server": {"addr": "10.0.0.100:9999"},
           "socks5": [{"listen": "127.0.0.1:1080", "username": ""}],
           "kcp": {"block": "aes", "mtu": 1350, "flag": True}}
    y = _dump_yaml(doc)
    assert "role: client" in y
    assert 'addr: 10.0.0.100:9999' in y          # colon value -> quoted
    assert "listen: 127.0.0.1:1080" in y           # inside socks5 list item
    assert "- listen:" in y                        # list item marker
    assert "mtu: 1350" in y
    assert "flag: true" in y
    # parseable round-trip if PyYAML is around (best effort)
    try:
        import yaml
        assert yaml.safe_load(y)["server"]["addr"] == "10.0.0.100:9999"
        assert yaml.safe_load(y)["socks5"][0]["listen"] == "127.0.0.1:1080"
    except ImportError:
        pass


def _adapter(tmp=None, cfg_extra=None, role="client", executor=None):
    cfg = {
        "role": role,
        "binary_path": "/bin/true",             # exists everywhere
        "server_addr": "198.51.100.9:9999" if role == "client" else None,
        "listen_addr": ":9999" if role == "server" else None,
        "socks_listen": "127.0.0.1:41003",
        "interface": "eth0",
        "local_ipv4": "192.0.2.10:0" if role == "client" \
            else "198.51.100.9:9999",
        "router_mac": "aa:bb:cc:dd:ee:ff",
        "kcp_key": "s3cret",
        "forward": [{"listen": "127.0.0.1:8080", "target": "10.0.0.5:80"}],
        **(cfg_extra or {}),
    }
    t = {"id": 7, "name": "paq-de", "engine": "paqet", "iface": "pq7",
         "remote_host": "198.51.100.9", "config": json.dumps(cfg)}
    return PaqetAdapter(t, executor)


# --------------------------------------------------------------- render
def test_render_client_yaml_has_socks_forward_kcp():
    a = _adapter()
    arts = a.render()
    y = list(arts.values())[0]
    assert "role: client" in y
    assert "socks5:" in y and "listen: 127.0.0.1:41003" in y
    assert "forward:" in y and "target: 10.0.0.5:80" in y
    assert "protocol: kcp" in y and "key: s3cret" in y
    assert "addr: 198.51.100.9:9999" in y


def test_render_server_yaml_listen_and_firewall_script():
    a = _adapter(role="server")
    arts = a.render()
    assert any(v.startswith("role: server") for v in arts.values())
    fw = [v for v in arts.values() if "NOTRACK" in v][0]
    assert "--dport 9999 -j NOTRACK" in fw
    assert "--tcp-flags RST RST -j DROP" in fw


def test_routing_capable_is_false():
    assert _adapter().routing_capable is False


# ------------------------------------------------------------- precheck
def test_precheck_missing_everything_tells_the_truth(monkeypatch):
    t = {"id": 1, "name": "x", "engine": "paqet", "config": "{}"}
    a = PaqetAdapter(t)
    monkeypatch.setattr("tfd.engines.paqet.os.geteuid", lambda: 0)
    problems = a.precheck()
    joined = " | ".join(problems)
    assert "binary not found" in joined
    assert "interface missing" in joined or "network.interface" in joined
    assert "router_mac" in joined
    assert "kcp.key missing" in joined
    assert "server.addr missing" in joined


def test_precheck_warns_weak_block_and_standard_port(monkeypatch):
    a = _adapter(role="server", cfg_extra={"kcp_block": "none",
                                           "listen_addr": ":443"})
    monkeypatch.setattr("tfd.engines.paqet.os.geteuid", lambda: 0)
    monkeypatch.setattr(a, "_iptables_missing", lambda: False)
    problems = a.precheck()
    joined = " | ".join(problems)
    assert "'none'/'null'" in joined
    assert "standard port" in joined


def test_precheck_clean_client(monkeypatch):
    a = _adapter()
    monkeypatch.setattr("tfd.engines.paqet.os.geteuid", lambda: 0)
    monkeypatch.setattr(a, "_port_in_use", lambda p, expect_own=False: False)
    assert a.precheck() == []


def test_precheck_requires_root_for_raw_sockets(monkeypatch):
    a = _adapter()
    monkeypatch.setattr("tfd.engines.paqet.os.geteuid", lambda: 1000)
    monkeypatch.setattr(a, "_port_in_use", lambda p, expect_own=False: False)
    assert any("raw sockets" in p for p in a.precheck())


# ----------------------------------------------------------- lifecycle
def test_up_writes_yaml_and_runs_standalone(monkeypatch):
    calls = {}

    def fake_popen(cmd, cwd=None, stdout=None, stderr=None, **kw):
        calls["cmd"] = cmd
        calls["cwd"] = cwd

        class P:
            pid = 434343
        return P()

    a = _adapter()
    monkeypatch.setattr("tfd.engines.paqet._popen", fake_popen)
    monkeypatch.setattr("tfd.engines.paqet.os.geteuid", lambda: 0)
    monkeypatch.setattr(a, "_socks_alive", lambda: True)
    cmds = a.up()
    assert any("standalone start" in c for c in cmds)
    assert calls["cmd"][:3] == ["/bin/true", "run", "-c"]
    conf = open(calls["cmd"][3]).read()
    assert "role: client" in conf
    assert calls["cwd"].endswith("paqet/paq-de")


def test_down_reports_pidfile_absence():
    a = _adapter()
    out = a.down()
    assert out and ("no standalone" in out[0] or "killed" in out[0])


def test_status_client_reflects_socks(monkeypatch):
    a = _adapter()
    monkeypatch.setattr(a, "_pid_alive", lambda: True)
    monkeypatch.setattr(a, "_socks_alive", lambda: True)
    st = a.status()
    assert st["up"] and st["extra"]["role"] == "client"
    monkeypatch.setattr(a, "_socks_alive", lambda: False)
    assert a.status()["up"] is False


# ---------------------------------------------------------- probe/receipt
def test_probe_cycle_client_uses_socks(monkeypatch):
    from tfd import probes
    seen = {}

    def fake_cycle(port, target, portp, count=2, timeout_s=4.0):
        seen.update(port=port, target=target, portp=portp)
        return {"ok": True, "rtt_ms": 42.0, "loss_pct": 0.0,
                "jitter_ms": 1.0, "method": "socks5"}

    monkeypatch.setattr(probes, "socks5_cycle", fake_cycle)
    a = _adapter()
    row = a._probe_cycle()
    assert row["ok"] and seen["port"] == 41003
    assert seen["target"] == "1.1.1.1" and seen["portp"] == 443


def test_probe_cycle_server_is_liveness(monkeypatch):
    a = _adapter(role="server")
    monkeypatch.setattr(a, "_pid_alive", lambda: True)
    row = a._probe_cycle()
    assert row["ok"] and row["method"] == "liveness"
    monkeypatch.setattr(a, "_pid_alive", lambda: False)
    row = a._probe_cycle()
    assert not row["ok"] and row["loss_pct"] == 100.0


def test_receipt_exit_ip(monkeypatch):
    from tfd import probes
    monkeypatch.setattr(probes, "socks5_http_get",
                        lambda port, host, path: "203.0.113.77")
    a = _adapter()
    rec = a.receipt()
    assert rec["through_tunnel"] and rec["exit_ip"] == "203.0.113.77"
    # server role has no receipt by definition
    a2 = _adapter(role="server")
    assert a2.receipt()["through_tunnel"] is False
