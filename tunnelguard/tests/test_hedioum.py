"""Tests for the Hedioum Pool Tunnel adapter + HajSaman pending slot.

Hedioum is tested on three honest levels:
 1. pairing-token decode (mirrors internal/pairing/token.go),
 2. adapter logic with a recording executor (config merge, precheck,
    up/down command plan),
 3. SOCKS5 probe helpers against a local fake SOCKS5 server.
The LIVE receipt (real hub+foreign, real egress) is scripts/run_hedioum_e2e.py.
"""
import base64
import json
import socket
import threading

import sys

import pytest

from tfd.engines.hedioum import HedioumAdapter, decode_pairing_token, CONFIG_PATH


# --------------------------------------------------------------- token v2
def _mk_token(payload: dict) -> str:
    raw = json.dumps(payload).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_pairing_token_v2_roundtrip():
    tok = _mk_token({"v": 2, "ip": "95.179.148.154",
                     "auth": "a" * 32, "persona": "devops",
                     "sni": "", "eps": {"ssh": 22, "tls": 443}})
    d = decode_pairing_token(tok)
    assert d["exit_ip"] == "95.179.148.154"
    assert d["auth_key"] == "a" * 32
    assert d["endpoints"] == {"ssh": 22, "tls": 443}
    assert d["persona"] == "devops"


def test_pairing_token_legacy_and_garbage():
    assert decode_pairing_token("a" * 32) is None       # v1 hex -> manual flow
    assert decode_pairing_token("!!!not-base64!!!") is None
    assert decode_pairing_token("") is None
    bad = base64.urlsafe_b64encode(b'{"v":3,"ip":"1.2.3.4"}').rstrip(b"=").decode()
    assert decode_pairing_token(bad) is None            # future version


# ------------------------------------------------------------ resolved cfg
def _adapter(tmp_path, cfg_extra=None, executor=None):
    t = {"id": 3, "name": "de-01", "engine": "hedioum",
         "iface": "hedioom3", "remote_host": "198.51.100.9",
         "config": json.dumps({
             "pairing_token": _mk_token({"v": 2, "ip": "198.51.100.9",
                                         "auth": "b" * 32,
                                         "eps": {"ssh": 22}}),
             "socks_port": 41003,
             **(cfg_extra or {})})}
    return HedioumAdapter(t, executor)


def test_resolved_prefers_token_over_manual():
    a = _adapter(None)
    r = a._resolved()
    assert r["foreign_ip"] == "198.51.100.9"
    assert r["auth_token"] == "b" * 32
    assert r["foreign_port"] == 22
    assert r["_endpoints"] == {"ssh": 22}


def test_legacy_hex_token_maps_to_auth_token():
    """Regression: a legacy 32-hex secret in pairing_token MUST become
    auth_token — otherwise the hub dials with an empty secret and the pool
    is dead while CONNECT replies still look OK."""
    a = _adapter(None, cfg_extra={"pairing_token": "c" * 32,
                                  "foreign_ip": "198.51.100.9",
                                  "foreign_port": 22})
    r = a._resolved()
    assert r["auth_token"] == "c" * 32
    node = a._node()
    assert node["auth_token"] == "c" * 32


@pytest.mark.linux_integration
@pytest.mark.skipif(sys.platform == "win32", reason="engine precheck uses POSIX os.geteuid")
def test_precheck_rejects_empty_resolved_auth():
    t = {"id": 5, "name": "x", "engine": "hedioum", "iface": "h5",
         "config": json.dumps({"foreign_ip": "1.2.3.4",
                               "foreign_port": 22, "auth_token": ""})}
    a = HedioumAdapter(t)
    problems = a.precheck()
    assert any("empty" in p for p in problems)


def test_render_merges_and_preserves_co_tenants(tmp_path):
    class Exec:
        def __init__(self):
            self.existing = json.dumps({
                "role": "iran",
                "foreign_nodes": [{"alias": "other-node", "target_ip": "1.1.1.1",
                                   "target_port": 22, "local_socks_port": 40002,
                                   "auth_token": "c" * 32}]})
        def __call__(self, cmd, timeout):
            class CP:
                returncode = 0
                stdout = self.existing
                stderr = ""
            return CP()

    ex = Exec()
    a = _adapter(None, executor=ex)
    arts = a.render()
    merged = json.loads(arts[CONFIG_PATH])
    aliases = [n["alias"] for n in merged["foreign_nodes"]]
    assert aliases == ["other-node", "de-01"]
    mine = merged["foreign_nodes"][1]
    assert mine["target_ip"] == "198.51.100.9"
    assert mine["local_socks_port"] == 41003
    assert mine["tun_name"] == "hedioom3"
    # re-render must not duplicate
    ex.existing = arts[CONFIG_PATH]
    merged2 = json.loads(a.render()[CONFIG_PATH])
    assert [n["alias"] for n in merged2["foreign_nodes"]] == \
        ["other-node", "de-01"]


@pytest.mark.linux_integration
@pytest.mark.skipif(sys.platform == "win32", reason="engine precheck uses POSIX os.geteuid")
def test_precheck_flags_missing_binary_and_config_role(tmp_path, monkeypatch):
    a = _adapter(None, cfg_extra={"binary_path": "/nonexistent/hedioum-tunnel"})
    monkeypatch.setattr(a, "_which", lambda b: None)
    monkeypatch.setattr(a, "_read_hub_config",
                        lambda: {"role": "foreign", "foreign_nodes": []})
    problems = a.precheck()
    assert any("binary not found" in p for p in problems)
    assert any("role=foreign" in p for p in problems)
    assert any("SOCKS-only" in p for p in problems)  # honest routing note


def test_precheck_clean_with_binary(tmp_path, monkeypatch):
    a = _adapter(None)
    monkeypatch.setattr(a, "_which", lambda b: "/usr/bin/hedioum-tunnel")
    monkeypatch.setattr(a, "_read_hub_config", lambda: None)
    monkeypatch.setattr(a, "_port_in_use", lambda p: False)
    problems = a.precheck()
    assert [p for p in problems if "SOCKS-only" not in p] == []


def test_routing_capable_requires_tun():
    assert _adapter(None).routing_capable is False
    assert _adapter(None, cfg_extra={"tun_enabled": True}).routing_capable


@pytest.mark.linux_integration
@pytest.mark.skipif(sys.platform == "win32", reason="engine precheck uses POSIX os.geteuid")
def test_up_standalone_writes_config_and_persists_node(tmp_path, monkeypatch):
    """Standalone up() spawns the real binary only if present; here we check
    the config+artifact path with the spawn monkeypatched out."""
    a = _adapter(None, cfg_extra={"standalone": True})
    calls = {}

    def fake_popen(cmd, cwd=None, stdout=None, stderr=None, **kwargs):
        calls["cmd"] = cmd
        calls["cwd"] = cwd

        class P:
            pid = 424242
        return P()

    monkeypatch.setattr("tfd.engines.hedioum._popen", fake_popen)
    monkeypatch.setattr(a, "_socks_alive", lambda: True)
    monkeypatch.setattr(a, "_binary", lambda: "/bin/true")
    cmds = a.up()
    assert any("standalone start" in c for c in cmds)
    assert calls["cwd"].endswith("hedioum/de-01")
    wd = calls["cwd"]
    cfg = json.load(open(f"{wd}/hedioum.json"))
    assert cfg["role"] == "iran"
    assert cfg["foreign_nodes"][0]["alias"] == "de-01"


# ---------------------------------------------------------- SOCKS5 probes
class _FakeSocks(threading.Thread):
    """Minimal SOCKS5 server: no-auth, CONNECT always succeeds."""
    def __init__(self):
        super().__init__(daemon=True)
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.stop = False

    def run(self):
        while not self.stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            c.recv(64)                       # greeting
            c.sendall(b"\x05\x00")
            c.recv(64)                       # CONNECT
            c.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            c.close()


def test_socks5_cycle_ok_and_refused():
    from tfd import probes
    fk = _FakeSocks()
    fk.start()
    r = probes.socks5_cycle(fk.port, "1.1.1.1", 443, count=3, timeout_s=2)
    assert r["ok"] and r["loss_pct"] == 0 and r["rtt_ms"] is not None
    fk.stop = True
    fk.srv.close()
    # dead port: bind+close to grab a guaranteed-free port, then use it
    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    free_port = dead.getsockname()[1]
    dead.close()
    r2 = probes.socks5_cycle(free_port, "1.1.1.1", 443, count=2, timeout_s=0.5)
    assert not r2["ok"] and r2["loss_pct"] == 100.0


# ---------------------------------------------------------- hajsaman (v1.2)
def test_hajsaman_auto_without_cli_goes_native_and_tells_truth():
    """Repo access landed. On a box with neither the wizard tool nor any
    config, auto mode picks 'native' and the precheck lists exactly which
    keys/bins are missing — no pretending."""
    from tfd.engines.hajsaman import HajSamanAdapter
    t = {"id": 1, "name": "haj", "engine": "hajsaman", "config": "{}"}
    a = HajSamanAdapter(t)
    assert a.mode == "native"                       # auto-detect: tool absent
    problems = a.precheck()
    assert any("local_public_ip" in p for p in problems)
    assert any("private_key" in p for p in problems)
    assert a.routing_capable is True                # WG-in-SIT = real L3


def test_hajsaman_cli_mode_without_tool_is_honest():
    """Forcing cli mode without the tool installed says exactly that."""
    from tfd.engines.hajsaman import HajSamanAdapter
    t = {"id": 2, "name": "haj2", "engine": "hajsaman",
         "config": '{"mode": "cli"}'}
    problems = HajSamanAdapter(t).precheck()
    assert problems and "CLI not found" in problems[0]
