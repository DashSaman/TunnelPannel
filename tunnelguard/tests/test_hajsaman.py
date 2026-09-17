"""Tests for the HajSamanTunnel engine adapter (v1.2 — real, repo access).

Two honest layers:
 1. cli mode — recording executor simulating the real `hajsaman-tunnel`
    tool + a tunnels.d/<slot>.conf in the format the wizard writes
    (KEY=value, keys verified against lib/part-0*.sh of the repo).
 2. native mode — artifact render (WG conf + SIT up/down scripts) and
    precheck truth-telling on a clean box.
"""
import json

import pytest

from tfd.engines.hajsaman import HajSamanAdapter, parse_slot_conf

SLOT_CONF = """
ROLE=iran
ALIAS_IP=
FOREIGN_IPV4=198.51.100.9
SIT_IF=sit-hst427
WG_IF=wgHST427
WG_NET=10.77.77.0/30
GW_WG_IP=10.77.77.1
FOREIGN_WG_IP=10.77.77.2
GW_WG_PORT=42711
FOREIGN_WG_PORT=42712
GW_V6=fd00:05a1:0427::1
FOREIGN_V6=fd00:05a1:0427::2
MARK=31427
TABLE=31427
MTU_SIT=1480
MTU_WG=1420
ADMIN_STATE=running
"""


class FakeExec:
    """Records commands; answers per-prefix like the real tool would."""

    def __init__(self, status_out="hst-427 running | SIT ok | WG ok"):
        self.calls: list[list[str]] = []
        self.status_out = status_out
        self.curl_out = "203.0.113.77"
        self.conf = SLOT_CONF

    def __call__(self, cmd, timeout):
        self.calls.append(list(cmd) if not isinstance(cmd, str) else [cmd])
        cp = type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})

        if cmd[:2] == ["cat", "/etc/hajsaman-tunnel/tunnels.d/hst-427.conf"]:
            cp.stdout = self.conf
        elif cmd[:1] == ["cat"] and str(cmd[1]).endswith(".conf"):
            cp.returncode = 1
        elif cmd[:2] == ["hajsaman-tunnel", "status"]:
            cp.stdout = self.status_out
        elif cmd[:2] == ["hajsaman-tunnel", "start"]:
            cp.stdout = "slot hst-427 started"
        elif cmd[:2] == ["hajsaman-tunnel", "stop"]:
            cp.stdout = "slot hst-427 stopped"
        elif cmd[:1] == ["curl"]:
            cp.stdout = self.curl_out
        elif cmd[:3] == ["ping", "-6", "-I"] or cmd[:1] == ["ping"]:
            cp.returncode = 0
        elif cmd[:2] == ["ip", "-o"] and len(cmd) >= 6 and "wgHST427" in cmd:
            cp.returncode = 0
        elif cmd[:2] == ["ip", "-o"]:
            cp.returncode = 1
        return cp


def _adapter(cfg_extra=None, executor=None, tid=3):
    cfg = {"mode": "cli", "slot": "hst-427", "cli_path": "/bin/true",
           **(cfg_extra or {})}
    t = {"id": tid, "name": "hst", "engine": "hajsaman", "iface": "tfh3",
         "remote_host": "198.51.100.9", "config": json.dumps(cfg)}
    return HajSamanAdapter(t, executor)


# ------------------------------------------------------------- slot conf
def test_parse_slot_conf():
    d = parse_slot_conf(SLOT_CONF)
    assert d["WG_IF"] == "wgHST427"
    assert d["GW_WG_IP"] == "10.77.77.1"
    assert d["FOREIGN_WG_IP"] == "10.77.77.2"
    assert d["MARK"] == "31427"
    assert d["ADMIN_STATE"] == "running"
    assert "#" not in d            # comments skipped


# ------------------------------------------------------------- cli mode
def test_routing_capable_true():
    assert _adapter().routing_capable is True


def test_cli_precheck_clean_and_notes_proto41():
    ex = FakeExec()
    a = _adapter(executor=ex)          # cli_path=/bin/true exists
    problems = a.precheck()
    assert len(problems) == 1 and "proto 41" in problems[0]


def test_cli_precheck_missing_conf(monkeypatch):
    ex = FakeExec()
    ex.conf = ""
    a = _adapter(executor=ex)
    problems = a.precheck()
    assert len(problems) == 1 and "slot conf" in problems[0] \
        and "not found" in problems[0]


def test_cli_precheck_flags_admin_stopped():
    ex = FakeExec()
    ex.conf = SLOT_CONF.replace("ADMIN_STATE=running", "ADMIN_STATE=stopped")
    a = _adapter(executor=ex)
    assert any("intentionally stopped" in p for p in a.precheck())


def test_cli_up_down_via_real_cli():
    ex = FakeExec()
    a = _adapter(executor=ex)
    cmds = a.up()
    assert any("hajsaman-tunnel start hst-427" in c for c in cmds)
    out = a.down()
    assert any("stop hst-427" in c for c in out)
    assert [c[1:] for c in ex.calls[:1]] == [["start", "hst-427"]]
    assert ["stop", "hst-427"] in [c[1:] for c in ex.calls]


class FailingExec:
    """Every command fails (like a broken install would)."""

    def __call__(self, cmd, timeout):
        return type("CP", (), {"returncode": 7, "stdout": "",
                               "stderr": "nope"})()


def test_cli_up_failure_raises():
    a = _adapter(executor=FailingExec())
    with pytest.raises(Exception) as ei:
        a.up()
    assert "rc=7" in str(ei.value)


def test_cli_status_uses_slot_output_and_iface():
    ex = FakeExec()
    a = _adapter(executor=ex)
    st = a.status()
    assert st["up"] is True
    assert st["extra"]["wg_if"] == "wgHST427"
    assert st["extra"]["wg_iface_present"] is True
    ex.status_out = "nothing running"
    st2 = a.status()
    assert st2["up"] is False or st2["extra"]["wg_iface_present"]


# --------------------------------------------------------------- probe
def test_probe_iran_side_pings_foreign_through_wg(monkeypatch):
    from tfd import probes
    seen = {}

    def fake_cycle(target, count, timeout, source=None):
        seen.update(target=target, source=source)
        return {"ok": True, "rtt_ms": 55.0, "loss_pct": 0.0,
                "jitter_ms": 2.0, "method": "icmp"}

    monkeypatch.setattr(probes, "ping_cycle", fake_cycle)
    a = _adapter(executor=FakeExec())
    row = a._probe_cycle()
    assert row["ok"]
    assert seen["target"] == "10.77.77.2"          # peer
    assert seen["source"] == "10.77.77.1"          # own WG /32 (policy rule)


def test_probe_foreign_side_pings_gateway(monkeypatch):
    from tfd import probes
    seen = {}
    monkeypatch.setattr(probes, "ping_cycle",
                        lambda t, c, to, source=None:
                        seen.update(target=t, source=source) or
                        {"ok": True, "rtt_ms": 55.0, "loss_pct": 0.0,
                         "jitter_ms": 2.0, "method": "icmp"})
    conf = SLOT_CONF.replace("ROLE=iran", "ROLE=foreign")
    a = _adapter(executor=FakeExec())
    a._slot_conf = lambda: parse_slot_conf(conf)
    a._probe_cycle()
    assert seen["target"] == "10.77.77.1"
    assert seen["source"] == "10.77.77.2"


def test_probe_dead_wg_reports_underlay_state(monkeypatch):
    from tfd import probes
    monkeypatch.setattr(probes, "ping_cycle",
                        lambda t, c, to, source=None:
                        {"ok": False, "rtt_ms": None, "loss_pct": 100.0,
                         "jitter_ms": None, "method": "icmp"})
    ex = FakeExec()
    a = _adapter(executor=ex)
    row = a._probe_cycle()
    assert not row["ok"]
    assert "SIT underlay ALIVE" in (row.get("detail") or "")


# ------------------------------------------------------------- receipt
def test_receipt_curl_via_wg_source_ip():
    ex = FakeExec()
    a = _adapter(executor=ex)
    rec = a.receipt()
    assert rec["through_tunnel"] is True
    assert rec["exit_ip"] == "203.0.113.77"
    curl_call = [c for c in ex.calls if c[:1] == ["curl"]][0]
    assert "--interface" in curl_call and "10.77.77.1" in curl_call


def test_receipt_all_providers_fail():
    ex = FakeExec()
    ex.curl_out = ""
    a = _adapter(executor=ex)
    rec = a.receipt()
    assert rec["through_tunnel"] is False and rec["attempts"] >= 3


# ---------------------------------------------------------- native mode
def _native_adapter(cfg_extra=None, tid=9):
    cfg = {"mode": "native", "role": "iran",
           "local_public_ip": "91.98.0.10",
           "foreign_ipv4": "198.51.100.9",
           "wg_listen_port": 51830,
           "private_key": "PK" * 22,
           "peer_public_key": "PU" * 22,
           "mark": 31409, "table": 31409, **(cfg_extra or {})}
    t = {"id": tid, "name": "hst-native", "engine": "hajsaman",
         "iface": "tf-hst9", "remote_host": "198.51.100.9",
         "config": json.dumps(cfg)}
    return HajSamanAdapter(t)


def test_native_render_iran_stack():
    a = _native_adapter()
    arts = a.render()
    wg = arts["/etc/wireguard/tf-hst9.conf"]
    assert "Address = 10.90.9.1/30" in wg
    assert "Endpoint = [fd00:05a1:0009::2]:51830" in wg
    assert "AllowedIPs = 10.90.9.2/32, 0.0.0.0/0" in wg
    assert "Table = 31409" in wg
    up = arts["commands/hajsaman-hst-9-up.sh"]
    assert "mode sit local 91.98.0.10 remote 198.51.100.9" in up
    assert "wg-quick up tf-hst9" in up
    assert "ip rule add fwmark 0x7ab1 table 31409" in up   # 31409 = 0x7AB1
    assert "MASQUERADE" not in up                          # iran side: no snat
    down = arts["commands/hajsaman-hst-9-down.sh"]
    assert "wg-quick down" in down and "ip tunnel del" in down


def test_native_render_foreign_stack_snats():
    a = _native_adapter(cfg_extra={"role": "foreign"}, tid=9)
    up = a.render()["commands/hajsaman-hst-9-up.sh"]
    assert "MASQUERADE" in up
    assert "ip rule add" not in up                         # no policy route


def test_native_precheck_missing_keys():
    t = {"id": 4, "name": "h", "engine": "hajsaman",
         "config": json.dumps({"mode": "native"})}
    a = HajSamanAdapter(t)
    problems = a.precheck()
    joined = " | ".join(problems)
    for needle in ("local_public_ip", "foreign_ipv4", "private_key",
                   "peer_public_key"):
        assert needle in joined
    assert "native mode" in joined          # honest scope note
