"""Kernel adapter tests (P5b) — unit_portable tier.

Asserts the generated command stream (the Linux behavior itself runs in
the privileged/E2E tiers), the probe truth-gate semantics, rollback
inverse order, and the full SDK contract for the real adapters.
"""
import pytest

from engines.adapters import get_adapter, registered
from engines.adapters.kernel import FakeExecutor, GreAdapter, WireGuardAdapter

pytestmark = pytest.mark.unit_portable


def wg_params():
    return {
        "interface": "tp0", "port": 24000, "subnet": "10.174.0.0/24",
        "inner_ip_a": "10.174.0.1/24", "inner_ip_b": "10.174.0.2",
        "probe_target": "10.174.0.2", "endpoint_b": "203.0.113.20:24000",
    }


class TestWireGuardAdapter:
    def make(self, **exec_kw):
        ex = FakeExecutor(**exec_kw)
        ad = WireGuardAdapter({"id": "a", "name": "a", "host": "198.51.100.1"},
                              {"id": "b", "name": "b", "host": "203.0.113.20"},
                              executor=ex, params=wg_params())
        return ad, ex

    def test_registered_under_engine(self):
        assert ("wireguard", "default") in registered()
        assert get_adapter("wireguard") is WireGuardAdapter

    def test_detect_true_when_binaries_present(self):
        ad, ex = self.make()
        assert ad.detect() is True
        assert "command -v wg" in ex.commands[0]

    def test_detect_false_when_missing(self):
        ad, _ = self.make(default=(1, "not found"))
        assert ad.detect() is False

    def test_precheck_flags_missing_params(self):
        ad, _ = self.make()
        ad.node_b = None                                  # no peer anywhere
        ad.params = {"interface": "tp0"}                  # most params missing
        problems = ad.precheck()
        assert any("endpoint" in p for p in problems)
        assert any("subnet" in p for p in problems)

    def test_plan_is_declarative_and_covers_commands(self):
        ad, ex = self.make()
        plan = ad.plan()
        verbs = [p.detail for p in plan]
        assert any("ip link add tp0 type wireguard" in d for d in verbs)
        assert any("listen-port 24000" in d for d in verbs)
        assert ex.commands == []                          # planning mutates nothing

    def test_configure_emits_command_stream(self):
        ad, ex = self.make()
        ad.configure()
        joined = " && ".join(ex.commands)
        assert "ip link add tp0 type wireguard" in joined
        assert "wg genkey" in joined
        assert "allowed-ips 10.174.0.0/24" in joined

    def test_configure_failure_raises(self):
        ad, _ = self.make(default=(1, "RTNETLINK answers: File exists"))
        with pytest.raises(RuntimeError, match="configure failed"):
            ad.configure()

    def test_probe_pass_requires_real_ping(self):
        ad, ex = self.make(results={"ping": (0, "3 packets transmitted, 3 received")})
        r = ad.probe()
        assert r.ok and "ping" in ex.commands[-1]
        assert "tp0" in ex.commands[-1]                    # bound to the tunnel iface

    def test_probe_fails_when_no_traffic(self):
        ad, _ = self.make(results={"ping": (1, "3 packets transmitted, 0 received")})
        assert ad.probe().ok is False

    def test_metrics_parses_ping_rtt(self):
        ad, _ = self.make(results={"ping": (0, "rtt min/avg/max/mdev = 1.2/2.3/4.0/0.5 ms")})
        m = ad.metrics()
        assert m["rtt_avg_ms"] == pytest.approx(2.3)
        assert m["rtt_max_ms"] == pytest.approx(4.0)

    def test_rollback_runs_inverse_in_reverse(self):
        ad, ex = self.make()
        ad.rollback()
        # inverse of apply order: keys were created after the interface,
        # so key removal precedes interface deletion; all tolerant of absence
        assert "rm -f /etc/wireguard/tp0.key" in ex.commands[0]
        assert ex.commands[1].startswith("ip link del tp0")
        assert all("2>/dev/null" in c or c.endswith("; true") for c in ex.commands[:2])


class TestGreAdapter:
    def make(self, **exec_kw):
        ex = FakeExecutor(**exec_kw)
        ad = GreAdapter({"id": "a", "host": "198.51.100.1"},
                        {"id": "b", "host": "203.0.113.20"},
                        executor=ex,
                        params={"interface": "tp1", "inner_ip_a": "10.174.1.1/30",
                                "probe_target": "10.174.1.2", "local_ip": "198.51.100.1"})
        return ad, ex

    def test_registered(self):
        assert get_adapter("gre") is GreAdapter

    def test_command_shape(self):
        ad, ex = self.make()
        ad.configure()
        assert any("ip tunnel add tp1 mode gre remote 203.0.113.20 local 198.51.100.1" in c
                   for c in ex.commands)
        assert any("mtu 1476" in c for c in ex.commands)

    def test_rollback_deletes_tunnel(self):
        ad, ex = self.make()
        ad.rollback()
        assert ex.commands == ["ip tunnel del tp1 2>/dev/null; true"] or \
               any("ip tunnel del tp1" in c for c in ex.commands)

    def test_precheck_detects_missing_module(self):
        ad, _ = self.make(default=(1, ""))
        assert "ip_gre kernel module missing" in ad.precheck()
