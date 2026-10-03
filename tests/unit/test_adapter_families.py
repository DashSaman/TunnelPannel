"""P5 adapter-family test suite — table-driven (§13) + honesty negatives (§14)
+ secret redaction (§8) + coverage gate (§16).

Portable tier: command streams and parsing only. Real network execution is
LINUX_PRIVILEGED / REAL_NODE_E2E and stays out of this file.
"""
import pytest

from core.catalog import CATALOG
from engines.adapters import get_adapter, registered
from engines.adapters.kernel import FakeExecutor
from engines.executors import FakeExecutor as CanonFake
from engines.packages import PackageService, PackageSpec

pytestmark = pytest.mark.unit_portable

NODE_A = {"id": "a", "name": "a", "host": "198.51.100.1"}
NODE_B = {"id": "b", "name": "b", "host": "203.0.113.20"}

KERNEL_PARAMS = {"interface": "tp0", "inner_ip_a": "10.174.0.1/24",
                 "inner_ip_b": "10.174.0.2",
                 "probe_target": "10.174.0.2", "port": 24000, "mtu": 1420}
USERSPACE_PARAMS = {"server_port": 14101, "client_port": 14102,
                    "probe_port": 14102, "interface": "tp0",
                    "probe_target": "10.174.0.2", "auth": "tp:tp",
                    "password": "sekrit", "token": "tok-1", "auth_token": "frp-tok",
                    "pairing_token": "pair-1", "slot_conf": "slot 1 mode full",
                    "identity_file": "/etc/tunnelpannel/id_ed25519",
                    "user_id": "uuid-1"}


def adapters_module():
    import engines.adapters.kernel             # noqa: F401
    import engines.adapters.kernel_extra       # noqa: F401
    import engines.adapters.ssh_family         # noqa: F401
    import engines.adapters.userspace          # noqa: F401


@pytest.fixture(scope="module", autouse=True)
def _load_all_adapters():
    adapters_module()


# ── §16 coverage gate ─────────────────────────────────────────────────

class TestCoverageGate:
    def test_every_catalog_engine_has_an_adapter(self):
        for engine in CATALOG.engines():
            assert any(e == engine for e, _p in registered()), \
                f"engine {engine} has no adapter"

    def test_every_profile_resolves(self):
        for ident in CATALOG.identities.values():
            if ident.is_composite:
                continue
            adapter = get_adapter(ident.engine, ident.profile)
            assert adapter is not None

    def test_composites_map_to_templates_not_adapters(self):
        for lid, ident in CATALOG.composite_templates.items():
            assert ident.is_composite and ident.overlay and ident.underlay
            assert (ident.engine, ident.profile) not in registered()

    def test_legacy_ids_resolve_end_to_end(self):
        for legacy in list(CATALOG.identities) + list(CATALOG.composite_templates):
            ident = CATALOG.by_legacy(legacy)     # raises on unknown
            assert ident.engine


# ── §13 table-driven family tests ─────────────────────────────────────

FAMILY_CASES = [
    # (engine, profile, params-kind, expect-substring-in-commands)
    ("gretap", "default", "kernel", "type gretap"),
    ("gretap", "ip6", "kernel", "ip6gretap"),
    ("ipip", "default", "kernel", "mode ipip"),
    ("sit", "default", "kernel", "mode sit"),
    ("vxlan", "default", "kernel", "type vxlan"),
    ("vti", "default", "kernel", "mode vti"),
    ("vti", "v6", "kernel", "mode vti6"),
    ("openvpn", "default", "kernel", "openvpn --genkey secret"),
    ("ipsec", "ikev2", "kernel", "swanctl --load-all"),
    ("ipsec", "l2tp", "kernel", "swanctl --load-all"),
    ("ssh", "local_forward", "userspace", "-L 127.0.0.1:14102:"),
    ("ssh", "dynamic_socks", "userspace", "-D 127.0.0.1:14102"),
    ("ssh", "reverse", "userspace", "autossh"),
    ("gost", "socks5", "userspace", "socks5://127.0.0.1:14102"),
    ("gost", "grpc", "userspace", "-F grpc://127.0.0.1:14101"),
    ("gost", "tcp_forward", "userspace", "tcp://127.0.0.1:14101/127.0.0.1:14080"),
    ("frp", "tcp", "userspace", "frps"),
    ("rathole", "noise", "userspace", "rathole"),
    ("chisel", "socks5", "userspace", "chisel"),
    ("wstunnel", "socks5", "userspace", "wstunnel"),
    ("waterwall", "direct", "userspace", "waterwall"),
    ("paqet", "socks5", "userspace", "paqet"),
    ("xray", "vless_grpc", "userspace", "xray run -c"),
    ("singbox", "hysteria2", "userspace", "sing-box run -c"),
    ("hedioum", "tun", "userspace", "hedioum"),
    ("hajsaman", "full", "userspace", "hajsaman"),
]


class TestFamilies:
    @pytest.mark.parametrize("engine,profile,kind,needle", FAMILY_CASES)
    def test_plan_and_commands(self, engine, profile, kind, needle):
        cls = get_adapter(engine, profile)
        params = dict(KERNEL_PARAMS if kind == "kernel" else USERSPACE_PARAMS)
        params["profile"] = profile
        ex = FakeExecutor()
        ad = cls(NODE_A, NODE_B, executor=ex, params=params)
        before = len(ex.commands)
        plan = ad.plan()
        assert plan
        assert len(ex.commands) == before                   # plan mutates nothing
        ad.configure()
        joined = "\n".join(ex.commands)
        assert needle in joined, f"{engine}/{profile}: {needle!r} not in command stream"

    @pytest.mark.parametrize("engine,profile,kind,_n", FAMILY_CASES)
    def test_rollback_produces_cleanup(self, engine, profile, kind, _n):
        cls = get_adapter(engine, profile)
        params = dict(KERNEL_PARAMS if kind == "kernel" else USERSPACE_PARAMS)
        params["profile"] = profile
        ex = FakeExecutor()
        ad = cls(NODE_A, NODE_B, executor=ex, params=params)
        ad.rollback()
        assert ex.commands, f"{engine}/{profile}: rollback did nothing"

    def test_unknown_profile_rejected(self):
        from engines.adapters.userspace import GostAdapter
        with pytest.raises(KeyError, match="unknown profile"):
            GostAdapter(NODE_A, NODE_B, executor=FakeExecutor(),
                        params={"profile": "carrier-pigeons"})


# ── §14 honesty negative tests (mandatory) ────────────────────────────

class TestProbeHonesty:
    def _adapter(self, engine, profile, results=None, params_extra=None):
        cls = get_adapter(engine, profile)
        params = dict(USERSPACE_PARAMS)
        params["profile"] = profile
        params.update(params_extra or {})
        ex = FakeExecutor(results=results)
        return cls(NODE_A, NODE_B, executor=ex, params=params), ex

    def test_socks_listener_up_but_connect_fails_is_FAIL(self):
        ad, _ = self._adapter("gost", "socks5",
                              results={"curl": (0, "000")})     # port answers nothing
        assert ad.probe().ok is False

    def test_socks_connect_succeeds_is_PASS(self):
        ad, ex = self._adapter("gost", "socks5", results={"curl": (0, "200")})
        r = ad.probe()
        assert r.ok and "socks5" in r.evidence
        assert "--socks5-hostname" in ex.commands[-1]

    def test_tcp_forward_listener_up_payload_missing_is_FAIL(self):
        ad, _ = self._adapter("chisel", "tcp", results={"curl": (0, "000")})
        assert ad.probe().ok is False

    def test_kernel_iface_exists_but_destination_unreachable_is_FAIL(self):
        cls = get_adapter("wireguard")
        ad = cls(NODE_A, NODE_B, executor=FakeExecutor(results={"ping": (1, "3 packets transmitted, 0 received")}),
                 params=dict(KERNEL_PARAMS))
        assert ad.probe().ok is False

    def test_wireguard_no_handshake_traffic_is_FAIL(self):
        cls = get_adapter("wireguard")
        ad = cls(NODE_A, NODE_B,
                 executor=FakeExecutor(results={"ping": (1, "Network is unreachable")}),
                 params=dict(KERNEL_PARAMS))
        r = ad.probe()
        assert r.ok is False and "probe failed" in r.evidence

    def test_udp_payload_never_returned_is_FAIL(self):
        ad, _ = self._adapter("gost", "udp_forward",
                              results={"nc": (1, "")})
        assert ad.probe().ok is False

    def test_udp_roundtrip_is_PASS(self):
        ad, _ = self._adapter("gost", "udp_forward",
                              results={"nc": (0, "tp-probe")})
        assert ad.probe().ok is True

    def test_process_alive_is_never_sufficient(self):
        # pidfile exists and kill -0 succeeds, but no data-plane probe passed
        ad, ex = self._adapter("rathole", "tcp", results={"curl": (0, "000")})
        ex.run(f"kill -0 $(cat {RUN_DIR_PLACEHOLDER}) 2>/dev/null")  # process check alone
        assert ad.probe().ok is False


RUN_DIR_PLACEHOLDER = "/run/tunnelpannel/rathole-tcp.pid"


# ── §8 secret redaction ───────────────────────────────────────────────

class TestSecretRedaction:
    def test_gost_password_redacted(self):
        cls = get_adapter("gost", "socks5")
        ad = cls(NODE_A, NODE_B, executor=FakeExecutor(),
                 params={**USERSPACE_PARAMS, "profile": "socks5", "password": "hunter2"})
        assert ad.redacted_params()["password"] == "***REDACTED***"

    def test_paqet_config_contains_secret_but_plan_redacts(self):
        cls = get_adapter("paqet", "socks5")
        ex = FakeExecutor()
        ad = cls(NODE_A, NODE_B, executor=ex,
                 params={**USERSPACE_PARAMS, "profile": "socks5", "password": "hunter2"})
        ad.configure()
        assert any("hunter2" in c for c in ex.commands)      # config file itself
        red = ad.redacted_params()
        assert red["password"] == "***REDACTED***"           # but reports redact

    def test_ipsec_psk_redacted(self):
        cls = get_adapter("ipsec", "ikev2")
        ad = cls(NODE_A, NODE_B, executor=FakeExecutor(),
                 params={**KERNEL_PARAMS, "psk": "super-secret-psk"})
        assert ad.redacted_params()["psk"] == "***REDACTED***"

    def test_hedioum_token_redacted(self):
        cls = get_adapter("hedioum", "tun")
        ad = cls(NODE_A, NODE_B, executor=FakeExecutor(),
                 params={**USERSPACE_PARAMS, "profile": "tun", "pairing_token": "tok-xyz"})
        assert ad.redacted_params()["pairing_token"] == "***REDACTED***"


# ── §6 executor / §9 package service ──────────────────────────────────

class TestExecutorsAndPackages:
    def test_fake_executor_records_and_scripts(self):
        ex = CanonFake(results={"boom": (3, "err")}, default=(0, "ok"))
        assert ex.run("ls -la") == (0, "ok")
        assert ex.run("run boom now") == (3, "err")
        assert ex.commands == ["ls -la", "run boom now"]

    def test_package_service_detects_debian(self):
        ex = FakeExecutor(results={"os-release": (0, 'ID=ubuntu\nID_LIKE=debian')})
        svc = PackageService(ex)
        assert svc.detect_manager() == "apt"

    def test_package_service_blocks_unknown_distro(self):
        ex = FakeExecutor(results={"os-release": (0, "ID=plan9")})
        svc = PackageService(ex)
        status, why = svc.ensure(PackageSpec("x", ["foo"]))
        assert status == "BLOCKED" and "unsupported distribution" in why

    def test_package_service_already_present(self):
        ex = FakeExecutor(results={"os-release": (0, "ID=ubuntu\nID_LIKE=debian")},
                          default=(0, ""))            # command -v succeeds
        svc = PackageService(ex)
        status, _ = svc.ensure(PackageSpec("wireguard", ["wg"]))
        assert status == "ALREADY_PRESENT"

    def test_install_command_per_manager(self):
        ex = FakeExecutor(default=(0, ""))
        svc = PackageService(ex)
        cmd = svc.install_command(PackageSpec("foo", ["bar"]), "dnf")
        assert cmd == "dnf install -y bar"
        cmd = svc.install_command(PackageSpec("foo", ["bar"]), "apk")
        assert cmd == "apk add --no-cache bar"
        assert svc.install_command(PackageSpec("foo", ["bar"]), "brew") is None
