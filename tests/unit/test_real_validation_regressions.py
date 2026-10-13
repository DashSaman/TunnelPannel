"""Negative acceptance cases found while auditing the real-node runner."""
import pytest

from tests.unit.test_p14_prep import make_config, pinned, RecordingChannel
from scripts import p14_validate as p14


@pytest.fixture
def context(tmp_path, monkeypatch):
    monkeypatch.setattr(p14, "ARTIFACTS", tmp_path / "artifacts")
    pinned(tmp_path)
    cfg, _ = make_config(tmp_path, n_nodes=3)
    route = "198.51.100.1 50000 198.51.100.10 22\n198.51.100.1 via 198.51.100.254 dev eth0 src 198.51.100.10"
    channels = {key: RecordingChannel(key, outputs={"ip route get": (0, route)})
                for key in cfg.nodes}
    ctx = p14.RunContext(cfg, p14.new_run_id(), channels=channels)
    ctx.snapshot_management_routes()
    return ctx


def test_preflight_accepts_the_actual_channel_interface(context):
    class RealInterface:
        def run(self, cmd, timeout=60):
            return context.channels["node-a"].run(cmd, timeout)
    context.channels["node-c"] = RealInterface()
    p14.stage_preflight(context)


@pytest.mark.parametrize("result", [(1, "route query failed"), (0, "")])
def test_failed_route_query_cannot_authorize_mutation(context, result):
    context.channels["node-a"].outputs["ip route get"] = result
    with pytest.raises(p14.SafetyGate):
        context.snapshot_management_routes()


def test_failover_without_real_data_plane_is_blocked(context):
    result = p14.stage_failover(context)
    assert result["status"] == "BLOCKED_EXTERNAL_DEPENDENCY"


def test_three_nodes_without_real_multihop_probe_is_blocked(context):
    result = p14.stage_multihop(context)
    assert result["status"] == "BLOCKED_EXTERNAL_DEPENDENCY"
    assert "REAL" in result["reason"]


@pytest.mark.parametrize("stage", ["quick", "normal", "profiles"])
@pytest.mark.parametrize("statuses", [["FAILED"], ["PASS", "FAILED"], ["CANCELLED"]])
def test_profile_stage_never_hides_unsuccessful_results(context, monkeypatch, stage, statuses):
    monkeypatch.setattr(p14, "run_profiles", lambda *args: [{"status": s} for s in statuses])
    assert p14.run_stage(context, stage) != "PASS"


def test_installed_service_survives_into_dependent_stages(context, monkeypatch):
    def install(ctx):
        ctx.ledger.add("service", "tunnelpannel-api", "node-a", "systemctl stop tunnelpannel-api")
        return {"status": "PASS"}
    monkeypatch.setattr(p14, "stage_install", install)
    p14.run_stage(context, "install")
    assert "systemctl stop tunnelpannel-api" not in context.channels["node-a"].commands


def test_resume_restores_management_route_baseline(context):
    p14.stage_preflight(context)
    resumed = p14.RunContext(context.cfg, context.run_id, channels=context.channels)
    resumed.assert_mutation_allowed()


def test_profile_failed_teardown_keeps_durable_cleanup(context):
    from core.catalog import CATALOG
    from engines.adapters import ProbeResult
    class Adapter:
        def detect(self): return True
        def precheck(self): return []
        def configure(self): pass
        def start(self): pass
        def probe(self): return ProbeResult(ok=True, evidence="actual probe")
        def metrics(self): return {}
        def rollback_commands(self): return [("remove owned interface", "ip link del tp-owned")]
        def rollback(self): raise RuntimeError("cleanup failed")
    result = p14._run_one_profile(context, CATALOG.by_legacy("GRE"), "QUICK", lambda _: Adapter())
    assert result["status"] == "FAILED"
    assert context.ledger.unreleased_for_run()
    assert "ip link del tp-owned" in context.ledger.unreleased_for_run()[0]["rollback_cmd"]


def test_blocked_profile_never_rolls_back_uncreated_resources(context):
    from core.catalog import CATALOG
    class Blocked:
        def detect(self): return True
        def precheck(self): return ["binary missing"]
        def rollback(self): raise RuntimeError("would delete an unowned resource")
    result = p14._run_one_profile(context, CATALOG.by_legacy("GRE"), "QUICK", lambda _: Blocked())
    assert result["status"] == "BLOCKED_EXTERNAL_DEPENDENCY"
    assert not context.orphans


def test_uninstall_does_not_delete_preexisting_unrelated_directory(context):
    ch = context.channels["node-a"]
    ch.outputs.update({"test ! -d /opt/tunnelpannel": (0, "gone"),
                       "test -f ": (0, "kept")})
    p14.stage_uninstall(context)
    assert not any("rm -rf /opt/unrelated-app" in cmd for cmd in ch.commands)
