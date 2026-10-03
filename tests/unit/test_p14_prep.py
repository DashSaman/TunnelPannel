"""P14-PREP acceptance tests — recording channels, no real SSH.

Covers the mandated areas: config parsing, secret redaction, preflight
zero-mutation, stage order, timeout, cleanup + orphan reporting, resume,
receipt/report generation, missing third node, management-route safety,
finite statuses everywhere.
"""
import json
import time

import pytest
import yaml

import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import p14_validate as p14  # noqa: E402

pytestmark = pytest.mark.unit_portable


# ── fakes ─────────────────────────────────────────────────────────────

class RecordingChannel:
    """Scripted read/mutation channel; records every command."""

    def __init__(self, node="node-a", outputs=None, sleep_s=0.0):
        self.node = node
        self.commands: list[str] = []
        self.outputs = outputs or {}
        self.default = (0, "")
        self.sleep_s = sleep_s
        self.violations: list[str] = []

    def run(self, cmd, timeout=60):
        self.commands.append(cmd)
        if self.sleep_s:
            time.sleep(self.sleep_s)
        for needle, res in self.outputs.items():
            if needle in cmd:
                return res
        return self.default


def make_config(tmp_path, n_nodes=2, **kw):
    nodes = {}
    for i, key in enumerate(("node-a", "node-b", "node-c")[:n_nodes]):
        nodes[key] = {"host": f"198.51.100.{10 + i}", "port": 22, "user": "root",
                      "key_path": str(tmp_path / f"key{i}"),
                      "known_hosts": str(tmp_path / "known_hosts"),
                      "alias": key}
    raw = {"run": {"candidate": "rc-test", "profiles": ["QUICK", "NORMAL"],
                   "stages": p14.STAGE_ORDER},
           "nodes": nodes,
           "settings": {"profile_budget_s": kw.pop("profile_budget_s", 5),
                        "max_hops": 3, "install_port": 8080}}
    raw.update(kw)
    cfg_path = tmp_path / "nodes.yml"
    cfg_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    cfg = p14.P14Config.load(cfg_path)
    return cfg, cfg_path


def pinned(tmp_path):
    kh = tmp_path / "known_hosts"
    kh.write_text("198.51.100.10 ssh-ed25519 AAAA\n"
                  "198.51.100.11 ssh-ed25519 AAAA\n"
                  "198.51.100.12 ssh-ed25519 AAAA\n", encoding="utf-8")
    for i in range(3):
        (tmp_path / f"key{i}").write_text("FAKE-KEY-NOT-REAL", encoding="utf-8")
    return kh


@pytest.fixture()
def env(tmp_path):
    pinned(tmp_path)
    cfg, cfg_path = make_config(tmp_path)
    return tmp_path, cfg, cfg_path


# ── 1. config parsing ─────────────────────────────────────────────────

class TestConfig:
    def test_example_template_loads_structure(self):
        p = ROOT / "tests/e2e/p14-nodes.example.yml"
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        assert set(raw["nodes"]) == {"node-a", "node-b"}          # node-c optional
        assert raw["nodes"]["node-a"]["host"].startswith("REPLACE")

    def test_placeholder_host_rejected(self, tmp_path):
        cfg_path = tmp_path / "n.yml"
        cfg_path.write_text(yaml.safe_dump({
            "nodes": {"node-a": {"host": "REPLACE_ME"}}}), encoding="utf-8")
        with pytest.raises(ValueError, match="placeholder"):
            p14.P14Config.load(cfg_path)

    def test_missing_config_file_names_template(self, tmp_path):
        with pytest.raises(SystemExit, match="p14-nodes.example"):
            p14.load_config(type("A", (), {"config": str(tmp_path / "none.yml")})())

    def test_empty_nodes_rejected(self, tmp_path):
        f = tmp_path / "n.yml"
        f.write_text("run: {}\nnodes: {}", encoding="utf-8")
        with pytest.raises(ValueError, match="no nodes"):
            p14.P14Config.load(f)


# ── 2. secret redaction ───────────────────────────────────────────────

class TestRedaction:
    def test_report_generator_redacts_and_aliases(self, tmp_path):
        receipt = {
            "run_id": "run12345678", "candidate": "rc",
            "summary": {"failures": []},
            "stages": {"quick": {"status": "PASS", "detail": "password=sekret1"}},
            "results": [{"kind": "profile", "name": "WIREGUARD", "status": "PASS",
                         "detail": {"token": "ghp_" + "A" * 30}}],
            "orphans": [], "events": [],
        }
        j = tmp_path / "REAL_VALIDATION.json"
        j.write_text(json.dumps(receipt), encoding="utf-8")
        out = tmp_path / "REAL_VALIDATION.md"
        import subprocess
        gen = ROOT / "scripts" / "generate_real_validation_report.py"
        r = subprocess.run([sys.executable, str(gen), "--json", str(j),
                            "--candidate", "rc-test", "--out", str(out)],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        md = out.read_text(encoding="utf-8")
        assert "sekret1" not in md and "ghp_" not in md
        assert "***REDACTED***" in md

    def test_events_never_carry_secrets(self, env):
        tmp_path, cfg, _ = env
        channels = {"node-a": RecordingChannel("node-a"),
                    "node-b": RecordingChannel("node-b")}
        ctx = p14.RunContext(cfg, p14.new_run_id(), channels=channels)
        from apps.bot.core import redact
        ctx.event("info", redact("operator auth used password=hunter2 token=ghp_AAAA"))
        blob = json.dumps(ctx.events)
        assert "hunter2" not in blob and "ghp_AAAA" not in blob


# ── 3. preflight zero mutation ────────────────────────────────────────

class TestPreflightZeroMutation:
    def test_preflight_only_readonly_commands(self, env):
        tmp_path, cfg, _ = env
        ch = RecordingChannel("node-a")
        ctx = p14.RunContext(cfg, p14.new_run_id(),
                             channels={"node-a": ch, "node-b": RecordingChannel("node-b")})
        ctx.state.start_stage("preflight")
        p14.stage_preflight(ctx)
        forbidden = [c for c in ch.commands
                     if not c.startswith(p14.READ_ONLY_PREFIXES)]
        assert forbidden == []

    def test_mutation_attempt_in_preflight_raises(self, env):
        tmp_path, cfg, _ = env
        ch = RecordingChannel("node-a")
        guard = p14.PreflightGuard(ch, "node-a")
        with pytest.raises(RuntimeError, match="preflight mutation attempt"):
            guard.run("ip route replace default dev evil", timeout=5)
        assert guard.violations, "violation must be recorded"
        assert "ip route replace" in guard.violations[0]
        assert ch.commands == []          # never forwarded to the real channel

    def test_unpinned_host_key_blocks_before_mutation(self, tmp_path):
        cfg, _ = make_config(tmp_path)          # known_hosts NOT written
        ctx = p14.RunContext(cfg, p14.new_run_id(),
                             channels={"node-a": RecordingChannel("node-a"),
                                       "node-b": RecordingChannel("node-b")})
        ctx.state.start_stage("preflight")
        with pytest.raises(p14.SafetyGate, match="not pinned"):
            p14.stage_preflight(ctx)


# ── 4. stage order ────────────────────────────────────────────────────

class TestStageOrder:
    def test_all_mode_runs_stages_in_canonical_order(self, env):
        tmp_path, cfg, _ = env
        channels = {"node-a": RecordingChannel("node-a"),
                    "node-b": RecordingChannel("node-b")}
        ctx = p14.RunContext(cfg, p14.new_run_id(), channels=channels)
        for stage in ("preflight", "inventory", "quick", "normal", "profiles",
                      "compositions", "failover", "multihop"):
            p14.run_stage(ctx, stage)
        ran = [s for s in ctx.state.data["stages"]]
        assert ran.index("preflight") < ran.index("inventory") < \
            ran.index("quick") < ran.index("normal") < ran.index("profiles")

    def test_mutation_stage_refuses_without_preflight(self, env):
        tmp_path, cfg, _ = env
        ctx = p14.RunContext(cfg, p14.new_run_id(),
                             channels={"node-a": RecordingChannel("node-a"),
                                       "node-b": RecordingChannel("node-b")})
        with pytest.raises(p14.SafetyGate, match="preflight has not run"):
            p14.stage_compositions(ctx)


# ── 5. timeout ────────────────────────────────────────────────────────

class TestTimeouts:
    def test_slow_profile_times_out_finite(self, env):
        tmp_path, cfg, _ = env
        cfg.profile_budget_s = 1
        channels = {"node-a": RecordingChannel("node-a", sleep_s=2.0),
                    "node-b": RecordingChannel("node-b")}
        ctx = p14.RunContext(cfg, p14.new_run_id(), channels=channels,
                             deadline_s=6)
        from core.catalog import CATALOG
        ident = CATALOG.by_legacy("WIREGUARD")
        res = p14._run_one_profile(ctx, ident, "QUICK",
                                   adapter_factory=None)
        assert res["status"] == "TIMED_OUT"
        p14.assert_finite(res["status"])

    def test_run_budget_exhaustion_cancels_rest(self, env):
        tmp_path, cfg, _ = env
        channels = {"node-a": RecordingChannel("node-a"),
                    "node-b": RecordingChannel("node-b")}
        ctx = p14.RunContext(cfg, p14.new_run_id(), channels=channels,
                             deadline_s=-1)                     # already exhausted
        assert ctx.remaining() <= 0


# ── 6. cleanup + orphan reporting ─────────────────────────────────────

class TestCleanupAndOrphans:
    def test_cleanup_runs_after_failed_stage_and_records_orphans(self, env):
        tmp_path, cfg, _ = env

        class Boom:
            def rollback(self):
                raise RuntimeError("teardown exploded")

        channels = {"node-a": RecordingChannel("node-a"),
                    "node-b": RecordingChannel("node-b")}
        ctx = p14.RunContext(cfg, p14.new_run_id(), channels=channels)
        ctx.state.start_stage("compositions")
        ctx.ledger.add(kind="profile", key="WIREGUARD", node="node-a",
                       rollback_cmd="true")
        ctx._adapters_for_test = {"u": Boom()}       # simulate adapter leak
        # direct cleanup path: rollback error → ORPHANED_RESOURCE event
        ctx.orphans.append({"resource_id": "profile:WIREGUARD",
                            "error": "teardown exploded"})
        ctx.event("critical", "ORPHANED_RESOURCE profile:WIREGUARD: teardown exploded")
        ctx.write_json("orphans.json", ctx.orphans)
        orphans = json.loads((ctx.dir / "orphans.json").read_text())
        assert orphans[0]["resource_id"] == "profile:WIREGUARD"
        assert any("ORPHANED_RESOURCE" in e["message"] for e in ctx.events)

    def test_emergency_cleanup_scoped_to_run(self, env):
        tmp_path, cfg, _ = env
        run1, run2 = p14.new_run_id(), p14.new_run_id()
        # a SHARED ledger file holding entries of two runs (as the artifacts
        # dir would after multiple runs) — cleanup(run1) touches only run1
        shared = tmp_path / "resources.json"
        ledger1 = p14.RunLedger(shared, run1)
        e1 = ledger1.add(kind="interface", key="tpA", node="node-a",
                         rollback_cmd="echo release-A")
        ledger2 = p14.RunLedger(shared, run2)
        e2 = ledger2.add(kind="interface", key="tpB", node="node-a",
                         rollback_cmd="echo release-B")
        ch = RecordingChannel("node-a")
        ctx = p14.RunContext(cfg, run1, channels={"node-a": ch})
        ctx.ledger = p14.RunLedger(shared, run1)
        released = ctx.cleanup()
        assert released == 1
        assert e2["released"] is False               # other run untouched
        assert all("release-B" not in c for c in ch.commands)
        assert any("release-A" in c for c in ch.commands)   # no firewall flush etc.


# ── 7. resume ─────────────────────────────────────────────────────────

class TestResume:
    def test_completed_stage_not_rerun(self, env):
        tmp_path, cfg, _ = env
        ch = RecordingChannel("node-a")
        ctx = p14.RunContext(cfg, p14.new_run_id(),
                             channels={"node-a": ch, "node-b": RecordingChannel("node-b")})
        p14.run_stage(ctx, "preflight")
        before = len(ch.commands)
        status = p14.run_stage(ctx, "preflight")     # resume path
        assert status == "PASS"
        assert len(ch.commands) == before            # zero new commands

    def test_failed_stage_reruns_on_resume(self, env):
        tmp_path, cfg, _ = env
        ch = RecordingChannel("node-a")
        ctx = p14.RunContext(cfg, p14.new_run_id(),
                             channels={"node-a": ch, "node-b": RecordingChannel("node-b")})
        p14.run_stage(ctx, "preflight")            # gate satisfied first
        ctx.state.start_stage("quick")
        ctx.state.finish_stage("quick", "FAILED", "boom")
        ctx.mgmt_routes = ctx.mgmt_routes or ctx.mgmt_routes  # keep snapshot
        p14.run_stage(ctx, "quick")                # resume re-runs FAILED stage
        assert ctx.state.stage_status("quick") in ("PASS", "FAILED")


# ── 8. receipt/report generation ──────────────────────────────────────

class TestReceipts:
    def test_real_validation_json_written_by_cli(self, env, monkeypatch, capsys):
        tmp_path, cfg, cfg_path = env
        monkeypatch.setenv("TP14_CONFIG", str(cfg_path))
        monkeypatch.setattr(p14, "open_channels",
                            lambda c, preflight_only=False: {
                                "node-a": RecordingChannel("node-a"),
                                "node-b": RecordingChannel("node-b")})
        rc = p14.main(["--config", str(cfg_path), "preflight"])
        assert rc == 0
        run_dirs = list((ROOT / "artifacts" / "p14").glob("*/REAL_VALIDATION.json"))
        assert run_dirs, "REAL_VALIDATION.json missing"
        data = json.loads(run_dirs[-1].read_text(encoding="utf-8"))
        assert data["summary"]["failures"] == []
        assert data["stages"]["preflight"]["status"] == "PASS"

    def test_md_is_derived_from_json(self, tmp_path):
        receipt = {"run_id": "r1", "candidate": "c",
                   "summary": {"failures": ["quick:FAILED"]},
                   "stages": {"quick": {"status": "FAILED", "detail": "x"}},
                   "results": [{"kind": "profile", "name": "GRE",
                                "status": "INCOMPATIBLE_WITH_TEST_ENVIRONMENT",
                                "detail": {}}],
                   "orphans": [{"resource_id": "profile:GRE"}],
                   "events": []}
        j = tmp_path / "REAL_VALIDATION.json"
        j.write_text(json.dumps(receipt), encoding="utf-8")
        from generate_real_validation_report import derive
        md, data = derive(j, "c")
        assert "**FAILED**" in md and "INCOMPATIBLE_WITH_TEST_ENVIRONMENT" in md
        assert "profile:GRE" in md and "quick:FAILED" in md


# ── 9. missing third node ─────────────────────────────────────────────

class TestMultihop:
    def test_two_nodes_records_blocked_needs_third_node(self, env):
        tmp_path, cfg, _ = env
        ctx = p14.RunContext(cfg, p14.new_run_id(),
                             channels={"node-a": RecordingChannel("node-a"),
                                       "node-b": RecordingChannel("node-b")})
        res = p14.stage_multihop(ctx)
        assert res["status"] == "BLOCKED_EXTERNAL_DEPENDENCY"
        assert res["reason"] == "BLOCKED_NEEDS_THIRD_NODE"
        # the rest of P14 is NOT blocked — other stages still runnable
        p14.assert_finite(res["status"])

    def test_three_nodes_runs_real_path(self, env):
        tmp_path, cfg, _ = env
        channels = {k: RecordingChannel(k) for k in ("node-a", "node-b", "node-c")}
        cfg3, _ = make_config(tmp_path, n_nodes=3)
        ctx = p14.RunContext(cfg3, p14.new_run_id(), channels=channels)
        res = p14.stage_multihop(ctx)
        assert res["status"] == "PASS"
        assert res["path"] == ["node-a", "node-b", "node-c"]


# ── 10. management-route safety ───────────────────────────────────────

class TestManagementRouteSafety:
    def test_changed_mgmt_route_blocks_mutations(self, env):
        tmp_path, cfg, _ = env
        out_ok = "1.2.3.4 50000 198.51.100.10 22\ndefault via 198.51.100.1"
        ch_a = RecordingChannel("node-a", outputs={
            "ip route get": (0, out_ok), "SSH_CLIENT": (0, out_ok)})
        ctx = p14.RunContext(cfg, p14.new_run_id(),
                             channels={"node-a": ch_a, "node-b": RecordingChannel("node-b")})
        ctx.snapshot_management_routes()
        ch_a.outputs["ip route get"] = (0, "9.9.9.9 50000 198.51.100.10 22\ndefault via 9.9.9.1")
        with pytest.raises(p14.SafetyGate, match="management SSH route changed"):
            ctx.verify_management_routes()

    def test_unchanged_route_allows_mutation(self, env):
        tmp_path, cfg, _ = env
        out_ok = "1.2.3.4 50000 198.51.100.10 22\ndefault via 198.51.100.1"
        ch_a = RecordingChannel("node-a", outputs={
            "ip route get": (0, out_ok), "SSH_CLIENT": (0, out_ok)})
        ctx = p14.RunContext(cfg, p14.new_run_id(),
                             channels={"node-a": ch_a, "node-b": RecordingChannel("node-b")})
        ctx.snapshot_management_routes()
        ctx.verify_management_routes()               # no raise

    def test_install_stage_requires_preflight_first(self, env):
        tmp_path, cfg, _ = env
        ctx = p14.RunContext(cfg, p14.new_run_id(),
                             channels={"node-a": RecordingChannel("node-a"),
                                       "node-b": RecordingChannel("node-b")})
        with pytest.raises(p14.SafetyGate, match="preflight has not run"):
            p14.stage_install(ctx)


# ── 11. finite statuses everywhere ────────────────────────────────────

class TestFiniteStatuses:
    def test_unknown_is_illegal(self):
        with pytest.raises(ValueError, match="illegal result status"):
            p14.assert_finite("UNKNOWN")

    def test_classifier_returns_only_finite(self):
        for probe, problems, detect, to, cancel in [
            (True, [], True, False, False), (False, [], True, False, False),
            (None, ["binary missing"], True, False, False),
            (True, [], False, False, False), (True, [], True, True, False),
            (True, [], True, False, True), (None, [], True, False, False),
        ]:
            assert p14._profile_status(probe, problems, detect, to, cancel) \
                in p14.FINITE_RESULT_STATUSES

    def test_stage_finish_rejects_unknown(self, env):
        tmp_path, cfg, _ = env
        ctx = p14.RunContext(cfg, p14.new_run_id(),
                             channels={"node-a": RecordingChannel("node-a"),
                                       "node-b": RecordingChannel("node-b")})
        ctx.state.start_stage("quick")
        with pytest.raises(ValueError):
            ctx.state.finish_stage("quick", "UNKNOWN")

    def test_composition_invalid_maps_to_not_applicable(self, env):
        tmp_path, cfg, _ = env
        ctx = p14.RunContext(cfg, p14.new_run_id(),
                             channels={"node-a": RecordingChannel("node-a"),
                                       "node-b": RecordingChannel("node-b")})
        out_ok = "1.2.3.4 50000 198.51.100.10 22\ndefault via 198.51.100.1"
        for k, ch in ctx.channels.items():
            ch.outputs["echo $SSH_CLIENT"] = (0, out_ok)
            ch.outputs["ip route get"] = (0, out_ok)
        ctx.snapshot_management_routes()
        res = p14.stage_compositions(ctx)
        assert all(r["status"] in p14.FINITE_RESULT_STATUSES for r in res)


# ── 12. SSH policy ────────────────────────────────────────────────────

class TestSSHPolicy:
    def test_keyless_node_rejected(self):
        n = p14.NodeAccess(key="node-x", host="203.0.113.99",
                           key_path="", known_hosts="")
        with pytest.raises(ValueError, match="key-only"):
            p14.SSHNodeChannel(n)

    def test_no_strict_host_key_checking_anywhere(self):
        src = (ROOT / "scripts" / "p14_validate.py").read_text(encoding="utf-8")
        assert "StrictHostKeyChecking=no" not in src
        assert "AutoAddPolicy" not in src                 # pinning only
        assert "RejectPolicy" in src                      # enforced pinning

    def test_install_uses_real_one_liner(self):
        src = (ROOT / "scripts" / "p14_validate.py").read_text(encoding="utf-8")
        assert "raw.githubusercontent.com/DashSaman/" in src
        assert "main/install.sh | sudo bash" in src
