"""Transactional deployment tests (P4b) — unit_portable tier.

Mandatory matrix: dry-run makes zero mutations · reverse rollback order ·
partial apply failure · verification failure · resource release on failure ·
idempotent re-run of the same desired deployment.
"""
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from core.models import Base, Deployment, Event, Node, ResourceAllocation
from orchestrator.deployment import DeploymentError, Step, Transaction
from orchestrator.resources import ResourceManager

pytestmark = pytest.mark.unit_portable


@pytest.fixture()
def env():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    with Session(eng) as s:
        node = Node(name="n1", host="203.0.113.1")
        s.add(node)
        s.flush()
        dep = Deployment(node_a=node.id)
        s.add(dep)
        s.flush()
        yield s, node, dep
        s.rollback()


class Recorder:
    """Fake step behavior: logs calls; can fail apply/verify on demand."""

    def __init__(self, name, fail_apply=False, fail_verify=False, reserves=None):
        self.calls: list[str] = []
        self.name = name
        self._fail_apply = fail_apply
        self._fail_verify = fail_verify
        self._reserves = reserves or []

    def step(self) -> Step:
        return Step(
            name=self.name,
            apply=self._apply,
            verify=self._verify,
            rollback=self._rollback,
            reserves=self._reserves,
        )

    def _apply(self, tx):
        if self._fail_apply:
            self.calls.append("apply-fail")
            raise RuntimeError(f"{self.name}: apply blew up")
        self.calls.append("apply")

    def _verify(self, tx):
        self.calls.append("verify")
        return not self._fail_verify

    def _rollback(self, tx):
        self.calls.append("rollback")


class TestHappyPath:
    def test_full_lifecycle_commits(self, env):
        s, node, dep = env
        r1, r2 = Recorder("underlay"), Recorder("overlay")
        steps = [r1.step(), r2.step()]
        tx = Transaction(s, dep, steps)
        tx.plan(); tx.validate(); tx.dry_run(); tx.reserve(); tx.apply()
        assert dep.state == "COMMITTED"
        assert dep.committed_at is not None
        # both steps applied then both verified, in order
        assert r1.calls == ["apply", "verify"]
        assert r2.calls == ["apply", "verify"]

    def test_run_executes_canonical_order(self, env):
        s, node, dep = env
        rec = Recorder("only")
        Transaction(s, dep, [rec.step()]).run()
        states = [e.message.split("] ", 1)[1].split(":", 1)[0]
                  for e in s.scalars(select(Event)).all()]
        assert states == ["PLANNED", "VALIDATED", "DRY_RUN", "RESERVED",
                          "APPLYING", "VERIFYING", "COMMITTED"]


class TestDryRun:
    def test_dry_run_makes_zero_mutations(self, env):
        s, node, dep = env
        r1 = Recorder("a", reserves=[{"kind": "udp_port", "node_id": node.id}])
        r2 = Recorder("b")
        steps = [r1.step(), r2.step()]
        tx = Transaction(s, dep, steps)
        actions = tx.plan(); tx.validate(); preview = tx.dry_run()
        assert dep.state == "DRY_RUN"
        assert preview == actions and "RESERVE udp_port auto(udp_port)" in preview
        assert r1.calls == [] and r2.calls == []             # zero step calls
        assert s.query(ResourceAllocation).count() == 0      # zero reservations
        assert dep.plan_preview                             # preview persisted


class TestRollback:
    def test_partial_apply_failure_rolls_back_in_reverse(self, env):
        s, node, dep = env
        ok1 = Recorder("underlay", reserves=[{"kind": "udp_port", "node_id": node.id}])
        ok2 = Recorder("middle")
        boom = Recorder("overlay", fail_apply=True)
        recs = [ok1.step(), ok2.step(), boom.step()]
        tx = Transaction(s, dep, recs)
        tx.plan(); tx.validate(); tx.reserve()
        with pytest.raises(RuntimeError, match="apply blew up"):
            tx.apply()
        assert dep.state == "ROLLED_BACK"
        # reverse order: middle rolled back before underlay; failed step never completed apply
        assert boom.calls == ["apply-fail"]
        assert ok2.calls == ["apply", "rollback"]
        assert ok1.calls == ["apply", "rollback"]
        # reserved resources were released on failure
        assert ResourceManager(s).owned_keys("udp_port", node.id) == set()

    def test_verification_failure_triggers_rollback(self, env):
        s, node, dep = env
        ok = Recorder("underlay")
        liar = Recorder("overlay", fail_verify=True)   # applies fine, lies about data-plane
        tx = Transaction(s, dep, [ok.step(), liar.step()])
        tx.plan(); tx.validate(); tx.reserve()
        with pytest.raises(DeploymentError, match="verification failed"):
            tx.apply()
        assert dep.state == "ROLLED_BACK"
        assert liar.calls == ["apply", "verify", "rollback"]
        assert ok.calls == ["apply", "verify", "rollback"]

    def test_first_step_failure_never_applied(self, env):
        s, node, dep = env
        boom = Recorder("first", fail_apply=True)
        tx = Transaction(s, dep, [boom.step()])
        tx.reserve()
        with pytest.raises(RuntimeError):
            tx.apply()
        assert dep.state == "FAILED"                    # nothing completed apply
        assert boom.calls == ["apply-fail"]

    def test_rollback_error_still_unwinds_rest(self, env):
        s, node, dep = env
        rec: list[str] = []

        def bad_rollback(tx):
            raise RuntimeError("rollback exploded")

        s2 = Step("s2", apply=lambda tx: rec.append("s2-apply"), verify=lambda tx: True,
                  rollback=bad_rollback)
        s1 = Step("s1", apply=lambda tx: rec.append("s1-apply"), verify=lambda tx: False,
                  rollback=lambda tx: rec.append("s1-rb"))
        tx = Transaction(s, dep, [s2, s1])              # s2 applied first, s1 fails verify
        tx.reserve()
        with pytest.raises(DeploymentError):
            tx.apply()
        # s2's rollback raised, but the unwind continued and the state is final
        assert dep.state == "ROLLED_BACK"
        assert "s1-rb" in rec
        sev = [e.severity for e in s.scalars(select(Event)).all()]
        assert "critical" in sev                          # rollback error surfaced


class TestReserveAndIdempotency:
    def test_reserve_creates_ledger_rows_with_provenance(self, env):
        s, node, dep = env
        step = Recorder("wg", reserves=[
            {"kind": "udp_port", "key": "24000", "node_id": node.id, "component_id": "c-wg"},
            {"kind": "interface", "node_id": node.id},
        ]).step()
        tx = Transaction(s, dep, [step])
        tx.plan(); tx.validate(); tx.reserve()
        keys = ResourceManager(s).owned_keys("udp_port", node.id)
        assert keys == {"24000"}
        row = s.scalars(select(ResourceAllocation)).all()[0]
        assert row.component_id == "c-wg" and row.owner == "TunnelPannel"

    def test_rerunning_same_deployment_creates_no_duplicates(self, env):
        s, node, dep = env
        reserves = [{"kind": "udp_port", "key": "24000", "node_id": node.id}]
        tx1 = Transaction(s, dep, [Recorder("wg", reserves=reserves).step()])
        tx1.plan(); tx1.validate(); tx1.reserve()
        tx2 = Transaction(s, dep, [Recorder("wg", reserves=reserves).step()])
        tx2.reserve()                                   # idempotent re-reserve
        assert s.query(ResourceAllocation).count() == 1

    def test_validate_rejects_bad_reserve(self, env):
        s, node, dep = env
        bad = Step("x", apply=lambda tx: None, verify=lambda tx: True,
                   rollback=lambda tx: None,
                   reserves=[{"node_id": node.id}])     # missing kind
        tx = Transaction(s, dep, [bad])
        tx.plan()
        with pytest.raises(DeploymentError, match="without kind"):
            tx.validate()

    def test_empty_transaction_rejected(self, env):
        s, node, dep = env
        with pytest.raises(DeploymentError, match="at least one step"):
            Transaction(s, dep, [])
