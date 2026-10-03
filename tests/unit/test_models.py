"""Canonical model + migration tests (P2) — unit_portable tier.

Uses a throwaway SQLite file (create_all is fine for tests; production uses
Alembic). Also verifies the committed Alembic revision upgrades a fresh DB
to head and matches the model metadata.
"""
import pathlib
import subprocess
import sys

import pytest
from sqlalchemy import create_engine, inspect, text

from core.models import Base

pytestmark = pytest.mark.unit_portable

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXPECTED_TABLES = {
    "nodes", "node_inventories", "engines", "engine_profiles", "engine_manifests",
    "method_verifications", "chains", "chain_components", "deployments",
    "deployment_revisions", "resource_allocations", "benchmark_runs",
    "benchmark_samples", "benchmark_receipts", "scores", "failover_groups",
    "failover_members", "health_samples", "events", "alerts", "audit_logs",
    "jobs", "secret_references",
}


class TestModels:
    def test_table_set_complete(self):
        assert set(Base.metadata.tables) == EXPECTED_TABLES

    def test_create_and_roundtrip_core_objects(self, tmp_path):
        eng = create_engine(f"sqlite:///{tmp_path/'m.db'}")
        Base.metadata.create_all(eng)
        from core.models import (BenchmarkRun, Chain, ChainComponent, Deployment,
                                 Engine, EngineProfile, FailoverGroup,
                                 FailoverMember, Node, ResourceAllocation)
        from sqlalchemy.orm import Session
        with Session(eng) as s:
            node = Node(name="gw1", host="203.0.113.10")
            s.add(node)
            e = Engine(id="gost", display_name="GOST", family="proxy", implementation_status="IMPLEMENTED")
            s.add(e)
            p = EngineProfile(engine_id="gost", profile_id="grpc", legacy_method_id="GOST_GRPC",
                              display_name="GOST gRPC")
            s.add(p)
            s.flush()
            chain = Chain(name="gre over wg")
            chain.components = [
                ChainComponent(component_id="c-gre", parent_id="c-wg", engine_id="gre"),
                ChainComponent(component_id="c-wg", parent_id=None, engine_id="wireguard"),
            ]
            s.add(chain)
            s.flush()
            dep = Deployment(node_a=node.id, chain_id=chain.id)
            dep.resources = [ResourceAllocation(kind="udp_port", key="51820", node_id=node.id,
                                                component_id="c-wg", chain_id=chain.id)]
            s.add(dep)
            fg = FailoverGroup(name="edge")
            fg.members = [FailoverMember(priority=1, candidate="gost/grpc"),
                          FailoverMember(priority=2, candidate="chain:gre-over-wg", candidate_kind="chain")]
            s.add(fg)
            s.add(BenchmarkRun(node_a=node.id, node_b=node.id))
            s.commit()
            with Session(eng) as q:
                group = q.query(FailoverGroup).one()
                assert [m.priority for m in group.members] == [1, 2]
                alloc = q.query(ResourceAllocation).one()
                assert alloc.owner == "TunnelPannel" and alloc.key == "51820"
                comp = q.query(ChainComponent).filter_by(component_id="c-gre").one()
                assert comp.parent_id == "c-wg"  # DAG edge: gre rides wg


class TestAlembic:
    def test_upgrade_head_matches_models(self, tmp_path):
        db = tmp_path / "mig.db"
        env = {**__import__("os").environ,
               "DATABASE_URL": f"sqlite:///{db.as_posix()}",
               "PATH": __import__("os").environ["PATH"]}
        r = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"],
                           cwd=ROOT, env=env, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr[-2000:]
        eng = create_engine(f"sqlite:///{db}")
        insp = inspect(eng)
        migrated = set(insp.get_table_names()) - {"alembic_version"}
        assert migrated == EXPECTED_TABLES
        with eng.connect() as c:
            assert c.execute(text("select version_num from alembic_version")).fetchone() is not None
