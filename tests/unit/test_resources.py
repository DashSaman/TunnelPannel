"""ResourceManager tests (P4a) — unit_portable tier.

Covers the mandatory P4 matrix: port/interface/subnet/table/fwmark
collisions, release, idempotent reservation, ownership enforcement.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from core.models import Base, Deployment, Node, ResourceAllocation
from orchestrator.resources import NEVER_PORTS, ResourceManager, ResourceConflict

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


class FakeInUse:
    def __init__(self, mapping):
        self.mapping = mapping  # {(node_id, kind): {keys}}

    def in_use(self, node_id, kind):
        return self.mapping.get((node_id, kind), set())


class TestPortAllocation:
    def test_scan_allocates_sequential_free_ports(self, env):
        s, node, dep = env
        rm = ResourceManager(s)
        a = rm.allocate_port(kind="tcp_port", deployment_id=dep.id, node_id=node.id)
        b = rm.allocate_port(kind="tcp_port", deployment_id=dep.id, node_id=node.id)
        assert (int(a.key), int(b.key)) == (21000, 21001)
        assert a.owner == "TunnelPannel"

    def test_port_collision_across_deployments(self, env):
        s, node, dep = env
        rm = ResourceManager(s)
        rm.allocate_port(kind="tcp_port", deployment_id=dep.id, node_id=node.id)
        dep2 = Deployment(node_a=node.id)
        s.add(dep2)
        s.flush()
        with pytest.raises(ResourceConflict, match="already allocated"):
            rm.reserve(kind="tcp_port", key="21000", deployment_id=dep2.id, node_id=node.id)

    def test_external_in_use_is_respected(self, env):
        s, node, dep = env
        rm = ResourceManager(s, FakeInUse({(node.id, "tcp_port"): {"21000"}}))
        a = rm.allocate_port(kind="tcp_port", deployment_id=dep.id, node_id=node.id)
        assert a.key == "21001"

    def test_never_ports_are_skipped(self, env):
        s, node, dep = env
        rm = ResourceManager(s)
        with pytest.raises(ResourceConflict, match="NEVER"):
            rm.allocate_port(kind="udp_port", deployment_id=dep.id, node_id=node.id,
                             preferred=51820)  # WireGuard default — system-adjacent
        # 53 (dns) skipped in scan
        rm2 = ResourceManager(s, FakeInUse({(node.id, "udp_port"): {"26000"}}))
        b = rm2.allocate_port(kind="udp_port", deployment_id=dep.id, node_id=node.id)
        assert b.key == "26001"

    def test_preferred_out_of_range_rejected(self, env):
        s, node, dep = env
        with pytest.raises(ResourceConflict, match="outside"):
            ResourceManager(s).allocate_port(kind="tcp_port", deployment_id=dep.id,
                                             node_id=node.id, preferred=27015)


class TestIdempotencyAndRelease:
    def test_reserve_is_idempotent_same_deployment(self, env):
        s, node, dep = env
        rm = ResourceManager(s)
        first = rm.reserve(kind="udp_port", key="26000", deployment_id=dep.id, node_id=node.id)
        second = rm.reserve(kind="udp_port", key="26000", deployment_id=dep.id, node_id=node.id)
        assert first.id == second.id
        assert s.query(ResourceAllocation).count() == 1

    def test_release_makes_key_free_again(self, env):
        s, node, dep = env
        rm = ResourceManager(s)
        a = rm.reserve(kind="udp_port", key="26000", deployment_id=dep.id, node_id=node.id)
        rm.release(a.id)
        assert "26000" not in rm.owned_keys("udp_port", node.id)
        b = rm.reserve(kind="udp_port", key="26000", deployment_id=dep.id, node_id=node.id)
        assert b.id != a.id

    def test_release_deployment_releases_only_that_deployment(self, env):
        s, node, dep = env
        dep2 = Deployment(node_a=node.id)
        s.add(dep2)
        s.flush()
        rm = ResourceManager(s)
        rm.reserve(kind="udp_port", key="26000", deployment_id=dep.id, node_id=node.id)
        rm.reserve(kind="interface", key="tp9", deployment_id=dep.id, node_id=node.id)
        rm.reserve(kind="udp_port", key="26001", deployment_id=dep2.id, node_id=node.id)
        assert rm.release_deployment(dep.id) == 2
        assert rm.owned_keys("udp_port", node.id) == {"26001"}

    def test_foreign_owner_never_released(self, env):
        s, node, dep = env
        rm = ResourceManager(s)
        a = rm.reserve(kind="interface", key="wg0", deployment_id=dep.id, node_id=node.id)
        a.owner = "someone-else"                       # simulate an unowned resource
        s.flush()
        with pytest.raises(ResourceConflict, match="not TunnelPannel"):
            rm.release(a.id)


class TestOtherKinds:
    def test_interface_collision_and_scan(self, env):
        s, node, dep = env
        rm = ResourceManager(s)
        i0 = rm.allocate_interface(deployment_id=dep.id, node_id=node.id)
        i1 = rm.allocate_interface(deployment_id=dep.id, node_id=node.id)
        assert (i0.key, i1.key) == ("tp0", "tp1")
        dep2 = Deployment(node_a=node.id)
        s.add(dep2)
        s.flush()
        with pytest.raises(ResourceConflict):
            rm.reserve(kind="interface", key="tp0", deployment_id=dep2.id, node_id=node.id)

    def test_subnet_pool_steps_and_collides(self, env):
        s, node, dep = env
        rm = ResourceManager(s)
        a = rm.allocate_subnet(version=4, deployment_id=dep.id)
        b = rm.allocate_subnet(version=4, deployment_id=dep.id)
        assert (a.key, b.key) == ("10.174.0.0/24", "10.174.1.0/24")
        with pytest.raises(ResourceConflict):
            rm.reserve(kind="subnet_v4", key=a.key, deployment_id="other", node_id=None)
        v6 = rm.allocate_subnet(version=6, deployment_id=dep.id)
        assert v6.key.startswith("fd00:174:")

    def test_routing_table_and_fwmark_ranges(self, env):
        s, node, dep = env
        rm = ResourceManager(s)
        t = rm.allocate_table(deployment_id=dep.id, node_id=node.id)
        f = rm.allocate_fwmark(deployment_id=dep.id, node_id=node.id)
        assert (t.key, f.key) == ("51000", "5100")
        # same node re-allocation collides, other node does not (node-scoped kinds)
        with pytest.raises(ResourceConflict):
            rm.reserve(kind="route_table", key="51000", deployment_id="d2", node_id=node.id)

    def test_systemd_unit_nft_chain_namespace_temp(self, env):
        s, node, dep = env
        rm = ResourceManager(s)
        assert rm.allocate_systemd_unit(name="tp-wg0", deployment_id=dep.id).key == "tp-wg0.service"
        assert rm.allocate_nft_chain(name="mtf-clamp", deployment_id=dep.id).key == "mtf-clamp"
        assert rm.allocate_namespace(deployment_id=dep.id, node_id=node.id).key == "tpns0"
        assert rm.allocate_temp(key="bench-42", deployment_id=dep.id).kind == "temp"


class TestLedgerIntegrity:
    def test_every_allocation_carries_provenance(self, env):
        s, node, dep = env
        rm = ResourceManager(s)
        a = rm.allocate_port(kind="tcp_port", deployment_id=dep.id, node_id=node.id,
                             chain_id="ch1", component_id="c-wg")
        assert (a.deployment_id, a.chain_id, a.component_id, a.owner) == \
               (dep.id, "ch1", "c-wg", "TunnelPannel")
        assert a.created_at is not None and a.released_at is None

    def test_never_ports_list_is_sane(self):
        assert {22, 53, 443, 51820} <= NEVER_PORTS
