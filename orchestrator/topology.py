"""Topology + true multi-hop (P11).

Nodes reference real registered servers; edges reference deployable routes
(standalone tunnel or composed chain) — tunnel definitions are NEVER
duplicated inside topology objects. A traffic path is a loop-free edge
sequence with per-hop state, an end-to-end truth gate, correct aggregate
metrics (no naive averaging) and bounded search.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from orchestrator.composition import (ChainSpec, build_plan, validate_chain)


# ── model ──────────────────────────────────────────────────────────────

@dataclass
class TopologyEdge:
    edge_id: str
    from_node: str                        # real node id
    to_node: str
    route: str                            # legacy method id or "chain:<name>"
    route_kind: str = "single"            # single | chain
    chain_spec: ChainSpec | None = None   # resolved chain (chain routes only)
    rtt_ms: float | None = None           # hop measurements (latest)
    loss_pct: float | None = None
    throughput_mbps: float | None = None
    availability: float | None = None     # 0..1
    effective_mtu: int | None = None
    verification: str = "UNTESTED"


@dataclass
class Topology:
    name: str
    edges: list[TopologyEdge] = field(default_factory=list)

    def by_id(self) -> dict[str, TopologyEdge]:
        return {e.edge_id: e for e in self.edges}


@dataclass
class TopologyPath:
    path_id: str
    edge_ids: list[str]                   # ordered, loop-free
    state: str = "PLANNED"                # PLANNED|VERIFIED|HOP_FAILED|PATH_FAILED

    def nodes(self, topo: Topology) -> list[str]:
        edges = topo.by_id()
        out = [edges[self.edge_ids[0]].from_node]
        for eid in self.edge_ids:
            out.append(edges[eid].to_node)
        return out


# ── graph rules (§2): loop prevention ─────────────────────────────────

def path_loops(topo: Topology, edge_ids: list[str]) -> str | None:
    """Return the repeated node if the path revisits any node
    (covers A→B→C→A and return-to-source)."""
    edges = topo.by_id()
    seen: set[str] = set()
    nodes = [edges[edge_ids[0]].from_node] + [edges[e].to_node for e in edge_ids]
    for n in nodes:
        if n in seen:
            return n
        seen.add(n)
    return None


def route_reused(edge_ids: list[str]) -> bool:
    return len(set(edge_ids)) != len(edge_ids)


def route_dependency_cycle(topo: Topology, edge_ids: list[str]) -> bool:
    """A chain route whose composition graph itself cycles — delegated to
    the P8 validator; here we check the path does not feed a route back
    into itself (same route object appearing twice in one path)."""
    edges = topo.by_id()
    routes = [edges[e].route for e in edge_ids]
    return len(set(routes)) != len(routes)


# ── hop + path validation (§3, §4) ─────────────────────────────────────

def validate_hop(edge: TopologyEdge, manifests: dict | None = None) -> list[str]:
    problems: list[str] = []
    if edge.route_kind == "chain":
        if edge.chain_spec is None:
            problems.append(f"{edge.edge_id}: chain route without a spec")
        else:
            v = validate_chain(edge.chain_spec, manifests)
            problems.extend(f"{edge.edge_id}: {r}" for r in v.reasons)
    else:
        from core.catalog import CATALOG
        try:
            CATALOG.by_legacy(edge.route)
        except KeyError:
            problems.append(f"{edge.edge_id}: unknown route {edge.route}")
    if edge.from_node == edge.to_node:
        problems.append(f"{edge.edge_id}: self-loop edge")
    return problems


def validate_path(topo: Topology, edge_ids: list[str],
                  manifests: dict | None = None) -> tuple[bool, list[str]]:
    problems: list[str] = []
    edges = topo.by_id()
    if not edge_ids:
        return False, ["EMPTY_PATH"]
    for eid in edge_ids:
        if eid not in edges:
            return False, [f"UNKNOWN_EDGE: {eid}"]
    # continuity: hop N's to_node must be hop N+1's from_node
    for a, b in zip(edge_ids, edge_ids[1:]):
        if edges[a].to_node != edges[b].from_node:
            problems.append(f"DISCONTINUOUS: {a}({edges[a].to_node}) -> {b}({edges[b].from_node})")
    loop = path_loops(topo, edge_ids)
    if loop:
        problems.append(f"NODE_CYCLE: path revisits {loop}")
    if route_dependency_cycle(topo, edge_ids):
        problems.append("ROUTE_CYCLE: same route reused inside one path")
    for eid in edge_ids:
        problems.extend(validate_hop(edges[eid], manifests))
    return (not problems), problems


# ── path metrics (§5, §6) ──────────────────────────────────────────────

@dataclass
class PathMetrics:
    latency_ms: float | None = None       # sum of hops (derived)
    loss_pct: float | None = None         # 1 - Π(1-loss) (derived)
    throughput_mbps: float | None = None  # bottleneck hop
    availability: float | None = None     # weakest mandatory hop
    effective_mtu: int | None = None      # minimum along path
    e2e_latency_ms: float | None = None   # MEASURED end-to-end (priority)
    e2e_loss_pct: float | None = None
    source: str = "derived"               # derived | measured

    def summary(self) -> dict:
        return {
            "latency_ms": self.e2e_latency_ms if self.e2e_latency_ms is not None else self.latency_ms,
            "loss_pct": self.e2e_loss_pct if self.e2e_loss_pct is not None else self.loss_pct,
            "throughput_mbps": self.throughput_mbps,
            "availability": self.availability,
            "effective_mtu": self.effective_mtu,
            "source": "measured" if self.e2e_latency_ms is not None else "derived",
        }


def derive_path_metrics(topo: Topology, edge_ids: list[str]) -> PathMetrics:
    edges = topo.by_id()
    hops = [edges[e] for e in edge_ids]
    lat = [h.rtt_ms for h in hops if h.rtt_ms is not None]
    losses = [h.loss_pct for h in hops if h.loss_pct is not None]
    tput = [h.throughput_mbps for h in hops if h.throughput_mbps is not None]
    avail = [h.availability for h in hops if h.availability is not None]
    mtus = [h.effective_mtu for h in hops if h.effective_mtu is not None]
    return PathMetrics(
        latency_ms=sum(lat) if lat else None,
        loss_pct=(100.0 * (1.0 - _prod(1.0 - l / 100.0 for l in losses))) if losses else None,
        throughput_mbps=min(tput) if tput else None,       # bottleneck
        availability=min(avail) if avail else None,        # weakest hop
        effective_mtu=min(mtus) if mtus else None,
    )


def _prod(xs) -> float:
    out = 1.0
    for x in xs:
        out *= x
    return out


def path_score(metrics: PathMetrics) -> float | None:
    """Path receives its OWN score — never an average of hop scores."""
    if metrics.availability is not None and metrics.availability < 0.5:
        return 0.0
    from orchestrator.benchmarking.scoring import (latency_score, loss_score,
                                                   throughput_score)
    parts = []
    lat = latency_score(metrics.e2e_latency_ms or metrics.latency_ms)
    if lat is not None:
        parts.append(lat * 0.45)
    ls = loss_score(metrics.e2e_loss_pct if metrics.e2e_loss_pct is not None
                    else metrics.loss_pct)
    if ls is not None:
        parts.append(ls * 0.35)
    ts = throughput_score(metrics.throughput_mbps)
    if ts is not None:
        parts.append(ts * 0.20)
    return round(sum(parts), 2) if parts else None


# ── end-to-end truth gate (§4) ─────────────────────────────────────────

def verify_path_end_to_end(topo: Topology, path: TopologyPath,
                           hop_probes: dict[str, bool],
                           e2e_probe: bool) -> tuple[bool, str]:
    """Healthy hops alone NEVER verify a path — the end-to-end probe must
    pass AND every hop must be up."""
    missing = [eid for eid in path.edge_ids if eid not in hop_probes]
    if missing:
        return False, f"missing hop probes: {missing}"
    failed_hops = [e for e, ok in hop_probes.items() if not ok]
    if failed_hops:
        path.state = "HOP_FAILED"
        return False, f"hop(s) down: {failed_hops}"
    if not e2e_probe:
        path.state = "PATH_FAILED"
        return False, "end-to-end probe failed while all hops healthy (gate tripped)"
    path.state = "VERIFIED"
    return True, "end-to-end traffic verified through every hop"


# ── failure propagation (§10) ──────────────────────────────────────────

def hop_failure_effect(topo: Topology, path: TopologyPath, failed_edge: str) -> dict:
    """B→C failing does not destroy A→B. Returns which hops stay healthy."""
    healthy = [e for e in path.edge_ids if e != failed_edge]
    return {"failed_hop": failed_edge,
            "classification": "HOP_FAILED",
            "whole_path_failed": True,          # path unusable…
            "healthy_hops_to_preserve": healthy}  # …but these must NOT be torn down


# ── shared failure domains across paths (§7) ───────────────────────────

def shared_path_domains(paths: dict[str, TopologyPath], topo: Topology) -> dict:
    out: dict[str, dict] = {}
    edges = topo.by_id()
    for a, b in itertools.combinations(sorted(paths), 2):
        na, nb = set(paths[a].nodes(topo)), set(paths[b].nodes(topo))
        ea = set(paths[a].edge_ids)
        eb = set(paths[b].edge_ids)
        shared_nodes = na & nb
        shared_edges = ea & eb
        shared_relays = {edges[e].to_node for e in shared_edges} | \
                        {edges[e].from_node for e in shared_edges}
        out[f"{a}|{b}"] = {
            "shared_nodes": sorted(shared_nodes),
            "shared_edges": sorted(shared_edges),
            "shared_relays": sorted(shared_relays),
            "diversity_score": round(1.0 - (len(shared_nodes) / len(na | nb)
                                             if (na | nb) else 1.0), 3),
        }
    return out


# ── bounded path search (§8) ───────────────────────────────────────────

@dataclass(frozen=True)
class PathSearchConfig:
    max_hops: int = 3
    max_candidate_paths: int = 25
    beam_width: int = 8
    time_budget_s: float = 5.0


def candidate_paths(topo: Topology, source: str, destination: str,
                    config: PathSearchConfig | None = None,
                    manifests: dict | None = None) -> list[list[str]]:
    """Bounded DFS beam over the edge graph. Terminates on hop limit,
    candidate budget, beam width or time budget — never open-ended."""
    import time
    config = config or PathSearchConfig()
    deadline = time.monotonic() + config.time_budget_s
    results: list[list[str]] = []
    beam = [[e.edge_id] for e in topo.edges if e.from_node == source]
    beam.sort(key=lambda p: _path_cost(topo, p))
    beam = beam[:config.beam_width]
    while beam and len(results) < config.max_candidate_paths:
        if time.monotonic() > deadline:
            break
        nxt: list[list[str]] = []
        for partial in beam:
            tail = topo.by_id()[partial[-1]]
            if tail.to_node == destination:
                if validate_path(topo, partial, manifests)[0]:
                    results.append(partial)
                continue
            if len(partial) >= config.max_hops:
                continue
            for e in topo.edges:
                if e.from_node != tail.to_node:
                    continue
                if e.edge_id in partial:
                    continue
                extended = partial + [e.edge_id]
                if path_loops(topo, extended):
                    continue
                nxt.append(extended)
        nxt.sort(key=lambda p: _path_cost(topo, p))
        beam = nxt[:config.beam_width]
    return results[:config.max_candidate_paths]


def _path_cost(topo: Topology, edge_ids: list[str]) -> float:
    edges = topo.by_id()
    return sum(edges[e].rtt_ms or 500.0 for e in edge_ids)


# ── multi-hop routing plan (§9) ────────────────────────────────────────

def path_plan(topo: Topology, path: TopologyPath) -> list[dict]:
    """Per-hop actions with the EXACT node each action executes on."""
    edges = topo.by_id()
    actions: list[dict] = []
    for idx, eid in enumerate(path.edge_ids):
        e = edges[eid]
        iface = f"tp{idx}"
        actions.append({
            "hop": idx + 1, "edge": eid, "route": e.route,
            "node": e.from_node,
            "actions": [
                f"CREATE interface {iface}",
                f"ASSIGN addressing per route {e.route}",
                f"ADD route via {iface} table 51{idx:02d}",
                f"ADD fwmark {5100 + idx} policy rule",
                f"SET MTU {e.effective_mtu or 1420}",
                f"ENDPOINT-GUARD pin outer endpoint via physical underlay",
            ],
        })
        if e.route_kind == "chain" and e.chain_spec is not None:
            plan = build_plan(e.chain_spec)
            if plan:
                actions[-1]["chain_install_order"] = plan.install_order
                actions[-1]["chain_rollback_order"] = plan.rollback_order
    return actions


# ── failover integration (§11) ─────────────────────────────────────────

def path_member_candidate(path: TopologyPath) -> str:
    """TopologyPaths plug into P10 FailoverGroups as first-class members."""
    return f"path:{path.path_id}"
