"""Ranking web API (P7): serves the operator page + selection persistence.

Selection (§37) is recorded on the Job payload — input for P10
FailoverGroups. It never triggers a deployment.
"""
from __future__ import annotations

import pathlib

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from core.models import Deployment, Job

HTML_PATH = pathlib.Path(__file__).with_name("ranking.html")


class SelectionBody(BaseModel):
    selected: list[str]


def create_web_router(session_factory) -> APIRouter:
    router = APIRouter(tags=["ranking-ui"])

    @router.get("/ranking", response_class=HTMLResponse)
    def ranking_page():
        return HTMLResponse(HTML_PATH.read_text(encoding="utf-8"))

    @router.get("/api/nodes")
    def nodes():
        with session_factory() as session:
            from core.models import Node
            rows = session.query(Node).all()
            return [{"id": n.id, "name": n.name, "host": n.host} for n in rows]

    @router.post("/benchmarks/{job_id}/selection")
    def save_selection(job_id: str, body: SelectionBody):
        with session_factory() as session:
            job = session.get(Job, job_id)
            if job is None:
                raise HTTPException(404, "no such benchmark job")
            payload = dict(job.payload or {})
            payload["selection"] = body.selected
            job.payload = payload
            session.commit()
            return {"job_id": job_id, "saved": len(body.selected)}

    @router.get("/benchmarks/{job_id}/selection")
    def get_selection(job_id: str):
        with session_factory() as session:
            job = session.get(Job, job_id)
            if job is None:
                raise HTTPException(404, "no such benchmark job")
            return {"job_id": job_id, "selection": (job.payload or {}).get("selection", [])}

    @router.get("/benchmarks/{job_id}/selection-deployments")
    def selection_created_no_deployments(job_id: str):
        """Transparency endpoint: prove selection alone deploys nothing."""
        with session_factory() as session:
            job = session.get(Job, job_id)
            if job is None:
                raise HTTPException(404, "no such benchmark job")
            deps = session.query(Deployment).filter(
                Deployment.desired_state.contains("selection")).count()
            return {"selection_deployments": deps}

    create_topology_routes(router, session_factory)
    return router


# ── topology endpoints (P11) ──────────────────────────────────────────

def _topology_payload(session):
    from core.models import TopologyDB, TopologyEdgeDB, TopologyPathDB
    topo = session.query(TopologyDB).first()
    if topo is None:
        topo = TopologyDB(name="default")
        session.add(topo)
        session.commit()
    edges = session.query(TopologyEdgeDB).filter(
        TopologyEdgeDB.topology_id == topo.id).all()
    paths = session.query(TopologyPathDB).filter(
        TopologyPathDB.topology_id == topo.id).all()
    return topo, edges, paths


def create_topology_routes(router, session_factory):
    from core.models import TopologyDB, TopologyEdgeDB, TopologyPathDB
    from orchestrator.topology import (Topology, TopologyEdge, TopologyPath,
                                       PathSearchConfig, candidate_paths,
                                       derive_path_metrics, path_score,
                                       shared_path_domains, validate_path)
    from core.models import Node

    @router.get("/topology", response_class=HTMLResponse)
    def topology_page():
        return HTMLResponse(HTML_PATH.with_name("topology.html")
                             .read_text(encoding="utf-8"))

    @router.get("/api/topology")
    def get_topology():
        with session_factory() as session:
            topo, edges, paths = _topology_payload(session)
            nodes = [{"id": n.id, "name": n.name} for n in session.query(Node).all()]
            return {"topology_id": topo.id, "nodes": nodes,
                    "edges": [{"edge_id": e.edge_id, "from_node": e.from_node,
                               "to_node": e.to_node, "route": e.route,
                               "route_kind": e.route_kind,
                               **(e.metrics or {}),
                               "verification": e.verification} for e in edges],
                    "paths": [{"path_id": p.path_id, "edge_ids": p.edge_ids,
                               "state": p.state, "metrics": p.metrics} for p in paths],
                    "shared": {}}

    @router.post("/api/topology/edges")
    def add_edge(body: dict):
        route = body.get("route", "")
        kind = "chain" if route.startswith("chain:") else "single"
        with session_factory() as session:
            topo, _e, _p = _topology_payload(session)
            n = session.query(TopologyEdgeDB).filter(
                TopologyEdgeDB.topology_id == topo.id).count()
            session.add(TopologyEdgeDB(
                topology_id=topo.id, edge_id=f"e{n}",
                from_node=body["from_node"], to_node=body["to_node"],
                route=route, route_kind=kind, metrics={},
                verification="UNTESTED"))
            session.commit()
        return {"ok": True}

    @router.post("/api/topology/paths")
    def search_paths(body: dict):
        with session_factory() as session:
            topo_db, edges, _paths = _topology_payload(session)
            topo = Topology("runtime", edges=[
                TopologyEdge(e.edge_id, e.from_node, e.to_node, e.route,
                             e.route_kind, **(e.metrics or {}))
                for e in edges])
            found = candidate_paths(topo, body["source"], body["destination"],
                                    PathSearchConfig())
            session.query(TopologyPathDB).filter(
                TopologyPathDB.topology_id == topo_db.id).delete()
            out = []
            objs = {}
            for i, edge_ids in enumerate(found):
                ok, problems = validate_path(topo, edge_ids)
                metrics = derive_path_metrics(topo, edge_ids)
                path = TopologyPath(f"p{i}", edge_ids)
                nodes = path.nodes(topo)
                by_id = topo.by_id()
                row = TopologyPathDB(topology_id=topo_db.id, path_id=path.path_id,
                                     edge_ids=edge_ids, state="PLANNED",
                                     metrics=metrics.summary())
                session.add(row)
                objs[path.path_id] = path
                out.append({"path_id": path.path_id, "nodes": nodes,
                            "route_labels": [by_id[e].route for e in edge_ids],
                            "state": "PLANNED", "metrics": metrics.summary(),
                            "score": path_score(metrics),
                            "warnings": problems})
            session.commit()
            shared = shared_path_domains(objs, topo) if len(objs) >= 2 else {}
        return {"paths": out, "shared": shared}
