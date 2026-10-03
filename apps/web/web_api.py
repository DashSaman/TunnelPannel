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

    return router
