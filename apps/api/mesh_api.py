"""Customer-scoped all-pairs testing and evidence-based route selection."""
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.models import Job
from core.security import require_role
from core.workspaces import scope_limits
from orchestrator.mesh_campaign import select_methods
from orchestrator.mesh_service import campaign_job, campaign_view, route_samples


class CampaignRequest(BaseModel):
    nodes: list[str] = Field(min_length=2, max_length=100)
    profile: Literal["NORMAL", "DEEP"] = "NORMAL"
    methods: list[str] | None = None
    recommend_count: int = Field(default=5, ge=1, le=100)
    purpose: Literal["any", "ip", "socks", "tcp_forward", "udp_forward", "tcp_egress"] = "any"


class RouteSelection(BaseModel):
    methods: list[str] = Field(min_length=1, max_length=100)


def create_mesh_router(factory, service):
    router = APIRouter(prefix="/api/mesh", tags=["mesh"],
                       dependencies=[Depends(require_role("SUPER_ADMIN", "OPERATOR", "VIEWER"))])

    @router.get('/config')
    def configuration():
        return {'limits': scope_limits(), 'recommendation_default': 5,
                'capability': 'independent authenticated TCP SOCKS egress per destination',
                'session_failover': 'new connections switch; existing TCP sessions reconnect'}

    @router.post("/campaigns", status_code=202)
    def start(body: CampaignRequest, _=Depends(require_role("SUPER_ADMIN", "OPERATOR"))):
        job_id = service.create(factory, body, scope_limits())
        return {"id": job_id, "state": "QUEUED"}

    @router.get("/campaigns")
    def history():
        with factory() as session:
            return [{"id": j.id, "state": j.state, "progress": j.progress, "created_at": j.created_at}
                    for j in session.query(Job).filter_by(kind="mesh_campaign").order_by(Job.created_at.desc()).limit(30)]

    @router.get("/campaigns/{campaign_id}")
    def detail(campaign_id: str):
        with factory() as session:
            return campaign_view(session, campaign_job(session, campaign_id))

    @router.post("/campaigns/{campaign_id}/cancel")
    def cancel(campaign_id: str, _=Depends(require_role("SUPER_ADMIN", "OPERATOR"))):
        with factory() as session:
            job = campaign_job(session, campaign_id)
            job.cancel_requested = True
            session.commit()
            return {"id": job.id, "state": job.state, "cancel_requested": True}

    @router.put("/campaigns/{campaign_id}/routes/{route_id}/selection")
    def select(campaign_id: str, route_id: str, body: RouteSelection,
               _=Depends(require_role("SUPER_ADMIN", "OPERATOR"))):
        with factory() as session:
            job = campaign_job(session, campaign_id)
            if job.state in {"QUEUED", "RUNNING"}:
                raise HTTPException(409, "wait for campaign completion")
            routes = [dict(route) for route in job.payload["routes"]]
            route = next((route for route in routes if route["id"] == route_id), None)
            if route is None:
                raise HTTPException(404, "route not found")
            route["selection"] = select_methods(route_samples(session, route["job_id"]), body.methods,
                                                 scope_limits()["max_tunnels_per_route"])
            job.payload = {**job.payload, "routes": routes}
            session.commit()
            return {"route_id": route_id, "selection": route["selection"]}

    return router
