"""Owner provisioning API; billing services may update limits separately."""
from fastapi import APIRouter
from pydantic import BaseModel, Field


class WorkspaceRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    limits: dict[str, int] | None = None


class WorkspaceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    limits: dict[str, int] | None = None
    enabled: bool | None = None


def create_workspace_router(registry):
    router = APIRouter(prefix="/api/workspaces", tags=["workspaces"])

    @router.post("", status_code=201)
    def create(body: WorkspaceRequest):
        return registry.create(body.name, body.limits)

    @router.get("")
    def list_workspaces():
        return registry.list()

    @router.post("/{workspace_id}/disable")
    def disable(workspace_id: str):
        registry.disable(workspace_id)
        return {"disabled": True}

    @router.patch('/{workspace_id}')
    def update(workspace_id: str, body: WorkspaceUpdate):
        return registry.update(workspace_id, **body.model_dump())

    @router.post('/{workspace_id}/rotate-key')
    def rotate(workspace_id: str):
        return registry.rotate_key(workspace_id)

    return router
