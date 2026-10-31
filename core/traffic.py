"""Tenant ceilings for route payload controls; rate is combined Mbps."""
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from orchestrator.mesh_gateway import validate_traffic

TRAFFIC_CEILINGS = {'max_route_mbps': 100000, 'max_route_bytes': 10**16,
                    'max_route_connections': 10000}


class TrafficPolicy(BaseModel):
    model_config = ConfigDict(extra='forbid', allow_inf_nan=False)
    rate_mbps: float = Field(default=0, strict=True, ge=0, le=100000)
    quota_bytes: int = Field(default=0, strict=True, ge=0, le=10**16)
    max_connections: int = Field(default=256, strict=True, ge=1, le=10000)


def bounded_traffic(value, limits):
    if hasattr(value, 'model_dump'):
        value = value.model_dump(exclude_unset=True)
    value = value or {}
    try:
        result = validate_traffic(value)
    except ValueError:
        raise HTTPException(400, 'invalid traffic policy') from None
    for field, ceiling in [('rate_mbps', 'max_route_mbps'), ('quota_bytes', 'max_route_bytes'),
                           ('max_connections', 'max_route_connections')]:
        cap = limits.get(ceiling, TRAFFIC_CEILINGS[ceiling])
        if field == 'max_connections' and field not in value:
            result[field] = min(result[field], cap)
        if result[field] > cap:
            raise HTTPException(403, 'workspace traffic ceiling exceeded: ' + field)
        if result[field] == 0:
            result[field] = cap
    return result
