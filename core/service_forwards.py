"""Strict, secret-free customer TCP service definitions; no execution here."""
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from core.models import Job
from orchestrator.service_forward_protocol import canonical_address, normalize_cidrs, validate_exposure


class ForwardSpec(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    name: str = Field(min_length=1, max_length=80, pattern=r'^[^<>\x00-\x1f\x7f]+$')
    route_id: str = Field(pattern=r'^[0-9a-f]{32}$')
    bind_host: str = '127.0.0.1'
    bind_port: int = Field(ge=1024, le=65535)
    target_host: str
    target_port: int = Field(ge=1, le=65535)
    source_cidrs: list[str] = Field(default_factory=list, max_length=32)
    allow_public: bool = False

    @field_validator('name', mode='before')
    @classmethod
    def strip_name(cls, value):
        return value.strip() if isinstance(value, str) else value

    @field_validator('bind_host', 'target_host')
    @classmethod
    def address(cls, value, info):
        return canonical_address(value, target=info.field_name == 'target_host')

    @field_validator('source_cidrs')
    @classmethod
    def cidrs(cls, values):
        return normalize_cidrs(values)

    @model_validator(mode='after')
    def network_exposure(self):
        validate_exposure(self.bind_host, self.allow_public, self.source_cidrs)
        return self


class ForwardUpdate(ForwardSpec):
    expected_revision: int = Field(ge=1, le=2**31 - 1)


class ForwardPreflight(ForwardSpec):
    service_id: str | None = Field(default=None, pattern=r'^[0-9a-f]{32}$')
    expected_revision: int | None = Field(default=None, ge=1, le=2**31 - 1)

    @model_validator(mode='after')
    def paired_revision(self):
        if (self.service_id is None) != (self.expected_revision is None):
            raise ValueError('service identity and expected revision must be supplied together')
        return self


class ApplyProof(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    request_id: str = Field(pattern=r'^[0-9a-f]{32}$')
    preflight_id: str = Field(pattern=r'^[0-9a-f]{32}$')
    preflight_token: str = Field(pattern=r'^[0-9a-f]{64}$')


class ForwardCreate(ForwardSpec, ApplyProof):
    pass


class ForwardApplyUpdate(ForwardUpdate, ApplyProof):
    pass


def normalize_forward(value: dict) -> dict:
    return ForwardSpec.model_validate(value).model_dump()


def service_job(session, service_id):
    job = session.get(Job, service_id)
    if job is None or job.kind != 'mesh_service_forward':
        raise HTTPException(404, 'service not found')
    return job


def service_public(job):
    payload = job.payload or {}
    fields = {*ForwardSpec.model_fields, 'revision', 'source', 'destination'}
    pending = payload.get('pending_spec') or {}
    return {'id': job.id, 'state': job.state,
            'pending_settings': {key: pending[key] for key in ForwardSpec.model_fields if key in pending} or None,
            **{key: payload[key] for key in fields if key in payload},
            'error': 'service operation failed; inspect the private operator record' if job.error else None}
