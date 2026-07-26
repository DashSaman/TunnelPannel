from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=8, max_length=200)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    must_change_password: bool
    role: str


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=8, max_length=200)
    new_password: str = Field(min_length=12, max_length=200)


class TelegramLanguageRequest(BaseModel):
    telegram_id: int
    username: str | None = None
    language: str


class EndpointCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    ssh_username: str = Field(min_length=1, max_length=100)
    auth_method: str
    secret: str = Field(min_length=1, max_length=30000)
    sudo_mode: str = "NONE"
    sudo_password: str | None = Field(
        default=None,
        max_length=500,
    )
    display_location: str | None = Field(
        default=None,
        max_length=255,
    )
    technical_zone: str = "AUTO"
    description: str | None = Field(
        default=None,
        max_length=2000,
    )


class EndpointDraftValueRequest(BaseModel):
    telegram_id: int
    value: str = Field(max_length=30000)


class BotTelegramRequest(BaseModel):
    telegram_id: int



class EndpointUpdateRequest(BaseModel):
    name: str | None = Field(
        default=None,
        min_length=2,
        max_length=150,
    )

    host: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
    )

    port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
    )

    ssh_username: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )

    auth_method: str | None = None

    secret: str | None = Field(
        default=None,
        max_length=30000,
    )

    sudo_mode: str | None = None

    sudo_password: str | None = Field(
        default=None,
        max_length=500,
    )

    display_location: str | None = Field(
        default=None,
        max_length=255,
    )

    description: str | None = Field(
        default=None,
        max_length=2000,
    )



class PairPrecheckCreateRequest(BaseModel):
    endpoint_a_id: int = Field(gt=0)
    endpoint_b_id: int = Field(gt=0)


class InventoryConflictRequest(BaseModel):
    endpoint_ids: list[int] = Field(
        min_length=1,
        max_length=10,
    )

    candidate_cidr: str | None = Field(
        default=None,
        max_length=100,
    )

    interface_name: str | None = Field(
        default=None,
        max_length=100,
    )

    protocol: str | None = Field(
        default=None,
        max_length=10,
    )

    port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
    )

    vxlan_vni: int | None = Field(
        default=None,
        ge=1,
        le=16777215,
    )

    tunnel_key: str | None = Field(
        default=None,
        max_length=200,
    )

class TunnelPlanItemInput(BaseModel):
    endpoint_a_id: int = Field(gt=0)
    endpoint_b_id: int = Field(gt=0)
    item_name: str = Field(min_length=1, max_length=180)
    method_id: str = Field(min_length=2, max_length=100)
    carrier_method_id: str | None = Field(default=None, max_length=100)
    traffic_direction: str = Field(default="BIDIRECTIONAL", max_length=30)
    initiator: str = Field(default="AUTO", max_length=20)
    config: dict = Field(default_factory=dict)

class TunnelPlanCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=180)
    topology: str = Field(default="PAIR", max_length=30)
    stop_policy: str = Field(default="STOP_ON_ERROR", max_length=30)
    rollback_policy: str = Field(default="FAILED_ITEM_ONLY", max_length=40)
    items: list[TunnelPlanItemInput] = Field(min_length=1, max_length=200)
