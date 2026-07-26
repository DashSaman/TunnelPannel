import enum
from datetime import datetime
from sqlalchemy import BigInteger, Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.db import Base


class UserRole(str, enum.Enum):
    SUPER_ADMIN = "SUPER_ADMIN"
    ADMIN = "ADMIN"
    USER = "USER"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.USER)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    telegram_id: Mapped[int | None] = mapped_column(BigInteger, unique=True, nullable=True, index=True)
    telegram_2fa_required: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class TelegramProfile(Base):
    __tablename__ = "telegram_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    telegram_id: Mapped[int] = mapped_column(BigInteger, unique=True, index=True)
    username: Mapped[str | None] = mapped_column(String(100), nullable=True)
    language: Mapped[str] = mapped_column(String(10), default="en")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(150), index=True)
    target_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)



class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    owner_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(150),
        index=True,
    )

    device_type: Mapped[str] = mapped_column(
        String(30),
        default="LINUX",
    )

    host: Mapped[str] = mapped_column(
        String(255),
        index=True,
    )

    port: Mapped[int] = mapped_column(
        Integer,
        default=22,
    )

    ssh_username: Mapped[str] = mapped_column(
        String(100),
    )

    auth_method: Mapped[str] = mapped_column(
        String(30),
    )

    display_location: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    technical_zone: Mapped[str] = mapped_column(
        String(30),
        default="UNKNOWN",
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="PENDING",
        index=True,
    )

    detected_os: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    detected_version: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    detected_hostname: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    detected_arch: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    primary_interface: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    public_ip: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    host_key_fingerprint: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    last_error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


class EndpointCredential(Base):
    __tablename__ = "endpoint_credentials"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    endpoint_id: Mapped[int] = mapped_column(
        ForeignKey("endpoints.id"),
        unique=True,
        index=True,
    )

    encrypted_blob: Mapped[str] = mapped_column(
        Text,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


class EndpointDraft(Base):
    __tablename__ = "endpoint_drafts"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    owner_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        index=True,
    )

    channel: Mapped[str] = mapped_column(
        String(30),
        default="WEB",
    )

    current_step: Mapped[str] = mapped_column(
        String(50),
        default="name",
    )

    payload_json: Mapped[str] = mapped_column(
        Text,
        default="{}",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    owner_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        index=True,
    )

    endpoint_id: Mapped[int | None] = mapped_column(
        ForeignKey("endpoints.id"),
        nullable=True,
        index=True,
    )

    job_type: Mapped[str] = mapped_column(
        String(100),
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="QUEUED",
        index=True,
    )

    progress: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )

    current_step: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )


class JobEvent(Base):
    __tablename__ = "job_events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    job_id: Mapped[int] = mapped_column(
        ForeignKey("jobs.id"),
        index=True,
    )

    level: Mapped[str] = mapped_column(
        String(30),
        default="INFO",
    )

    step: Mapped[str] = mapped_column(
        String(100),
    )

    public_message: Mapped[str] = mapped_column(
        Text,
    )

    command: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    output: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )



class PairPrecheck(Base):
    __tablename__ = "pair_prechecks"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )
    owner_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        index=True,
    )
    endpoint_a_id: Mapped[int] = mapped_column(
        ForeignKey("endpoints.id"),
        index=True,
    )
    endpoint_b_id: Mapped[int] = mapped_column(
        ForeignKey("endpoints.id"),
        index=True,
    )
    job_id: Mapped[int] = mapped_column(
        ForeignKey("jobs.id"),
        unique=True,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(30),
        default="QUEUED",
        index=True,
    )
    result_json: Mapped[str] = mapped_column(
        Text,
        default="{}",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )



class NetworkInventory(Base):
    __tablename__ = "network_inventories"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    endpoint_id: Mapped[int] = mapped_column(
        ForeignKey("endpoints.id"),
        unique=True,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="PENDING",
        index=True,
    )

    summary_json: Mapped[str] = mapped_column(
        Text,
        default="{}",
    )

    inventory_json: Mapped[str] = mapped_column(
        Text,
        default="{}",
    )

    last_error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    scanned_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


class TunnelPlan(Base):
    __tablename__ = "tunnel_plans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(180))
    topology: Mapped[str] = mapped_column(String(30), default="PAIR", index=True)
    status: Mapped[str] = mapped_column(String(30), default="DRAFT", index=True)
    execution_mode: Mapped[str] = mapped_column(String(30), default="SEQUENTIAL")
    stop_policy: Mapped[str] = mapped_column(String(30), default="STOP_ON_ERROR")
    rollback_policy: Mapped[str] = mapped_column(String(40), default="FAILED_ITEM_ONLY")
    total_items: Mapped[int] = mapped_column(Integer, default=0)
    current_order: Mapped[int] = mapped_column(Integer, default=0)
    config_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class TunnelPlanItem(Base):
    __tablename__ = "tunnel_plan_items"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    plan_id: Mapped[int] = mapped_column(ForeignKey("tunnel_plans.id"), index=True)
    order_index: Mapped[int] = mapped_column(Integer, index=True)
    endpoint_a_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id"), index=True)
    endpoint_b_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id"), index=True)
    item_name: Mapped[str] = mapped_column(String(180))
    method_id: Mapped[str] = mapped_column(String(100), index=True)
    carrier_method_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    traffic_direction: Mapped[str] = mapped_column(String(30), default="BIDIRECTIONAL")
    initiator: Mapped[str] = mapped_column(String(20), default="AUTO")
    status: Mapped[str] = mapped_column(String(30), default="WAITING", index=True)
    config_json: Mapped[str] = mapped_column(Text, default="{}")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AppSetting(Base):
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    value_json: Mapped[str] = mapped_column(Text, default="null")
    is_public: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )
