"""Canonical data model (P2, ADR-001) — single source of truth.

SQLAlchemy 2 declarative models covering the whole product domain. Portable
across SQLite (single-node panel mode) and PostgreSQL (multi-service mode);
production schema changes go through Alembic migrations only — never
``create_all()`` in app bootstrap (that stays limited to throwaway tests).

Status vocabularies are enforced at the application layer (not DB enums) so
vocabulary evolution does not require a migration on every addition; see
core/catalog.py for the canonical engine/profile identity rules.
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer,
                        String, Text, UniqueConstraint, text)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Base(DeclarativeBase):
    pass


# ─── Nodes ────────────────────────────────────────────────────────────

class Node(Base):
    __tablename__ = "nodes"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    host: Mapped[str] = mapped_column(String(255))           # IP / FQDN
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    ssh_username: Mapped[str] = mapped_column(String(64), default="root")
    auth_type: Mapped[str] = mapped_column(String(16), default="key")  # key|password
    secret_ref: Mapped[str | None] = mapped_column(String(64))         # -> SecretReference
    host_key_fingerprint: Mapped[str | None] = mapped_column(String(128))
    sudo_mode: Mapped[str] = mapped_column(String(16), default="none")  # none|password|nopasswd
    role: Mapped[str] = mapped_column(String(32), default="worker")     # panel|gateway|worker|test
    location: Mapped[str | None] = mapped_column(String(64))
    tags: Mapped[list] = mapped_column(JSON, default=list)
    agent_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    inventories: Mapped[list["NodeInventory"]] = relationship(back_populates="node", cascade="all, delete-orphan")


class NodeInventory(Base):
    """Read-only discovery snapshot per node, always timestamped."""
    __tablename__ = "node_inventories"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    node_id: Mapped[str] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"))
    collected_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    source: Mapped[str] = mapped_column(String(16), default="ssh")     # ssh|agent
    snapshot: Mapped[dict] = mapped_column(JSON)                       # full structured inventory
    summary: Mapped[dict] = mapped_column(JSON, default=dict)          # derived quick facts

    node: Mapped[Node] = relationship(back_populates="inventories")


# ─── Engines & identities ─────────────────────────────────────────────

class Engine(Base):
    """A tunnel technology (wireguard, gost, xray, …) — distinct from profiles."""
    __tablename__ = "engines"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)      # stable immutable id
    display_name: Mapped[str] = mapped_column(String(120))
    family: Mapped[str] = mapped_column(String(32))                     # kernel|vpn|proxy|forwarder|custom
    implementation_status: Mapped[str] = mapped_column(String(16), default="PARTIAL")
        # IMPLEMENTED | PARTIAL | UNSUPPORTED | DEPRECATED
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    profiles: Mapped[list["EngineProfile"]] = relationship(back_populates="engine", cascade="all, delete-orphan")


class EngineProfile(Base):
    """Transport variant of an engine (gost/grpc, xray/vless_xhttp, …)."""
    __tablename__ = "engine_profiles"
    __table_args__ = (UniqueConstraint("engine_id", "profile_id", name="uq_engine_profile"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    engine_id: Mapped[str] = mapped_column(ForeignKey("engines.id", ondelete="CASCADE"))
    profile_id: Mapped[str] = mapped_column(String(64))                 # stable immutable id
    legacy_method_id: Mapped[str] = mapped_column(String(64), unique=True)  # e.g. GOST_GRPC
    display_name: Mapped[str] = mapped_column(String(120))
    implementation_status: Mapped[str] = mapped_column(String(16), default="PARTIAL")

    engine: Mapped[Engine] = relationship(back_populates="profiles")
    verifications: Mapped[list["MethodVerification"]] = relationship(back_populates="profile", cascade="all, delete-orphan")


class EngineManifest(Base):
    """Machine-readable capability declaration (schema validated in P3)."""
    __tablename__ = "engine_manifests"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    engine_id: Mapped[str] = mapped_column(String(64), index=True)      # engine or engine/profile
    version: Mapped[str] = mapped_column(String(32), default="1")
    manifest: Mapped[dict] = mapped_column(JSON)                        # full manifest document
    validated: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class MethodVerification(Base):
    """Honest verification evidence per engine/profile — never inferred from config generation."""
    __tablename__ = "method_verifications"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    profile_id: Mapped[str] = mapped_column(ForeignKey("engine_profiles.id", ondelete="CASCADE"))
    level: Mapped[str] = mapped_column(String(32), default="UNTESTED")
        # UNTESTED | LAB_VERIFIED | REAL_PAIR_VERIFIED | PRODUCTION_VERIFIED
    evidence_ref: Mapped[str | None] = mapped_column(Text)              # receipt/log reference
    verified_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    notes: Mapped[str | None] = mapped_column(Text)

    profile: Mapped[EngineProfile] = relationship(back_populates="verifications")


# ─── Chains (composition graph) ───────────────────────────────────────

class Chain(Base):
    """A composed route: A over B over C (A uses B as its underlay/carrier)."""
    __tablename__ = "chains"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(120))
    maturity: Mapped[str] = mapped_column(String(16), default="EXPERIMENTAL")  # STANDARD|ADVANCED|EXPERIMENTAL
    components: Mapped[list["ChainComponent"]] = relationship(back_populates="chain", cascade="all, delete-orphan")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ChainComponent(Base):
    """DAG node: component_id/parent_id/chain_id/deployment_id per spec."""
    __tablename__ = "chain_components"
    __table_args__ = (UniqueConstraint("chain_id", "component_id", name="uq_chain_component"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    chain_id: Mapped[str] = mapped_column(ForeignKey("chains.id", ondelete="CASCADE"))
    component_id: Mapped[str] = mapped_column(String(64))
    parent_id: Mapped[str | None] = mapped_column(String(64))           # None = rides physical underlay
    engine_id: Mapped[str] = mapped_column(String(64))
    profile_id: Mapped[str | None] = mapped_column(String(64))
    legacy_method_id: Mapped[str | None] = mapped_column(String(64))
    node_a: Mapped[str | None] = mapped_column(String(32))
    node_b: Mapped[str | None] = mapped_column(String(32))

    chain: Mapped[Chain] = relationship(back_populates="components")


# ─── Deployments ──────────────────────────────────────────────────────

class Deployment(Base):
    """Transactional deployment of a method or chain."""
    __tablename__ = "deployments"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    chain_id: Mapped[str | None] = mapped_column(ForeignKey("chains.id", ondelete="SET NULL"))
    node_a: Mapped[str] = mapped_column(String(32), ForeignKey("nodes.id"))
    node_b: Mapped[str | None] = mapped_column(String(32), ForeignKey("nodes.id"))
    state: Mapped[str] = mapped_column(String(16), default="PLANNED")
        # PLANNED|VALIDATED|DRY_RUN|RESERVED|APPLYING|VERIFYING|COMMITTED|ROLLING_BACK|ROLLED_BACK|FAILED
    desired_state: Mapped[dict] = mapped_column(JSON, default=dict)
    plan_preview: Mapped[list] = mapped_column(JSON, default=list)      # dry-run actions
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    committed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    revisions: Mapped[list["DeploymentRevision"]] = relationship(back_populates="deployment", cascade="all, delete-orphan")
    resources: Mapped[list["ResourceAllocation"]] = relationship(back_populates="deployment", cascade="all, delete-orphan")


class DeploymentRevision(Base):
    __tablename__ = "deployment_revisions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    deployment_id: Mapped[str] = mapped_column(ForeignKey("deployments.id", ondelete="CASCADE"))
    rev: Mapped[int] = mapped_column(Integer, default=1)
    desired_state: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    deployment: Mapped[Deployment] = relationship(back_populates="revisions")


class ResourceAllocation(Base):
    """Ownership ledger: every shared resource TunnelPannel creates is recorded here.

    Uniqueness applies only to LIVE rows (released allocations stay in the
    ledger as history), expressed as a partial unique index.
    """
    __tablename__ = "resource_allocations"
    __table_args__ = (
        Index("uq_resource_live", "kind", "key", "node_id", unique=True,
              postgresql_where=text("released_at IS NULL"),
              sqlite_where=text("released_at IS NULL")),
    )
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    deployment_id: Mapped[str] = mapped_column(ForeignKey("deployments.id", ondelete="CASCADE"))
    chain_id: Mapped[str | None] = mapped_column(String(32))
    component_id: Mapped[str | None] = mapped_column(String(64))
    node_id: Mapped[str | None] = mapped_column(String(32))
    owner: Mapped[str] = mapped_column(String(32), default="TunnelPannel")
    kind: Mapped[str] = mapped_column(String(32))
        # tcp_port|udp_port|interface|subnet_v4|subnet_v6|route_table|fwmark|
        # nft_chain|systemd_unit|namespace|socket|docker
    key: Mapped[str] = mapped_column(String(255))                       # e.g. "51820" / "wg0" / "10.173.3.0/24"
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    released_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    deployment: Mapped[Deployment] = relationship(back_populates="resources")


# ─── Benchmarks & scores ──────────────────────────────────────────────

class BenchmarkRun(Base):
    """One bounded benchmark job over a set of candidates (fair same-profile comparison)."""
    __tablename__ = "benchmark_runs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    node_a: Mapped[str] = mapped_column(String(32), ForeignKey("nodes.id"))
    node_b: Mapped[str] = mapped_column(String(32), ForeignKey("nodes.id"))
    profile: Mapped[str] = mapped_column(String(8), default="NORMAL")  # QUICK|NORMAL|DEEP
    methodology: Mapped[dict] = mapped_column(JSON, default=dict)      # exact fairness parameters
    state: Mapped[str] = mapped_column(String(16), default="QUEUED")   # job states
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    samples: Mapped[list["BenchmarkSample"]] = relationship(back_populates="run", cascade="all, delete-orphan")


class BenchmarkSample(Base):
    """Per-candidate metrics inside one run."""
    __tablename__ = "benchmark_samples"
    __table_args__ = (UniqueConstraint("run_id", "candidate", name="uq_run_candidate"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(ForeignKey("benchmark_runs.id", ondelete="CASCADE"))
    candidate: Mapped[str] = mapped_column(String(120))                 # engine/profile or chain id
    candidate_kind: Mapped[str] = mapped_column(String(8), default="single")  # single|chain
    status: Mapped[str] = mapped_column(String(16), default="UNTESTED")
        # PASS|DEGRADED|FAILED|BLOCKED|INCOMPATIBLE|UNTESTED
    reason: Mapped[str | None] = mapped_column(Text)
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
        # rtt_min/avg/p50/p95/p99, jitter, loss, throughput, mtu, cpu, ram,
        # setup_s, reconnect_s, recovery_s, stability, dns/http results …

    run: Mapped[BenchmarkRun] = relationship(back_populates="samples")
    receipts: Mapped[list["BenchmarkReceipt"]] = relationship(back_populates="sample", cascade="all, delete-orphan")


class BenchmarkReceipt(Base):
    """Evidence document per measurement — no PASS without one."""
    __tablename__ = "benchmark_receipts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    sample_id: Mapped[str] = mapped_column(ForeignKey("benchmark_samples.id", ondelete="CASCADE"))
    document: Mapped[dict] = mapped_column(JSON)                        # full receipt (evidence, refs)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    sample: Mapped[BenchmarkSample] = relationship(back_populates="receipts")


class Score(Base):
    """Transparent 0–100 score with the weights that produced it."""
    __tablename__ = "scores"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    candidate: Mapped[str] = mapped_column(String(120), index=True)
    run_id: Mapped[str | None] = mapped_column(ForeignKey("benchmark_runs.id", ondelete="SET NULL"))
    score: Mapped[float] = mapped_column(Float)
    weights: Mapped[dict] = mapped_column(JSON, default=dict)
    reasons: Mapped[list] = mapped_column(JSON, default=list)           # explainable, deterministic
    computed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


# ─── Failover ─────────────────────────────────────────────────────────

class FailoverGroup(Base):
    """Operator-defined ordered membership — only selected routes may participate."""
    __tablename__ = "failover_groups"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    mode: Mapped[str] = mapped_column(String(16), default="MANUAL_PRIORITY")  # MANUAL_PRIORITY|SCORE_PRIORITY
    preemption: Mapped[str] = mapped_column(String(16), default="NO_PREEMPT")  # NO_PREEMPT|PREFER_PRIMARY|BEST_SCORE
    health_policy: Mapped[dict] = mapped_column(JSON, default=dict)
    failure_threshold: Mapped[int] = mapped_column(Integer, default=3)
    recovery_threshold: Mapped[int] = mapped_column(Integer, default=3)
    cooldown_s: Mapped[int] = mapped_column(Integer, default=30)
    hysteresis_margin: Mapped[float] = mapped_column(Float, default=5.0)
    max_switches_per_window: Mapped[int] = mapped_column(Integer, default=3)
    maintenance: Mapped[bool] = mapped_column(Boolean, default=False)
    pinned_member: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    members: Mapped[list["FailoverMember"]] = relationship(back_populates="group", cascade="all, delete-orphan",
                                                            order_by="FailoverMember.priority")


class FailoverMember(Base):
    __tablename__ = "failover_members"
    __table_args__ = (UniqueConstraint("group_id", "priority", name="uq_member_priority"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    group_id: Mapped[str] = mapped_column(ForeignKey("failover_groups.id", ondelete="CASCADE"))
    priority: Mapped[int] = mapped_column(Integer)                      # 1 = Primary, 2 = Backup 1, …
    candidate: Mapped[str] = mapped_column(String(120))                 # engine/profile or chain id
    candidate_kind: Mapped[str] = mapped_column(String(8), default="single")
    deployment_id: Mapped[str | None] = mapped_column(ForeignKey("deployments.id", ondelete="SET NULL"))

    group: Mapped[FailoverGroup] = relationship(back_populates="members")


# ─── Health, events, alerts, audit, jobs, secrets ─────────────────────

class HealthSample(Base):
    """Lightweight continuous probe history (post-deploy monitoring)."""
    __tablename__ = "health_samples"
    id: Mapped[int] = mapped_column(String(32), primary_key=True, default=_uuid)
    candidate: Mapped[str] = mapped_column(String(120), index=True)
    node_id: Mapped[str | None] = mapped_column(String(32))
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    ok: Mapped[bool] = mapped_column(Boolean)
    rtt_ms: Mapped[float | None] = mapped_column(Float)
    jitter_ms: Mapped[float | None] = mapped_column(Float)
    loss_pct: Mapped[float | None] = mapped_column(Float)
    state: Mapped[str | None] = mapped_column(String(16))                # UP|DEGRADED|DOWN
    extra: Mapped[dict] = mapped_column(JSON, default=dict)


class Event(Base):
    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    severity: Mapped[str] = mapped_column(String(8), default="info")    # info|warn|error|critical
    source: Mapped[str] = mapped_column(String(64))
    message: Mapped[str] = mapped_column(Text)
    context: Mapped[dict] = mapped_column(JSON, default=dict)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(64), index=True)
        # tunnel_down|chain_down|degraded_path|high_loss|high_jitter|frequent_failover|
        # resource_conflict|node_unreachable|cert_expiry|drift|backup_failure
    severity: Mapped[str] = mapped_column(String(8), default="warn")
    context: Mapped[dict] = mapped_column(JSON, default=dict)
    raised_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    notified_telegram: Mapped[bool] = mapped_column(Boolean, default=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    actor: Mapped[str] = mapped_column(String(120))                     # user|bot|system:<subsystem>
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str | None] = mapped_column(String(120))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class Job(Base):
    """Finite job: QUEUED→RUNNING→PASS/FAILED/BLOCKED/CANCELLED/TIMED_OUT (never RUNNING forever)."""
    __tablename__ = "jobs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(64), index=True)
        # inventory|benchmark|chain_benchmark|deployment|deep_test|backup|restore
    state: Mapped[str] = mapped_column(String(16), default="QUEUED", index=True)
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict | None] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text)
    timeout_s: Mapped[int] = mapped_column(Integer, default=3600)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class SecretReference(Base):
    """Pointer to an encrypted secret — plaintext never lives in the DB."""
    __tablename__ = "secret_references"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(32))                       # ssh_password|ssh_key|token
    cipher: Mapped[str] = mapped_column(String(32), default="fernet")
    ciphertext: Mapped[bytes] = mapped_column(Text)                     # encrypted blob (b64)
    fingerprint: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    rotated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class ComponentDependency(Base):
    """Explicit edge beyond parentage: overlay binds to underlay resources."""
    __tablename__ = "component_dependencies"
    __table_args__ = (UniqueConstraint("chain_id", "component_id", "depends_on", name="uq_dep"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    chain_id: Mapped[str] = mapped_column(String(32), index=True)
    component_id: Mapped[str] = mapped_column(String(64))
    depends_on: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(32), default="underlay")  # underlay|address|route
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class CompositionValidation(Base):
    """Persisted validation verdicts with reason codes (explainability)."""
    __tablename__ = "composition_validations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    chain_id: Mapped[str | None] = mapped_column(String(32), index=True)
    spec_hash: Mapped[str] = mapped_column(String(64), index=True)
    valid: Mapped[bool] = mapped_column(Boolean)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    warnings: Mapped[list] = mapped_column(JSON, default=list)
    adapters_used: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class CompositionTemplate(Base):
    """Named reusable chain template (incl. legacy composite compatibility)."""
    __tablename__ = "composition_templates"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    template_key: Mapped[str] = mapped_column(String(64), unique=True)  # e.g. GRE_OVER_WIREGUARD
    source: Mapped[str] = mapped_column(String(16), default="legacy")  # legacy|operator|auto
    spec: Mapped[dict] = mapped_column(JSON)                            # ChainSpec as dict
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class TopologyDB(Base):
    __tablename__ = "topologies"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class TopologyEdgeDB(Base):
    __tablename__ = "topology_edges"
    __table_args__ = (UniqueConstraint("topology_id", "edge_id", name="uq_topo_edge"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    topology_id: Mapped[str] = mapped_column(ForeignKey("topologies.id", ondelete="CASCADE"))
    edge_id: Mapped[str] = mapped_column(String(64))
    from_node: Mapped[str] = mapped_column(String(32))
    to_node: Mapped[str] = mapped_column(String(32))
    route: Mapped[str] = mapped_column(String(120))
    route_kind: Mapped[str] = mapped_column(String(8), default="single")
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    verification: Mapped[str] = mapped_column(String(32), default="UNTESTED")


class TopologyPathDB(Base):
    __tablename__ = "topology_paths"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    topology_id: Mapped[str] = mapped_column(ForeignKey("topologies.id", ondelete="CASCADE"))
    path_id: Mapped[str] = mapped_column(String(64))
    edge_ids: Mapped[list] = mapped_column(JSON)
    state: Mapped[str] = mapped_column(String(16), default="PLANNED")
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)


class TopologyRevisionDB(Base):
    __tablename__ = "topology_revisions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    topology_id: Mapped[str] = mapped_column(ForeignKey("topologies.id", ondelete="CASCADE"))
    revision: Mapped[int] = mapped_column(Integer, default=1)
    snapshot: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
