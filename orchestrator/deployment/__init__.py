"""Transactional deployment engine (P4b).

Lifecycle: PLAN → VALIDATE → DRY_RUN → RESERVE → APPLY → VERIFY → COMMIT.
On any failure after mutations begin: ROLLBACK in REVERSE step order.
Dry-run makes ZERO mutations. Every transition is recorded on the
``deployments`` row (state) and as events.

Portable: steps are callables supplied by the caller (engine adapters in
P5 wire real SSH work); the transaction discipline itself is what is
tested and enforced here.
"""
from __future__ import annotations

import dataclasses
from typing import Callable

from sqlalchemy.orm import Session

from core.models import Deployment, Event
from orchestrator.resources import ResourceManager

STATES = ("PLANNED", "VALIDATED", "DRY_RUN", "RESERVED", "APPLYING",
          "VERIFYING", "COMMITTED", "ROLLING_BACK", "ROLLED_BACK", "FAILED")


class DeploymentError(RuntimeError):
    """Lifecycle violation or step failure."""


@dataclasses.dataclass
class Step:
    """One transactional unit: mutate via apply(), prove via verify(),
    undo via rollback(). Rollback must tolerate being called after a
    partially-failed apply."""
    name: str
    apply: Callable[["Transaction"], None]
    verify: Callable[["Transaction"], bool]
    rollback: Callable[["Transaction"], None]
    reserves: list[dict] = dataclasses.field(default_factory=list)
    # each reserve: {"kind": ..., "key": ... (optional — scan if absent),
    #               "node_id": ..., plus extra kwargs}

    def plan_actions(self) -> list[str]:
        acts = [f"STEP {self.name}: apply/verify/rollback"]
        for r in self.reserves:
            key = r.get("key") or f"auto({r.get('kind', '?')})"
            acts.append(f"RESERVE {r.get('kind', '?')} {key}")
        return acts


class Transaction:
    """Drives one Deployment through the canonical lifecycle."""

    def __init__(self, session: Session, deployment: Deployment, steps: list[Step],
                 resources: ResourceManager | None = None):
        if not steps:
            raise DeploymentError("a transaction needs at least one step")
        self.session = session
        self.deployment = deployment
        self.steps = steps
        self.rm = resources or ResourceManager(session)
        self._applied: list[Step] = []

    # ── plumbing ──
    def _set_state(self, state: str, message: str = "", severity: str = "info") -> None:
        if state not in STATES:
            raise DeploymentError(f"unknown state {state!r}")
        self.deployment.state = state
        self.session.add(Event(severity=severity, source="deployment",
                               message=f"[{self.deployment.id[:8]}] {state}: {message}",
                               context={"deployment_id": self.deployment.id, "state": state}))
        self.session.flush()

    # ── lifecycle ──
    def _collect_actions(self) -> list[str]:
        actions: list[str] = []
        for step in self.steps:
            actions.extend(step.plan_actions())
        return actions

    def plan(self) -> list[str]:
        """Collect the full action list without touching anything."""
        actions = self._collect_actions()
        self.deployment.plan_preview = actions
        self._set_state("PLANNED", f"{len(self.steps)} steps, {len(actions)} actions")
        return actions

    def validate(self) -> None:
        """Static validation: reserves well-formed, dependency order sane."""
        for step in self.steps:
            for r in step.reserves:
                if "kind" not in r:
                    raise DeploymentError(f"step {step.name}: reserve without kind")
                if "key" not in r and r["kind"] not in (
                        "tcp_port", "udp_port", "interface", "subnet_v4", "subnet_v6",
                        "route_table", "fwmark", "namespace", "temp"):
                    raise DeploymentError(
                        f"step {step.name}: kind {r['kind']} requires an explicit key")
        self._set_state("VALIDATED", "static checks passed")

    def dry_run(self) -> list[str]:
        """Zero mutations: returns the plan preview and marks DRY_RUN
        (does not re-emit PLANNED if planning already happened)."""
        actions = self._collect_actions()
        self.deployment.plan_preview = actions
        self._set_state("DRY_RUN", f"{len(actions)} planned actions, 0 mutations")
        return actions

    def reserve(self) -> None:
        """Reserve every declared resource (idempotent)."""
        for step in self.steps:
            for r in step.reserves:
                kwargs = {k: v for k, v in r.items() if k not in ("kind", "key")}
                if "key" in r:
                    self.rm.reserve(kind=r["kind"], key=r["key"],
                                    deployment_id=self.deployment.id, **kwargs)
                elif r["kind"] in ("tcp_port", "udp_port"):
                    self.rm.allocate_port(kind=r["kind"],
                                          deployment_id=self.deployment.id, **kwargs)
                elif r["kind"] == "interface":
                    self.rm.allocate_interface(deployment_id=self.deployment.id, **kwargs)
                elif r["kind"] == "subnet_v4":
                    self.rm.allocate_subnet(version=4, deployment_id=self.deployment.id, **kwargs)
                elif r["kind"] == "subnet_v6":
                    self.rm.allocate_subnet(version=6, deployment_id=self.deployment.id, **kwargs)
                elif r["kind"] == "route_table":
                    self.rm.allocate_table(deployment_id=self.deployment.id, **kwargs)
                elif r["kind"] == "fwmark":
                    self.rm.allocate_fwmark(deployment_id=self.deployment.id, **kwargs)
                elif r["kind"] == "namespace":
                    self.rm.allocate_namespace(deployment_id=self.deployment.id, **kwargs)
                else:  # temp
                    self.rm.allocate_temp(key=r.get("key", f"{step.name}-tmp"),
                                          deployment_id=self.deployment.id, **kwargs)
        self._set_state("RESERVED", f"{sum(len(s.reserves) for s in self.steps)} resources")

    def apply(self) -> None:
        """Run steps in order; rollback in reverse on failure."""
        self._set_state("APPLYING", f"{len(self.steps)} steps")
        try:
            for step in self.steps:
                step.apply(self)
                self._applied.append(step)
            self._set_state("VERIFYING", "verifying all steps")
            for step in self.steps:
                if not step.verify(self):
                    raise DeploymentError(f"verification failed at step {step.name!r}")
        except Exception as exc:
            self._fail(str(exc))
            raise
        import datetime as dt
        self.deployment.committed_at = dt.datetime.now(dt.timezone.utc)
        self._set_state("COMMITTED", "all steps applied and verified")

    def _fail(self, reason: str) -> None:
        self._set_state("ROLLING_BACK", reason, severity="error")
        for step in reversed(self._applied):
            try:
                step.rollback(self)
            except Exception as rb_exc:                      # keep unwinding
                self._set_state("ROLLING_BACK",
                                f"rollback error on {step.name}: {rb_exc}", severity="critical")
        self.rm.release_deployment(self.deployment.id)
        final = "ROLLED_BACK" if self._applied else "FAILED"
        self._set_state(final, f"after failure: {reason[:200]}", severity="error")

    # convenience: full lifecycle in canonical order
    def run(self, skip_dry_run: bool = False) -> "Transaction":
        self.plan()
        self.validate()
        if not skip_dry_run:
            self.dry_run()
        self.reserve()
        self.apply()
        return self
