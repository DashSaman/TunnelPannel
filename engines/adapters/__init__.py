"""Canonical engine adapter SDK (P3).

Contract per ADR-001: every engine adapter implements the full lifecycle
(detect → … → rollback). ``probe()`` is the truth gate — process running,
interface UP or port listening are NOT success; only real intended
data-plane traffic passing through the tunnel counts.

Adapters wrap EXISTING proven code (Gen1 executor deploy bodies, Gen2
harnesses, Gen3 adapters) — they do not rewrite working commands. Concrete
adapters land in P5; this module fixes the interface + result types.
"""
from __future__ import annotations

import dataclasses
from abc import ABC, abstractmethod
from typing import Any, Protocol


@dataclasses.dataclass(frozen=True)
class ProbeResult:
    """Data-plane verification outcome — the honesty gate."""
    ok: bool
    evidence: str                      # human-readable proof of real traffic
    rtt_ms: float | None = None
    loss_pct: float | None = None
    via: str = "data-plane"            # how it was measured


@dataclasses.dataclass(frozen=True)
class PlanAction:
    """One dry-run action: CREATE/ALLOCATE/ADD/INSTALL/START/…"""
    verb: str
    target: str
    detail: str = ""


class Executor(Protocol):
    """Remote command channel (SSH transport or node agent)."""

    def run(self, cmd: str, timeout: int = 60) -> tuple[int, str]:
        ...


class EngineAdapter(ABC):
    """12-method canonical contract. Subclasses must implement all of them."""

    engine_id: str = ""                # must match a manifest id
    profile_id: str = "default"

    def __init__(self, node_a: dict, node_b: dict | None = None,
                 executor: Executor | None = None, params: dict | None = None):
        self.node_a = node_a
        self.node_b = node_b
        self.executor = executor
        self.params = params or {}

    # ── lifecycle ──
    @abstractmethod
    def detect(self) -> bool:
        """Is this technology present/possible on the node(s)?"""

    @abstractmethod
    def inventory(self) -> dict:
        """What exactly is installed (versions, binaries, modules)."""

    @abstractmethod
    def precheck(self) -> list[str]:
        """Hard requirement checks; returns list of problems (empty = ok)."""

    @abstractmethod
    def plan(self) -> list[PlanAction]:
        """Declarative mutation plan for dry-run display."""

    @abstractmethod
    def install(self) -> None:
        ...

    @abstractmethod
    def configure(self) -> None:
        ...

    @abstractmethod
    def start(self) -> None:
        ...

    @abstractmethod
    def probe(self) -> ProbeResult:
        """TRUTH GATE: verify real data-plane traffic through the tunnel."""

    @abstractmethod
    def metrics(self) -> dict[str, Any]:
        """RTT/loss/jitter/throughput/CPU/RAM as applicable."""

    @abstractmethod
    def stop(self) -> None:
        ...

    @abstractmethod
    def remove(self) -> None:
        ...

    @abstractmethod
    def rollback(self) -> None:
        """Undo in reverse dependency order; safe to call after partial failure."""


_LIFECYCLE = ("detect", "inventory", "precheck", "plan", "install", "configure",
              "start", "probe", "metrics", "stop", "remove", "rollback")

_REGISTRY: dict[tuple[str, str], type[EngineAdapter]] = {}


def register_adapter(cls: type[EngineAdapter]) -> type[EngineAdapter]:
    """Class decorator: register an adapter under (engine_id, profile_id)."""
    if not cls.engine_id:
        raise ValueError(f"{cls.__name__}: engine_id must be set")
    for name in _LIFECYCLE:
        if getattr(cls, name) is getattr(EngineAdapter, name):
            raise TypeError(f"{cls.__name__} does not implement {name}()")
    key = (cls.engine_id, getattr(cls, "profile_id", "default"))
    _REGISTRY[key] = cls
    return cls


def get_adapter(engine_id: str, profile_id: str = "default") -> type[EngineAdapter]:
    try:
        return _REGISTRY[(engine_id, profile_id)]
    except KeyError:
        # fall back to the engine's default profile adapter if any
        for (eid, _pid), cls in _REGISTRY.items():
            if eid == engine_id:
                return cls
        raise KeyError(f"no adapter registered for engine {engine_id!r}") from None


def registered() -> dict[tuple[str, str], type[EngineAdapter]]:
    return dict(_REGISTRY)
