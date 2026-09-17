"""TunnelGuard — simulation engine + registry.

SimAdapter exists for three honest reasons:
 1. Verify the WHOLE pipeline (probe -> score -> FSM -> routing hooks -> API
    -> dashboard) end-to-end on machines without kernel privileges (CI,
    containers) — no fake 'pass' receipts for real engines ever come from it.
 2. Let the operator preview the dashboard and tune thresholds safely before
    touching production routing.
 3. Provide synthetic failure scenarios (config 'script') to test failover
    deterministically.

Registry maps engine name -> adapter class. In sim_mode every engine maps to
SimAdapter so the API/FSM paths are identical to production.
"""
from __future__ import annotations

import random
import threading
import time

from .base import EngineAdapter
from .kernel import GREAdapter, SITAdapter
from .openvpn import OpenVPNAdapter
from .ipsec import IKEv2Adapter, L2TPv3Adapter
from .wireguard import WireGuardAdapter
from .hedioum import HedioumAdapter
from .hajsaman import HajSamanAdapter
from .paqet import PaqetAdapter

_real_registry: dict[str, type[EngineAdapter]] = {
    "wireguard": WireGuardAdapter,
    "gre": GREAdapter,
    "sit": SITAdapter,
    "openvpn": OpenVPNAdapter,
    "ikev2": IKEv2Adapter,
    "l2tp": L2TPv3Adapter,
    "hedioum": HedioumAdapter,
    "hajsaman": HajSamanAdapter,
    "paqet": PaqetAdapter,
    "sim": None,  # filled below
}


# --------------------------------------------------------------------- sim
class SimAdapter(EngineAdapter):
    name = "sim"
    _states: dict[int, bool] = {}
    _lock = threading.Lock()

    # profile keys in config: base_rtt_ms, jitter_ms, loss_pct, script
    # script: list of {"after_s": int, "state": "up"|"down"} steps relative
    # to tunnel creation; deterministic lab behaviour.
    def _state(self) -> bool:
        tid = int(self.t.get("id", 0) or 0)
        with SimAdapter._lock:
            if tid not in SimAdapter._states:
                SimAdapter._states[tid] = True
            return SimAdapter._states[tid]

    def set_state(self, up: bool) -> None:
        tid = int(self.t.get("id", 0) or 0)
        with SimAdapter._lock:
            SimAdapter._states[tid] = up

    def _script_state(self) -> bool | None:
        """If a script step says we should be down by now, return False."""
        script = self.cfg.get("script") or []
        created = self.cfg.get("_created_ts") or time.time()
        if not self.cfg.get("_created_ts"):
            self.cfg["_created_ts"] = created
        elapsed = time.time() - created
        want = None
        for step in sorted(script, key=lambda x: x.get("after_s", 0)):
            if elapsed >= float(step.get("after_s", 0)):
                want = step.get("state") == "up"
        return want

    def render(self) -> dict[str, str]:
        return {"sim/{}.json".format(self.iface): str(self.cfg)}

    def precheck(self) -> list[str]:
        return []  # sim never blocks

    def up(self) -> list[str]:
        self.set_state(True)
        return [f"sim {self.iface} up"]

    def down(self) -> list[str]:
        self.set_state(False)
        return [f"sim {self.iface} down"]

    def status(self) -> dict:
        want = self._script_state()
        if want is not None:
            self.set_state(want)
        up = self._state()
        return {"up": up, "detail": "simulated tunnel", "extra": {"engine": "sim"}}

    # ---- synthetic probe used by the failover loop when engine == sim ----
    def synthetic_probe(self) -> dict:
        want = self._script_state()
        if want is not None:
            self.set_state(want)
        if not self._state():
            return {"rtt_ms": None, "loss_pct": 100.0, "jitter_ms": None,
                    "ok": False, "method": "sim", "detail": "sim down"}
        base = float(self.cfg.get("base_rtt_ms", 45))
        jit = float(self.cfg.get("jitter_ms", 5))
        loss = float(self.cfg.get("loss_pct", 0))
        rtt = max(0.4, random.gauss(base, jit / 2))
        if random.random() * 100 < loss:
            return {"rtt_ms": rtt, "loss_pct": 100.0, "jitter_ms": jit,
                    "ok": False, "method": "sim", "detail": "sim loss"}
        return {"rtt_ms": round(rtt, 2), "loss_pct": loss,
                "jitter_ms": round(abs(random.gauss(jit, jit / 3)), 2),
                "ok": True, "method": "sim", "detail": None}


_real_registry["sim"] = SimAdapter


def get_adapter(tunnel: dict, executor=None, force_sim: bool | None = None):
    from .. import db as dbm
    sim_mode = force_sim
    if sim_mode is None:
        try:
            sim_mode = bool(dbm.get_settings().get("sim_mode"))
        except Exception:
            sim_mode = False  # DB not initialized yet -> production mode
    engine = tunnel.get("engine", "sim")
    if sim_mode or engine == "sim":
        return SimAdapter(tunnel, executor)
    cls = _real_registry.get(engine)
    if cls is None:
        raise ValueError(f"unknown engine: {engine}")
    return cls(tunnel, executor)


def registry() -> dict[str, type[EngineAdapter]]:
    return dict(_real_registry)


# API-facing alias (registry snapshot at import time)
ENGINE_REGISTRY = dict(_real_registry)
