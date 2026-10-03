"""Failover engine (P10 §37-§56).

Operator-selected membership is LAW: nothing unselected can ever be
activated. FSM semantics distilled from the proven TunnelGuard engine
(streaks, cooldown, sliding-window anti-flap with flap lock, emergency
override, preemption modes) plus canonical additions: component-level
repair before chain abandonment, underlay-failure propagation, shared
failure-domain warnings and decision receipts (AUTO/OPERATOR/EMERGENCY).
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ── configuration ──────────────────────────────────────────────────────


@dataclass
class FailoverPolicy:
    mode: str = "MANUAL_PRIORITY"            # MANUAL_PRIORITY | SCORE_PRIORITY
    preemption: str = "NO_PREEMPT"           # NO_PREEMPT | PREFER_PRIMARY | BEST_SCORE
    failure_threshold: int = 3               # consecutive bad probes to fail
    recovery_threshold: int = 3              # consecutive good probes to recover
    cooldown_s: float = 30.0                  # suppress non-emergency switches
    hysteresis_margin: float = 5.0            # BEST_SCORE improvement margin
    max_switches_per_window: int = 3
    flap_window_s: float = 300.0
    flap_lock_s: float = 120.0
    prefer_primary_recovery_s: float = 60.0


# ── decision receipts (§56) ────────────────────────────────────────────

@dataclass
class SwitchReceipt:
    frm: str
    to: str
    reason: str
    actor: str                                # AUTO | OPERATOR | EMERGENCY
    health_evidence: dict = field(default_factory=dict)
    threshold_state: dict = field(default_factory=dict)
    cooldown_state: dict = field(default_factory=dict)
    shared_failure_context: dict = field(default_factory=dict)
    ts: float = 0.0


@dataclass
class MemberRuntime:
    member_id: str
    candidate: str
    priority: int
    score: float | None = None
    maintenance: bool = False
    ok: bool | None = None
    bad_streak: int = 0
    good_streak: int = 0
    last_probe_ts: float = 0.0


class FailoverController:
    """Pure decision engine — no I/O, fully testable. Persistence of groups
    lives in the service layer; probes feed on_probe()."""

    def __init__(self, members: list[MemberRuntime], policy: FailoverPolicy | None = None,
                 now: float = 0.0):
        if not members:
            raise ValueError("a failover group needs at least one member")
        self.policy = policy or FailoverPolicy()
        self.members: dict[str, MemberRuntime] = {m.member_id: m for m in members}
        self.active: str = self._first_choice(now)
        self.pinned: str | None = None
        self.switch_receipts: list[SwitchReceipt] = []
        self._last_switch_ts: float | None = None
        self._flap_lock_until: float | None = None
        self._switch_times: list[float] = []
        self.now = now
        self._best_score_seen: dict[str, float] = {}

    # ── membership ──
    def _ordered(self) -> list[MemberRuntime]:
        if self.policy.mode == "SCORE_PRIORITY":
            eligible = [m for m in self.members.values()
                        if self._available(m) and m.score is not None]
            return sorted(eligible, key=lambda m: (-m.score, m.priority, m.member_id))
        return sorted(self.members.values(), key=lambda m: (m.priority, m.member_id))

    def _available(self, m: MemberRuntime) -> bool:
        return not m.maintenance and (m.ok is not False) and m.bad_streak < self.policy.failure_threshold

    def _first_choice(self, now: float) -> str:
        for m in self._ordered():
            if self._available(m):
                return m.member_id
        return min(self.members.values(), key=lambda m: (m.priority, m.member_id)).member_id

    # ── probes (§43, §44) ──
    def on_probe(self, member_id: str, ok: bool, ts: float | None = None) -> None:
        m = self.members[member_id]
        m.ok = ok
        m.last_probe_ts = self.now if ts is None else ts
        if ok:
            m.good_streak += 1
            m.bad_streak = 0
        else:
            m.bad_streak += 1
            m.good_streak = 0

    def set_score(self, member_id: str, score: float) -> None:
        self.members[member_id].score = score
        self._best_score_seen[member_id] = score

    def is_failed(self, member_id: str) -> bool:
        return self.members[member_id].bad_streak >= self.policy.failure_threshold

    def is_recovered(self, member_id: str) -> bool:
        return self.members[member_id].good_streak >= self.policy.recovery_threshold

    # ── anti-flap (§47) ──
    def _flap_blocked(self) -> bool:
        return self._flap_lock_until is not None and self.now < self._flap_lock_until

    def _record_switch_time(self) -> None:
        self._switch_times = [t for t in self._switch_times
                              if self.now - t <= self.policy.flap_window_s]
        self._switch_times.append(self.now)
        if len(self._switch_times) > self.policy.max_switches_per_window:
            self._flap_lock_until = self.now + self.policy.flap_lock_s
            self._switch_times = []

    def _cooldown_active(self) -> bool:
        return (self._last_switch_ts is not None
                and self.now - self._last_switch_ts < self.policy.cooldown_s)

    def _switch(self, to: str, reason: str, actor: str,
                evidence: dict | None = None) -> SwitchReceipt:
        frm = self.active
        self.active = to
        self._last_switch_ts = self.now
        self._record_switch_time()
        receipt = SwitchReceipt(
            frm=frm, to=to, reason=reason, actor=actor,
            health_evidence=evidence or {"bad_streak": self.members[frm].bad_streak,
                                         "good_streak": self.members[to].good_streak},
            threshold_state={"failure_threshold": self.policy.failure_threshold,
                             "recovery_threshold": self.policy.recovery_threshold},
            cooldown_state={"cooldown_s": self.policy.cooldown_s,
                            "flap_locked": self._flap_blocked()},
            ts=self.now)
        self.switch_receipts.append(receipt)
        return receipt

    # ── main decision point ──
    def decide(self) -> SwitchReceipt | None:
        active = self.members[self.active]

        # manual pin overrides everything until released (§54)
        if self.pinned:
            if self.active != self.pinned:
                return self._switch(self.pinned, "manual pin", "OPERATOR")
            return None

        # maintenance: active in maintenance must move off it (§55)
        if active.maintenance:
            replacement = self._next_available()
            if replacement:
                return self._switch(replacement, "active in maintenance", "OPERATOR")
            return None

        # active hard-failed → EMERGENCY path bypasses cooldown/flap (§48)
        if self.is_failed(self.active):
            replacement = self._next_available()
            if replacement is None:
                return None
            emergency = active.ok is False
            if emergency or not (self._cooldown_active() or self._flap_blocked()):
                return self._switch(
                    replacement,
                    f"active failed ({active.bad_streak} consecutive bad probes)",
                    "EMERGENCY" if emergency else "AUTO")
            return None

        # preemption (§53)
        if self.policy.preemption == "PREFER_PRIMARY":
            primary = self._ordered()[0] if self._ordered() else None
            if primary and primary.member_id != self.active \
                    and self.is_recovered(primary.member_id) \
                    and self.now - (self._last_switch_ts or 0) >= self.policy.prefer_primary_recovery_s:
                if not (self._cooldown_active() or self._flap_blocked()):
                    return self._switch(primary.member_id,
                                        "primary recovered for the stable window", "AUTO")
        elif self.policy.preemption == "BEST_SCORE":
            best = self._ordered()[0] if self._ordered() else None
            if best and best.member_id != self.active and best.score is not None \
                    and active.score is not None:
                margin = best.score - active.score
                if margin >= self.policy.hysteresis_margin \
                        and self.is_recovered(best.member_id) \
                        and not (self._cooldown_active() or self._flap_blocked()):
                    return self._switch(best.member_id,
                                        f"score margin {margin:.1f} >= "
                                        f"{self.policy.hysteresis_margin}", "AUTO")
        return None

    def _next_available(self) -> str | None:
        for m in self._ordered():
            if m.member_id != self.active and self._available(m):
                return m.member_id
        return None

    # ── operator actions ──
    def advance(self, seconds: float) -> None:
        """Move the controller clock (tests / offline simulation)."""
        self.now += seconds

    def pin(self, member_id: str | None) -> None:
        assert member_id is None or member_id in self.members
        self.pinned = member_id

    def set_maintenance(self, member_id: str, on: bool) -> None:
        self.members[member_id].maintenance = on

    def reset_flap(self) -> None:
        self._flap_lock_until = None
        self._switch_times = []


# ── component repair before abandonment (§49) ─────────────────────────

@dataclass
class RepairDecision:
    action: str            # REPAIR_COMPONENT | SWITCH_CHAIN | NO_ACTION
    component: str | None
    reason: str


def decide_repair(failed_components: list[str], healthy_components: list[str],
                  repair_attempts: int = 0, max_repair_attempts: int = 2) -> RepairDecision:
    """FRP failed, WireGuard healthy → repair only FRP; never destroy the
    healthy underlay. Give up on the chain only when repair budget is out."""
    if not failed_components:
        return RepairDecision("NO_ACTION", None, "chain healthy")
    if healthy_components:
        if repair_attempts < max_repair_attempts:
            return RepairDecision("REPAIR_COMPONENT", failed_components[0],
                                  f"underlay {healthy_components} healthy — "
                                  f"repair only the failed overlay component")
        return RepairDecision("SWITCH_CHAIN", None,
                              f"repair budget exhausted ({repair_attempts} attempts)")
    return RepairDecision("SWITCH_CHAIN", None, "underlay itself failed — chain dead")


# ── underlay failure propagation (§50) ─────────────────────────────────

def propagate_underlay_failure(chain_components: dict[str, str],
                               failed: str) -> list[str]:
    """chain_components: component_id -> parent_id (None = underlay root).
    When `failed` dies, every transitive rider is DEPENDENCY_FAILED — no
    independent probing needed."""
    riders: set[str] = set()
    changed = True
    while changed:
        changed = False
        for cid, parent in chain_components.items():
            if cid in riders or cid == failed:
                continue
            if parent == failed or parent in riders:
                riders.add(cid)
                changed = True
    return sorted(riders)


# ── diversity (§40, §41) ───────────────────────────────────────────────

def diversity_warnings(primary: ChainLike, backups: list[ChainLike]) -> list[dict]:
    from orchestrator.benchmarking.chains import shared_failure_domains
    out = []
    for backup in backups:
        d = shared_failure_domains(primary, backup)
        if d["warning"]:
            out.append({"backup": getattr(backup, "name", "backup"),
                        "warning": d["warning"],
                        "shared": d["shared_components"]})
    return out


def diversity_recommendation(primary: ChainLike, backups: list[ChainLike]) -> str | None:
    """Deterministic suggestion only — never overrides the operator."""
    from orchestrator.benchmarking.chains import shared_failure_domains
    best, best_score = None, -1.0
    for backup in backups:
        d = shared_failure_domains(primary, backup)
        if d["diversity_score"] > best_score:
            best, best_score = getattr(backup, "name", "backup"), d["diversity_score"]
    if best is not None:
        return f"{best} gives the highest path diversity (score {best_score})"
    return None


class ChainLike:                             # structural hint for type readers
    name: str
    components: list
