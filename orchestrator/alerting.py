"""Alert engine (P12 §18-§21): deterministic rules, severities, dedupe
with notification cooldown, resolution with duration. One active incident
per dedupe key — recurring failures update it instead of storming
Telegram."""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field

INFO, WARNING, CRITICAL = "INFO", "WARNING", "CRITICAL"

ALERT_KINDS = (
    "NODE_DOWN", "TUNNEL_DOWN", "CHAIN_DOWN", "PATH_DOWN", "DEGRADED",
    "HIGH_LOSS", "HIGH_JITTER", "HIGH_LATENCY", "FREQUENT_FAILOVER",
    "FLAP_LOCK", "RESOURCE_CONFLICT", "ORPHANED_RESOURCE", "DRIFT",
    "BACKUP_FAILURE", "CERTIFICATE_EXPIRY", "INSTALL_UPGRADE_FAILURE",
)


@dataclass
class AlertThresholds:
    loss_pct: float = 5.0
    jitter_ms: float = 50.0
    rtt_ms: float = 500.0
    failover_per_hour: int = 5
    degraded_streak: int = 3


DEFAULT_THRESHOLDS = AlertThresholds()


# ── deterministic rules (§18) ──────────────────────────────────────────

def evaluate_health(target: str, kind_hint: str,
                    samples: list[dict], t: AlertThresholds | None = None) -> list[tuple[str, str]]:
    """Pure rule evaluation over recent lightweight samples →
    [(alert_kind, severity), ...]. samples: [{ok, rtt_ms, jitter_ms, loss_pct}]."""
    t = t or DEFAULT_THRESHOLDS
    out: list[tuple[str, str]] = []
    if not samples:
        return out
    down_kind = {"node": "NODE_DOWN", "tunnel": "TUNNEL_DOWN",
                 "chain": "CHAIN_DOWN", "path": "PATH_DOWN"}.get(kind_hint, "TUNNEL_DOWN")
    recent_bad = sum(1 for s in samples if not s.get("ok", True))
    if recent_bad and recent_bad == len(samples):
        out.append((down_kind, CRITICAL))
    elif recent_bad >= t.degraded_streak:
        out.append(("DEGRADED", WARNING))
    losses = [s["loss_pct"] for s in samples if s.get("loss_pct") is not None]
    if losses and max(losses) >= t.loss_pct:
        out.append(("HIGH_LOSS", WARNING if max(losses) < 2 * t.loss_pct else CRITICAL))
    jitters = [s["jitter_ms"] for s in samples if s.get("jitter_ms") is not None]
    if jitters and max(jitters) >= t.jitter_ms:
        out.append(("HIGH_JITTER", WARNING))
    rtts = [s["rtt_ms"] for s in samples if s.get("rtt_ms") is not None]
    if rtts and max(rtts) >= t.rtt_ms:
        out.append(("HIGH_LATENCY", WARNING))
    return out


# ── incident lifecycle with dedupe + cooldown (§20, §21) ───────────────

@dataclass
class Incident:
    key: str
    kind: str
    severity: str
    first_seen: float
    last_seen: float
    occurrences: int = 1
    resolved_at: float | None = None
    last_notified: float | None = None
    evidence: str = ""


@dataclass
class Notification:
    incident: Incident
    text: str
    is_resolution: bool = False


@dataclass
class AlertEngine:
    notification_cooldown_s: float = 900.0      # 15 min per incident key
    thresholds: AlertThresholds = field(default_factory=AlertThresholds)
    _active: dict[str, Incident] = field(default_factory=dict)

    def evaluate(self, key: str, kind: str, severity: str, ts: float,
                 evidence: str = "") -> list[Notification]:
        """Feed one observation; returns notifications to deliver."""
        notifications: list[Notification] = []
        existing = self._active.get(key)
        if existing is not None and existing.resolved_at is None:
            existing.last_seen = ts
            existing.occurrences += 1
            if severity == CRITICAL and existing.severity != CRITICAL:
                existing.severity = CRITICAL      # escalation updates the incident
        else:
            incident = Incident(key=key, kind=kind, severity=severity,
                                first_seen=ts, last_seen=ts, evidence=evidence)
            self._active[key] = incident
            existing = incident
        if existing.last_notified is None or ts - existing.last_notified >= self.notification_cooldown_s:
            existing.last_notified = ts
            notifications.append(Notification(
                existing,
                f"[{existing.severity}] {existing.kind} on {key} "
                f"(x{existing.occurrences}) {evidence}".strip()))
        return notifications

    def resolve(self, key: str, ts: float, evidence: str = "condition cleared") -> Notification | None:
        incident = self._active.get(key)
        if incident is None or incident.resolved_at is not None:
            return None
        incident.resolved_at = ts
        duration = ts - incident.first_seen
        return Notification(
            incident,
            f"[RESOLVED] {incident.kind} on {key} after {duration:.0f}s "
            f"({incident.occurrences} occurrences) — {evidence}",
            is_resolution=True)

    def active(self) -> list[Incident]:
        return [i for i in self._active.values() if i.resolved_at is None]

    def sweep_resolution(self, key: str, condition_ok: bool, ts: float) -> Notification | None:
        """Convenience: resolve when the underlying condition is healthy."""
        if condition_ok:
            return self.resolve(key, ts)
        return None


# ── switch/failover → alert mapping (§18 FREQUENT_FAILOVER) ───────────

def failover_alerts(switch_times: list[float], now: float,
                    thresholds: AlertThresholds | None = None) -> list[tuple[str, str]]:
    t = thresholds or DEFAULT_THRESHOLDS
    hour_ago = now - 3600.0
    recent = [x for x in switch_times if x >= hour_ago]
    if len(recent) >= t.failover_per_hour:
        return [("FREQUENT_FAILOVER", CRITICAL if len(recent) >= 2 * t.failover_per_hour else WARNING)]
    return []
