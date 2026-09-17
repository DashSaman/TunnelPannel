"""TunnelGuard — failover finite state machine.

Guarantees / semantics (all operator-tunable, see config.DEFAULT_SETTINGS):

 mode=auto    -> active tunnel is chosen by weighted health score.
                 * hard failure: N consecutive bad probe cycles => switch
                   to best surviving candidate (cooldown-gated).
                 * proactive: a candidate that beats the active score by
                   `hysteresis_margin` for `proactive_k` consecutive cycles
                   triggers a guarded switch (anti-flap budget applies).
 mode=manual  -> active is operator-pinned; the FSM never overrides until
                 auto is re-enabled. One-click manual switching from UI.

 Anti-flapping: sliding window `flap_window_s` with max `flap_max_switches`
 switches; exceeding it engages `flap_lock_s` during which auto switching
 pauses UNLESS the current active is dead (safety override, logged critical).

 Everything is persisted (db.state) so restarts resume deterministically.
"""
from __future__ import annotations

import json
import threading
import time

from . import config, db as dbm
from . import probes, routing
from .engines import get_adapter
from .engines import SimAdapter


class FlapLocked(RuntimeError):
    pass


class FailoverEngine:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._streaks: dict[int, int] = {}       # tunnel_id -> consecutive bad
        self._better_streak: dict[int, int] = {} # candidate_id -> how long better
        self._switches: list[float] = []         # timestamps of switches
        self._flap_lock_until = 0.0
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.sim_clock_offset = 0.0              # tests can fast-forward
        self.listeners: list = []                # callables(dict) for WS

    # ------------------------------------------------------------ helpers
    def _broadcast(self, event: dict) -> None:
        for fn in list(self.listeners):
            try:
                fn(event)
            except Exception:
                pass

    def _settings(self) -> dict:
        return dbm.get_settings()

    def _now(self) -> float:
        return time.time() + self.sim_clock_offset

    def recent_switch_count(self) -> int:
        with self._lock:
            s = self._settings()
            cut = self._now() - float(s.get("flap_window_s", 300))
            return len([t for t in self._switches if t >= cut])

    def is_flap_locked(self) -> bool:
        with self._lock:
            return self._now() < self._flap_lock_until

    # ------------------------------------------------------------ probing
    def probe_tunnel(self, tunnel: dict) -> dict:
        s = self._settings()
        adapter = get_adapter(tunnel)
        if isinstance(adapter, SimAdapter):
            row = adapter.synthetic_probe()
            row["ts"] = self._now()
            row["tunnel_id"] = tunnel["id"]
            return row
        row = adapter._probe_cycle()
        row["ts"] = self._now()
        row["tunnel_id"] = tunnel["id"]
        row.setdefault("method", "icmp")
        return row

    def _record_probe(self, row: dict) -> None:
        with dbm.tx() as d:
            d.execute(
                "INSERT INTO probes(tunnel_id,ts,rtt_ms,loss_pct,jitter_ms,method,ok,detail)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (row["tunnel_id"], row["ts"], row.get("rtt_ms"),
                 row.get("loss_pct", 100.0), row.get("jitter_ms"),
                 row.get("method", "icmp"), 1 if row.get("ok") else 0,
                 row.get("detail")))
        bucket = int(row["ts"] // 60 * 60)
        with dbm.tx() as d:
            d.execute(
                "INSERT INTO rollup(tunnel_id,bucket,rtt_ms,loss_pct,jitter_ms)"
                " VALUES(?,?,?,?,?) ON CONFLICT(tunnel_id,bucket) DO UPDATE SET"
                " rtt_ms=excluded.rtt_ms, loss_pct=excluded.loss_pct,"
                " jitter_ms=excluded.jitter_ms",
                (row["tunnel_id"], bucket, row.get("rtt_ms"),
                 row.get("loss_pct", 100.0), row.get("jitter_ms")))

    # ------------------------------------------------------------ cycling
    def run_once(self) -> dict:
        """One probe+decision cycle. Returns a summary dict (testable)."""
        with self._lock:
            s = self._settings()
            tunnels = [t for t in dbm.list_tunnels(include_disabled=False)]
            if not tunnels:
                return {"action": "none", "reason": "no enabled tunnels"}
            state = dbm.get_state()
            mode = state["mode"]

            # ---- probe everything
            results: dict[int, dict] = {}
            for t in tunnels:
                row = self.probe_tunnel(t)
                self._record_probe(row)
                results[t["id"]] = row

            # ---- streaks
            for t in tunnels:
                ok = results[t["id"]].get("ok")
                streak = self._streaks.get(t["id"], 0)
                streak = 0 if ok else streak + 1
                self._streaks[t["id"]] = streak

            active_id = state["active_tunnel_id"]
            active = next((t for t in tunnels if t["id"] == active_id), None)

            # ---- windows & scores
            ws = {t["id"]: _window_for(t["id"]) for t in tunnels}
            scores = {tid: w["score"] for tid, w in ws.items()}
            fail_thr = int(s.get("fail_threshold", 3))

            if mode == "manual":
                pinned = state["pinned_tunnel_id"]
                if pinned and (active is None or active["id"] != pinned):
                    t = next((x for x in tunnels if x["id"] == pinned), None)
                    if t:
                        return self._do_switch(t, "manual_pin")
                return {"action": "hold", "reason": "manual mode",
                        "active": active_id, "scores": scores}

            # -------------------------------------------------- auto mode
            # routing capability guard: a tunnel the kernel cannot route
            # through (e.g. Hedioum in SOCKS-only mode) must never carry
            # the virtual IP — it stays probe-monitored on the dashboard.
            alive = [t for t in tunnels
                     if self._streaks[t["id"]] < fail_thr and self._routing_ok(t)]
            if not alive:
                nonrouting = [t for t in tunnels
                              if self._streaks[t["id"]] < fail_thr]
                if nonrouting:
                    self._event("error", "no_routable_tunnel",
                                "Probes pass but no tunnel is routable "
                                "(proxy-mode tunnels need TUN to carry the "
                                "virtual IP); holding last active")
                    return {"action": "hold", "reason": "no routable tunnel",
                            "scores": scores}
                self._event("critical", "all_tunnels_down",
                            "All tunnels failing probes; holding last active")
                return {"action": "hold", "reason": "all tunnels down",
                        "scores": scores}

            if active is None or self._streaks[active["id"]] >= fail_thr:
                if active is not None and self.is_flap_locked():
                    self._event("critical", "switch_under_flap_lock",
                                f"Active tunnel {active['name']} dead during "
                                "flap-lock — emergency switch")
                best = max(alive, key=lambda t: scores[t["id"]])
                return self._do_switch(best, "active_dead" if active else "first_pick")

            # proactive guarded upgrade
            if s.get("proactive_switch_enabled", True):
                cooldown = float(s.get("cooldown_s", 60))
                margin = float(s.get("hysteresis_margin", 8.0))
                k = int(s.get("proactive_k", 5))
                flap_budget = self._flap_budget_ok(s)
                now = self._now()
                last_sw = state["last_switch_ts"] or 0.0
                if flap_budget and (now - last_sw) >= cooldown:
                    best = max(alive, key=lambda t: scores[t["id"]])
                    if best["id"] != active["id"]:
                        if scores[best["id"]] >= scores[active["id"]] + margin:
                            self._better_streak[best["id"]] = \
                                self._better_streak.get(best["id"], 0) + 1
                            if self._better_streak[best["id"]] >= k:
                                return self._do_switch(
                                    best, "proactive_upgrade",
                                    detail=f"score {scores[best['id']]} >= "
                                           f"{scores[active['id']]}+{margin} "
                                           f"for {k} cycles")
                        else:
                            self._better_streak[best["id"]] = 0
            return {"action": "hold", "reason": "healthy", "active": active["id"],
                    "scores": scores}

    def _routing_ok(self, tunnel: dict) -> bool:
        try:
            return bool(getattr(get_adapter(tunnel), "routing_capable", True))
        except Exception:
            return True

    def _flap_budget_ok(self, s: dict) -> bool:
        if self.is_flap_locked():
            return False
        if self.recent_switch_count() > int(s.get("flap_max_switches", 4)):
            self._flap_lock_until = self._now() + float(s.get("flap_lock_s", 900))
            self._event("critical", "flap_lock",
                        f"More than {s.get('flap_max_switches')} switches in "
                        f"{s.get('flap_window_s')}s — auto switching paused "
                        f"{s.get('flap_lock_s')}s")
            return False
        return True

    # ------------------------------------------------------------ switching
    def _do_switch(self, target: dict, reason: str, detail: str = "") -> dict:
        s = self._settings()
        state = dbm.get_state()
        prev = dbm.get_tunnel(state["active_tunnel_id"]) \
            if state["active_tunnel_id"] else None
        sim = routing.SimulatedSystem() if s.get("sim_mode") else None
        try:
            done = routing.activate_tunnel_routes(target, prev, sim=sim)
        except Exception as e:
            done = [f"routing error: {e}"]
        with self._lock:
            self._switches.append(self._now())
            self._better_streak[target["id"]] = 0
        dbm.update_state(active_tunnel_id=target["id"],
                         last_switch_ts=self._now())
        msg = (f"ACTIVE -> {target['name']} ({reason})"
               + (f" — {detail}" if detail else ""))
        self._event("warn", "switch", msg, target["id"])
        out = {"action": "switch", "reason": reason, "new_active": target["id"],
               "prev": prev["id"] if prev else None,
               "routing": done, "detail": detail}
        self._broadcast({"type": "switch", **out})
        return out

    def _event(self, level, type_, msg, tid=None):
        ev = dbm.add_event(level, type_, msg, tid)
        self._broadcast({"type": "event", **ev})

    # ------------------------------------------------------------ public API
    def set_mode(self, mode: str, pinned_tunnel_id: int | None = None) -> dict:
        if mode not in ("auto", "manual"):
            raise ValueError("mode must be auto|manual")
        dbm.update_state(mode=mode, pinned_tunnel_id=pinned_tunnel_id)
        self._event("info", "mode", f"Mode -> {mode}"
                    + (f" (pinned #{pinned_tunnel_id})" if pinned_tunnel_id else ""))
        if mode == "auto":
            self._better_streak.clear()
            out = {"mode": mode, "pinned": pinned_tunnel_id}
        elif pinned_tunnel_id:
            # one-click semantics: pinning an active tunnel switches NOW
            t = dbm.get_tunnel(pinned_tunnel_id)
            if not t:
                raise ValueError("tunnel not found")
            out = self._do_switch(t, "manual_pin")
            out["mode"] = mode
        else:
            out = {"mode": mode, "pinned": pinned_tunnel_id}
        self._broadcast({"type": "mode", **out})
        return out

    def manual_switch(self, tunnel_id: int) -> dict:
        state = dbm.get_state()
        t = dbm.get_tunnel(tunnel_id)
        if not t:
            raise ValueError("tunnel not found")
        dbm.update_state(pinned_tunnel_id=tunnel_id, mode="manual")
        out = self._do_switch(t, "manual_click")
        out["mode"] = "manual"
        return out

    def mark_tunnel_updown(self, tunnel_id: int, up: bool) -> list[str]:
        t = dbm.get_tunnel(tunnel_id)
        if not t:
            raise ValueError("tunnel not found")
        adapter = get_adapter(t)
        cmds = adapter.up() if up else adapter.down()
        self._event("info", "tunnel_up" if up else "tunnel_down",
                    f"{t['name']} {'up' if up else 'down'}: {cmds[-1] if cmds else ''}",
                    tunnel_id)
        return cmds

    def reset_flap_lock(self) -> None:
        with self._lock:
            self._flap_lock_until = 0.0
            self._switches.clear()
        self._event("info", "flap_unlock", "Flap lock reset by operator")

    # ------------------------------------------------------------ throughput
    def sample_throughput(self) -> list[dict]:
        s = self._settings()
        out = []
        for t in dbm.list_tunnels(include_disabled=False):
            if t["engine"] == "sim" or s.get("sim_mode"):
                rx = random.gauss(2_000_000, 400_000)
                tx = random.gauss(1_000_000, 300_000)
                row = {"tunnel_id": t["id"], "ts": self._now(),
                       "rx_bps": max(0, rx), "tx_bps": max(0, tx)}
            else:
                adapter = get_adapter(t)
                counters = adapter.status().get("extra") or {}
                rx = counters.get("rx_bytes")
                tx = counters.get("tx_bytes")
                prev = _prev_counters(t["id"])
                if rx is None or not prev:
                    row = {"tunnel_id": t["id"], "ts": self._now(),
                           "rx_bps": 0, "tx_bps": 0}
                else:
                    dt = max(1.0, self._now() - prev["ts"])
                    row = {"tunnel_id": t["id"], "ts": self._now(),
                           "rx_bps": max(0, (rx - prev["rx"]) / dt),
                           "tx_bps": max(0, (tx - prev["tx"]) / dt)}
                _prev_counters_store(t["id"], rx or 0, tx or 0, self._now())
            with dbm.tx() as d:
                d.execute("INSERT OR REPLACE INTO throughput(tunnel_id,ts,rx_bps,tx_bps)"
                          " VALUES(?,?,?,?)",
                          (row["tunnel_id"], row["ts"], row["rx_bps"], row["tx_bps"]))
            out.append(row)
        return out

    # ------------------------------------------------------------ threads
    def start(self) -> None:
        if self._threads:
            return
        t1 = threading.Thread(target=self._probe_loop, name="tg-probe", daemon=True)
        t2 = threading.Thread(target=self._throughput_loop, name="tg-bw", daemon=True)
        self._threads = [t1, t2]
        t1.start()
        t2.start()

    def stop(self) -> None:
        self._stop.set()

    def _probe_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as e:
                self._event("error", "loop_error", f"probe loop: {e}")
            try:
                dbm.trim_probes()
            except Exception:
                pass
            self._stop.wait(max(1, int(self._settings().get("probe_interval_s", 3))))

    def _throughput_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.sample_throughput()
            except Exception:
                pass
            self._stop.wait(max(2, int(self._settings().get("throughput_sample_s", 5))))


_prev_counters_mem: dict[int, dict] = {}


def _prev_counters(tid: int) -> dict | None:
    return _prev_counters_mem.get(tid)


def _prev_counters_store(tid: int, rx: int, tx: int, ts: float) -> None:
    _prev_counters_mem[tid] = {"rx": rx, "tx": tx, "ts": ts}


def _window_for(tid: int) -> dict:
    s = dbm.get_settings()
    rows = dbm.db().execute(
        "SELECT ts,rtt_ms,loss_pct,jitter_ms,ok FROM probes WHERE tunnel_id=? "
        "ORDER BY id DESC LIMIT 40", (tid,)).fetchall()
    return probes.stats_from_rows([dict(r) for r in reversed(rows)], s,
                                  _recent_count())


def _recent_count() -> int:
    with engine._lock:
        s = engine._settings()
        cut = engine._now() - float(s.get("flap_window_s", 300))
        return len([t for t in engine._switches if t >= cut])


# module-level singleton
engine = FailoverEngine()
