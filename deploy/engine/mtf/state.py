"""SQLite state store: methods, probes, events, settings, receipts."""
import json
import os
import sqlite3
import threading
import time

BASE = "/opt/multitunnel"
DB_PATH = os.path.join(BASE, "data", "mtf.db")
_lock = threading.Lock()


def conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _lock, conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS methods(
          id TEXT PRIMARY KEY,
          selected INTEGER DEFAULT 0,
          deployed INTEGER DEFAULT 0,
          state TEXT DEFAULT 'STOPPED',      -- UP DEGRADED DOWN STOPPED DEPLOYING ERROR
          detail TEXT DEFAULT '',
          updated REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS probes(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          method_id TEXT, ts REAL,
          rtt_ms REAL, loss_pct REAL, jitter_ms REAL, ok INTEGER
        );
        CREATE INDEX IF NOT EXISTS probes_mid ON probes(method_id, ts DESC);
        CREATE TABLE IF NOT EXISTS events(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts REAL, level TEXT, scope TEXT, msg TEXT
        );
        CREATE TABLE IF NOT EXISTS receipts(
          method_id TEXT PRIMARY KEY,
          ts REAL, verdict TEXT, evidence TEXT
        );
        CREATE TABLE IF NOT EXISTS settings(
          key TEXT PRIMARY KEY, value TEXT
        );
        """)
        defaults = {
            "mode": "auto",                 # auto | manual
            "manual_active": "",            # method id when manual
            "active": "",                   # current active method id
            "cooldown_s": "30",
            "hysteresis_n": "3",
            "loss_degraded": "20",          # %
            "loss_down": "60",
            "jitter_degraded": "80",        # ms
            "rtt_degraded": "600",          # ms
            "probe_interval_s": "5",
            "last_switch": "0",
        }
        for k, v in defaults.items():
            c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))


def get_setting(key: str, default: str = "") -> str:
    with _lock, conn() as c:
        r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return r["value"] if r else default


def set_setting(key: str, value: str):
    with _lock, conn() as c:
        c.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def all_settings() -> dict:
    with _lock, conn() as c:
        return {r["key"]: r["value"] for r in c.execute("SELECT * FROM settings")}


def event(level: str, scope: str, msg: str):
    with _lock, conn() as c:
        c.execute("INSERT INTO events(ts,level,scope,msg) VALUES(?,?,?,?)",
                  (time.time(), level, scope, msg))


def recent_events(limit: int = 200) -> list[dict]:
    with _lock, conn() as c:
        rows = c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


def ensure_methods(ids: list[str]):
    with _lock, conn() as c:
        for mid in ids:
            c.execute("INSERT OR IGNORE INTO methods(id) VALUES(?)", (mid,))


def set_method(mid: str, **fields):
    fields["updated"] = time.time()
    keys = ",".join(f"{k}=?" for k in fields)
    with _lock, conn() as c:
        c.execute(f"UPDATE methods SET {keys} WHERE id=?", (*fields.values(), mid))


def get_method(mid: str) -> dict | None:
    with _lock, conn() as c:
        r = c.execute("SELECT * FROM methods WHERE id=?", (mid,)).fetchone()
        return dict(r) if r else None


def all_methods() -> list[dict]:
    with _lock, conn() as c:
        rows = c.execute("SELECT * FROM methods ORDER BY id").fetchall()
        return [dict(r) for r in rows]


def save_probe(mid: str, rtt: float | None, loss: float, jitter: float, ok: bool):
    with _lock, conn() as c:
        c.execute("INSERT INTO probes(method_id,ts,rtt_ms,loss_pct,jitter_ms,ok) "
                  "VALUES(?,?,?,?,?,?)", (mid, time.time(), rtt, loss, jitter, int(ok)))
        c.execute("DELETE FROM probes WHERE method_id=? AND ts < ?",
                  (mid, time.time() - 3600))


def last_probe(mid: str) -> dict | None:
    with _lock, conn() as c:
        r = c.execute("SELECT * FROM probes WHERE method_id=? ORDER BY ts DESC LIMIT 1",
                      (mid,)).fetchone()
        return dict(r) if r else None


def save_receipt(mid: str, verdict: str, evidence: dict):
    with _lock, conn() as c:
        c.execute("INSERT INTO receipts(method_id,ts,verdict,evidence) VALUES(?,?,?,?) "
                  "ON CONFLICT(method_id) DO UPDATE SET ts=excluded.ts, "
                  "verdict=excluded.verdict, evidence=excluded.evidence",
                  (mid, time.time(), verdict, json.dumps(evidence, ensure_ascii=False)))


def all_receipts() -> list[dict]:
    with _lock, conn() as c:
        rows = c.execute("SELECT * FROM receipts ORDER BY ts DESC").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["evidence"] = json.loads(d["evidence"])
            except Exception:
                pass
            out.append(d)
        return out
