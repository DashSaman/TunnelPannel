"""TunnelGuard — SQLite persistence layer (WAL mode).

Tables:
  users            dashboard operators (pbkdf2 hashes)
  tunnels          tunnel definitions + engine configs (JSON)
  probes           raw probe samples (ring-trimmed)
  rollup           per-minute aggregates for charts
  throughput       rx/tx bps samples
  events           audit / failover event log
  settings         key/value runtime settings
  state            singleton failover state (mode, active, history)
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager

from . import config

_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'admin',
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tunnels(
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  engine TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  priority INTEGER NOT NULL DEFAULT 100,
  iface TEXT NOT NULL,
  local_ip TEXT,            -- source IP inside the tunnel
  remote_ip TEXT,           -- peer IP inside the tunnel (probe target)
  remote_lan TEXT,          -- optional network routed via tunnel (split mode)
  remote_host TEXT,         -- public endpoint of the peer
  mtu INTEGER,
  config TEXT NOT NULL DEFAULT '{}',   -- engine-specific options (JSON)
  remote_ssh TEXT NOT NULL DEFAULT '{}', -- peer creds for route sync (JSON, encrypted)
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS probes(
  id INTEGER PRIMARY KEY,
  tunnel_id INTEGER NOT NULL,
  ts REAL NOT NULL,
  rtt_ms REAL,              -- avg rtt of the cycle (NULL when dead)
  loss_pct REAL NOT NULL,
  jitter_ms REAL,
  method TEXT NOT NULL DEFAULT 'icmp',   -- icmp | tcp | sim
  ok INTEGER NOT NULL,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS ix_probes_tid_ts ON probes(tunnel_id, ts);
CREATE TABLE IF NOT EXISTS rollup(
  tunnel_id INTEGER NOT NULL,
  bucket INTEGER NOT NULL,   -- epoch seconds truncated to minute
  rtt_ms REAL, loss_pct REAL, jitter_ms REAL,
  PRIMARY KEY(tunnel_id, bucket)
);
CREATE TABLE IF NOT EXISTS throughput(
  tunnel_id INTEGER NOT NULL,
  ts REAL NOT NULL,
  rx_bps REAL NOT NULL,
  tx_bps REAL NOT NULL,
  PRIMARY KEY(tunnel_id, ts)
);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY,
  ts REAL NOT NULL,
  level TEXT NOT NULL,       -- info | warn | error | critical
  type TEXT NOT NULL,        -- switch | flap_lock | tunnel_down | ...
  tunnel_id INTEGER,
  message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL        -- JSON encoded
);
CREATE TABLE IF NOT EXISTS state(
  id INTEGER PRIMARY KEY CHECK (id = 1),
  mode TEXT NOT NULL DEFAULT 'auto',
  active_tunnel_id INTEGER,
  pinned_tunnel_id INTEGER,
  last_switch_ts REAL DEFAULT 0,
  updated_at REAL NOT NULL DEFAULT 0
);
"""


def connect() -> sqlite3.Connection:
    con = sqlite3.connect(config.DB_PATH, timeout=15, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=10000")
    return con


_conn: sqlite3.Connection | None = None


def db() -> sqlite3.Connection:
    global _conn
    with _lock:
        if _conn is None:
            _conn = connect()
        return _conn


def init() -> None:
    d = db()
    d.executescript(SCHEMA)
    # default settings
    for k, v in config.DEFAULT_SETTINGS.items():
        d.execute(
            "INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)",
            (k, json.dumps(v)),
        )
    d.execute(
        "INSERT OR IGNORE INTO state(id, mode, updated_at) VALUES(1,'auto',?)",
        (time.time(),),
    )
    d.commit()


@contextmanager
def tx():
    d = db()
    try:
        yield d
        d.commit()
    except Exception:
        d.rollback()
        raise


# ------------------------------------------------------------------ helpers
def get_settings() -> dict:
    rows = db().execute("SELECT key,value FROM settings").fetchall()
    out = dict(config.DEFAULT_SETTINGS)
    for r in rows:
        try:
            out[r["key"]] = json.loads(r["value"])
        except (json.JSONDecodeError, TypeError):
            pass
    return out


def set_settings(patch: dict) -> None:
    with tx() as d:
        for k, v in patch.items():
            d.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (k, json.dumps(v)),
            )


def get_state() -> sqlite3.Row:
    return db().execute("SELECT * FROM state WHERE id=1").fetchone()


def update_state(**kw) -> None:
    if not kw:
        return
    kw["updated_at"] = time.time()
    cols = ",".join(f"{k}=?" for k in kw)
    with tx() as d:
        d.execute(f"UPDATE state SET {cols} WHERE id=1", tuple(kw.values()))


def add_event(level: str, type_: str, message: str, tunnel_id=None) -> dict:
    ev = {"ts": time.time(), "level": level, "type": type_,
          "tunnel_id": tunnel_id, "message": message}
    with tx() as d:
        d.execute(
            "INSERT INTO events(ts,level,type,tunnel_id,message) VALUES(?,?,?,?,?)",
            (ev["ts"], level, type_, tunnel_id, message),
        )
        # trim
        d.execute("DELETE FROM events WHERE id < (SELECT MAX(id)-5000 FROM events)")
    return ev


def list_tunnels(include_disabled: bool = True) -> list[dict]:
    q = "SELECT * FROM tunnels"
    if not include_disabled:
        q += " WHERE enabled=1"
    rows = db().execute(q + " ORDER BY priority, id").fetchall()
    return [dict(r) for r in rows]


def get_tunnel(tid: int) -> dict | None:
    r = db().execute("SELECT * FROM tunnels WHERE id=?", (tid,)).fetchone()
    return dict(r) if r else None


def trim_probes(keep_seconds: int = 6 * 3600) -> None:
    cut = time.time() - keep_seconds
    with tx() as d:
        d.execute("DELETE FROM probes WHERE ts < ?", (cut,))
        d.execute("DELETE FROM throughput WHERE ts < ?", (cut,))
        d.execute("DELETE FROM rollup WHERE bucket < ?", (cut - 4 * 3600,))
