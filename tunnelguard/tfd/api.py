"""TunnelGuard — FastAPI application.

Routes
  GET  /api/health                 public liveness (installer wait-loop)
  POST /api/auth/login             username/password -> JWT
  GET  /api/me
  GET  /api/state                  mode, active tunnel, vip, flap status
  POST /api/mode                   {mode: auto|manual, pinned_tunnel_id?}
  POST /api/failover/switch/{tid}  manual one-click switch (pins manual)
  POST /api/failover/reset-flap
  GET  /api/tunnels                list + live window stats
  POST /api/tunnels                create
  PUT  /api/tunnels/{tid}          update
  DEL  /api/tunnels/{tid}
  POST /api/tunnels/{tid}/up       engine up   (root commands)
  POST /api/tunnels/{tid}/down     engine down
  POST /api/tunnels/{tid}/precheck engine precheck report
  GET  /api/tunnels/{tid}/config   rendered artifacts ("final config")
  GET  /api/metrics?tid&range      probes + throughput series
  GET  /api/events
  GET  /api/settings   PUT /api/settings
  GET  /api/engines                engine metadata (MTU table for the UI)
  WS   /ws?token=                  live state/probe/switch stream
"""
from __future__ import annotations

import json
import time

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from . import config, db as dbm, events, probes, routing, security
from .engines import ENGINE_REGISTRY, get_adapter
from .engines.base import AdapterError
from .failover import engine as fsm

app = FastAPI(title="TunnelGuard", version="1.2.0",
              docs_url="/docs", openapi_url="/openapi.json")
_bearer = HTTPBearer(auto_error=False)


# ------------------------------------------------------------------ auth
def current_user(creds: HTTPAuthorizationCredentials = Depends(_bearer)) -> dict:
    if creds is None:
        raise HTTPException(401, "missing bearer token")
    payload = security.decode_token(creds.credentials)
    if not payload:
        raise HTTPException(401, "invalid or expired token")
    return payload


def admin(user: dict = Depends(current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(403, "admin only")
    return user


@app.get("/api/health")
def health():
    return {"ok": True, "service": config.APP_NAME,
            "time": time.time(),
            "system": routing.system_health()}


class LoginIn(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
def login(body: LoginIn):
    row = dbm.db().execute(
        "SELECT * FROM users WHERE username=?", (body.username,)).fetchone()
    if not row or not security.verify_password(body.password, row["pw_hash"]):
        raise HTTPException(401, "invalid credentials")
    return {"token": security.create_token(row["username"], row["role"]),
            "username": row["username"], "role": row["role"]}


@app.get("/api/me")
def me(user: dict = Depends(current_user)):
    return {"username": user.get("sub"), "role": user.get("role")}


# ------------------------------------------------------------------ state
@app.get("/api/state")
def get_state(user: dict = Depends(current_user)):
    st = dict(dbm.get_state())
    s = dbm.get_settings()
    active = dbm.get_tunnel(st["active_tunnel_id"]) if st["active_tunnel_id"] else None
    if active:
        active = {k: active[k] for k in ("id", "name", "engine", "iface", "remote_host")}
    return {
        "mode": st["mode"],
        "pinned_tunnel_id": st["pinned_tunnel_id"],
        "active": active,
        "virtual_ip": s.get("virtual_ip"),
        "sim_mode": bool(s.get("sim_mode")),
        "flap_locked": fsm.is_flap_locked(),
        "switches_recent": fsm.recent_switch_count(),
        "uptime_state_ts": st["updated_at"],
    }


class ModeIn(BaseModel):
    mode: str = Field(pattern="^(auto|manual)$")
    pinned_tunnel_id: int | None = None


@app.post("/api/mode")
def set_mode(body: ModeIn, user: dict = Depends(admin)):
    try:
        return fsm.set_mode(body.mode, body.pinned_tunnel_id)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/failover/switch/{tid}")
def manual_switch(tid: int, user: dict = Depends(admin)):
    try:
        return fsm.manual_switch(tid)
    except ValueError as e:
        raise HTTPException(404, str(e))


@app.post("/api/failover/reset-flap")
def reset_flap(user: dict = Depends(admin)):
    fsm.reset_flap_lock()
    return {"ok": True}


# ----------------------------------------------------------------- tunnels
class TunnelIn(BaseModel):
    name: str
    engine: str
    iface: str | None = None
    local_ip: str | None = None
    remote_ip: str | None = None
    remote_lan: str | None = None
    remote_host: str | None = None
    mtu: int | None = None
    enabled: bool = True
    priority: int = 100
    config: dict = {}
    remote_ssh: dict | None = None  # {host, port, username, password/private_key, peer_iface}


def _serialize_tunnel(t: dict, with_secrets: bool = False) -> dict:
    out = dict(t)
    out["config"] = json.loads(t.get("config") or "{}")
    if with_secrets:
        out["remote_ssh"] = security.decrypt_creds(t.get("remote_ssh") or "")
    else:
        out["remote_ssh"] = bool(security.decrypt_creds(t.get("remote_ssh") or ""))
    return out


@app.get("/api/tunnels")
def list_tunnels(user: dict = Depends(current_user)):
    s = dbm.get_settings()
    out = []
    for t in dbm.list_tunnels():
        item = _serialize_tunnel(t)
        adapter = get_adapter(t)
        try:
            item["engine_status"] = adapter.status()
        except Exception as e:
            item["engine_status"] = {"up": False, "detail": str(e)[:120], "extra": {}}
        w = _window_snapshot(t["id"])
        item["window"] = w
        out.append(item)
    state = dbm.get_state()
    return {"tunnels": out, "active_id": state["active_tunnel_id"],
            "mode": state["mode"], "sim_mode": bool(s.get("sim_mode"))}


def _window_snapshot(tid: int) -> dict:
    rows = dbm.db().execute(
        "SELECT ts,rtt_ms,loss_pct,jitter_ms,ok FROM probes WHERE tunnel_id=? "
        "ORDER BY id DESC LIMIT 40", (tid,)).fetchall()
    from .probes import WindowStats
    w = WindowStats(60)
    for r in reversed(rows):
        w.add(dict(r))
    return w.snapshot()


@app.post("/api/tunnels")
def create_tunnel(body: TunnelIn, user: dict = Depends(admin)):
    return {"id": _create_one(body)}


def _create_one(body: TunnelIn) -> int:
    if body.engine not in ENGINE_REGISTRY:
        raise HTTPException(400, f"unknown engine '{body.engine}'")
    iface = body.iface or f"tf{body.engine[:2]}{int(time.time()) % 10000}"
    with dbm.tx() as d:
        cur = d.execute(
            "INSERT INTO tunnels(name,engine,iface,local_ip,remote_ip,remote_lan,"
            "remote_host,mtu,config,remote_ssh,enabled,priority,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (body.name, body.engine, iface, body.local_ip, body.remote_ip,
             body.remote_lan, body.remote_host, body.mtu,
             json.dumps(body.config), "", 1 if body.enabled else 0,
             body.priority, time.time()))
        tid = cur.lastrowid
    if body.remote_ssh:
        _store_ssh_creds(tid, body.remote_ssh)
    return tid


# ------------------------------------------------------- activation flow
def _activation_pipeline(t: dict, verify: bool = True) -> dict:
    """create -> precheck -> engine up -> live verify. Used by the single
    activate endpoint and the batch wizard. Every step is reported so the
    UI can show exactly what happened (and what failed, honestly)."""
    tid = t["id"]
    steps: list[dict] = []

    def _step(name: str, ok: bool, detail=""):
        steps.append({"step": name, "ok": bool(ok), "detail": str(detail)[:300]})
        return ok

    adapter = get_adapter(t)
    engine_name = t["engine"]

    # 1. precheck
    try:
        problems = adapter.precheck()
    except Exception as e:
        problems = [f"precheck crashed: {e}"]
    if not _step("precheck", not problems, "; ".join(problems) or "clean"):
        dbm.add_event("error", "activate_failed",
                      f"{t['name']}: precheck failed", tid)
        return {"id": tid, "name": t["name"], "engine": engine_name,
                "ok": False, "steps": steps}

    # 2. engine up (writes final configs, brings the tunnel up)
    try:
        cmds = adapter.up()
        _step("engine_up", True, " | ".join(cmds[-2:]))
    except Exception as e:
        _step("engine_up", False, e)
        dbm.add_event("error", "activate_failed",
                      f"{t['name']}: engine up failed: {e}", tid)
        return {"id": tid, "name": t["name"], "engine": engine_name,
                "ok": False, "steps": steps}
    dbm.add_event("info", "tunnel_up", f"{t['name']} activated (engine up)",
                  tid)

    # 3. live verify — status now + one real probe round
    ok = _step("status_check", _status_up(adapter), "")
    if ok and verify:
        try:
            row = fsm.probe_tunnel(t)
            ok = _step("first_probe", bool(row.get("ok")),
                       f"rtt={row.get('rtt_ms')}ms loss={row.get('loss_pct')}% "
                       f"method={row.get('method')}")
            if ok and hasattr(adapter, "receipt"):
                rec = adapter.receipt()
                _step("exit_ip_receipt", rec.get("through_tunnel", False),
                      f"exit_ip={rec.get('exit_ip')}")
        except Exception as e:
            _step("first_probe", False, e)
    dbm.add_event("info" if ok else "warn", "activate",
                  f"{t['name']}: activation {'verified' if ok else 'completed but verify failed'}",
                  tid)
    return {"id": tid, "name": t["name"], "engine": engine_name,
            "ok": ok, "steps": steps}


def _status_up(adapter) -> bool:
    try:
        return bool(adapter.status().get("up"))
    except Exception:
        return False


class BatchIn(BaseModel):
    tunnels: list[TunnelIn]
    activate: bool = True
    verify: bool = True


@app.post("/api/tunnels/batch")
def create_tunnels_batch(body: BatchIn, user: dict = Depends(admin)):
    """Wizard endpoint: create N tunnels and auto-activate each one.
    Returns a per-tunnel report; never raises for individual failures."""
    if len(body.tunnels) > 12:
        raise HTTPException(400, "max 12 tunnels per batch")
    results = []
    created_ids = []
    for spec in body.tunnels:
        try:
            tid = _create_one(spec)
            created_ids.append(tid)
        except HTTPException as e:
            results.append({"name": spec.name, "engine": spec.engine,
                            "ok": False, "error": e.detail})
            continue
        t = dbm.get_tunnel(tid)
        if not body.activate:
            results.append({"id": tid, "name": t["name"],
                            "engine": t["engine"], "ok": True,
                            "steps": [{"step": "created", "ok": True}]})
            continue
        results.append(_activation_pipeline(t, verify=body.verify))
    ok_count = sum(1 for r in results if r.get("ok"))
    dbm.add_event("info", "batch",
                  f"batch add: {ok_count}/{len(results)} tunnels active")
    return {"results": results, "ok": ok_count,
            "total": len(results), "created_ids": created_ids}


@app.post("/api/tunnels/{tid}/activate")
def activate_tunnel(tid: int, user: dict = Depends(admin)):
    t = dbm.get_tunnel(tid)
    if not t:
        raise HTTPException(404, "tunnel not found")
    return _activation_pipeline(t, verify=True)


def _store_ssh_creds(tid: int, creds: dict) -> None:
    with dbm.tx() as d:
        d.execute("UPDATE tunnels SET remote_ssh=? WHERE id=?",
                  (security.encrypt_creds(creds), tid))


@app.put("/api/tunnels/{tid}")
def update_tunnel(tid: int, body: TunnelIn, user: dict = Depends(admin)):
    t = dbm.get_tunnel(tid)
    if not t:
        raise HTTPException(404, "tunnel not found")
    with dbm.tx() as d:
        d.execute(
            "UPDATE tunnels SET name=?,engine=?,iface=?,local_ip=?,remote_ip=?,"
            "remote_lan=?,remote_host=?,mtu=?,config=?,enabled=?,priority=? WHERE id=?",
            (body.name, body.engine, body.iface or t["iface"], body.local_ip,
             body.remote_ip, body.remote_lan, body.remote_host, body.mtu,
             json.dumps(body.config), 1 if body.enabled else 0,
             body.priority, tid))
    if body.remote_ssh:
        _store_ssh_creds(tid, body.remote_ssh)
    return {"ok": True}


@app.delete("/api/tunnels/{tid}")
def delete_tunnel(tid: int, user: dict = Depends(admin)):
    t = dbm.get_tunnel(tid)
    if not t:
        raise HTTPException(404, "tunnel not found")
    try:
        get_adapter(t).down()
    except Exception:
        pass
    with dbm.tx() as d:
        d.execute("DELETE FROM tunnels WHERE id=?", (tid,))
        d.execute("DELETE FROM probes WHERE tunnel_id=?", (tid,))
        d.execute("DELETE FROM rollup WHERE tunnel_id=?", (tid,))
        d.execute("DELETE FROM throughput WHERE tunnel_id=?", (tid,))
    st = dbm.get_state()
    if st["active_tunnel_id"] == tid:
        dbm.update_state(active_tunnel_id=None)
    return {"ok": True}


@app.post("/api/tunnels/{tid}/up")
def tunnel_up(tid: int, user: dict = Depends(admin)):
    try:
        return {"commands": fsm.mark_tunnel_updown(tid, True)}
    except (ValueError, AdapterError) as e:
        raise HTTPException(400, str(e))


@app.post("/api/tunnels/{tid}/down")
def tunnel_down(tid: int, user: dict = Depends(admin)):
    try:
        return {"commands": fsm.mark_tunnel_updown(tid, False)}
    except (ValueError, AdapterError) as e:
        raise HTTPException(400, str(e))


@app.post("/api/tunnels/{tid}/precheck")
def tunnel_precheck(tid: int, user: dict = Depends(admin)):
    t = dbm.get_tunnel(tid)
    if not t:
        raise HTTPException(404, "tunnel not found")
    try:
        return {"problems": get_adapter(t).precheck()}
    except Exception as e:
        return {"problems": [f"precheck crashed: {e}"]}


@app.get("/api/tunnels/{tid}/config")
def tunnel_config(tid: int, user: dict = Depends(admin)):
    t = dbm.get_tunnel(tid)
    if not t:
        raise HTTPException(404, "tunnel not found")
    return {"artifacts": get_adapter(t).render()}


# ------------------------------------------------------------------ metrics
@app.get("/api/metrics")
def metrics(tid: int | None = None, range_s: int = 900,
            user: dict = Depends(current_user)):
    now = time.time()
    out = {}
    tids = [tid] if tid else [t["id"] for t in dbm.list_tunnels(include_disabled=False)]
    for t_id in tids:
        probes_rows = dbm.db().execute(
            "SELECT ts,rtt_ms,loss_pct,jitter_ms,method,ok FROM probes "
            "WHERE tunnel_id=? AND ts>=? ORDER BY ts", (t_id, now - range_s)
        ).fetchall()
        bw_rows = dbm.db().execute(
            "SELECT ts,rx_bps,tx_bps FROM throughput WHERE tunnel_id=? AND ts>=? "
            "ORDER BY ts", (t_id, now - range_s)).fetchall()
        out[str(t_id)] = {
            "probes": [dict(r) for r in probes_rows],
            "throughput": [dict(r) for r in bw_rows],
        }
    return {"range_s": range_s, "series": out}


# ------------------------------------------------------------------ events
@app.get("/api/events")
def list_events(limit: int = 200, user: dict = Depends(current_user)):
    rows = dbm.db().execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (min(limit, 1000),)
    ).fetchall()
    return {"events": [dict(r) for r in rows]}


# ------------------------------------------------------------------ settings
class SettingsIn(BaseModel):
    patch: dict


@app.get("/api/settings")
def get_settings(user: dict = Depends(current_user)):
    return dbm.get_settings()


@app.put("/api/settings")
def put_settings(body: SettingsIn, user: dict = Depends(admin)):
    allowed = set(config.DEFAULT_SETTINGS) | {"dnat_rules", "proactive_switch_enabled",
                                              "proactive_k"}
    patch = {k: v for k, v in body.patch.items() if k in allowed}
    if not patch:
        raise HTTPException(400, "no valid keys")
    current = dbm.get_settings()
    merged = {**current, **patch}
    problems = probes.validate_settings_numbers(merged)
    if problems:
        raise HTTPException(400, "; ".join(problems))
    dbm.set_settings(patch)
    if "virtual_ip" in patch or "mss_clamp_enabled" in patch or "dnat_rules" in patch:
        sim = routing.SimulatedSystem() if merged.get("sim_mode") else None
        warnings = []
        try:
            warnings += routing.ensure_vip(sim=sim)
            warnings += routing.apply_nft(sim=sim)
        except Exception as e:  # never fail settings save on system ops
            warnings.append(f"system apply warning: {e}")
        return {**dbm.get_settings(), "apply": warnings}
    return dbm.get_settings()


# ------------------------------------------------------------------ engines
@app.get("/api/engines")
def engines(user: dict = Depends(current_user)):
    return {"engines": config.ENGINE_META,
            "sim_mode": bool(dbm.get_settings().get("sim_mode"))}


# ------------------------------------------------------------------ WS
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket, token: str = ""):
    payload = security.decode_token(token)
    if not payload:
        await ws.close(code=4401)
        return
    import asyncio
    ws._tg_loop = asyncio.get_running_loop()
    await ws.accept()
    events.subscribe(ws)
    try:
        while True:
            await ws.receive_text()  # keepalive pings from client
    except WebSocketDisconnect:
        pass
    finally:
        events.unsubscribe(ws)


# ------------------------------------------------------------------ static
def mount_web(app_: FastAPI) -> None:
    import os
    from fastapi.staticfiles import StaticFiles
    web_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web")
    if os.path.isdir(web_dir):
        app_.mount("/", StaticFiles(directory=web_dir, html=True), name="web")


mount_web(app)
