#!/usr/bin/env python3
"""MTF FastAPI panel API — login, methods, apply, status, failover controls."""
import json
import os
import secrets
import subprocess
import threading
import time

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import core, installer, metrics, portmgr, probe_engine, registry, servertunnels, state

BASE = "/opt/multitunnel"
PANEL = f"{BASE}/panel"
DATA = f"{BASE}/data"

engine = None
_session = {"username": None, "password": None, "token": None}


def _load_password():
    os.makedirs(DATA, exist_ok=True)
    sp = f"{DATA}/panel_secret.json"
    data = {}
    if os.path.exists(sp):
        with open(sp) as f:
            data = json.load(f)
    _session["password"] = data.get("password") or secrets.token_urlsafe(9)
    _session["username"] = data.get("username") or "admin"
    data.update({"username": _session["username"], "password": _session["password"]})
    with open(sp, "w") as f:
        json.dump(data, f)


_load_password()
state.init_db()
methods = registry.load_registry()
state.ensure_methods([m.id for m in methods])

app = FastAPI(title="MTF Multi-Tunnel Failover", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=f"{PANEL}/templates")
app.mount("/static", StaticFiles(directory=f"{PANEL}/static"), name="static")


def authed(request: Request) -> bool:
    return request.cookies.get("mtf_session") == _session["token"]


def require(request: Request):
    if not authed(request):
        raise HTTPException(401, "unauthorized")


@app.on_event("startup")
def _startup():
    global engine
    if engine is None:
        engine = core.start_engine()
    metrics.start_bg()
    servertunnels.restart_supervisors()


@app.get("/health")
def health():
    return {"ok": True, "ts": time.time()}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"err": "", "count": len(methods)})


@app.post("/login")
async def login(request: Request):
    form = await request.form()
    if (form.get("username") == _session["username"]
            and form.get("password") == _session["password"]):
        _session["token"] = secrets.token_urlsafe(24)
        state.event("info", "panel", "admin login ok")
        resp = RedirectResponse("/", 303)
        resp.set_cookie("mtf_session", _session["token"], httponly=True, samesite="lax")
        return resp
    state.event("warn", "panel", "bad login attempt")
    return templates.TemplateResponse(request, "login.html",
                                      {"err": "نام کاربری یا رمز اشتباه است / wrong credentials",
                                       "count": len(methods)})


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", 303)
    resp.delete_cookie("mtf_session")
    return resp


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if not authed(request):
        return RedirectResponse("/login", 303)
    fams = []
    for m in methods:
        if m.set not in fams:
            fams.append(m.set)
    return templates.TemplateResponse(request, "index.html", {
        "families": fams,
        "vip": core.VIP, "count": len(methods), "username": _session["username"],
    })


@app.get("/api/methods")
def api_methods(request: Request):
    require(request)
    rows = {m["id"]: m for m in state.all_methods()}
    out = []
    for m in methods:
        r = rows.get(m.id, {})
        p = state.last_probe(m.id)
        out.append({
            "id": m.id, "name_fa": m.name_fa, "name_en": m.name_en,
            "family_fa": m.family_fa, "family_en": m.family_en,
            "set": m.set, "cls": m.cls, "binary": m.binary,
            "star": m.id.startswith(("HEDIOUM", "HAJSAMAN", "PAQET")),
            "selected": bool(r.get("selected")), "deployed": bool(r.get("deployed")),
            "state": r.get("state", "STOPPED"),
            "detail": (r.get("detail") or "")[:140],
            "rtt_ms": p["rtt_ms"] if p else None,
            "loss_pct": p["loss_pct"] if p else None,
            "jitter_ms": p["jitter_ms"] if p else None,
        })
    return {"methods": out, "ts": time.time()}


@app.post("/api/methods/select")
async def select(request: Request):
    require(request)
    body = await request.json()
    ids = set(body.get("ids", []))
    from .registry import REG_PATH  # noqa
    all_ids = {m.id for m in methods}
    unknown = ids - all_ids
    if unknown:
        raise HTTPException(400, f"unknown ids: {sorted(unknown)[:5]}")
    with state.conn() as c:
        c.execute("UPDATE methods SET selected=0")
        for mid in ids:
            c.execute("UPDATE methods SET selected=1 WHERE id=?", (mid,))
    state.event("info", "panel", f"selection updated: {len(ids)} methods")
    return {"ok": True, "selected": sorted(ids)}


_DEPLOY_LOCK = threading.Lock()


def _apply_worker(ids: list[str]):
    fammap = {m.id: (m.set.replace("_METHODS", "").replace("KERNEL_BASE", "KERNEL"), m.cls)
              for m in methods}
    with _DEPLOY_LOCK:
        for mid in ids:
            state.set_method(mid, state="DEPLOYING", deployed=0)
            fam, cls = fammap.get(mid, ("KERNEL", "kernel"))
            try:
                if cls == "kernel" or mid in ("SSH_LOCAL_FORWARD", "SSH_DYNAMIC_SOCKS",
                                              "SSH_REMOTE_FORWARD", "SSH_TUN_L3", "SSH_TAP_L2",
                                              "AUTOSSH_REVERSE", "GRE_OVER_SSH", "SIT_OVER_SSH",
                                              "GRE_OVER_GOST", "GRETAP_OVER_GOST", "SIT_OVER_GOST",
                                              "GRE_OVER_WIREGUARD"):
                    rc, out = subprocess.run(["bash", f"{BASE}/engine/mtf_kernel.sh", mid],
                                             capture_output=True, text=True, timeout=180)
                    if rc == 0:
                        ev = {"runner": "kernel", "raw": out[-500:]}
                        state.save_receipt(mid, "PASS", ev)
                        state.set_method(mid, state="UP", deployed=1, detail="deployed+verified")
                        state.event("info", "deploy", f"{mid} kernel harness PASS")
                    else:
                        state.save_receipt(mid, "FAIL", {"runner": "kernel", "err": (out[-500:])})
                        state.set_method(mid, state="ERROR", deployed=0, detail=out[-140:])
                        state.event("error", "deploy", f"{mid} kernel FAIL")
                else:
                    import sys
                    sys.path.insert(0, f"{BASE}/engine")
                    from mtf_userspace import test_method
                    verdict, ev = test_method(mid, fam)
                    state.save_receipt(mid, verdict, ev)
                    if verdict == "PASS":
                        state.set_method(mid, state="UP", deployed=1, detail="deployed+verified")
                    elif verdict == "PARTIAL":
                        state.set_method(mid, state="DEGRADED", deployed=1, detail="partial: see receipt")
                    else:
                        state.set_method(mid, state="ERROR", deployed=0, detail="failed: see receipt")
            except Exception as e:
                state.set_method(mid, state="ERROR", deployed=0, detail=str(e)[:140])
        # activate VIP on best deployed kernel method
        core.point_vip_route(ids[0]) if ids else None
        state.event("info", "panel", f"apply finished: {len(ids)} methods")


@app.post("/api/methods/apply")
async def apply(request: Request):
    require(request)
    with state.conn() as c:
        rows = c.execute("SELECT id FROM methods WHERE selected=1").fetchall()
    ids = [r["id"] for r in rows]
    threading.Thread(target=_apply_worker, args=(ids,), daemon=True).start()
    state.event("info", "panel", f"apply started: {len(ids)} selected methods")
    return {"ok": True, "job": len(ids)}


@app.get("/api/status")
def api_status(request: Request):
    require(request)
    s = state.all_settings()
    rows = {m["id"]: m for m in state.all_methods()}
    counters = {"UP": 0, "DEGRADED": 0, "DOWN": 0, "STOPPED": 0, "ERROR": 0, "DEPLOYING": 0}
    for r in rows.values():
        st = r.get("state", "STOPPED")
        counters[st] = counters.get(st, 0) + 1
    return {
        "mode": s.get("mode", "auto"),
        "active": s.get("active", ""),
        "vip": core.VIP,
        "vip_ok": subprocess.run(["ip", "addr", "show", "lo"], capture_output=True).returncode == 0,
        "counters": counters,
        "last_switch": float(s.get("last_switch", 0) or 0),
        "settings": {k: s.get(k) for k in
                     ("cooldown_s", "hysteresis_n", "loss_degraded", "loss_down",
                      "jitter_degraded", "rtt_degraded", "probe_interval_s")},
        "events": state.recent_events(40),
        "ts": time.time(),
    }


@app.post("/api/mode")
async def set_mode(request: Request):
    require(request)
    body = await request.json()
    mode = body.get("mode")
    if mode not in ("auto", "manual"):
        raise HTTPException(400, "mode must be auto|manual")
    state.set_setting("mode", mode)
    state.event("info", "panel", f"mode -> {mode}")
    return {"ok": True, "mode": mode}


@app.post("/api/manual/{mid}")
def manual_switch(mid: str, request: Request):
    require(request)
    if mid not in {m.id for m in methods}:
        raise HTTPException(404, mid)
    state.set_setting("mode", "manual")
    ok = core.point_vip_route(mid)
    state.event("info" if ok else "warn", "panel", f"manual switch -> {mid}")
    return {"ok": ok, "active": state.get_setting("active")}


@app.post("/api/settings")
async def set_settings(request: Request):
    require(request)
    body = await request.json()
    allowed = {"cooldown_s", "hysteresis_n", "loss_degraded", "loss_down",
               "jitter_degraded", "rtt_degraded", "probe_interval_s"}
    for k, v in body.items():
        if k in allowed:
            state.set_setting(k, str(v))
    state.event("info", "panel", f"settings updated: {body}")
    return {"ok": True}


@app.post("/api/credentials")
async def set_credentials(request: Request):
    """Change panel username and/or password."""
    require(request)
    body = await request.json()
    user = (body.get("username") or "").strip()
    pwd = body.get("password") or ""
    if user:
        _session["username"] = user[:40]
    if pwd:
        _session["password"] = pwd[:80]
    with open(f"{DATA}/panel_secret.json", "w") as f:
        json.dump({"username": _session["username"], "password": _session["password"]}, f)
    state.event("info", "panel", "credentials updated")
    return {"ok": True}


@app.post("/api/probe")
async def probe_start(request: Request):
    """Start SSH probe of user-supplied servers (IP, SSH port, user, pass)."""
    require(request)
    body = await request.json()
    clean = []
    for s in (body.get("servers") or [])[:12]:
        host = (s.get("host") or "").strip()
        if not host:
            continue
        try:
            port = int(s.get("ssh_port") or 22)
        except Exception:
            port = 22
        clean.append({"name": (s.get("name") or "").strip()[:40],
                      "host": host[:120], "ssh_port": port,
                      "username": (s.get("username") or "root").strip()[:64],
                      "password": (s.get("password") or "")[:128]})
    if not clean:
        raise HTTPException(400, "no valid servers given")
    if probe_engine.JOB["running"]:
        raise HTTPException(409, "probe already running")
    threading.Thread(target=probe_engine.run_probe, args=(clean,), daemon=True).start()
    state.event("info", "probe", f"ssh probe started: {len(clean)} servers")
    return {"ok": True, "started": True, "n": len(clean)}


@app.get("/api/probe")
def probe_get(request: Request):
    require(request)
    return probe_engine.status()


@app.get("/api/recommend")
def recommend(request: Request):
    """Rank best tunnels per server pair based on last probe results."""
    require(request)
    ids = [m.id for m in methods]
    return probe_engine.build_recommendations(ids)


@app.get("/api/receipts")
def receipts(request: Request):
    require(request)
    return {"receipts": state.all_receipts()}


@app.get("/api/events")
def events(request: Request):
    require(request)
    return {"events": state.recent_events(200)}


@app.post("/api/install")
async def install_start(request: Request):
    """Deploy+verify selected tunnel methods on a real target server over SSH."""
    require(request)
    body = await request.json()
    host = (body.get("host") or "").strip()[:120]
    if not host:
        raise HTTPException(400, "host required")
    try:
        port = int(body.get("ssh_port") or 22)
    except Exception:
        port = 22
    user = (body.get("username") or "root").strip()[:64]
    pw = (body.get("password") or "")[:128]
    mids = [str(x).strip()[:64] for x in (body.get("methods") or []) if str(x).strip()][:90]
    if not mids:
        raise HTTPException(400, "no methods selected")
    if installer.JOB["running"]:
        raise HTTPException(409, "install job already running")
    threading.Thread(target=installer.run_install, args=(host, port, user, pw, mids),
                     daemon=True).start()
    state.event("info", "install", f"remote install started on {host}: {len(mids)} methods")
    return {"ok": True, "started": len(mids), "target": host}


@app.get("/api/install")
def install_status(request: Request):
    require(request)
    return {"job": installer.JOB, "deployments": installer.status()}


@app.get("/api/password-hint")
def password_hint():
    """First-run helper: shows the generated admin password ONLY until first login."""
    if _session["token"] is None:
        return {"bootstrap_password": _session["password"],
                "note": "visible until first login; change via /api/password"}
    raise HTTPException(404)


# ------------------------------------------------ server tunnels (scan/install)
@app.post("/api/st/scan")
async def st_scan(request: Request):
    """Scan every side (panel + given SSH servers) for existing tunnels."""
    require(request)
    body = await request.json()
    servers = []
    for s in (body.get("servers") or [])[:12]:
        host = (s.get("host") or "").strip()
        if not host:
            continue
        try:
            port = int(s.get("ssh_port") or 22)
        except Exception:
            port = 22
        servers.append({"name": (s.get("name") or host)[:40], "host": host,
                        "ssh_port": port,
                        "username": (s.get("username") or "root")[:64],
                        "password": (s.get("password") or "")[:128]})
    if servertunnels.SCAN_JOB["running"]:
        raise HTTPException(409, "scan already running")
    threading.Thread(target=servertunnels.run_scan, args=(servers,), daemon=True).start()
    state.event("info", "server-tunnels", f"tunnel scan started: panel + {len(servers)} servers")
    return {"ok": True, "sides": 1 + len(servers)}


@app.get("/api/st/scan")
def st_scan_get(request: Request):
    require(request)
    return servertunnels.scan_status()


@app.get("/api/st/book")
def st_book(request: Request):
    """Installed-tunnel book + job state."""
    require(request)
    return servertunnels.install_status()


@app.post("/api/st/deploy")
async def st_deploy(request: Request):
    """Install ticked tunnel methods between two real sides (persistent)."""
    require(request)
    body = await request.json()
    mids = [str(x).strip()[:64] for x in (body.get("methods") or []) if str(x).strip()][:90]
    if not mids:
        raise HTTPException(400, "no methods selected")
    sides = []
    for s in (body.get("sides") or [])[:2]:
        host = (s.get("host") or "").strip()
        if not host:
            continue
        try:
            port = int(s.get("ssh_port") or 22)
        except Exception:
            port = 22
        sides.append({"name": (s.get("name") or host)[:40], "host": host,
                      "ssh_port": port,
                      "username": (s.get("username") or "root")[:64],
                      "password": (s.get("password") or "")[:128]})
    if not sides:
        sides = [{"local": True, "name": "Panel container"}]
    pair = bool(body.get("pair", True)) and len(sides) >= 2
    if servertunnels.JOB["running"]:
        raise HTTPException(409, "deploy job already running")
    threading.Thread(target=servertunnels.run_deploy,
                     args=(sides, mids, pair), daemon=True).start()
    state.event("info", "server-tunnels",
                f"persistent install started: {len(mids)} methods, pair={pair}")
    return {"ok": True, "started": len(mids), "pair": pair}


@app.post("/api/st/remove")
async def st_remove(request: Request):
    """Remove a previously installed tunnel from one side."""
    require(request)
    body = await request.json()
    mid = (body.get("mid") or "").strip()[:64]
    s = body.get("side") or {}
    host = (s.get("host") or "").strip()
    if not mid:
        raise HTTPException(400, "mid required")
    if host:
        try:
            port = int(s.get("ssh_port") or 22)
        except Exception:
            port = 22
        spec = {"host": host, "ssh_port": port,
                "username": (s.get("username") or "root")[:64],
                "password": (s.get("password") or "")[:128]}
    else:
        spec = {"local": True}
    res = servertunnels.run_remove(spec, mid)
    state.event("info" if res.get("ok") else "warn", "server-tunnels",
                f"remove {mid} from {host or 'panel'}: {res.get('ok')}")
    return res


# ----------------------------------------------------- ports & conflict manager
@app.post("/api/ports/scan")
async def ports_scan(request: Request):
    require(request)
    body = await request.json()
    servers = [{"host": (s.get("host") or "").strip(),
                "ssh_port": int(s.get("ssh_port") or 22),
                "username": (s.get("username") or "root")[:64],
                "password": (s.get("password") or "")[:128]}
               for s in (body.get("servers") or [])[:12]
               if (s.get("host") or "").strip()]
    threading.Thread(target=portmgr.run_scan, args=(servers,), daemon=True).start()
    state.event("info", "ports", f"port scan started: panel + {len(servers)} servers")
    return {"ok": True}


@app.get("/api/ports/report")
def ports_report(request: Request):
    require(request)
    return portmgr.report_conflicts()


@app.get("/api/ports/allocs")
def ports_allocs(request: Request):
    require(request)
    return portmgr.allocations()


@app.post("/api/ports/assign")
async def ports_assign(request: Request):
    require(request)
    body = await request.json()
    mid = (body.get("mid") or "").strip()[:64]
    proto = (body.get("proto") or "tcp").lower()
    if not mid:
        raise HTTPException(400, "mid required")
    sides = list((portmgr.last_report().get("sides") or {}).keys())
    r = portmgr.assign(mid, {"server": proto}, sides)
    if not r.get("ok"):
        raise HTTPException(409, r.get("err", "assign failed"))
    return r


@app.post("/api/ports/release")
async def ports_release(request: Request):
    require(request)
    body = await request.json()
    return portmgr.release((body.get("mid") or "").strip()[:64])


@app.get("/api/ports/protos")
def ports_protos(request: Request):
    require(request)
    return portmgr.ip_proto_report()


# ------------------------------------------------------------- live metrics
@app.get("/api/metrics")
def api_metrics(request: Request):
    require(request)
    snap = metrics.sample()
    return {"now": snap, "hist": metrics.history(120),
            "info": metrics.info(), "ts": time.time()}


def main():
    import uvicorn
    cert = f"{BASE}/certs/panel.pem"
    key = f"{BASE}/certs/panel-key.pem"
    kw = {}
    if os.path.exists(cert) and os.path.exists(key):
        kw = {"ssl_certfile": cert, "ssl_keyfile": key}
    uvicorn.run(app, host="0.0.0.0", port=9443, log_level="info", **kw)


if __name__ == "__main__":
    main()
