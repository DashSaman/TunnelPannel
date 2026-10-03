#!/usr/bin/env python3
"""MTF core: probes (ping/loss/jitter) + FSM + VIP manager + failover loop.

VIP model (honest, single-server):
- VIP 10.10.10.5/32 lives on lo (always up).
- Policy routing: `ip rule from 10.10.10.5 lookup 51000`.
- Each kernel tunnel writes its route into table 51000 atomically on switch:
    WIREGUARD -> default dev wg-mtf
    GRE/GRETAP -> default dev gre-mtf / gretap-mtf
    SIT_6IN4 -> default dev sit-mtf
    IPIP -> default dev ipip-mtf
    VTI/VTI6 -> default dev vti-mtf
    L2TP_IPSEC -> default dev l2tp-mtf
    OPENVPN -> default dev tun0 (ovpn)
    IKEV2_IPSEC -> default dev vti-mtf
    composites over wg/ssh -> default dev gre-wg / tun11 ...
- Userspace methods: health-monitored for failover ranking; egress path is a
  SOCKS port (no kernel interface) -> they participate in "active" selection
  for proxy-level consumers, documented honestly.
"""
import json
import os
import statistics
import subprocess
import threading
import time

from . import state

VIP = "10.10.10.5"
VIP_TABLE = 51000

KERNEL_DEV = {
    "WIREGUARD": "wg-mtf",
    "GRE": "gre-mtf",
    "GRETAP": "gretap-mtf",
    "SIT_6IN4": "sit-mtf",
    "IPIP": "ipip-mtf",
    "VXLAN": "vxlan-mtf",
    "IP6GRE": "ip6gre-mtf",
    "IP6GRETAP": "ip6gretap-mtf",
    "VTI": "vti-mtf",
    "VTI6": "vti-mtf",
    "L2TP_IPSEC": "l2tp-mtf",
    "OPENVPN": "tun0",
    "IKEV2_IPSEC": "vti-mtf",
    "GRE_OVER_WIREGUARD": "gre-wg",
    "GRE_OVER_SSH": "gre-os",
    "SIT_OVER_SSH": "sit-os",
    "SSH_TUN_L3": "tun11",
    "SSH_TAP_L2": "tap12",
    "GRE_OVER_GOST": "gre-og",
    "GRETAP_OVER_GOST": "gre-og",
    "SIT_OVER_GOST": "sit-og",
}
KERNEL_PEER_IP = {
    "WIREGUARD": "10.200.0.2", "GRE": "10.60.0.2", "GRETAP": "10.61.0.2",
    "SIT_6IN4": "fc00:60::2", "IPIP": "10.62.0.2", "VXLAN": "10.63.0.2",
    "IP6GRE": "10.64.0.2", "IP6GRETAP": "10.66.0.2", "VTI": "10.65.0.2",
    "VTI6": "10.65.0.2", "L2TP_IPSEC": "10.67.0.2", "OPENVPN": "10.68.0.2",
    "IKEV2_IPSEC": "10.65.0.2", "GRE_OVER_WIREGUARD": "10.69.0.2",
    "GRE_OVER_SSH": "10.73.0.2", "SIT_OVER_SSH": "fc00:73::2",
    "SSH_TUN_L3": "10.70.0.2", "SSH_TAP_L2": "10.71.0.2",
    "GRE_OVER_GOST": "10.72.0.2", "GRETAP_OVER_GOST": "10.72.0.2",
    "SIT_OVER_GOST": "fc00:72::2",
}
USERSPACE_SOCKS = {  # client proxy port when deployed for serving
    "GOST_SOCKS5": 14102, "GOST_HTTP": 14102, "GOST_WS": 14102,
}


def sh(cmd: str, timeout: int = 25) -> tuple[int, str]:
    try:
        p = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr)[-800:]
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def ensure_vip():
    sh(f"ip addr add {VIP}/32 dev lo 2>/dev/null; true")
    sh(f"ip rule list | grep -q '{VIP} lookup {VIP_TABLE}' || "
       f"ip rule add from {VIP} lookup {VIP_TABLE}")


def install_mss_clamp(dev: str):
    sh(f"nft list table inet mtf >/dev/null 2>&1 || "
       f"nft add table inet mtf && "
       f"nft list chain inet mtf clamp >/dev/null 2>&1 || "
       f"nft add chain inet mtf clamp '{{ type filter hook forward priority -100 ; }}' ; "
       f"nft add rule inet mtf clamp oifname \"{dev}\" tcp flags syn tcp option maxseg size set rt mtu")


def point_vip_route(mid: str) -> bool:
    """Make VIP egress ride the given kernel tunnel. Returns success."""
    dev = KERNEL_DEV.get(mid)
    if not dev:
        return False
    ensure_vip()
    rc, out = sh(f"ip link show {dev} 2>/dev/null | head -1")
    if rc != 0:
        state.event("warn", "vip", f"device {dev} missing for {mid}")
        return False
    if "SIT" in mid:
        rc, _ = sh(f"ip -6 route replace default dev {dev} table {VIP_TABLE}")
    else:
        rc, _ = sh(f"ip route replace default dev {dev} table {VIP_TABLE}")
    install_mss_clamp(dev)
    state.set_setting("active", mid)
    state.event("info", "vip", f"VIP {VIP} now rides {dev} via method {mid} (table {VIP_TABLE})")
    return rc == 0


def probe_kernel(mid: str, tries: int = 4) -> dict:
    peer = KERNEL_PEER_IP.get(mid)
    if not peer:
        return {"ok": False, "rtt": None, "loss": 100.0, "jitter": None, "why": "no peer map"}
    bin6 = "-6" if ":" in peer else ""
    rc, out = sh(f"ping {bin6} -c {tries} -i 0.3 -W 2 -q {peer}", timeout=20)
    loss, rtt, jit = 100.0, None, None
    for tok in out.splitlines():
        if "packet loss" in tok:
            try:
                loss = float(tok.split(",")[2].strip().split("%")[0])
            except Exception:
                pass
        if "rtt" in tok or "round-trip" in tok:
            try:
                parts = tok.split("=")[1].split("/")
                rtt = float(parts[1])
                mn, avg, mx, mdev = (float(x) for x in parts[:4])
                jit = mdev
            except Exception:
                pass
    ok = rc == 0 and loss < 100
    return {"ok": ok, "rtt": rtt, "loss": loss, "jitter": jit, "why": out.strip()[-160:]}


def probe_userspace(mid: str) -> dict:
    """Health check a userspace tunnel by round-tripping through its proxy."""
    port = USERSPACE_SOCKS.get(mid)
    if port is None:
        # No persistent proxy deployment exists for this method (the test harness
        # tears down after verify) — report honestly instead of curling :None.
        # Proper fix (persistent userspace deploy + probe port from deployment
        # record) is tracked as P4/P5 work; see docs/adr/ADR-001.
        return {"ok": False, "rtt": None, "loss": 100.0, "jitter": 0.0,
                "why": "no persistent proxy deployment to probe"}
    results, rtts = [], []
    n = 3
    fails = 0
    for _ in range(n):
        t0 = time.time()
        rc, out = sh(f"curl -s -o /dev/null -w '%{{http_code}}' "
                     f"--socks5-hostname 127.0.0.1:{port} --max-time 6 "
                     f"http://127.0.0.1:9999/", timeout=10)
        dt = (time.time() - t0) * 1000
        if rc == 0 and out.strip() == "200":
            rtts.append(dt)
        else:
            fails += 1
        time.sleep(0.2)
    loss = 100.0 * fails / n
    rtt = statistics.mean(rtts) if rtts else None
    jit = statistics.pstdev(rtts) if len(rtts) >= 2 else 0.0
    return {"ok": loss < 100, "rtt": rtt, "loss": loss, "jitter": jit,
            "why": f"socks :{port} probes n={n} fails={fails}"}


class FailoverEngine(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="mtf-failover")
        self.stop_flag = threading.Event()
        self._fsm_fail: dict[str, int] = {}
        self._fsm_state: dict[str, str] = {}
        self._last_switch = 0.0

    # ---------- FSM ----------
    def classify(self, mid: str, probe: dict) -> str:
        if not probe["ok"]:
            return "DOWN"
        s = state.all_settings()
        loss_deg = float(s.get("loss_degraded", 20))
        loss_down = float(s.get("loss_down", 60))
        jit_deg = float(s.get("jitter_degraded", 80))
        rtt_deg = float(s.get("rtt_degraded", 600))
        loss = probe.get("loss") or 0
        jit = probe.get("jitter") or 0
        rtt = probe.get("rtt") or 0
        if loss >= loss_down:
            return "DOWN"
        if loss >= loss_deg or (jit and jit >= jit_deg) or (rtt and rtt >= rtt_deg):
            return "DEGRADED"
        return "UP"

    def update_fsm(self, mid: str, state_name: str) -> str:
        """Hysteresis: N consecutive bad probes before DOWN transitions."""
        n = int(state.get_setting("hysteresis_n", "3"))
        prev = self._fsm_state.get(mid, "STOPPED")
        if state_name == "DOWN":
            self._fsm_fail[mid] = self._fsm_fail.get(mid, 0) + 1
            if prev in ("UP", "DEGRADED") and self._fsm_fail[mid] < n:
                return prev  # hold
            return "DOWN"
        self._fsm_fail[mid] = 0
        return state_name

    # ---------- ranking ----------
    def score(self, item: tuple[str, dict]) -> float:
        mid, probe = item
        st = self._fsm_state.get(mid, "DOWN")
        base = {"UP": 1000, "DEGRADED": 400, "DOWN": 0}.get(st, 0)
        rtt = probe.get("rtt") or 2000
        loss = probe.get("loss") or 100
        jit = probe.get("jitter") or 500
        return base - rtt / 10 - loss * 5 - jit / 5

    def pick_best(self, probes: dict[str, dict]) -> str | None:
        ranked = sorted(probes.items(), key=self.score, reverse=True)
        for mid, probe in ranked:
            if self._fsm_state.get(mid) in ("UP", "DEGRADED"):
                return mid
        return None

    # ---------- switching ----------
    def switch(self, mid: str, reason: str):
        cd = int(state.get_setting("cooldown_s", "30"))
        if time.time() - self._last_switch < cd and self._last_switch:
            state.event("warn", "failover",
                        f"switch to {mid} suppressed by cooldown ({cd}s)")
            return
        ok = point_vip_route(mid)
        self._last_switch = time.time()
        state.set_setting("last_switch", str(self._last_switch))
        state.event("info" if ok else "warn", "failover",
                    f"ACTIVE -> {mid} ({reason})" if ok else f"switch to {mid} failed ({reason})")

    # ---------- main loop ----------
    def run(self):
        ensure_vip()
        state.event("info", "core", "failover engine started")
        while not self.stop_flag.is_set():
            try:
                interval = int(state.get_setting("probe_interval_s", "5"))
                probes: dict[str, dict] = {}
                rows = [m for m in state.all_methods() if m["deployed"]]
                for m in rows:
                    mid = m["id"]
                    if mid in KERNEL_PEER_IP:
                        probe = probe_kernel(mid)
                    else:
                        probe = probe_userspace(mid)
                    cls = self.classify(mid, probe)
                    final = self.update_fsm(mid, cls)
                    state.save_probe(mid, probe["rtt"], probe["loss"],
                                     probe["jitter"] or 0, probe["ok"])
                    state.set_method(mid, state=final, detail=probe["why"][:160])
                    probes[mid] = probe
                    if final != self._fsm_state.get(mid):
                        state.event("info", "fsm", f"{mid}: {self._fsm_state.get(mid, 'STOPPED')} -> {final}")
                        self._fsm_state[mid] = final
                mode = state.get_setting("mode", "auto")
                active = state.get_setting("active", "")
                active_state = self._fsm_state.get(active, "STOPPED")
                if mode == "auto" and probes:
                    best = self.pick_best(probes)
                    if best and (active_state in ("DOWN", "STOPPED") or not active):
                        self.switch(best, f"auto (active {active or 'none'} {active_state})")
            except Exception as e:  # never die
                try:
                    state.event("error", "core", f"loop error: {e}")
                except Exception:
                    pass
            time.sleep(interval)


def start_engine() -> FailoverEngine:
    eng = FailoverEngine()
    eng.start()
    return eng
