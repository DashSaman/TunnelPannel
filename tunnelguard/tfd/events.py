"""TunnelGuard — in-process event hub feeding WebSocket subscribers."""
from __future__ import annotations

import asyncio
import json
import threading

_lock = threading.Lock()
_subscribers: set = set()


def subscribe(ws) -> None:
    with _lock:
        _subscribers.add(ws)


def unsubscribe(ws) -> None:
    with _lock:
        _subscribers.discard(ws)


def publish(event: dict) -> int:
    data = json.dumps(event, default=str)
    dead = []
    with _lock:
        targets = list(_subscribers)
    for ws in targets:
        try:
            loop = getattr(ws, "_tg_loop", None)
            if loop and loop.is_running():
                asyncio.run_coroutine_threadsafe(ws.send_text(data), loop)
            else:
                asyncio.ensure_future(ws.send_text(data))
        except Exception:
            dead.append(ws)
    with _lock:
        for ws in dead:
            _subscribers.discard(ws)
    return len(targets)


def attach(failover_engine) -> None:
    """Route failover broadcasts into the WS hub."""
    failover_engine.listeners.append(publish)
