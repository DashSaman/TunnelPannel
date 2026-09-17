"""TunnelGuard — process entrypoint.

  python -m tfd                 # init DB, bootstrap admin, start FSM, serve API
Environment:
  TF_HOST / TF_PORT             bind address (default 127.0.0.1:8080)
  TF_ADMIN_USERNAME/TF_ADMIN_PASSWORD   bootstrap admin (created once)
  TF_SECRET_KEY                 persistent master secret (else file-backed)
  TF_SIM_MODE=1                 force simulation engines (lab/preview)
"""
from __future__ import annotations

import os
import secrets
import sys

import uvicorn

from . import config, db as dbm, events, security


def bootstrap_admin() -> tuple[str, str]:
    row = dbm.db().execute("SELECT * FROM users LIMIT 1").fetchone()
    if row:
        return row["username"], ""
    username = os.environ.get("TF_ADMIN_USERNAME", "admin")
    password = os.environ.get("TF_ADMIN_PASSWORD") or secrets.token_urlsafe(12)
    with dbm.tx() as d:
        d.execute("INSERT INTO users(username,pw_hash,role,created_at) VALUES(?,?,?,?)",
                  (username, security.hash_password(password), "admin",
                   __import__("time").time()))
    return username, password


def main() -> None:
    dbm.init()
    if os.environ.get("TF_SIM_MODE") == "1":
        dbm.set_settings({"sim_mode": True})
    username, password = bootstrap_admin()

    from .failover import engine as fsm
    events.attach(fsm)
    fsm.start()

    if password:
        pw_file = config.DATA_DIR / "bootstrap_password.txt"
        try:
            pw_file.write_text(f"{username}: {password}\n")
            pw_file.chmod(0o600)
            print(f"[tunnelguard] bootstrap admin -> {username} / {password}")
            print(f"[tunnelguard] (also stored in {pw_file} — chmod 600)")
        except OSError:
            print(f"[tunnelguard] bootstrap admin -> {username} / {password}")
    else:
        print(f"[tunnelguard] admin '{username}' already exists")

    host = os.environ.get("TF_HOST", "127.0.0.1")
    port = int(os.environ.get("TF_PORT", "8080"))
    print(f"[tunnelguard] dashboard http://{host}:{port}/  (API docs /docs)")
    uvicorn.run("tfd.api:app", host=host, port=port, log_level="warning")


if __name__ == "__main__":
    sys.exit(main())
