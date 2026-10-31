#!/usr/bin/env python3
"""Initialize/migrate a durable management store; owner secret is stdin only.

Run in a stopped management container with its own private data volume mounted.
Never contacts execution nodes or starts the API lifespan/recovery workers.
"""
import json
import os
from pathlib import Path
import sqlite3
import sys

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.accounts import AccountStore  # noqa: E402
from core.control_plane import configuration  # noqa: E402
from core.workspaces import WorkspaceRegistry  # noqa: E402


def initialize(data, owner, *, retire_pending=False):
    if configuration() is None:
        raise ValueError('management-only mode is required')
    data = Path(data)
    data.mkdir(parents=True, exist_ok=True, mode=0o700)
    registry = WorkspaceRegistry(data/'workspaces')
    root = Path(__file__).resolve().parents[1]
    paths = [data/'tunnelpannel.db', *sorted((data/'workspaces').glob('*.db'))]
    changes = []
    for path in paths:
        if path.name == 'registry.db':
            continue
        engine = create_engine('sqlite:///'+path.as_posix())
        config = Config(str(root/'alembic.ini'))
        config.set_main_option('script_location', str(root/'migrations'))
        with engine.begin() as connection:
            config.attributes['connection'] = connection
            command.upgrade(config, 'head')
        engine.dispose()
        with sqlite3.connect(path) as db:
            if retire_pending:
                cursor = db.execute("UPDATE jobs SET state='INTERRUPTED',error=? WHERE "
                    "state IN ('QUEUED','RUNNING','APPLYING','UPDATING','STOPPING')",
                    ('Recovered historical snapshot; old execution nodes were removed. No automatic replay.',))
                changes.append({'database':path.name,'interrupted_pending':cursor.rowcount})
                db.execute('UPDATE operation_policies SET enabled=0')
        os.chmod(path, 0o600)
    store = AccountStore(registry)
    # Retain existing users and hashes. Only the explicitly named system owner
    # receives the owner's requested login; an ambiguous customer match aborts.
    existing = [row for row in store.list_accounts() if row['username'] == owner['username'].lower()]
    if existing:
        if len(existing) != 1 or existing[0]['workspace_id'] != 'system' or existing[0]['role'] != 'SUPER_ADMIN':
            raise ValueError('owner name belongs to another identity')
        account = store.update_managed(existing[0]['id'], {'password':owner['password'], 'enabled':True})
    else:
        account = store.create_managed('system', username=owner['username'], password=owner['password'],
                                       display_name='TehNet administrator', role='SUPER_ADMIN')
    if retire_pending:
        with store._db() as db:
            db.execute('DELETE FROM account_sessions')
    return {'status':'PASS','owner':account['username'],'changes':changes,
            'historical_workers_replayed':False,'accounts':len(store.list_accounts())}


if __name__ == '__main__':
    request = json.load(sys.stdin)
    if set(request)-{'username','password','retire_pending'}:
        raise ValueError('unsupported owner initialization input')
    print(json.dumps(initialize(Path(os.environ['TP_WORKSPACES_DIR']).parent, request,
                                retire_pending=request.get('retire_pending', False))))
