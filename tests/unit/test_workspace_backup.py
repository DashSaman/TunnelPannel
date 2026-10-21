import hashlib
import sqlite3

import pytest

pytestmark = pytest.mark.unit_portable


def test_online_workspace_backup_includes_registry_keys_limits_and_each_database(tmp_path):
    from core.workspace_backup import snapshot_workspaces, validate_snapshot
    source, target = tmp_path / 'customers', tmp_path / 'snapshot'
    source.mkdir()
    identity = 'a' * 32
    with sqlite3.connect(source / 'registry.db') as db:
        db.execute('CREATE TABLE workspaces(id TEXT PRIMARY KEY, key_hash TEXT, limits TEXT)')
        db.execute('INSERT INTO workspaces VALUES(?,?,?)', (identity, hashlib.sha256(b'key').hexdigest(), '{}'))
    with sqlite3.connect(source / (identity + '.db')) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE example(value TEXT)')
        db.execute('INSERT INTO example VALUES(?)', ('customer desired state',))
        db.commit()
        result = snapshot_workspaces(source, target)
    assert result['workspaces'] == 1
    assert validate_snapshot(target)['workspaces'] == 1
    with sqlite3.connect(target / (identity + '.db')) as db:
        assert db.execute('SELECT value FROM example').fetchone()[0] == 'customer desired state'
    (target / (identity + '.db')).write_bytes(b'corrupted')
    with pytest.raises(ValueError, match='integrity'):
        validate_snapshot(target)
