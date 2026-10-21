"""SQLite online snapshots of the registry and each customer database."""
import hashlib
import json
from pathlib import Path
import re
import sqlite3


def _copy_database(source, destination):
    if source.is_symlink() or not source.is_file():
        raise ValueError('workspace database must be a regular file')
    with sqlite3.connect(source.as_uri() + '?mode=ro', uri=True, timeout=30) as live:
        with sqlite3.connect(destination) as copy:
            live.backup(copy)
            if copy.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise ValueError('workspace database integrity check failed')
    destination.chmod(0o600)


def snapshot_workspaces(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    destination.mkdir(parents=True, mode=0o700)
    files, count = {}, 0
    if (source / 'registry.db').exists():
        _copy_database(source / 'registry.db', destination / 'registry.db')
        with sqlite3.connect(destination / 'registry.db') as registry:
            ids = [row[0] for row in registry.execute('SELECT id FROM workspaces')]
        for identity in ids:
            if not re.fullmatch('[0-9a-f]{32}', identity):
                raise ValueError('invalid workspace identity in registry')
            _copy_database(source / (identity + '.db'), destination / (identity + '.db'))
        count = len(ids)
        for path in destination.glob('*.db'):
            files[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    receipt = {'format': 1, 'workspaces': count, 'files': files,
               'installation_encryption_key_included': False,
               'contains_hashed_api_keys_and_encrypted_credentials': True}
    (destination / 'manifest.json').write_text(json.dumps(receipt), encoding='utf-8')
    return receipt


def validate_snapshot(directory):
    directory = Path(directory).resolve()
    manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
    if manifest.get('format') != 1:
        raise ValueError('unsupported workspace snapshot format')
    for name, expected in manifest['files'].items():
        if name != 'registry.db' and not re.fullmatch(r'[0-9a-f]{32}\.db', name):
            raise ValueError('invalid workspace snapshot file')
        path = directory / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('workspace snapshot integrity mismatch')
        with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
            if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise ValueError('workspace database integrity check failed')
    expected_files = set(manifest['files'])
    if expected_files:
        if 'registry.db' not in expected_files:
            raise ValueError('workspace snapshot registry missing')
        with sqlite3.connect(directory / 'registry.db') as db:
            ids = [row[0] for row in db.execute('SELECT id FROM workspaces')]
        if {'registry.db', *(identity + '.db' for identity in ids)} != expected_files:
            raise ValueError('workspace snapshot membership mismatch')
        if len(ids) != manifest['workspaces']:
            raise ValueError('workspace snapshot count mismatch')
    elif manifest['workspaces'] != 0:
        raise ValueError('workspace snapshot databases missing')
    return manifest
