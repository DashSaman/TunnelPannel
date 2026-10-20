"""Durable customer-wide credit reservations. No optimistic timeout refunds."""
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
import uuid

MAX_CREDIT = 8 * 1024 * 1024


class MonthlyUsage:
    def __init__(self, path, *, clock=time.time):
        self.path, self.clock = str(path), clock
        if Path(path).is_symlink():
            raise ValueError('quota database cannot be a symlink')
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.db() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS monthly_periods (
                    id TEXT PRIMARY KEY, workspace TEXT NOT NULL, starts REAL NOT NULL,
                    ends REAL NOT NULL, quota INTEGER NOT NULL, revision INTEGER NOT NULL,
                    current INTEGER NOT NULL);
                CREATE UNIQUE INDEX IF NOT EXISTS monthly_current ON monthly_periods(workspace) WHERE current=1;
                CREATE TABLE IF NOT EXISTS monthly_routes (
                    route TEXT PRIMARY KEY, workspace TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL,
                    enabled INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS monthly_credits (
                    id TEXT PRIMARY KEY, route TEXT NOT NULL, period TEXT NOT NULL,
                    request TEXT NOT NULL, amount INTEGER NOT NULL, requested INTEGER NOT NULL,
                    upload INTEGER NOT NULL DEFAULT 0, download INTEGER NOT NULL DEFAULT 0,
                    closed INTEGER NOT NULL DEFAULT 0, updated REAL NOT NULL,
                    UNIQUE(route,request));
                CREATE TABLE IF NOT EXISTS monthly_audit (
                    id INTEGER PRIMARY KEY, workspace TEXT NOT NULL, at REAL NOT NULL,
                    actor TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS monthly_rejections (
                    route TEXT NOT NULL, request TEXT NOT NULL, period TEXT,
                    amount INTEGER NOT NULL, PRIMARY KEY(route,request));
            ''')
        os.chmod(self.path, 0o600)

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA synchronous=FULL')
        try:
            with db:
                yield db
        finally:
            db.close()

    def _period(self, db, workspace):
        return db.execute('SELECT * FROM monthly_periods WHERE workspace=? AND current=1', (workspace,)).fetchone()

    def _totals(self, db, period):
        row = db.execute('SELECT COALESCE(SUM(upload+download),0), '
            'COALESCE(SUM(CASE WHEN closed=0 THEN amount-upload-download ELSE 0 END),0) '
            'FROM monthly_credits WHERE period=?', (period,)).fetchone()
        return row[0], row[1]

    def grant(self, workspace, quota, ends, *, expected_revision, actor, new_period=False):
        now = self.clock()
        if (type(quota) is not int or not 1 <= quota <= 10**16
                or isinstance(ends, bool) or not isinstance(ends, (int, float))
                or not math.isfinite(ends) or not now < ends <= now + 366*86400
                or type(expected_revision) is not int or expected_revision < 0):
            raise ValueError('invalid allowance or period')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            old = self._period(db, workspace)
            if expected_revision != (old['revision'] if old else 0):
                raise ValueError('allowance revision changed; refresh first')
            used, held = self._totals(db, old['id']) if old else (0, 0)
            if new_period and held:
                raise ValueError('close outstanding credits before opening another period')
            if not new_period and quota < used + held:
                raise ValueError('allowance cannot be lower than consumed plus held credit')
            revision = expected_revision + 1
            if old and not new_period:
                db.execute('UPDATE monthly_periods SET quota=?,ends=?,revision=? WHERE id=?',
                           (quota, ends, revision, old['id']))
                identity = old['id']
            else:
                if old:
                    db.execute('UPDATE monthly_periods SET current=0 WHERE id=?', (old['id'],))
                identity = uuid.uuid4().hex
                db.execute('INSERT INTO monthly_periods VALUES(?,?,?,?,?,?,1)',
                           (identity, workspace, now, ends, quota, revision))
            db.execute('INSERT INTO monthly_audit(workspace,at,actor,event,detail) VALUES(?,?,?,?,?)',
                       (workspace, now, actor, 'new_period' if new_period or not old else 'edit_allowance',
                        json.dumps({'period': identity, 'quota_bytes': quota, 'ends_at': ends, 'revision': revision})))
        return self.status(workspace)['period']

    def status(self, workspace):
        with self.db() as db:
            row = self._period(db, workspace)
            used, held = self._totals(db, row['id']) if row else (0, 0)
            period = ({'id': row['id'], 'starts_at': row['starts'], 'ends_at': row['ends'],
                       'quota_bytes': row['quota'], 'revision': row['revision'],
                       'expired': self.clock() >= row['ends']} if row else None)
            history = [dict(r) for r in db.execute('SELECT at,event,detail FROM monthly_audit '
                       'WHERE workspace=? ORDER BY id DESC LIMIT 100', (workspace,))]
            periods = []
            for old in db.execute('SELECT * FROM monthly_periods WHERE workspace=? ORDER BY starts DESC LIMIT 100', (workspace,)):
                old_used, old_held = self._totals(db, old['id'])
                periods.append({'id':old['id'], 'starts_at':old['starts'], 'ends_at':old['ends'],
                                'quota_bytes':old['quota'], 'used_bytes':old_used, 'held_bytes':old_held})
        return {'period': period, 'used_bytes': used, 'held_bytes': held,
                'available_bytes': max(0, row['quota'] - used - held) if row else 0,
                'history': history, 'periods': periods,
                'basis': 'combined accepted payload; outstanding reserved credit shown separately'}

    def register_route(self, workspace, route):
        token = 'tpq_' + secrets.token_urlsafe(36)
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            previous = db.execute('SELECT enabled FROM monthly_routes WHERE route=?', (route,)).fetchone()
            if previous and previous['enabled']:
                raise ValueError('route credential is already active')
            db.execute('INSERT INTO monthly_routes VALUES(?,?,?,1) ON CONFLICT(route) DO UPDATE '
                       'SET workspace=excluded.workspace,token_hash=excluded.token_hash,enabled=1',
                       (route, workspace, hashlib.sha256(token.encode()).hexdigest()))
        return token

    def _route(self, db, token):
        if not isinstance(token, str) or not token.startswith('tpq_') or len(token) > 128:
            raise PermissionError('invalid route credential')
        row = db.execute('SELECT * FROM monthly_routes WHERE token_hash=? AND enabled=1',
                         (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if row is None:
            raise PermissionError('invalid route credential')
        return row

    def token_workspace(self, token):
        with self.db() as db:
            return self._route(db, token)['workspace']

    def exchange(self, token, *, request_id=None, amount=0, period_id=None,
                 grant_id=None, upload=None, download=None, close=False):
        if (type(amount) is not int or not 0 <= amount <= MAX_CREDIT or type(close) is not bool
                or any(v is not None and (type(v) is not int or not 0 <= v <= MAX_CREDIT)
                       for v in (upload, download))
                or request_id is not None and not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', request_id)
                or request_id and grant_id):
            raise ValueError('invalid credit message')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            route = self._route(db, token)
            period = self._period(db, route['workspace'])
            now = self.clock()
            credit = None
            if grant_id:
                credit = db.execute('SELECT * FROM monthly_credits WHERE id=? AND route=?',
                                    (grant_id, route['route'])).fetchone()
                if credit is None:
                    raise ValueError('credit not found for this route')
                up = credit['upload'] if upload is None else upload
                down = credit['download'] if download is None else download
                if (up < credit['upload'] or down < credit['download'] or up + down > credit['amount']
                        or credit['closed'] and (up != credit['upload'] or down != credit['download'])):
                    raise ValueError('credit report must be monotonic and within grant')
                db.execute('UPDATE monthly_credits SET upload=?,download=?,closed=?,updated=? WHERE id=?',
                           (up, down, int(close or credit['closed']), now, credit['id']))
                credit = db.execute('SELECT * FROM monthly_credits WHERE id=?', (credit['id'],)).fetchone()
            elif request_id:
                credit = db.execute('SELECT * FROM monthly_credits WHERE route=? AND request=?',
                                    (route['route'], request_id)).fetchone()
                if credit and credit['period'] != period_id:
                    raise ValueError('request identity belongs to another period')
                if credit and credit['requested'] != amount:
                    raise ValueError('request identity has different credit parameters')
                if not credit:
                    rejected = db.execute('SELECT period,amount FROM monthly_rejections WHERE route=? AND request=?',
                                          (route['route'], request_id)).fetchone()
                    if rejected and (rejected['period'] != period_id or rejected['amount'] != amount):
                        raise ValueError('rejected request identity has different parameters')
                    if rejected or not period or period['id'] != period_id or now >= period['ends']:
                        db.execute('INSERT OR IGNORE INTO monthly_rejections VALUES(?,?,?,?)',
                                   (route['route'], request_id, period_id, amount))
                        return {'grant_id':None, 'amount':0, 'closed':True, 'ttl_s':0,
                                'period_id':None, 'ends_at':None, 'rejected':True}
                    if amount < 1:
                        raise ValueError('credit size is required')
                    if db.execute('SELECT 1 FROM monthly_credits WHERE route=? AND closed=0', (route['route'],)).fetchone():
                        raise ValueError('close the previous credit before requesting another')
                    used, held = self._totals(db, period['id'])
                    allowed = min(amount, max(0, period['quota'] - used - held))
                    if allowed:
                        identity = uuid.uuid4().hex
                        db.execute('INSERT INTO monthly_credits(id,route,period,request,amount,requested,updated) VALUES(?,?,?,?,?,?,?)',
                                   (identity, route['route'], period['id'], request_id, allowed, amount, now))
                        credit = db.execute('SELECT * FROM monthly_credits WHERE id=?', (identity,)).fetchone()
            ttl = (max(0, min(10, period['ends'] - now)) if period and credit
                   and credit['period'] == period['id'] and not credit['closed'] else 0)
            return {'grant_id': credit['id'] if credit else None,
                    'amount': credit['amount'] if credit else 0,
                    'closed': bool(credit['closed']) if credit else True, 'ttl_s': ttl,
                    'period_id': period['id'] if period and now < period['ends'] else None,
                    'ends_at': period['ends'] if period else None}

    def has_open_credits(self, route):
        with self.db() as db:
            return bool(db.execute('SELECT 1 FROM monthly_credits WHERE route=? AND closed=0', (route,)).fetchone())

    def retire_route(self, route, final_usage):
        """Only after a caller has independently stopped/fenced the owned worker."""
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            credits = db.execute('SELECT * FROM monthly_credits WHERE route=? AND closed=0', (route,)).fetchall()
            for credit in credits:
                up, down = final_usage.get(credit['id'], (0, 0))
                if (type(up) is not int or type(down) is not int or up < credit['upload']
                        or down < credit['download'] or up + down > credit['amount']):
                    raise ValueError('fenced usage is missing, corrupt or lower than reported usage')
                db.execute('UPDATE monthly_credits SET upload=?,download=?,closed=1,updated=? WHERE id=?',
                           (up, down, self.clock(), credit['id']))
            db.execute('UPDATE monthly_routes SET enabled=0 WHERE route=?', (route,))
