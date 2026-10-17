"""Replay-safe subscription entitlements; the default sandbox never collects money."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import json
import os
import re
import time
from typing import Literal
import uuid

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

PLAN_LIMITS = {
    'starter': {'max_nodes': 2, 'max_tunnels_per_route': 5, 'max_campaign_methods': 108,
                'max_active_campaigns': 1, 'max_active_routes': 2, 'max_daily_candidate_units': 500},
    'pro': {'max_nodes': 6, 'max_tunnels_per_route': 10, 'max_campaign_methods': 108,
            'max_active_campaigns': 1, 'max_active_routes': 12, 'max_daily_candidate_units': 5000},
    'team': {'max_nodes': 12, 'max_tunnels_per_route': 10, 'max_campaign_methods': 160,
             'max_active_campaigns': 2, 'max_active_routes': 24, 'max_daily_candidate_units': 25000},
}


class BillingEvent(BaseModel):
    model_config = ConfigDict(extra='forbid', allow_inf_nan=False)
    event_id: str = Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9_.:-]+$')
    workspace_id: str = Field(pattern=r'^[0-9a-f]{32}$')
    revision: int = Field(strict=True, ge=1, le=9007199254740991)
    plan: Literal['starter', 'pro', 'team']
    state: Literal['trial', 'active', 'past_due', 'cancelled']
    paid_through: float = Field(ge=0, le=7258118400)
    grace_until: float | None = Field(default=None, ge=0, le=7258118400)
    mode: Literal['sandbox', 'bridge'] = 'sandbox'

    @model_validator(mode='after')
    def interval(self):
        self.grace_until = self.paid_through if self.grace_until is None else self.grace_until
        if not self.paid_through <= self.grace_until <= self.paid_through+7*86400:
            raise ValueError('grace must end within seven days after the paid-through time')
        return self


class SubscriptionStore:
    def __init__(self, registry, *, clock=time.time, webhook_secret=None, mode=None):
        self.registry, self.clock = registry, clock
        self.webhook_secret = webhook_secret if webhook_secret is not None else os.environ.get('TP_BILLING_WEBHOOK_SECRET', '')
        self.mode = mode or os.environ.get('TP_BILLING_MODE', 'sandbox')
        if self.mode not in {'sandbox', 'bridge'}:
            raise ValueError('TP_BILLING_MODE must be sandbox or bridge')
        with self._db() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS billing_subscriptions (
                    workspace_id TEXT PRIMARY KEY, plan TEXT NOT NULL, revision INTEGER NOT NULL,
                    state TEXT NOT NULL, paid_through REAL NOT NULL, grace_until REAL NOT NULL,
                    mode TEXT NOT NULL, stop_on_expiry INTEGER NOT NULL DEFAULT 0,
                    cleanup_revision INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS billing_events (
                    event_id TEXT PRIMARY KEY, payload_hash TEXT NOT NULL, result TEXT NOT NULL,
                    received_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS billing_requests (
                    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, plan TEXT NOT NULL,
                    state TEXT NOT NULL, created_at REAL NOT NULL);
                CREATE UNIQUE INDEX IF NOT EXISTS billing_pending_request
                    ON billing_requests(workspace_id,plan) WHERE state='PENDING_OWNER_ACTIVATION';
            ''')

    @contextmanager
    def _db(self):
        db = self.registry._connect()
        try:
            with db:
                yield db
        finally:
            db.close()

    def plans(self):
        return {'mode': self.mode, 'payment_processor_configured': False,
                'external_bridge_configured': self.mode == 'bridge' and len(self.webhook_secret) >= 32,
                'checkout_available': False,
                'plans': [{'id': key, 'limits': dict(value), 'price_minor': None, 'currency': None}
                          for key, value in PLAN_LIMITS.items()],
                'notice': 'sandbox entitlements do not represent collected payments' if self.mode == 'sandbox'
                          else 'external billing bridge; configure your provider checkout separately'}

    def _base_limits(self, workspace_id):
        from core.workspaces import DEFAULT_LIMITS
        if workspace_id == 'system':
            return dict(DEFAULT_LIMITS)
        with self._db() as db:
            row = db.execute('SELECT limits FROM workspaces WHERE id=?', (workspace_id,)).fetchone()
        if row is None:
            raise HTTPException(404, 'workspace not found')
        return {**DEFAULT_LIMITS, **json.loads(row['limits'])}

    def status(self, workspace_id, base_limits=None):
        base = dict(base_limits) if base_limits is not None else self._base_limits(workspace_id)
        with self._db() as db:
            row = db.execute('SELECT * FROM billing_subscriptions WHERE workspace_id=?', (workspace_id,)).fetchone()
        if row is None:
            return {'workspace_id': workspace_id, 'state': 'legacy', 'plan': None, 'revision': 0,
                    'mode': 'legacy', 'limits': base, 'can_start_work': True, 'stop_on_expiry': False,
                    'payment_collected': False}
        state, now = row['state'], self.clock()
        if state != 'cancelled':
            state = ('expired' if now >= row['grace_until'] else
                     'past_due' if now >= row['paid_through'] or state == 'past_due' else state)
        return {'workspace_id': workspace_id, 'state': state, 'plan': row['plan'], 'revision': row['revision'],
                'mode': row['mode'], 'paid_through': row['paid_through'], 'grace_until': row['grace_until'],
                'limits': {key: min(value, PLAN_LIMITS[row['plan']].get(key, value)) for key, value in base.items()},
                'can_start_work': state not in {'expired', 'cancelled'},
                'stop_on_expiry': bool(row['stop_on_expiry']),
                'payment_collected': False if row['mode'] == 'sandbox' else None}

    def authorize_operation(self, workspace_id, method, path):
        if workspace_id == 'system' or method in {'GET', 'HEAD', 'OPTIONS'} or path.startswith('/auth/'):
            return
        permitted = (path in {'/api/billing/requests', '/api/mesh/estimate', '/api/operations/policy'} or
                     method == 'DELETE' and re.fullmatch(r'/api/mesh/routes/[^/]+', path) or
                     method == 'POST' and re.fullmatch(r'(?:/benchmarks/[^/]+|/api/mesh/campaigns/[^/]+)/cancel', path) or
                     method == 'POST' and re.fullmatch(r'/api/nodes/[^/]+/managed-key(?:/revoke)?', path) or
                     method == 'DELETE' and re.fullmatch(r'/api/nodes/[^/]+/agent', path) or
                     method == 'PUT' and re.fullmatch(r'/api/nodes/[^/]+', path))
        if not permitted and not self.status(workspace_id)['can_start_work']:
            raise HTTPException(402, 'subscription expired; read, export, credential refresh and owned stop remain available')

    def apply_event(self, raw, timestamp, signature):
        if len(raw) > 16384:
            raise HTTPException(413, 'billing payload too large')
        if len(self.webhook_secret) < 32:
            raise HTTPException(503, 'billing webhook is not configured')
        if not re.fullmatch(r'[0-9]{1,12}', timestamp or '') or abs(self.clock()-int(timestamp)) > 300:
            raise HTTPException(401, 'billing signature expired or invalid')
        expected = hmac.new(self.webhook_secret.encode(), timestamp.encode()+b'.'+raw, hashlib.sha256).hexdigest()
        if not re.fullmatch(r'[0-9a-f]{64}', signature or '') or not hmac.compare_digest(expected, signature):
            raise HTTPException(401, 'billing signature expired or invalid')
        try:
            event = BillingEvent.model_validate(json.loads(raw))
        except (ValidationError, ValueError, TypeError, RecursionError):
            raise HTTPException(400, 'billing event schema is invalid') from None
        if event.mode != self.mode:
            raise HTTPException(400, 'billing mode mismatch')
        return self._apply(event)

    def _apply(self, event):
        with self._db() as db:
            exists = db.execute('SELECT id FROM workspaces WHERE id=?', (event.workspace_id,)).fetchone()
        if exists is None:
            raise HTTPException(404, 'workspace not found')
        canonical = json.dumps(event.model_dump(), sort_keys=True, separators=(',', ':'))
        payload_hash = hashlib.sha256(canonical.encode()).hexdigest()
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            prior = db.execute('SELECT * FROM billing_events WHERE event_id=?', (event.event_id,)).fetchone()
            if prior:
                if not hmac.compare_digest(prior['payload_hash'], payload_hash):
                    raise HTTPException(409, 'billing event identity was reused with different content')
                return {**json.loads(prior['result']), 'duplicate': True}
            current = db.execute('SELECT revision FROM billing_subscriptions WHERE workspace_id=?',
                                 (event.workspace_id,)).fetchone()
            applied = current is None or event.revision > current['revision']
            if applied:
                db.execute('INSERT INTO billing_subscriptions '
                    '(workspace_id,plan,revision,state,paid_through,grace_until,mode) VALUES(?,?,?,?,?,?,?) '
                    'ON CONFLICT(workspace_id) DO UPDATE SET plan=excluded.plan,revision=excluded.revision,'
                    'state=excluded.state,paid_through=excluded.paid_through,grace_until=excluded.grace_until,mode=excluded.mode',
                    (event.workspace_id, event.plan, event.revision, event.state,
                     event.paid_through, event.grace_until, event.mode))
                if event.state in {'active','trial'}:
                    db.execute("UPDATE billing_requests SET state=? WHERE workspace_id=? AND plan=? AND state='PENDING_OWNER_ACTIVATION'",
                        ('APPROVED_SANDBOX' if event.mode == 'sandbox' else 'CONFIRMED_EXTERNAL', event.workspace_id,event.plan))
            result = {'event_id': event.event_id, 'workspace_id': event.workspace_id,
                      'revision': event.revision, 'applied': applied, 'duplicate': False, 'mode': event.mode}
            db.execute('INSERT INTO billing_events VALUES(?,?,?,?)',
                       (event.event_id, payload_hash, json.dumps(result), self.clock()))
            return result

    def set_policy(self, workspace_id, *, stop_on_expiry):
        with self._db() as db:
            changed = db.execute('UPDATE billing_subscriptions SET stop_on_expiry=? WHERE workspace_id=?',
                                 (int(stop_on_expiry), workspace_id))
            if not changed.rowcount:
                raise HTTPException(409, 'create a subscription before setting its expiry policy')
        return self.status(workspace_id)

    def expiry_candidates(self):
        with self._db() as db:
            rows = db.execute('SELECT workspace_id,revision FROM billing_subscriptions '
                'WHERE stop_on_expiry=1 AND cleanup_revision<revision').fetchall()
        return [{'workspace_id': r['workspace_id'], 'revision': r['revision']} for r in rows
                if self.status(r['workspace_id'])['state'] in {'expired', 'cancelled'}]

    def mark_cleanup(self, workspace_id, revision):
        with self._db() as db:
            db.execute('UPDATE billing_subscriptions SET cleanup_revision=? WHERE workspace_id=? AND revision=?',
                       (revision, workspace_id, revision))

    def run_expiry_action(self, workspace_id, revision, action):
        """Serialize authorization with renewal; never dispatch a stale revision."""
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM billing_subscriptions WHERE workspace_id=?', (workspace_id,)).fetchone()
            if (row is None or row['revision'] != revision or not row['stop_on_expiry']
                    or row['cleanup_revision'] >= revision
                    or row['state'] != 'cancelled' and self.clock() < row['grace_until']):
                return False
            if action():
                db.execute('UPDATE billing_subscriptions SET cleanup_revision=? WHERE workspace_id=?',
                           (revision, workspace_id))
                return True
        return False

    def request_plan(self, workspace_id, plan):
        if workspace_id == 'system' or plan not in PLAN_LIMITS:
            raise HTTPException(400, 'select a known customer plan')
        with self._db() as db:
            db.execute('INSERT OR IGNORE INTO billing_requests VALUES(?,?,?,?,?)',
                (uuid.uuid4().hex, workspace_id, plan, 'PENDING_OWNER_ACTIVATION', self.clock()))
            row = db.execute("SELECT * FROM billing_requests WHERE workspace_id=? AND plan=? AND state='PENDING_OWNER_ACTIVATION'",
                             (workspace_id, plan)).fetchone()
        return {**dict(row), 'mode': self.mode, 'payment_collected': False, 'checkout_available': False}

    def requests(self, workspace_id=None):
        with self._db() as db:
            rows = db.execute('SELECT * FROM billing_requests WHERE workspace_id=? ORDER BY created_at DESC LIMIT 100',
                              (workspace_id,)).fetchall() if workspace_id else db.execute(
                                  'SELECT * FROM billing_requests ORDER BY created_at DESC LIMIT 100').fetchall()
        return [dict(row) for row in rows]

    def sandbox_grant(self, workspace_id, plan, *, days=30, grace_hours=24):
        if self.mode != 'sandbox':
            raise HTTPException(409, 'manual sandbox grants are disabled in bridge mode')
        if plan not in PLAN_LIMITS or not 1 <= days <= 366 or not 0 <= grace_hours <= 168:
            raise HTTPException(400, 'invalid plan or duration')
        # Revision selection and write are serialized across local API processes.
        from orchestrator.host_lease import HostLease
        lease = HostLease({'host': 'billing-grant:'+str(self.registry.directory.resolve())+':'+workspace_id})
        if not lease.acquire(10):
            raise HTTPException(409, 'subscription update busy')
        try:
            prior = self.status(workspace_id)
            self._apply(BillingEvent(event_id='sandbox-'+uuid.uuid4().hex, workspace_id=workspace_id,
                revision=prior['revision']+1, plan=plan, state='active',
                paid_through=self.clock()+days*86400,
                grace_until=self.clock()+days*86400+grace_hours*3600, mode='sandbox'))
            return self.status(workspace_id)
        finally:
            lease.release()

    def sandbox_cancel(self, workspace_id):
        if self.mode!='sandbox':
            raise HTTPException(409,'manual cancellation is disabled in bridge mode')
        from orchestrator.host_lease import HostLease
        lease=HostLease({'host':'billing-grant:'+str(self.registry.directory.resolve())+':'+workspace_id})
        if not lease.acquire(10):
            raise HTTPException(409,'subscription update busy')
        try:
            prior=self.status(workspace_id)
            if prior['state']=='cancelled':
                return prior
            if not prior['plan']:
                raise HTTPException(409,'activate a sandbox subscription first')
            self._apply(BillingEvent(event_id='sandbox-cancel-'+uuid.uuid4().hex,workspace_id=workspace_id,
                revision=prior['revision']+1,plan=prior['plan'],state='cancelled',
                paid_through=self.clock(),grace_until=self.clock(),mode='sandbox'))
            return self.status(workspace_id)
        finally:
            lease.release()
