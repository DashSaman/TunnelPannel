"""Owner-confirmed offline payments. The ledger never claims a gateway charge."""
import hashlib
import json
import sqlite3
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictInt, ValidationError

from core.workspaces import validated_limits


class CommercialPlan(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=1, max_length=120)
    price_minor: int = Field(strict=True, gt=0, le=10**12)
    currency: Literal['IRT','IRR'] = 'IRT'
    duration_days: int = Field(default=30, strict=True, ge=1, le=366)
    enabled: bool = Field(default=True, strict=True)
    limits: dict[str, StrictInt]


class ManualPayment(BaseModel):
    model_config = ConfigDict(extra='forbid')
    request_id: str = Field(min_length=8,max_length=128,pattern=r'^[A-Za-z0-9_.:-]+$')
    plan: str = Field(min_length=1,max_length=48,pattern=r'^[a-z][a-z0-9_-]*$')
    amount_minor: int = Field(strict=True,gt=0,le=10**12)
    currency: Literal['IRT','IRR']
    reference: str = Field(min_length=3,max_length=120)


class OwnerTestGrant(BaseModel):
    model_config = ConfigDict(extra='forbid',str_strip_whitespace=True)
    request_id: str = Field(pattern=r'^[0-9a-f]{32}$')
    days: int = Field(default=1,strict=True,ge=1,le=7)
    reason: str = Field(min_length=8,max_length=200)


def initialize_commerce(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS commercial_plans (
            id TEXT PRIMARY KEY,name TEXT NOT NULL,price_minor INTEGER,currency TEXT,
            duration_days INTEGER NOT NULL,enabled INTEGER NOT NULL,limits TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS manual_payments (
            id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,plan_id TEXT NOT NULL,
            payload_hash TEXT NOT NULL,reference TEXT UNIQUE NOT NULL,result TEXT NOT NULL,
            actor TEXT NOT NULL,created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS billing_test_grants (
            id TEXT PRIMARY KEY,workspace_id TEXT UNIQUE NOT NULL,payload_hash TEXT NOT NULL,
            result TEXT NOT NULL,actor TEXT NOT NULL,reason TEXT NOT NULL,created_at REAL NOT NULL);
    ''')
    db.execute('BEGIN IMMEDIATE')
    if 'entitlement_limits' not in {r['name'] for r in db.execute('PRAGMA table_info(billing_subscriptions)')}:
        db.execute('ALTER TABLE billing_subscriptions ADD COLUMN entitlement_limits TEXT')


def _validated(model, body):
    try:
        return model.model_validate(body).model_dump()
    except ValidationError:
        raise HTTPException(400, 'invalid commercial fields') from None


def _plan(row):
    return {**dict(row), 'enabled':bool(row['enabled']), 'limits':validated_limits(json.loads(row['limits']))}


class ManualCommerce:
    def grant_test_access(self,workspace_id,body,*,actor):
        """One explicit audited trial for a new customer; never a payment or renewal."""
        from core.subscriptions import PLAN_LIMITS
        values=_validated(OwnerTestGrant,body)
        if self.mode!='manual':
            raise HTTPException(409,'internal test access requires manual billing mode')
        fingerprint=hashlib.sha256(json.dumps({'workspace':workspace_id,**values},sort_keys=True).encode()).hexdigest()
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            prior=db.execute('SELECT * FROM billing_test_grants WHERE id=?',(values['request_id'],)).fetchone()
            if prior:
                if prior['payload_hash']!=fingerprint:
                    raise HTTPException(409,'test grant identity reused with different content')
                return {**json.loads(prior['result']),'duplicate':True}
            workspace=db.execute('SELECT enabled FROM workspaces WHERE id=?',(workspace_id,)).fetchone()
            if not workspace or not workspace['enabled']:
                raise HTTPException(409,'select an enabled customer workspace')
            if (db.execute('SELECT 1 FROM billing_subscriptions WHERE workspace_id=?',(workspace_id,)).fetchone()
                    or db.execute('SELECT 1 FROM billing_test_grants WHERE workspace_id=?',(workspace_id,)).fetchone()):
                raise HTTPException(409,'test access is only available once for a new customer')
            now=self.clock();end=now+values['days']*86400
            result={'id':values['request_id'],'workspace_id':workspace_id,'plan':'starter','mode':'internal_test',
                    'state':'trial','ends_at':end,'revision':1,'duplicate':False,'payment_collected':False}
            db.execute('INSERT INTO billing_test_grants VALUES(?,?,?,?,?,?,?)',
                       (values['request_id'],workspace_id,fingerprint,json.dumps(result),actor,values['reason'],now))
            db.execute('INSERT INTO billing_subscriptions '
                       '(workspace_id,plan,revision,state,paid_through,grace_until,mode,stop_on_expiry,entitlement_limits) '
                       'VALUES(?,?,?,?,?,?,?,?,?)',
                       (workspace_id,'starter',1,'trial',end,end,'internal_test',1,json.dumps(PLAN_LIMITS['starter'])))
            return result

    def commercial_plans(self, *, include_disabled=False):
        from core.subscriptions import PLAN_LIMITS
        with self._db() as db:
            saved = {r['id']:_plan(r) for r in db.execute('SELECT * FROM commercial_plans ORDER BY id')}
        plans = {key:{'id':key,'name':key.upper(),'limits':validated_limits(value),'price_minor':None,
                     'currency':None,'duration_days':30,'enabled':True} for key,value in PLAN_LIMITS.items()}
        plans.update(saved)
        return [p for p in plans.values() if include_disabled or p['enabled']]

    def save_plan(self, plan_id, body):
        import re
        if not re.fullmatch(r'[a-z][a-z0-9_-]{0,47}',plan_id):
            raise HTTPException(400,'invalid plan identity')
        values = _validated(CommercialPlan,body)
        values['limits'] = validated_limits(changes=values['limits'])
        with self._db() as db:
            db.execute('INSERT INTO commercial_plans VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET '
                'name=excluded.name,price_minor=excluded.price_minor,currency=excluded.currency,'
                'duration_days=excluded.duration_days,enabled=excluded.enabled,limits=excluded.limits',
                (plan_id,values['name'],values['price_minor'],values['currency'],values['duration_days'],
                 int(values['enabled']),json.dumps(values['limits'])))
        return {'id':plan_id,**values}

    def manual_payments(self, workspace_id=None):
        with self._db() as db:
            rows = db.execute('SELECT result,created_at FROM manual_payments '+
                ('WHERE workspace_id=? ' if workspace_id else '')+'ORDER BY created_at DESC LIMIT 200',
                (workspace_id,) if workspace_id else ()).fetchall()
        return [{**json.loads(r['result']),'created_at':r['created_at']} for r in rows]

    def record_manual_payment(self, workspace_id, body, *, actor):
        if self.mode != 'manual':
            raise HTTPException(409,'manual payments require manual billing mode')
        values = _validated(ManualPayment,body)
        canonical = json.dumps({'workspace_id':workspace_id,**values},sort_keys=True,separators=(',',':'))
        fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            prior = db.execute('SELECT * FROM manual_payments WHERE id=?',(values['request_id'],)).fetchone()
            if prior:
                if prior['payload_hash'] != fingerprint:
                    raise HTTPException(409,'payment identity reused with different content')
                return {**json.loads(prior['result']),'duplicate':True}
            workspace = db.execute('SELECT enabled FROM workspaces WHERE id=?',(workspace_id,)).fetchone()
            if not workspace or not workspace['enabled']:
                raise HTTPException(409,'select an enabled customer workspace')
            row = db.execute('SELECT * FROM commercial_plans WHERE id=?',(values['plan'],)).fetchone()
            if not row or not row['enabled'] or not row['price_minor']:
                raise HTTPException(409,'configure an enabled priced plan before confirming payment')
            if values['amount_minor'] != row['price_minor'] or values['currency'] != row['currency']:
                raise HTTPException(400,'payment amount and currency must match the selected plan')
            previous = db.execute('SELECT * FROM billing_subscriptions WHERE workspace_id=?',(workspace_id,)).fetchone()
            revision = previous['revision']+1 if previous else 1
            now = self.clock()
            start = max(now,previous['paid_through']) if previous and previous['state']!='cancelled' and previous['mode'] in {'manual','bridge'} else now
            end = start + row['duration_days']*86400
            result = {'id':values['request_id'],'workspace_id':workspace_id,'plan':row['id'],
                'amount_minor':values['amount_minor'],'currency':values['currency'],'reference':values['reference'],
                'paid_through':end,'revision':revision,'duplicate':False,'mode':'manual',
                'confirmation':'recorded_by_owner','gateway_charge_performed':False}
            try:
                db.execute('INSERT INTO manual_payments VALUES(?,?,?,?,?,?,?,?)',
                    (values['request_id'],workspace_id,row['id'],fingerprint,values['reference'],json.dumps(result),actor,now))
            except sqlite3.IntegrityError:
                raise HTTPException(409,'payment reference was already recorded') from None
            db.execute('INSERT INTO billing_subscriptions '
                '(workspace_id,plan,revision,state,paid_through,grace_until,mode,entitlement_limits) VALUES(?,?,?,?,?,?,?,?) '
                'ON CONFLICT(workspace_id) DO UPDATE SET plan=excluded.plan,revision=excluded.revision,state=excluded.state,'
                'paid_through=excluded.paid_through,grace_until=excluded.grace_until,mode=excluded.mode,entitlement_limits=excluded.entitlement_limits',
                (workspace_id,row['id'],revision,'active',end,end,'manual',row['limits']))
            db.execute("UPDATE billing_requests SET state='CONFIRMED_MANUAL' WHERE workspace_id=? AND plan=? AND state='PENDING_OWNER_ACTIVATION'",
                       (workspace_id,row['id']))
            return result
