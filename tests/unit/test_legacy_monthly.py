import asyncio
import json
import sqlite3
from contextlib import suppress

import pytest

from core.monthly_usage import MonthlyUsage

pytestmark = pytest.mark.unit_portable


def test_unlimited_two_sources_then_real_ceiling_preserves_used_and_held(tmp_path):
    pool=MonthlyUsage(tmp_path/'pool.db',clock=lambda:1000)
    period=pool.ensure_unlimited('customer',actor='owner')
    assert period['unlimited'] and period['quota_bytes'] is None and period['ends_at'] is None
    tokens=[pool.register_route('customer',route) for route in ['a','b']]
    grants=[pool.exchange(token,request_id='first',amount=1000,period_id=period['id']) for token in tokens]
    for token,grant in zip(tokens,grants):pool.exchange(token,grant_id=grant['grant_id'],upload=20,download=30)
    state=pool.status('customer')
    assert (state['used_bytes'],state['held_bytes'],state['available_bytes'])==(100,1900,None)
    with pytest.raises(ValueError):pool.grant('customer',1999,4000,expected_revision=1,actor='owner')
    pool.grant('customer',2001,4000,expected_revision=1,actor='owner')
    state=pool.status('customer')
    assert not state['period']['unlimited'] and state['period']['id']==period['id']
    assert (state['used_bytes'],state['held_bytes'],state['available_bytes'])==(100,1900,1)
    for token,grant in zip(tokens,grants):pool.exchange(token,grant_id=grant['grant_id'],upload=20,download=30,close=True)
    new=pool.grant('customer',200,5000,expected_revision=2,actor='owner',new_period=True)
    assert new['id']!=period['id'] and pool.status('customer')['periods'][1]['used_bytes']==100


def test_additive_old_schema_retains_existing_records_and_unlimited_does_not_expire(tmp_path):
    path=tmp_path/'old.db'
    with sqlite3.connect(path) as db:
        db.executescript('''CREATE TABLE monthly_periods(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,starts REAL NOT NULL,ends REAL NOT NULL,quota INTEGER NOT NULL,revision INTEGER NOT NULL,current INTEGER NOT NULL);
          CREATE TABLE monthly_routes(route TEXT PRIMARY KEY,workspace TEXT NOT NULL,token_hash TEXT UNIQUE NOT NULL,enabled INTEGER NOT NULL);
          INSERT INTO monthly_periods VALUES('old','other',1,4000,99,1,1);''')
    pool=MonthlyUsage(path,clock=lambda:1000)
    assert pool.status('other')['period']['quota_bytes']==99
    p=pool.ensure_unlimited('customer',actor='owner')
    token=pool.register_route('customer','route',preserve_existing=True)
    assert pool.preserves_existing(token)
    future=MonthlyUsage(path,clock=lambda:1000+400*86400)
    assert future.exchange(token,request_id='future',amount=100,period_id=p['id'])['amount']==100
    assert not future.status('customer')['period']['expired']
    assert future.ensure_unlimited('customer',actor='owner')['id']==p['id']


def test_startup_uses_two_real_probe_rounds_without_waiting_regular_interval(tmp_path):
    from orchestrator.mesh_gateway import Gateway
    async def exercise():
        config={'listen_host':'127.0.0.1','listen_port':0,'username':'client','password':'long-qa-password-123',
                'probe_interval_s':60,'upstreams':[{'id':'one'}]}
        path=tmp_path/'config.json';path.write_text(json.dumps(config))
        gateway=Gateway(config,tmp_path/'state.json');calls=[]
        async def probe(upstream):
            calls.append(upstream['id']);return {'ok':True,'latency_ms':1}
        gateway.probe=probe
        task=asyncio.create_task(gateway.run(path))
        try:
            async def ready():
                while gateway.policy.active is None:await asyncio.sleep(.005)
            await asyncio.wait_for(ready(),.5)
            assert len(calls)==2 and gateway.policy.healthy['one']
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):await task
    asyncio.run(exercise())


def test_upgraded_gateway_retains_legacy_connection_ceiling_and_existing_counter(tmp_path):
    from orchestrator.mesh_gateway import Gateway,TrafficLedger
    ledger=TrafficLedger(tmp_path/'usage.sqlite3')
    assert ledger.charge('upload',123,0)==123
    gateway=Gateway({'username':'keep','password':'keep-private-password','max_connections':7,
                     'upstreams':[{'id':'GRE'}]},tmp_path/'state.json')
    gateway.write_state()
    state=json.loads((tmp_path/'state.json').read_text())
    assert state['traffic']['limits']['max_connections']==7
    assert state['traffic']['used']['total_bytes']==123
