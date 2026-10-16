"""Allowlisted support data: no raw errors, endpoints, payloads or receipts."""
import math
import time

from fastapi import HTTPException

from core.models import BenchmarkRun, BenchmarkSample, Job, OperationPolicy, OperationRecord
from core.workspaces import freeze_factory

METRICS = ('rtt_avg', 'rtt_p95', 'jitter', 'loss_pct', 'throughput_mbps', 'reconnect_s',
           'stability_ratio', 'cpu_pct', 'ram_mb')
STATES = {'QUEUED', 'RUNNING', 'PASS', 'FAILED', 'CANCELLED', 'TIMED_OUT', 'INTERRUPTED',
          'APPLYING', 'COMMITTED', 'DEGRADED', 'STOPPING', 'STOPPED', 'BLOCKED', 'INCOMPATIBLE'}


def numeric(value):
    return value if isinstance(value, (float, int)) and not isinstance(value, bool) and math.isfinite(value) else None


class OperationsStore:
    def __init__(self, factory, clock=time.time):
        self.factory, self.clock = freeze_factory(factory), clock

    def policy(self):
        with self.factory() as session:
            policy = session.get(OperationPolicy, 'monitor')
            return {'enabled': bool(policy and policy.enabled), 'interval_s': policy.interval_s if policy else 60,
                    'retention_days': 7, 'max_samples': 5000, 'max_events': 1000,
                    'alerts': 'in-panel transitions; external notifications are not configured'}

    def configure(self, enabled, interval_s=60):
        if not 60 <= interval_s <= 3600:
            raise HTTPException(400, 'monitor interval must be 60..3600 seconds')
        with self.factory() as session:
            row = session.get(OperationPolicy, 'monitor') or OperationPolicy(id='monitor')
            row.enabled, row.interval_s = bool(enabled), interval_s
            session.add(row)
            session.commit()
        return self.policy()

    def record(self, route_id, observation):
        from core.catalog import CATALOG
        now = self.clock()
        runtime = observation.get('runtime') or {}
        runtime = runtime if isinstance(runtime,dict) else {}
        healthy = runtime.get('healthy') or {}
        observed = observation.get('observed') is True
        counts = [v for k,v in healthy.items() if k in CATALOG.identities and isinstance(v, bool)] if isinstance(healthy, dict) else []
        observed = observed and bool(counts)
        health = ('UP' if counts and all(counts) else 'DEGRADED' if any(counts) else 'DOWN') if observed else 'UNAVAILABLE'
        state = observation.get('state')
        state = state if isinstance(state,str) and state in STATES else 'UNKNOWN'
        active = runtime.get('active')
        document = {'health': health, 'state': state, 'observed': observed,
                    'healthy_members': sum(counts) if observed else None,
                    'total_members': len(counts) if observed else None,
                    'active': active if isinstance(active,str) and active in CATALOG.identities else None,
                    'mode': runtime.get('mode') if isinstance(runtime.get('mode'),str) and runtime.get('mode') in {'balance','failover'} else None,
                    'gateway_updated_at': numeric(runtime.get('updated_at')) if observed else None,
                    'connections_total': numeric(runtime.get('connections_total')) if observed else None}
        probes=runtime.get('probes') or {}
        probes=probes if isinstance(probes,dict) else {}
        document['probe_latency_ms']={method:numeric(result.get('latency_ms'))
            for method,result in probes.items() if method in CATALOG.identities and isinstance(result,dict)} if observed else {}
        with self.factory() as session:
            if session.bind.dialect.name == 'sqlite':
                from sqlalchemy import text
                session.execute(text('BEGIN IMMEDIATE'))
            job = session.get(Job, route_id)
            if job is None or job.kind != 'mesh_route':
                raise HTTPException(404, 'route not found')
            previous = session.query(OperationRecord).filter_by(route_id=route_id, kind='sample').order_by(
                OperationRecord.ts.desc(), OperationRecord.id.desc()).first()
            if previous is None or any(previous.document.get(k) != document[k] for k in ('health','state','active','mode')):
                session.add(OperationRecord(route_id=route_id, ts=now, kind='transition',
                    document={k: document[k] for k in ('health','state','active','mode')}))
            session.add(OperationRecord(route_id=route_id, ts=now, kind='sample', document=document))
            session.flush()
            session.query(OperationRecord).filter(OperationRecord.ts < now-7*86400).delete()
            for kind, limit in [('sample',5000), ('transition',1000)]:
                excess = session.query(OperationRecord.id).filter_by(kind=kind).order_by(
                    OperationRecord.ts.desc(), OperationRecord.id.desc()).offset(limit).all()
                if excess:
                    session.query(OperationRecord).filter(OperationRecord.id.in_([r.id for r in excess])).delete()
            session.commit()

    def history(self, kind='sample', limit=200):
        with self.factory() as session:
            rows = session.query(OperationRecord).filter_by(kind=kind).filter(
                OperationRecord.ts >= self.clock()-7*86400).order_by(OperationRecord.ts.desc(),
                OperationRecord.id.desc()).limit(max(1,min(limit,1000))).all()
            return [{'id': r.id, 'route_id': r.route_id, 'at': r.ts, **r.document} for r in rows]

    def support_export(self):
        from core.catalog import CATALOG
        with self.factory() as session:
            routes = [{'id': j.id, 'state': j.state if j.state in STATES else 'UNKNOWN',
                       'methods': [m for m in j.payload.get('methods',[]) if m in CATALOG.identities]}
                      for j in session.query(Job).filter_by(kind='mesh_route').order_by(Job.created_at.desc()).limit(100)]
            samples = [{'candidate': r.candidate, 'status': r.status if r.status in STATES else 'UNKNOWN',
                        'metrics': {k: numeric((r.metrics or {}).get(k)) for k in METRICS}}
                       for r in session.query(BenchmarkSample).join(BenchmarkRun).order_by(BenchmarkRun.started_at.desc()).limit(500)
                       if r.candidate in CATALOG.identities]
        return {'schema': 'tunnelpannel-support-v1', 'generated_at': self.clock(), 'policy': self.policy(),
                'routes': routes, 'samples': samples, 'observations': self.history(),
                'events': self.history('transition'),
                'scope': 'current workspace only; addresses, names, raw errors, credentials and configs omitted'}
