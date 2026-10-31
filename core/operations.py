"""Allowlisted support data: no raw errors, endpoints, payloads or receipts."""
import math
import time

from fastapi import HTTPException

from core.models import (
    BenchmarkRun,
    BenchmarkSample,
    Job,
    OperationPolicy,
    OperationRecord,
)
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

    def summary(self, window_s=86400):
        """Summarize retained point observations, never infer uptime between samples."""
        from core.catalog import CATALOG
        if isinstance(window_s, bool) or not isinstance(window_s, int) or not 60 <= window_s <= 7*86400:
            raise ValueError('summary window must be 60..604800 seconds')
        now, policy = self.clock(), self.policy()
        with self.factory() as session:
            route_ids = [r.id for r in session.query(Job.id).filter_by(kind='mesh_route').order_by(
                Job.created_at.desc(), Job.id).limit(100)]
            rows = session.query(OperationRecord).filter(
                OperationRecord.kind == 'sample', OperationRecord.route_id.in_(route_ids),
                OperationRecord.ts >= now-window_s, OperationRecord.ts <= now).order_by(
                OperationRecord.ts.desc(), OperationRecord.id.desc()).limit(5000).all()
            groups = {identity: [] for identity in route_ids}
            for row in reversed(rows):
                groups[row.route_id].append((row.ts, row.document))
        routes = []
        for identity, samples in groups.items():
            counts = dict.fromkeys(('UP', 'DEGRADED', 'DOWN', 'UNAVAILABLE'), 0)
            latency = {}
            for _, raw in samples:
                doc = raw if isinstance(raw, dict) else {}
                health = doc.get('health')
                health = health if doc.get('observed') is True and health in ('UP','DEGRADED','DOWN') else 'UNAVAILABLE'
                counts[health] += 1
                probes = doc.get('probe_latency_ms')
                if health == 'UNAVAILABLE' or not isinstance(probes, dict):
                    continue
                for method, value in probes.items():
                    value = numeric(value)
                    if method in CATALOG.identities and value is not None and value >= 0:
                        latency.setdefault(method, []).append(value)
            first, last = (samples[0][0], samples[-1][0]) if samples else (None, None)
            gaps = [b[0]-a[0] for a, b in zip(samples, samples[1:])]
            age = max(0., now-last) if last is not None else None
            metrics = {}
            for method, values in sorted(latency.items()):
                values.sort()
                metrics[method] = {'samples':len(values), 'p50':values[math.ceil(len(values)*.5)-1],
                                   'p95':values[math.ceil(len(values)*.95)-1], 'max':values[-1]}
            latest = samples[-1][1] if samples and isinstance(samples[-1][1], dict) else {}
            health = latest.get('health')
            health = health if latest.get('observed') is True and health in ('UP','DEGRADED','DOWN') else 'UNAVAILABLE'
            routes.append({'route_id':identity, 'samples':len(samples), 'first_at':first, 'last_at':last,
                'span_s':last-first if samples else 0., 'last_age_s':age,
                'fresh':bool(policy['enabled'] and age is not None and age <= 2*policy['interval_s']+10),
                'latest_health':health, 'health_counts':counts,
                'up_sample_pct':100*counts['UP']/len(samples) if samples else None,
                'gap_count':sum(gap > 2*policy['interval_s'] for gap in gaps),
                'max_gap_s':max(gaps, default=0.), 'probe_latency_ms':metrics})
        return {'generated_at':now, 'window_s':window_s, 'interval_s':policy['interval_s'],
                'monitor_enabled':policy['enabled'], 'routes':routes,
                'scope':'latest100 workspace routes, latest5000 retained samples within window; point observations, not continuous uptime or SLA'}

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
                'events': self.history('transition'), 'summary': self.summary(),
                'scope': 'current workspace only; addresses, names, raw errors, credentials and configs omitted'}
