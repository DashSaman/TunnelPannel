"""Opt-in sampled history and explicitly opted-in expiry cleanup."""
import hashlib
import time

from core.models import Job, OperationRecord
from core.operations import OperationsStore
from orchestrator.host_lease import HostLease


def expire_workspace_routes(factory, routes):
    with factory() as session:
        jobs = session.query(Job).filter(Job.kind == 'mesh_route', Job.state != 'STOPPED').all()
        pending = [(j.id,j.state) for j in jobs]
    for identity, state in pending:
        if state != 'STOPPING':
            routes.stop(factory, identity)
    with factory() as session:
        return session.query(Job).filter(Job.kind == 'mesh_route', Job.state != 'STOPPED').count() == 0


class OperationsMonitor:
    def __init__(self, observe=None, clock=time.time):
        from orchestrator.mesh_routes import observe_route
        self.observe, self.clock = observe or observe_route, clock

    def tick(self, factory):
        store = OperationsStore(factory, self.clock)
        policy = store.policy()
        if not policy['enabled']:
            return
        key = hashlib.sha256(str(factory.kw['bind'].url).encode()).hexdigest()
        lease = HostLease({'host': 'operation-monitor:' + key})
        if not lease.acquire(0):
            return
        try:
            with factory() as session:
                ids = [j.id for j in session.query(Job).filter(Job.kind == 'mesh_route',
                    Job.state.in_(['COMMITTED','DEGRADED','STOPPING','FAILED','STOPPED']))]
            for identity in ids:
                with factory() as session:
                    last = session.query(OperationRecord).filter_by(route_id=identity, kind='sample').order_by(
                        OperationRecord.ts.desc()).first()
                    if last and self.clock()-last.ts < policy['interval_s']:
                        continue
                    if last and last.document.get('state')=='STOPPED':
                        continue
                try:
                    observation = self.observe(factory, identity)
                except Exception:
                    observation = {'state':'UNKNOWN', 'observed':False}
                store.record(identity, observation)
        finally:
            lease.release()
