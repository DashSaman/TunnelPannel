"""Owned warm tunnel groups and source-node forwarding actuators."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import secrets
import shlex
import threading
import time

from fastapi import HTTPException

from core.models import Deployment, Job, SecretReference
from core.workspaces import freeze_factory
from orchestrator.host_lease import HostLease
from orchestrator.mesh_campaign import quality_weights, recommendations, select_methods
from orchestrator.mesh_persistent import PersistentPairAdapter, egress_supported
from orchestrator.mesh_service import campaign_job, route_samples
from orchestrator.remote_nodes import NodeRemote, decrypt_credentials, encrypt_credentials, node_access


def route_job(session, route_id):
    job = session.get(Job, route_id)
    if job is None or job.kind != 'mesh_route':
        raise HTTPException(404, 'route not found')
    return job


def route_public(job):
    return {'id': job.id, 'state': job.state, 'progress': job.progress, 'error': job.error,
            **{key: job.payload.get(key) for key in ('source', 'destination', 'methods', 'members', 'campaign_id')},
            'created_at': job.created_at, 'capability': 'authenticated TCP SOCKS5 egress',
            'mode': job.payload.get('mode', 'failover'),
            'session_recovery': 'new connections switch; existing TCP sessions reconnect'}


def route_private(session, job):
    secret = session.get(SecretReference, job.payload.get('runtime_secret_id'))
    if secret is None:
        raise HTTPException(409, 'route runtime is not ready')
    return decrypt_credentials(secret.ciphertext)


def require_accounting_settled(job):
    if job.payload.get('accounting_migration', {}).get('phase') == 'pending':
        raise HTTPException(409, 'accounting migration requires source/controller recovery first')


def observe_route(factory, route_id):
    with factory() as session:
        job = route_job(session, route_id)
        result = route_public(job)
        if not job.payload.get('runtime_secret_id') or job.state in {'STOPPED', 'FAILED'}:
            return result
        runtime = route_private(session, job)
        endpoint, credentials = node_access(session, job.payload['source'])
    remote = None
    try:
        remote = NodeRemote(endpoint, credentials).connect()
        response = remote.run('cat ' + shlex.quote(runtime['directory'] + '/state.json'), root=True, check=False)
        if response['code']:
            return {**result, 'observed': False, 'observation_error': 'gateway state not available'}
        state = json.loads(response['stdout'])
        worker = remote.run('systemctl show --property=MainPID --value ' +
                            shlex.quote(runtime['service'] + '.service'), root=True, check=False)
        pid_matches = str(state.get('worker_pid', '')) == worker['stdout'].strip() and worker['stdout'].strip() != '0'
        return {**result, 'observed': pid_matches and 0 <= time.time() - state.get('updated_at', 0) < 30, 'runtime': state,
                'listen_host': runtime['config']['listen_host'], 'listen_port': runtime['config']['listen_port']}
    except Exception:  # remote outage/authentication is an unavailable observation
        return {**result, 'observed': False, 'observation_error': 'gateway observation failed'}
    finally:
        if remote:
            remote.close()


def route_lease(factory, route_id):
    key = str(factory.kw['bind'].url) + route_id
    return HostLease({'host': 'route-job:' + hashlib.sha256(key.encode()).hexdigest()})


class RouteService:
    def __init__(self, monthly=None):
        self._threads, self._lock = {}, threading.Lock()
        self.monthly = monthly

    def create(self, factory, request, limits):
        if not self.monthly:
            return self._create(factory, request, limits)
        workspace = self.monthly.identity()
        lease = self.monthly.lease(workspace)
        if not lease.acquire(10):
            raise HTTPException(409, 'customer allowance admission is busy')
        try:
            if self.monthly.store.status(workspace)['period']:
                self.monthly.callback_url()
            return self._create(factory, request, limits, workspace)
        finally:
            lease.release()

    def _create(self, factory, request, limits, workspace=None):
        from core.traffic import bounded_traffic
        traffic = bounded_traffic(getattr(request, 'traffic', None), limits)
        factory = freeze_factory(factory)
        with factory() as session:
            if session.bind.dialect.name == 'sqlite':
                from sqlalchemy import text
                session.execute(text('BEGIN IMMEDIATE'))
            active = session.query(Job).filter(Job.kind == 'mesh_route',
                Job.state.in_(['APPLYING', 'COMMITTED', 'DEGRADED', 'STOPPING'])).count()
            if active >= limits['max_active_routes']:
                raise HTTPException(409, 'workspace active route limit reached')
            campaign = campaign_job(session, request.campaign_id)
            if campaign.state in {'QUEUED', 'RUNNING'}:
                raise HTTPException(409, 'campaign must finish before deployment')
            route = next((r for r in campaign.payload['routes'] if r['id'] == request.route_id), None)
            if route is None:
                raise HTTPException(404, 'campaign route not found')
            samples = route_samples(session, route['job_id'])
            if request.methods is not None:
                selected = request.methods
            elif 'selection' in route:
                selected = route['selection']
            else:
                selected = recommendations([r for r in samples if egress_supported(r['candidate'])],
                    count=campaign.payload.get('recommend_count', 5),
                    objective=campaign.payload.get('objective', 'balanced'),
                    encrypted_only=campaign.payload.get('recommend_encrypted_only', False))['selected']
            methods = select_methods(samples, selected, limits['max_tunnels_per_route'])
            if not all(egress_supported(method) for method in methods):
                raise HTTPException(400, 'selection contains a profile without persistent TCP egress support')
            job = Job(kind='mesh_route', state='APPLYING', payload={
                'campaign_id': campaign.id, 'campaign_route_id': route['id'],
                'source': route['source'], 'destination': route['destination'],
                'methods': methods, 'members': [], 'listen_host': request.listen_host,
                'mode': request.mode, 'traffic': traffic},
                timeout_s=600 * len(methods))
            session.add(job)
            if self.monthly:
                session.flush()
                self.monthly.attach(session, job, workspace)
            session.commit()
            route_id = job.id
        self.kick(factory, route_id)
        return route_id

    def kick(self, factory, route_id):
        factory = freeze_factory(factory)
        key = str(factory.kw['bind'].url) + route_id
        with self._lock:
            if key in self._threads:
                return
            def work():
                lease = route_lease(factory, route_id)
                try:
                    if not lease.acquire(120):
                        return
                    self._run(factory, route_id)
                finally:
                    lease.release()
                    with self._lock:
                        self._threads.pop(key, None)
            thread = threading.Thread(target=work, daemon=True, name='route-' + route_id[:8])
            self._threads[key] = thread
            thread.start()

    def _run(self, factory, route_id):
        from orchestrator.mesh_reconcile import reconcile_benchmark
        try:
            with factory() as session:
                job = route_job(session, route_id)
                state, payload = job.state, dict(job.payload)
            if state == 'STOPPING':
                reconcile_benchmark(factory, route_id)
                if self.monthly:
                    self.monthly.retire(factory, route_id)
                with factory() as session:
                    job = route_job(session, route_id)
                    job.state, job.finished_at = 'STOPPED', dt.datetime.now(dt.timezone.utc)
                    session.commit()
                return
            if state != 'APPLYING':
                return
            # Idempotent restart: remove only this route job's recorded resources.
            reconcile_benchmark(factory, route_id)
            if self.monthly:
                self.monthly.retire(factory, route_id)
                self.monthly.renew(factory, route_id)
            with factory() as session:
                job = route_job(session, route_id)
                job.payload = {**job.payload, 'members': []}
                session.commit()
            self._deploy(factory, route_id, payload)
        except Exception:
            cleanup_ok = True
            try:
                reconcile_benchmark(factory, route_id)
                if self.monthly:
                    self.monthly.retire(factory, route_id)
            except Exception:
                cleanup_ok = False
            with factory() as session:
                job = route_job(session, route_id)
                stopping = job.state == 'STOPPING'
                job.state, job.error = ('STOPPED' if stopping and cleanup_ok else 'FAILED'), ('route deployment failed; owned resources reconciled' if cleanup_ok
                                                 else 'route deployment failed; owned resource reconciliation required')
                job.finished_at = dt.datetime.now(dt.timezone.utc)
                session.commit()

    def _deployment(self, factory, route_id, source, destination, method):
        with factory() as session:
            deployment = Deployment(node_a=source, node_b=destination, state='APPLYING',
                                    desired_state={'job_id': route_id, 'mesh': True, 'candidate': method})
            session.add(deployment)
            session.commit()
            deployment_id = deployment.id
        def persist(node_id, kind, key):
            from orchestrator.resources import ResourceManager
            with factory() as session:
                ResourceManager(session).reserve(kind=kind, key=key, node_id=node_id,
                    deployment_id=deployment_id, meta={'mesh_route': route_id, 'method': method})
                session.commit()
        return deployment_id, persist

    def _hold_entry_port(self, factory, route_id, payload, nonce, port):
        """Reserve the previous entry before a rebuilt member can allocate it."""
        from orchestrator.host_reservations import initialize
        from orchestrator.remote_journal import RemoteJournal
        from plan_executor import executor as bodies
        deployment_id,persist=self._deployment(factory,route_id,payload['source'],payload['destination'],'entry')
        with factory() as session:
            endpoint,credentials=node_access(session,payload['source'])
        lease=HostLease(endpoint)
        if not lease.acquire(120):raise RuntimeError('source host busy before entry reservation')
        remote=None
        try:
            remote=NodeRemote(endpoint,credentials).connect()
            journal=RemoteJournal(remote,nonce,0,endpoint['id'],persist)
            initialize(remote,journal,nonce,0)
            if bodies.free_port(remote,'tcp',port)!=port:
                raise RuntimeError('the stable gateway port is now owned by another listener')
            with factory() as session:
                session.get(Deployment,deployment_id).state='COMMITTED'
                session.commit()
        finally:
            if remote:remote.close()
            lease.release()

    def _deploy(self, factory, route_id, payload):
        from plan_executor import executor as bodies
        from orchestrator.pair_runtime import prepare_benchmark
        from types import SimpleNamespace
        prepare = prepare_benchmark(factory)
        upstreams, members = [], []
        previous_config = None
        if payload.get('runtime_secret_id'):
            with factory() as session:
                previous_config = route_private(session, route_job(session, route_id))['config']
        nonce = secrets.randbelow(900_000_000) + 100_000_000
        if previous_config:
            self._hold_entry_port(factory,route_id,payload,nonce,previous_config['listen_port'])
        with factory() as session:
            campaign = campaign_job(session, payload['campaign_id'])
            pair = next(r for r in campaign.payload['routes'] if r['id'] == payload['campaign_route_id'])
            samples = [row for row in route_samples(session, pair['job_id'])
                       if row['candidate'] in payload['methods']]
        weights = quality_weights(samples)
        metrics_by_method = {row['candidate']: row['metrics'] for row in samples}
        for index, method in enumerate(payload['methods']):
            with factory() as session:
                if route_job(session, route_id).state == 'STOPPING':
                    raise RuntimeError('route stop requested during deployment')
            request = SimpleNamespace(node_a={'node_id': payload['source']}, node_b={'node_id': payload['destination']},
                                      profile='NORMAL', methods=[method])
            _, _, candidates, adapter_factory = prepare(request)
            if hasattr(adapter_factory, 'prepare'):
                adapter_factory.prepare(candidates, lambda: False)
                if any(candidate.status != 'COMPATIBLE' for candidate in candidates):
                    raise RuntimeError('a required engine could not be prepared')
            temporary = adapter_factory(candidates[0])
            adapter = PersistentPairAdapter(candidates[0], temporary.access, 'NORMAL', nonce, index + 1,
                                            route_id=route_id)
            deployment_id, persist = self._deployment(factory, route_id, payload['source'], payload['destination'], method)
            adapter.bind(persist)
            try:
                adapter.configure()
                upstream = adapter.upstream()
                upstream.update(weight=weights[method], baseline_rtt_ms=metrics_by_method[method]['rtt_avg'])
                upstreams.append(upstream)
                members.append({'method': method, 'deployment_id': deployment_id, 'state': 'WARM'})
                with factory() as session:
                    deployment = session.get(Deployment, deployment_id)
                    deployment.state, deployment.committed_at = 'COMMITTED', dt.datetime.now(dt.timezone.utc)
                    job = route_job(session, route_id)
                    job.payload = {**job.payload, 'members': members}
                    job.progress = (index + 1) / (len(payload['methods']) + 1)
                    session.commit()
            except Exception:
                adapter.rollback()
                raise
            finally:
                adapter.detach()
        deployment_id, persist = self._deployment(factory, route_id, payload['source'], payload['destination'], 'gateway')
        with factory() as session:
            endpoint, credentials = node_access(session, payload['source'])
        lease = HostLease(endpoint)
        if not lease.acquire(120):
            raise RuntimeError('source host busy')
        remote = None
        try:
            remote = NodeRemote(endpoint, credentials).connect()
            from orchestrator.remote_journal import RemoteJournal
            journal = RemoteJournal(remote, nonce, len(payload['methods'])+1, endpoint['id'], persist)
            remote.observer = journal.observe
            from orchestrator.host_reservations import initialize
            initialize(remote, journal, nonce, len(payload['methods'])+1)
            directory = f'/var/lib/tunnelpannel/mesh/{route_id}/gateway'
            journal.record('path', directory)
            service = f'tpmesh-{nonce}-0-gateway'
            journal.record('service', service)
            if previous_config:
                # Our separate entry book still excludes this port from member
                # allocations. The listener check must still reject foreign use.
                remote.reserved_ports.discard(previous_config['listen_port'])
            port = bodies.free_port(remote, 'tcp', previous_config['listen_port'] if previous_config else 22000)
            if previous_config and port != previous_config['listen_port']:
                raise RuntimeError('the stable gateway port is now owned by another listener')
            config = {'listen_host': payload['listen_host'], 'listen_port': port,
                      'mode': payload.get('mode', (previous_config or {}).get('mode', 'failover')),
                      'username': previous_config['username'] if previous_config else 'tp-' + route_id[:10],
                      'password': previous_config['password'] if previous_config else secrets.token_urlsafe(32),
                      'upstreams': upstreams, 'probe_interval_s': 2, 'probe_timeout_s': 5,
                      'failures': 3, 'successes': 2, 'hold_down_s': 15}
            usage_dir = '/var/lib/tunnelpannel/route-usage'
            remote.run('install -d -m 700 ' + usage_dir, root=True)
            config.update(traffic=payload.get('traffic') or (previous_config or {}).get('traffic', {}),
                          usage_path=usage_dir + '/' + route_id + '.sqlite3')
            if self.monthly:
                with factory() as session:
                    monthly_config = self.monthly.config(session, route_job(session, route_id))
                if monthly_config:
                    config['monthly'] = monthly_config
                    bodies.write_remote_text(remote, directory + '/monthly_client.py',
                        Path(__file__).with_name('monthly_client.py').read_text(encoding='utf-8'), '0600')
            script = Path(__file__).with_name('mesh_gateway.py').read_text(encoding='utf-8')
            bodies.write_remote_text(remote, directory + '/gateway.py', script, '0600')
            bodies.write_remote_text(remote, directory + '/config.json', json.dumps(config), '0600')
            runtime = {'directory': directory, 'service': service, 'config': config}
            with factory() as session:
                secret = SecretReference(kind='mesh_runtime', ciphertext=encrypt_credentials(runtime))
                session.add(secret)
                session.flush()
                job = route_job(session, route_id)
                job.payload = {**job.payload, 'runtime_secret_id': secret.id}
                session.commit()
            bodies.persistent_service(remote, service,
                f'exec python3 {directory}/gateway.py {directory}/config.json {directory}/state.json')
            bodies.wait_listener(remote, 'tcp', port)
            observed = None
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                value = remote.run('cat ' + shlex.quote(directory + '/state.json'), root=True, check=False)
                if not value['code']:
                    observed = json.loads(value['stdout'])
                    if all(observed.get('healthy', {}).values()) and observed.get('active'):
                        break
                time.sleep(1)
            if not observed or not observed.get('active'):
                raise RuntimeError('gateway did not pass real owned nonce probes')
            with factory() as session:
                job = route_job(session, route_id)
                if job.state == 'STOPPING':
                    raise RuntimeError('route stop requested during gateway activation')
                job.state = 'COMMITTED' if all(observed['healthy'].values()) else 'DEGRADED'
                job.progress = 1
                session.get(Deployment, deployment_id).state = 'COMMITTED'
                session.commit()
        finally:
            if remote:
                remote.close()
            lease.release()

    def stop(self, factory, route_id):
        with factory() as session:
            job = route_job(session, route_id)
            if job.state == 'STOPPED':
                return
            job.state = 'STOPPING'
            session.commit()
        self.kick(factory, route_id)

    def reconcile(self, factory, route_id, methods, limits):
        if not self.monthly:
            return self._reconcile(factory, route_id, methods, limits)
        workspace = self.monthly.identity()
        lease = self.monthly.lease(workspace)
        if not lease.acquire(10):
            raise HTTPException(409, 'customer allowance admission is busy')
        try:
            return self._reconcile(factory, route_id, methods, limits, workspace)
        finally:
            lease.release()

    def _reconcile(self, factory, route_id, methods, limits, workspace=None):
        from core.traffic import bounded_traffic
        factory = freeze_factory(factory)
        lease = route_lease(factory, route_id)
        if not lease.acquire(2):
            raise HTTPException(409, 'route controller is busy')
        try:
            with factory() as session:
                if session.bind.dialect.name == 'sqlite':
                    from sqlalchemy import text
                    session.execute(text('BEGIN IMMEDIATE'))
                job = route_job(session, route_id)
                require_accounting_settled(job)
                if job.state in {'APPLYING', 'STOPPING'}:
                    raise HTTPException(409, 'wait for the route controller')
                others = session.query(Job).filter(Job.kind == 'mesh_route', Job.id != route_id,
                    Job.state.in_(['APPLYING', 'COMMITTED', 'DEGRADED', 'STOPPING'])).count()
                if others >= limits['max_active_routes']:
                    raise HTTPException(409, 'workspace active route limit reached')
                campaign = campaign_job(session, job.payload['campaign_id'])
                if campaign.state in {'QUEUED', 'RUNNING'}:
                    raise HTTPException(409, 'wait for campaign completion')
                pair = next((r for r in campaign.payload['routes'] if r['id'] == job.payload['campaign_route_id']
                    and r['source'] == job.payload['source'] and r['destination'] == job.payload['destination']), None)
                if pair is None:
                    raise HTTPException(400, 'the measured route does not match this deployment')
                selected = select_methods(route_samples(session, pair['job_id']),
                    methods if methods is not None else job.payload['methods'], limits['max_tunnels_per_route'])
                if not all(egress_supported(method) for method in selected):
                    raise HTTPException(400, 'selection requires persistent TCP egress support')
                traffic = bounded_traffic(job.payload.get('traffic'), limits)
                job.payload = {**job.payload, 'methods': selected, 'traffic': traffic}
                if self.monthly and not job.payload.get('monthly_secret_id'):
                    self.monthly.attach(session, job, workspace)
                job.state, job.progress, job.error, job.finished_at = 'APPLYING', 0, None, None
                session.commit()
        finally:
            lease.release()
        self.kick(factory, route_id)

    def recover(self, factory):
        with factory() as session:
            ids = [job.id for job in session.query(Job).filter(Job.kind == 'mesh_route',
                    Job.state.in_(['APPLYING', 'STOPPING']))]
        for route_id in ids:
            self.kick(factory, route_id)


def update_route_policy(factory, route_id, order=None, pin=None, mode=None, *, preserve_pin=False):
    factory = freeze_factory(factory)
    lease = route_lease(factory, route_id)
    if not lease.acquire(10):
        raise HTTPException(409, 'route controller is busy')
    try:
        return _update_route_policy(factory, route_id, order, pin, mode, preserve_pin=preserve_pin)
    finally:
        lease.release()


def _update_route_policy(factory, route_id, order, pin, mode, *, preserve_pin=False):
    from plan_executor import executor as bodies
    with factory() as session:
        job = route_job(session, route_id)
        require_accounting_settled(job)
        if job.state not in {'COMMITTED', 'DEGRADED'}:
            raise HTTPException(409, 'route must be active')
        runtime = route_private(session, job)
        endpoint, credentials = node_access(session, job.payload['source'])
    by_id = {u['id']: u for u in runtime['config']['upstreams']}
    if preserve_pin:
        pin = runtime['config'].get('pin')
    mode = mode if mode is not None else runtime['config'].get('mode', 'failover')
    if mode not in {'failover', 'balance'}:
        raise HTTPException(400, 'mode must be failover or balance')
    if order is not None and (len(order) != len(set(order)) or set(order) != set(by_id)):
        raise HTTPException(400, 'order must contain every deployed method exactly once')
    if pin is not None and pin not in by_id:
        raise HTTPException(400, 'pin must name a deployed method')
    config = {**runtime['config'], 'upstreams': [by_id[key] for key in (order or by_id)], 'pin': pin,
              'mode': mode}
    remote = NodeRemote(endpoint, credentials).connect()
    try:
        # Same-directory replace prevents the worker from reading partial JSON.
        target = runtime['directory'] + '/config.json'
        bodies.write_remote_text(remote, target + '.next', json.dumps(config), '0600')
        remote.run(f'mv -- {shlex.quote(target + ".next")} {shlex.quote(target)}', root=True)
        runtime['config'] = config
        with factory() as session:
            job = route_job(session, route_id)
            secret = session.get(SecretReference, job.payload['runtime_secret_id'])
            secret.ciphertext = encrypt_credentials(runtime)
            job.payload = {**job.payload, 'mode': mode}
            session.commit()
    finally:
        remote.close()
    return {'route_id': route_id, 'order': order or list(by_id), 'pin': pin, 'mode': mode}


def update_route_traffic(factory, route_id, value, limits):
    """Change v1 policy without restarting its listener or resetting its ledger."""
    from core.traffic import bounded_traffic
    from plan_executor import executor as bodies
    traffic = bounded_traffic(value, limits)
    factory = freeze_factory(factory)
    lease = route_lease(factory, route_id)
    if not lease.acquire(10):
        raise HTTPException(409, 'route controller is busy')
    remote = None
    try:
        with factory() as session:
            require_accounting_settled(route_job(session, route_id))
        observed = observe_route(factory, route_id)
        if not observed.get('observed') or observed.get('runtime', {}).get('traffic_control_version') != 1:
            raise HTTPException(409, 'this historical worker cannot enforce traffic controls; explicit reconciliation is required')
        with factory() as session:
            job = route_job(session, route_id)
            if job.state not in {'COMMITTED', 'DEGRADED'}:
                raise HTTPException(409, 'route must be active')
            runtime = route_private(session, job)
            endpoint, credentials = node_access(session, job.payload['source'])
        config = {**runtime['config'], 'traffic': traffic}
        remote = NodeRemote(endpoint, credentials).connect()
        target = runtime['directory'] + '/config.json'
        bodies.write_remote_text(remote, target + '.next', json.dumps(config), '0600')
        remote.run(f'mv -- {shlex.quote(target + ".next")} {shlex.quote(target)}', root=True)
        runtime['config'] = config
        with factory() as session:
            job = route_job(session, route_id)
            secret = session.get(SecretReference, job.payload['runtime_secret_id'])
            secret.ciphertext = encrypt_credentials(runtime)
            job.payload = {**job.payload, 'traffic': traffic}
            session.commit()
        return {'route_id': route_id, 'traffic': traffic, 'usage_reset': False}
    finally:
        if remote:
            remote.close()
        lease.release()
