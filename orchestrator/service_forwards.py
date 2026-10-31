"""Scoped TCP-service lifecycle; parent route remains the only payload actuator."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time

from fastapi import HTTPException
from sqlalchemy import text

from core.models import Deployment, Job, ResourceAllocation, SecretReference
from core.service_forwards import ForwardApplyUpdate, ForwardCreate, ForwardPreflight, ForwardSpec, service_job, service_public
from core.workspaces import freeze_factory, workspace_context
from orchestrator.host_lease import HostLease
from orchestrator.mesh_routes import require_accounting_settled, route_job, route_lease, route_private
from orchestrator.remote_nodes import decrypt_credentials, encrypt_credentials, node_access
from orchestrator.resources import ResourceConflict, ResourceManager
from orchestrator.service_forward_runtime import validate_runtime


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def plain(value):
    return value.model_dump() if hasattr(value, 'model_dump') else value


def spec_fields(value):
    return {key: value[key] for key in ForwardSpec.model_fields if key in value}


def begin(session):
    if session.bind.dialect.name == 'sqlite':
        session.execute(text('BEGIN IMMEDIATE'))


def matching(observation, runtime):
    row = observation.get('runtime') or {}
    return bool(observation.get('observed') and row.get('listening')
                and type(row.get('worker_pid')) is int and row['worker_pid'] > 0
                and row.get('config_sha256') == runtime['config_sha256']
                and row.get('revision') == runtime['config']['revision']
                and observation.get('reservation_ports') == [runtime['config']['listen_port']])


class ServiceForwardService:
    def __init__(self, routes, *, subscriptions=None, node_driver=None, remote_factory=None):
        self.routes, self.subscriptions = routes, subscriptions
        if node_driver is None:
            from orchestrator.service_forward_nodes import ForwardNodeDriver
            node_driver = ForwardNodeDriver(remote_factory=remote_factory)
        self.nodes, self.clock = node_driver, time.time
        self._threads, self._lock = {}, threading.Lock()
        self._launching = set()

    def _workspace(self):
        return (workspace_context.get() or {}).get('id', 'system')

    def _authorize(self, workspace, *, cleanup=False):
        if self.subscriptions is None:
            if workspace != 'system':
                raise HTTPException(503, 'customer admission service unavailable')
            return
        if not cleanup:
            if workspace != 'system' and not any(row['id'] == workspace and row['enabled']
                    for row in self.subscriptions.registry.list()):
                raise HTTPException(403, 'customer workspace disabled')
            self.subscriptions.authorize_operation(workspace, 'POST', '/api/mesh/services')

    def _context(self, factory, identity, *, live=True):
        with factory() as session:
            parent = route_job(session, identity)
            if live:
                require_accounting_settled(parent)
                if parent.state not in {'COMMITTED', 'DEGRADED'}:
                    raise HTTPException(409, 'select an active settled route group')
            runtime = route_private(session, parent)
            source, source_secret = node_access(session, parent.payload['source'])
            destination, destination_secret = node_access(session, parent.payload['destination'])
            if HostLease(source).key == HostLease(destination).key:
                raise HTTPException(409, 'service route must use two distinct pinned hosts')
            value = {'route_id': identity, 'source': source, 'destination': destination,
                     'access': {source['id']: source_secret, destination['id']: destination_secret},
                     'parent_runtime': runtime, 'parent_state': parent.state}
            value['requires_monthly'] = parent.payload.get('workspace_id', 'system') != 'system' or bool(runtime['config'].get('monthly'))
            value['forbidden_ports'] = [int(row.key) for row in session.query(ResourceAllocation).filter(
                ResourceAllocation.kind == 'tcp_port', ResourceAllocation.node_id == destination['id'],
                ResourceAllocation.released_at.is_(None)) if row.key.isdigit()]
            value['parent_digest'] = digest({'payload': parent.payload, 'config': runtime['config'], 'endpoints': [
                {key: endpoint[key] for key in ('id', 'host', 'port', 'ssh_username', 'host_key_fingerprint')}
                for endpoint in (source, destination)]})
            return value

    def _inspect(self, context, spec, owned=None):
        try:
            return self.nodes.inspect(context, spec, owned=owned)
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(409, 'fresh service coexistence inspection failed or found a conflict') from None

    def preflight(self, factory, body, limits):
        request = ForwardPreflight.model_validate(plain(body))
        workspace = self._workspace()
        self._authorize(workspace)
        factory = freeze_factory(factory)
        lease = route_lease(factory, request.route_id)
        if not lease.acquire(2):
            raise HTTPException(409, 'route controller busy')
        try:
            context = self._context(factory, request.route_id)
            owned = None
            if request.service_id:
                with factory() as session:
                    job = service_job(session, request.service_id)
                    if job.payload['route_id'] != request.route_id or job.payload['revision'] != request.expected_revision:
                        raise HTTPException(409, 'service revision or parent route changed')
                    owned = self._runtime(session, job)
                    if job.payload.get('pending_runtime_secret_id'):
                        owned = [owned, self._runtime(session, job, pending=True)]
            value = ForwardSpec.model_validate(spec_fields(request.model_dump())).model_dump()
            inspection = self._inspect(context, value, owned)
            token = secrets.token_hex(32)
            with factory() as session:
                begin(session)
                job = Job(kind='service_forward_preflight', state='PREFLIGHTED', payload={
                    'workspace_id': workspace, 'spec': value, 'token_sha256': hashlib.sha256(token.encode()).hexdigest(),
                    'expires_at': self.clock() + 120, 'parent_digest': context['parent_digest'],
                    'inspection': inspection, 'service_id': request.service_id,
                    'expected_revision': request.expected_revision})
                session.add(job)
                session.flush()
                result = {'id': job.id, 'token': token, 'expires_at': job.payload['expires_at'],
                          'state': 'PREFLIGHTED', 'spec': value}
                session.commit()
                return result
        finally:
            lease.release()

    def _runtime(self, session, job, *, pending=False):
        secret = session.get(SecretReference, job.payload.get('pending_runtime_secret_id' if pending else 'runtime_secret_id'))
        if secret is None or secret.kind != 'service_forward_runtime':
            raise HTTPException(409, 'service runtime identity unavailable')
        return decrypt_credentials(secret.ciphertext)

    def _candidate(self, context, identity, deployment_id, value, revision, limits):
        parent = context['parent_runtime']['config']
        upstream_host = {'0.0.0.0': '127.0.0.1', '::': '::1'}.get(parent['listen_host'], parent['listen_host'])
        config = validate_runtime({'schema': 1, 'id': identity, 'route_id': context['route_id'], 'revision': revision,
            'listen_host': value['bind_host'], 'listen_port': value['bind_port'],
            'target_host': value['target_host'], 'target_port': value['target_port'],
            'source_cidrs': value['source_cidrs'], 'allow_public': value['allow_public'],
            'max_connections': min(parent.get('traffic', {}).get('max_connections', 256),
                                   limits.get('max_route_connections', 10000)),
            'upstream': {'host': upstream_host, 'port': parent['listen_port'],
                         'username': parent['username'], 'password': parent['password']}})
        from orchestrator.service_forward_nodes import prepare_runtime
        return prepare_runtime({'config': config, 'config_sha256': digest(config), 'deployment_id': deployment_id,
                'owner': hashlib.sha256(os.environ.get('TP_SECRET_KEY', '').encode()).hexdigest(),
                'nonce': secrets.randbelow(900000000) + 100000000,
                'service': 'tpforward-' + identity,
                'directory': '/etc/tunnelpannel-forwards/' + identity,
                'code_directory': '/opt/tunnelpannel-forwards/' + identity,
                'state_path': '/var/lib/tunnelpannel-forward-' + identity + '/state.json'})

    def _ticket(self, session, request, workspace):
        row = session.get(Job, request.preflight_id)
        if row is None or row.kind != 'service_forward_preflight' or row.payload.get('workspace_id') != workspace:
            raise HTTPException(409, 'service preflight unavailable')
        value = ForwardSpec.model_validate(spec_fields(request.model_dump())).model_dump()
        if (not hmac.compare_digest(row.payload['token_sha256'], hashlib.sha256(request.preflight_token.encode()).hexdigest())
                or row.payload['spec'] != value):
            raise HTTPException(409, 'service preflight token or settings mismatch')
        if row.payload.get('applied_service_id'):
            if row.payload.get('request_id') != request.request_id:
                raise HTTPException(409, 'service preflight already consumed')
            return row, value, row.payload['applied_service_id']
        if row.payload['expires_at'] < self.clock() or row.state != 'PREFLIGHTED':
            raise HTTPException(409, 'service preflight expired; inspect again')
        return row, value, None

    def _fresh_inspection(self, factory, request, workspace, identity=None):
        # Caller holds the parent/admission leases. Close the read transaction
        # before SSH, then re-read all local admission state under BEGIN IMMEDIATE.
        # An inventory can take seconds; it must never own the SQLite writer lock.
        with factory() as session:
            ticket, value, replay = self._ticket(session, request, workspace)
            if replay:
                return None
            owned = None
            if identity:
                if (ticket.payload.get('service_id') != identity
                        or ticket.payload.get('expected_revision') != request.expected_revision):
                    raise HTTPException(409, 'service inspection identity mismatch')
                job = service_job(session, identity)
                if job.payload['route_id'] != request.route_id or job.payload['revision'] != request.expected_revision:
                    raise HTTPException(409, 'service changed before inspection')
                owned = self._runtime(session, job)
                if job.payload.get('pending_runtime_secret_id'):
                    owned = [owned, self._runtime(session, job, pending=True)]
            elif ticket.payload.get('service_id'):
                raise HTTPException(409, 'update preflight cannot create a new service')
        context = self._context(factory, request.route_id)
        return {'parent_digest': context['parent_digest'], 'inspection': self._inspect(context, value, owned)}

    def create(self, factory, body, limits):
        request = ForwardCreate.model_validate(plain(body))
        workspace = self._workspace()
        self._authorize(workspace)
        factory = freeze_factory(factory)
        admission = HostLease({'host': 'forward-admission:' + str(factory.kw['bind'].url)})
        lease = route_lease(factory, request.route_id)
        if not admission.acquire(2):
            raise HTTPException(409, 'service admission busy')
        launch_key, committed = None, False
        try:
            if not lease.acquire(2):
                raise HTTPException(409, 'route controller busy')
            try:
                fresh = self._fresh_inspection(factory, request, workspace)
                with factory() as session:
                    begin(session)
                    ticket, value, replay = self._ticket(session, request, workspace)
                    if replay:
                        service_job(session, replay)
                        return replay
                    if ticket.payload.get('service_id'):
                        raise HTTPException(409, 'update preflight cannot create a new service')
                    count = session.query(Job).filter(Job.kind == 'mesh_service_forward', Job.state != 'STOPPED').count()
                    maximum = min(32, limits['max_active_routes'])
                    if self.subscriptions:
                        maximum = min(maximum, self.subscriptions.status(workspace)['limits']['max_active_routes'])
                    if count >= maximum:
                        raise HTTPException(409, 'workspace active service limit reached')
                    # Parent lease is held; use a separate read transaction for its context.
                    context = self._context(factory, request.route_id)
                    if (fresh is None or context['parent_digest'] != ticket.payload['parent_digest']
                            or fresh != {'parent_digest': context['parent_digest'], 'inspection': ticket.payload['inspection']}):
                        raise HTTPException(409, 'parent route or source inspection changed')
                    identity = secrets.token_hex(16)
                    deployment = Deployment(node_a=context['source']['id'], node_b=context['destination']['id'],
                        state='APPLYING', desired_state={'job_id': identity, 'service_forward': True})
                    session.add(deployment)
                    session.flush()
                    runtime = self._candidate(context, identity, deployment.id, value, 1, limits)
                    secret = SecretReference(kind='service_forward_runtime', ciphertext=encrypt_credentials(runtime))
                    session.add(secret)
                    session.flush()
                    try:
                        ResourceManager(session).reserve(kind='tcp_port', key=str(value['bind_port']),
                            node_id=context['source']['id'], deployment_id=deployment.id, meta={'service_forward': identity})
                    except ResourceConflict:
                        raise HTTPException(409, 'service port already reserved; select another port') from None
                    session.add(Job(id=identity, kind='mesh_service_forward', state='APPLYING', payload={
                        **value, 'revision': 1, 'workspace_id': workspace, 'source': context['source']['id'],
                        'destination': context['destination']['id'], 'runtime_secret_id': secret.id,
                        'deployment_id': deployment.id, 'operation': {'request_id': request.request_id,
                            'parent_digest': context['parent_digest'], 'inspection': ticket.payload['inspection']}}))
                    ticket.state = 'APPLIED'
                    ticket.payload = {**ticket.payload, 'applied_service_id': identity, 'request_id': request.request_id}
                    launch_key = str(factory.kw['bind'].url) + identity
                    with self._lock:
                        self._launching.add(launch_key)
                    session.commit()
                    committed = True
            finally:
                lease.release()
        finally:
            admission.release()
            if launch_key:
                try:
                    if committed:
                        self.kick(factory, identity)
                finally:
                    with self._lock:
                        self._launching.discard(launch_key)
        return identity

    def update(self, factory, identity, body, limits):
        request = ForwardApplyUpdate.model_validate(plain(body))
        workspace = self._workspace()
        self._authorize(workspace)
        factory = freeze_factory(factory)
        lease = route_lease(factory, request.route_id)
        if not lease.acquire(2):
            raise HTTPException(409, 'route controller busy')
        committed, added, launch_key = False, False, str(factory.kw['bind'].url) + identity
        try:
            fresh = self._fresh_inspection(factory, request, workspace, identity)
            with factory() as session:
                begin(session)
                ticket, value, replay = self._ticket(session, request, workspace)
                if (ticket.payload.get('service_id') != identity
                        or ticket.payload.get('expected_revision') != request.expected_revision):
                    raise HTTPException(409, 'service update preflight identity mismatch')
                job = service_job(session, identity)
                if replay:
                    if replay != identity:
                        raise HTTPException(409, 'service operation identity changed')
                    return identity
                if (job.state != 'ACTIVE' or job.payload['revision'] != request.expected_revision
                        or job.payload['route_id'] != request.route_id or job.payload.get('pending_runtime_secret_id')):
                    raise HTTPException(409, 'service revision changed or requires recovery first')
                context = self._context(factory, request.route_id)
                previous = self._runtime(session, job)
                if (context['parent_digest'] != ticket.payload['parent_digest']
                        or fresh != {'parent_digest': context['parent_digest'], 'inspection': ticket.payload['inspection']}):
                    raise HTTPException(409, 'service parent or inspection changed')
                candidate = self._candidate(context, identity, previous['deployment_id'], value,
                    request.expected_revision + 1, limits)
                candidate['nonce'] = previous['nonce']
                candidate['owner'] = previous['owner']
                secret = SecretReference(kind='service_forward_runtime', ciphertext=encrypt_credentials(candidate))
                checkpoint = SecretReference(kind='service_forward_checkpoint', ciphertext=encrypt_credentials({
                    'runtime': previous, 'spec': spec_fields(job.payload), 'revision': job.payload['revision'],
                    'saved_at': self.clock()}))
                session.add_all([secret, checkpoint])
                session.flush()
                try:
                    ResourceManager(session).reserve(kind='tcp_port', key=str(value['bind_port']),
                        node_id=context['source']['id'], deployment_id=previous['deployment_id'],
                        meta={'service_forward': identity})
                except ResourceConflict:
                    raise HTTPException(409, 'service port already reserved; select another port') from None
                operation = Job(kind='service_forward_operation', state='UPDATING', payload={
                    'service_id': identity, 'workspace_id': workspace, 'request_id': request.request_id,
                    'old_runtime_secret_id': job.payload['runtime_secret_id'], 'new_runtime_secret_id': secret.id,
                    'checkpoint_secret_id': checkpoint.id})
                session.add(operation)
                session.flush()
                job.payload = {**job.payload, 'pending_runtime_secret_id': secret.id, 'pending_spec': value,
                    'operation': {'request_id': request.request_id, 'parent_digest': context['parent_digest'],
                        'inspection': ticket.payload['inspection'], 'checkpoint_secret_id': checkpoint.id,
                        'operation_id': operation.id}}
                job.state, job.error = 'UPDATING', None
                ticket.state, ticket.payload = 'APPLIED', {**ticket.payload, 'applied_service_id': identity,
                                                          'request_id': request.request_id}
                with self._lock:
                    self._launching.add(launch_key)
                    added = True
                session.commit()
                committed = True
        finally:
            lease.release()
            if added:
                try:
                    if committed:
                        self.kick(factory, identity)
                finally:
                    with self._lock:
                        self._launching.discard(launch_key)
        return identity

    @staticmethod
    def _observe_node(nodes, context, runtime):
        try:
            return nodes.observe(context, runtime)
        except Exception:
            return {'observed': False}

    def reconcile(self, factory, identity, body, limits):
        request = ForwardApplyUpdate.model_validate(plain(body))
        workspace = self._workspace()
        self._authorize(workspace)
        factory = freeze_factory(factory)
        lease = route_lease(factory, request.route_id)
        if not lease.acquire(2):
            raise HTTPException(409, 'route controller busy')
        committed, added, launch_key = False, False, str(factory.kw['bind'].url) + identity
        try:
            fresh = self._fresh_inspection(factory, request, workspace, identity)
            with factory() as session:
                begin(session)
                ticket, value, replay = self._ticket(session, request, workspace)
                if (ticket.payload.get('service_id') != identity
                        or ticket.payload.get('expected_revision') != request.expected_revision):
                    raise HTTPException(409, 'service recovery preflight identity mismatch')
                job = service_job(session, identity)
                if replay:
                    if replay == identity and ticket.payload.get('recovery') is True:
                        return identity
                    raise HTTPException(409, 'recovery requires a new preflight')
                if (job.state != 'NEEDS_RECOVERY' or job.payload['revision'] != request.expected_revision
                        or job.payload['route_id'] != request.route_id):
                    raise HTTPException(409, 'service recovery state or revision changed')
                intended = job.payload.get('pending_spec') or spec_fields(job.payload)
                if value != intended:
                    raise HTTPException(409, 'recover the recorded settings before editing them')
                previous = self._runtime(session, job)
                pending = self._runtime(session, job, pending=True) if job.payload.get('pending_runtime_secret_id') else None
                context = self._context(factory, request.route_id)
                if (context['parent_digest'] != ticket.payload['parent_digest']
                        or fresh != {'parent_digest': context['parent_digest'], 'inspection': ticket.payload['inspection']}):
                    raise HTTPException(409, 'service changed after recovery preflight')
                checkpoint = SecretReference(kind='service_forward_checkpoint', ciphertext=encrypt_credentials({
                    'runtime': previous, 'pending_runtime': pending, 'spec': spec_fields(job.payload),
                    'revision': job.payload['revision'], 'saved_at': self.clock()}))
                session.add(checkpoint)
                session.flush()
                operation = Job(kind='service_forward_recovery_operation', state='UPDATING' if pending else 'APPLYING',
                    payload={'service_id': identity, 'workspace_id': workspace, 'request_id': request.request_id,
                             'checkpoint_secret_id': checkpoint.id})
                session.add(operation)
                session.flush()
                job.payload = {**job.payload, 'operation': {**job.payload['operation'],
                    'request_id': request.request_id, 'parent_digest': context['parent_digest'],
                    'inspection': ticket.payload['inspection'], 'recovery_operation_id': operation.id,
                    'checkpoint_secret_id': checkpoint.id}}
                job.state, job.error = ('UPDATING' if pending else 'APPLYING'), None
                ticket.state, ticket.payload = 'APPLIED', {**ticket.payload, 'applied_service_id': identity,
                    'request_id': request.request_id, 'recovery': True}
                with self._lock:
                    self._launching.add(launch_key)
                    added = True
                session.commit()
                committed = True
        finally:
            lease.release()
            if added:
                try:
                    if committed:
                        self.kick(factory, identity)
                finally:
                    with self._lock:
                        self._launching.discard(launch_key)
        return identity

    def _finish_edit(self, session, job, *, rollback=False):
        payload = dict(job.payload)
        pending = self._runtime(session, job, pending=True)
        discarded_port = pending['config']['listen_port'] if rollback else payload['bind_port']
        kept_port = payload['bind_port'] if rollback else pending['config']['listen_port']
        if discarded_port != kept_port:
            for row in session.query(ResourceAllocation).filter(ResourceAllocation.deployment_id == payload['deployment_id'],
                    ResourceAllocation.node_id == payload['source'], ResourceAllocation.kind == 'tcp_port',
                    ResourceAllocation.key == str(discarded_port), ResourceAllocation.released_at.is_(None)):
                ResourceManager(session).release(row.id)
        operation = session.get(Job, payload['operation']['operation_id'])
        operation.state = 'ROLLED_BACK' if rollback else 'SUCCEEDED'
        if not rollback:
            payload.update(payload['pending_spec'], revision=pending['config']['revision'],
                           runtime_secret_id=payload['pending_runtime_secret_id'])
        payload.pop('pending_runtime_secret_id', None)
        payload.pop('pending_spec', None)
        job.payload = payload

    def _rollback_edit(self, factory, identity):
        with factory() as session:
            begin(session)
            job = service_job(session, identity)
            self._finish_edit(session, job, rollback=True)
            if job.payload['operation'].get('recovery_operation_id'):
                session.get(Job, job.payload['operation']['recovery_operation_id']).state = 'ROLLED_BACK'
            if job.state != 'STOPPING':
                job.state, job.error = 'ACTIVE', 'last forward edit failed; previous settings restored'
            session.commit()
            return job.state != 'STOPPING'

    def _activate(self, factory, identity):
        with factory() as session:
            begin(session)
            job = service_job(session, identity)
            if job.state == 'STOPPING':
                return False
            if job.state not in {'APPLYING', 'UPDATING'}:
                raise RuntimeError('service operation state changed')
            if job.state == 'UPDATING':
                self._finish_edit(session, job)
            if job.payload['operation'].get('recovery_operation_id'):
                session.get(Job, job.payload['operation']['recovery_operation_id']).state = 'SUCCEEDED'
            job.state, job.error = 'ACTIVE', None
            session.get(Deployment, job.payload['deployment_id']).state = 'COMMITTED'
            session.commit()
            return True

    def _failure(self, factory, identity):
        with factory() as session:
            job = service_job(session, identity)
            if job.state != 'STOPPING':
                job.state = 'NEEDS_RECOVERY'
            job.error = 'owned service operation needs explicit inspection'
            for key in ('operation_id', 'recovery_operation_id'):
                if job.payload.get('operation', {}).get(key):
                    session.get(Job, job.payload['operation'][key]).state = 'NEEDS_RECOVERY'
            session.commit()

    def _run(self, factory, identity):
        with factory() as session:
            job = service_job(session, identity)
            state, payload = job.state, dict(job.payload)
            runtime = self._runtime(session, job)
        if state not in {'APPLYING', 'UPDATING', 'STOPPING'}:
            return
        lease = route_lease(factory, payload['route_id'])
        if not lease.acquire(5):
            return
        try:
            with factory() as session:
                job = service_job(session, identity)
                state, payload, runtime = job.state, dict(job.payload), self._runtime(session, job)
            if state not in {'APPLYING', 'UPDATING', 'STOPPING'}:
                return
            if state == 'STOPPING':
                self._stop_sync(factory, identity)
                return
            context = self._context(factory, payload['route_id'])
            previous = runtime if state == 'UPDATING' else None
            if previous:
                with factory() as session:
                    runtime = self._runtime(session, service_job(session, identity), pending=True)
            found = self._observe_node(self.nodes, context, runtime)
            if not matching(found, runtime):
                self._authorize(payload['workspace_id'])
                if (context['parent_digest'] != payload['operation']['parent_digest'] or
                        self._inspect(context, payload['pending_spec'] if previous else spec_fields(payload),
                                      [previous, runtime] if previous else None)
                        != payload['operation']['inspection']):
                    raise HTTPException(409, 'parent changed after admission')
                def persist(node_id, kind, key):
                    if node_id != payload['source']:
                        raise RuntimeError('forward cannot own a destination resource')
                    with factory() as session:
                        ResourceManager(session).reserve(kind=kind, key=key, node_id=node_id,
                            deployment_id=runtime['deployment_id'], meta={'service_forward': identity})
                        session.commit()
                try:
                    found = self.nodes.apply(context, runtime, payload['operation']['inspection'], persist,
                                             **({'previous': previous} if previous else {}))
                except Exception:
                    found = self._observe_node(self.nodes, context, runtime)
                if previous and not matching(found, runtime):
                    old_found = self._observe_node(self.nodes, context, previous)
                    if matching(old_found, previous):
                        if not self._rollback_edit(factory, identity):
                            self._stop_sync(factory, identity)
                        return
                if not matching(found, runtime):
                    raise RuntimeError('forward source activation not verified')
            if not self._activate(factory, identity):
                self._stop_sync(factory, identity)
        except Exception:
            self._failure(factory, identity)
        finally:
            lease.release()

    def kick(self, factory, identity):
        factory = freeze_factory(factory)
        key = str(factory.kw['bind'].url) + identity
        with self._lock:
            if key in self._threads:
                return
            def work():
                handled_request = None
                try:
                    with factory() as session:
                        handled_request = service_job(session, identity).payload.get('operation', {}).get('request_id')
                    self._run(factory, identity)
                finally:
                    with self._lock:
                        self._threads.pop(key, None)
                    with factory() as session:
                        job = service_job(session, identity)
                        retry_stop = job.state == 'STOPPING' and not job.error
                        next_operation = handled_request is not None and job.state in {'APPLYING', 'UPDATING'} and (
                            job.payload.get('operation', {}).get('request_id') != handled_request)
                    if retry_stop or next_operation:
                        self.kick(factory, identity)
            thread = threading.Thread(target=work, daemon=True, name='service-' + identity[:8])
            self._threads[key] = thread
            thread.start()

    def observe(self, factory, identity):
        with factory() as session:
            job = service_job(session, identity)
            public = service_public(job)
            runtime = self._runtime(session, job)
        if public['state'] == 'STOPPED':
            return {**public, 'observed': False}
        try:
            context = self._context(factory, public['route_id'], live=False)
            result = self.nodes.observe(context, runtime)
            allowed = {'worker_pid', 'revision', 'listening', 'active_connections', 'connections_total',
                       'rejected_connections', 'connect_failures', 'accounting', 'target_health', 'updated_at'}
            return {**public, 'observed': matching(result, runtime),
                    'runtime': {k: v for k, v in (result.get('runtime') or {}).items() if k in allowed}}
        except Exception:
            return {**public, 'observed': False, 'observation_error': 'service observation unavailable'}

    def stop(self, factory, identity):
        factory = freeze_factory(factory)
        with factory() as session:
            job = service_job(session, identity)
            if job.state == 'STOPPED':
                return
            job.state = 'STOPPING'
            job.error = None
            session.commit()
        self.kick(factory, identity)

    def _stop_sync(self, factory, identity):
        with factory() as session:
            job = service_job(session, identity)
            if job.state == 'STOPPED':
                return
            runtime = self._runtime(session, job)
            parent_id = job.payload['route_id']
            pending = self._runtime(session, job, pending=True) if job.payload.get('pending_runtime_secret_id') else None
        context = self._context(factory, parent_id, live=False)
        self.nodes.stop(context, runtime, **({'alternative': pending} if pending else {}))
        with factory() as session:
            job = service_job(session, identity)
            ResourceManager(session).release_deployment(runtime['deployment_id'])
            session.get(Deployment, runtime['deployment_id']).state = 'ROLLED_BACK'
            job.state, job.error = 'STOPPED', None
            for key in ('operation_id', 'recovery_operation_id'):
                if job.payload.get('operation', {}).get(key):
                    operation = session.get(Job, job.payload['operation'][key])
                    if operation.state in {'APPLYING', 'UPDATING', 'NEEDS_RECOVERY'}:
                        operation.state = 'STOPPED'
            session.commit()

    def stop_for_route(self, factory, route_id):
        # Caller already holds parent lease. Never reacquire it here.
        with factory() as session:
            ids = [j.id for j in session.query(Job).filter(Job.kind == 'mesh_service_forward',
                Job.state != 'STOPPED') if j.payload['route_id'] == route_id]
        for identity in ids:
            try:
                self._stop_sync(factory, identity)
            except Exception:
                self._failure(factory, identity)
                raise RuntimeError('owned forward cleanup deferred; parent preserved') from None

    def recover(self, factory):
        with factory() as session:
            pending = [(j.id, j.state, dict(j.payload), self._runtime(session, j))
                       for j in session.query(Job).filter(Job.kind == 'mesh_service_forward',
                Job.state.in_(['APPLYING', 'UPDATING', 'STOPPING']))]
        for identity, state, payload, runtime in pending:
            key = str(factory.kw['bind'].url) + identity
            with self._lock:
                if key in self._threads or key in self._launching:
                    continue
            if state == 'STOPPING':
                self.kick(factory, identity)
                continue
            lease = route_lease(factory, payload['route_id'])
            if not lease.acquire(0):
                continue
            try:
                context = self._context(factory, payload['route_id'], live=False)
                if state == 'UPDATING':
                    with factory() as session:
                        runtime = self._runtime(session, service_job(session, identity), pending=True)
                if matching(self._observe_node(self.nodes, context, runtime), runtime):
                    if not self._activate(factory, identity):
                        self._stop_sync(factory, identity)
                else:
                    self._failure(factory, identity)  # Explicit fresh preflight, never blind reapply.
            except Exception:
                self._failure(factory, identity)
            finally:
                lease.release()
