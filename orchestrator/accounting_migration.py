"""Explicit owner gateway-only enrollment. Never reconcile tunnel members."""
import hashlib
import json
from pathlib import Path
import re
import time
import uuid


def upgraded_config(route_id, config, monthly):
    from orchestrator.monthly_client import validate_url
    if not re.fullmatch(r'[0-9a-f]{32}', route_id) or config.get('monthly'):
        raise ValueError('require an exact unenrolled route identity')
    path='/var/lib/tunnelpannel/route-usage/'+route_id+'.sqlite3'
    if config.get('usage_path') not in {None,path}:
        raise ValueError('noncanonical usage path requires separate investigation')
    validate_url(monthly['url'])
    if not monthly.get('token','').startswith('tpq_'):
        raise ValueError('route credential required')
    return {**config,'usage_path':path,'monthly':monthly}


def validate_idle(state, config, pid, now):
    ids=[u['id'] for u in config['upstreams']]
    if (state.get('worker_pid')!=pid or not 0<=now-state.get('updated_at',0)<8
            or state.get('order')!=ids or set(state.get('healthy',{}))!=set(ids)
            or not all(state['healthy'].values()) or set(state.get('active_connections',{}))!=set(ids)
            or any(state['active_connections'].values())
            or state.get('mode','failover')!=config.get('mode','failover') or state.get('pin')!=config.get('pin')):
        raise ValueError('require fresh matching healthy idle gateway without policy drift')


def finish_migration(factory, route_id, original_payload, runtime, config, candidate_id, report):
    from core.models import SecretReference
    from orchestrator.mesh_routes import route_job
    from orchestrator.remote_nodes import encrypt_credentials
    with factory() as session:
        job=route_job(session,route_id)
        if job.payload!=original_payload or job.state not in {'COMMITTED','DEGRADED'}:
            raise ValueError('route changed during migration; retain evidence and investigate')
        secret=session.get(SecretReference,job.payload['runtime_secret_id'])
        secret.ciphertext=encrypt_credentials({**runtime,'config':config})
        payload={**job.payload,'monthly_secret_id':candidate_id,'accounting_migrated_at':report['counting_started_at']}
        payload.pop('accounting_migration',None)
        job.payload=payload
        session.commit()


def migrate(hooks, workspace, route_id, *, expected_config_sha256, expected_pid, rescue_base):
    """Privileged controller call; caller must first snapshot installation/registry.

    The public API cannot request grandfathering or select these root-only flags.
    A failure retains both source rescue and persistent accounting evidence.
    """
    from core.models import SecretReference
    from orchestrator.host_lease import HostLease
    from orchestrator.mesh_routes import route_job,route_private,route_lease
    from orchestrator.remote_nodes import NodeRemote,decrypt_credentials,encrypt_credentials,node_access
    from orchestrator.monthly_client import validate_url
    if not re.fullmatch(r'[0-9a-f]{32}',route_id) or not re.fullmatch(r'[0-9a-f]{64}',expected_config_sha256):
        raise ValueError('exact route and configuration digest required')
    if type(expected_pid) is not int or expected_pid<=1:
        raise ValueError('exact live worker identity required')
    if workspace!='system' and hooks.registry.scope_for(workspace) is None:
        raise ValueError('customer workspace must be enabled')
    callback=validate_url(hooks.callback_url())
    factory=hooks.factory(workspace)
    admission=hooks.lease(workspace);route_lock=route_lease(factory,route_id)
    acquired=[];remote=None;token=None
    try:
        for lease in [admission,route_lock]:
            if not lease.acquire(5):raise ValueError('route admission/controller busy')
            acquired.append(lease)
        with factory() as session:
            job=route_job(session,route_id)
            if job.state not in {'COMMITTED','DEGRADED'} or job.payload.get('monthly_secret_id'):
                raise ValueError('require an explicitly selected live unmetered route')
            runtime=route_private(session,job);original_payload=dict(job.payload)
            endpoint,credentials=node_access(session,job.payload['source'])
        if runtime['directory']!='/var/lib/tunnelpannel/mesh/'+route_id+'/gateway':
            raise ValueError('gateway path ownership mismatch')
        if not re.fullmatch(r'tpmesh-[0-9]+-0-gateway',runtime['service']):
            raise ValueError('gateway service ownership mismatch')
        host=HostLease(endpoint)
        if not host.acquire(10):raise ValueError('source host busy')
        acquired.append(host)
        remote=NodeRemote(endpoint,credentials).connect()
        pending=original_payload.get('accounting_migration')
        candidate_id=None
        if pending:
            if pending.get('phase')!='pending' or pending['old_config_sha256']!=expected_config_sha256:
                raise ValueError('pending migration identity differs; investigate private intent')
            with factory() as session:
                candidate_id=pending['candidate_secret_id']
                config=decrypt_credentials(session.get(SecretReference,candidate_id).ciphertext)
            token=config['token']
            config=upgraded_config(route_id,runtime['config'],config)
            if hooks.store.token_workspace(token)!=workspace:raise ValueError('pending credential scope mismatch')
        # Check source drift before issuing credentials. A resumed exact candidate
        # may already be running after a lost SSH response or DB commit failure.
        result=remote.run('cat '+runtime['directory']+'/config.json',root=True)
        raw=result['stdout'].encode()
        live_config=json.loads(raw)
        if live_config!=runtime['config'] and (not pending or live_config!=config):
            raise ValueError('live and encrypted gateway configuration differ')
        if not pending:
            digest=remote.run('sha256sum '+runtime['directory']+'/config.json',root=True)['stdout'].split()[0]
            if digest!=expected_config_sha256:raise ValueError('source digest changed before migration intent')
            period=hooks.store.ensure_unlimited(workspace,actor='explicit-owner-gateway-migration')
            if not period['unlimited']:raise ValueError('migrate before setting a customer ceiling')
            token=hooks.store.register_route(workspace,route_id,preserve_existing=True)
            config=upgraded_config(route_id,runtime['config'],{'url':callback,'token':token})
            pending={'phase':'pending','old_config_sha256':expected_config_sha256,'started_at':time.time()}
            try:
                with factory() as session:
                    job=route_job(session,route_id)
                    if job.payload!=original_payload or job.state not in {'COMMITTED','DEGRADED'}:
                        raise ValueError('route changed before migration intent')
                    candidate=SecretReference(kind='monthly_route',ciphertext=encrypt_credentials(config['monthly']))
                    session.add(candidate);session.flush();candidate_id=candidate.id
                    pending['candidate_secret_id']=candidate_id
                    job.payload={**job.payload,'workspace_id':workspace,'accounting_migration':pending}
                    session.commit();original_payload=dict(job.payload)
            except Exception:
                # Credential has not left the controller; no worker can spend it.
                hooks.store.retire_route(route_id,{})
                raise
        root=Path(__file__).parent
        params={'route_id':route_id,'directory':runtime['directory'],'service':runtime['service'],
                'expected_sha':expected_config_sha256,'expected_pid':expected_pid,'old_config':runtime['config'],
                'new_config':config,'rescue_base':rescue_base,'started_at':pending['started_at'],'attempt_id':uuid.uuid4().hex,
                'files':{name:(root/name).read_text(encoding='utf8') for name in ['mesh_gateway.py','monthly_client.py']}}
        code='PARAMS='+repr(params)+'\n'+(root/'accounting_cutover.py').read_text(encoding='utf8')
        command="cd /opt/tunnelpannel\n/opt/tunnelpannel/.venv/bin/python - <<'ACCOUNTING_CUTOVER'\n"+code+'\nACCOUNTING_CUTOVER\n'
        response=remote.run(command,root=True,timeout=180)
        report=json.loads(response['stdout'])
        if report['status']!='PASS':
            raise RuntimeError('gateway migration incomplete ('+report['status']+'); resume the persisted private intent')
        try:
            finish_migration(factory,route_id,original_payload,runtime,config,candidate_id,report)
        except Exception:
            # Keep the new safely metered worker and durable root receipt. Never
            # silently revert live accounting when controller metadata commit is uncertain.
            raise RuntimeError('metered gateway active; metadata commit needs explicit recovery from resident receipt') from None
        return {**report,'workspace_id':workspace,'route_id':route_id,
                'old_config_sha256':expected_config_sha256,
                'new_config_semantic_sha256':hashlib.sha256(json.dumps(config,sort_keys=True).encode()).hexdigest()}
    finally:
        if remote:remote.close()
        for lease in reversed(acquired):lease.release()
