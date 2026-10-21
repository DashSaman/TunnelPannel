"""Opt-in acceptance against an operator-supplied disposable pair.

Run as the panel service user with its installation environment. The config and
private state contain access credentials; never commit them. Only allowlisted
seed hosts may be used. Public evidence is built from explicit safe fields.
"""
from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener


class Client:
    def __init__(self, origin, token=None):
        if origin not in {'http://127.0.0.1:8080', 'http://localhost:8080'}:
            raise ValueError('acceptance must use the controller loopback origin')
        self.origin, self.token, self.csrf = origin, token, ''
        self.cookies=http.cookiejar.CookieJar()
        self.opener=build_opener(ProxyHandler({}),HTTPCookieProcessor(self.cookies))

    def call(self, path, body=None, method=None, expected=200, csrf=True):
        method=method or ('GET' if body is None else 'POST')
        headers={'Content-Type':'application/json'}
        if self.token:
            headers['Authorization']='Bearer '+self.token
        if csrf and self.csrf:
            headers['X-CSRF-Token']=self.csrf
        request=Request(self.origin+path, data=None if body is None else json.dumps(body).encode(),
                        headers=headers, method=method)
        try:
            response=self.opener.open(request,timeout=150)
        except HTTPError as error:
            response=error
        with response:
            code=response.code
            result=json.loads(response.read())
        if code not in ([expected] if isinstance(expected,int) else expected):
            raise AssertionError(f'{method} {path} returned{code}, expected{expected}')
        return result

    def login(self, account, otp=''):
        result=self.call('/auth/login',{'email':account['email'],'password':account['password'],'otp':otp})
        self.csrf=result['csrf']
        return result


class Acceptance:
    def __init__(self, config_path):
        self.directory=config_path.parent
        self.config=json.loads(config_path.read_text())
        self.state_path=self.directory/'private-state.json'
        self.report_path=self.directory/'acceptance.json'
        self.state=json.loads(self.state_path.read_text()) if self.state_path.exists() else {}
        self.report=json.loads(self.report_path.read_text()) if self.report_path.exists() else {'schema':1,'checks':{}}
        self.owner=Client(self.config['origin'],self.config['owner_token'])

    def save(self):
        for path,content in [(self.state_path,self.state),(self.report_path,self.report)]:
            temporary=path.with_suffix('.tmp')
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
            with os.fdopen(fd,'w',encoding='utf-8') as stream:
                json.dump(content,stream,indent=2)
            os.replace(temporary,path)

    def check(self, name, result):
        if not result:
            raise AssertionError(name)
        self.report['checks'][name]=True
        self.save()
        print(json.dumps({'check':name,'pass':True}),flush=True)

    def bootstrap(self):
        if self.state.get('workspace'):
            if self.report['checks'].get('bootstrap_complete'):
                print('bootstrap already recorded; preserving private identities',flush=True)
                return
            raise RuntimeError('partial bootstrap retained; inspect private state before resuming')
        from core.accounts import totp_code
        suffix=secrets.token_hex(4)
        workspace=self.owner.call('/api/workspaces',{'name':'Commercial QA '+suffix},expected=201)
        self.state['workspace']=workspace['id']
        self.state['workspace_key']=workspace['api_key']
        self.state['accounts']={}
        self.save()
        for label,role in [('admin','SUPER_ADMIN'),('operator','OPERATOR'),('viewer','VIEWER'),('mfa','VIEWER')]:
            account={'email':label+'-'+suffix+'@acceptance.invalid','password':secrets.token_urlsafe(24)}
            invite=self.owner.call('/api/accounts/invitations',{'workspace_id':workspace['id'],
                'email':account['email'],'role':role},expected=201)
            client=Client(self.config['origin'])
            if label=='admin':
                client.call('/auth/register',{'invitation':invite['token'],'email':'wrong@acceptance.invalid',
                                             'password':account['password']},expected=400)
            client.call('/auth/register',{'invitation':invite['token'],**account},expected=201)
            client.call('/auth/register',{'invitation':invite['token'],**account},expected=400)
            self.state['accounts'][label]=account
            self.save()
            client.login(account)
            principal=client.call('/api/whoami')
            self.check('account_'+label+'_scoped',principal['workspace_id']==workspace['id'] and principal['role']==role)
            client.call('/api/accounts',expected=403)
            if label=='viewer':
                client.call('/api/operations/policy',{'enabled':True,'interval_s':60},method='PUT',expected=403)
                client.call('/auth/logout',{})
                client.call('/api/nodes',expected=401)
                self.check('viewer_and_logout',True)
            if label=='mfa':
                setup=client.call('/auth/mfa/setup',{'password':account['password']})
                enabled=client.call('/auth/mfa/enable',{'otp':totp_code(setup['secret'],time.time())})
                client.call('/api/nodes',expected=401)
                client.login(account,enabled['recovery_codes'][0])
                client.call('/auth/logout',{})
                client.call('/auth/login',{**account,'otp':enabled['recovery_codes'][0]},expected=401)
                client.login(account,totp_code(setup['secret'],time.time()+30))
                replacement=secrets.token_urlsafe(24)
                client.call('/auth/password',{'password':account['password'],'new_password':replacement,
                                              'otp':enabled['recovery_codes'][1]})
                client.call('/api/nodes',expected=401)
                client.call('/auth/login',{**account,'otp':enabled['recovery_codes'][2]},expected=401)
                account['password']=replacement
                client.login(account,enabled['recovery_codes'][2])
                self.state['accounts'][label]=account
                self.save()
                self.check('mfa_replay_password_and_session_revocation',True)
        admin=Client(self.config['origin'])
        admin.login(self.state['accounts']['admin'])
        admin.call('/api/operations/policy',{'enabled':False},method='PUT',csrf=False,expected=403)
        admin.call('/api/operations/policy',{'enabled':False,'interval_s':60},method='PUT')
        admin.call('/api/billing/requests',{'plan':'starter'},expected=201)
        self.owner.call('/api/billing/workspaces/'+workspace['id']+'/sandbox-grant',{'plan':'starter','days':30,'grace_hours':24})
        self.check('csrf_and_sandbox_activation',admin.call('/api/billing/status')['plan']=='starter')
        other=self.owner.call('/api/workspaces',{'name':'Queue QA '+suffix},expected=201)
        self.state['queue_workspace']=other['id']
        self.state['queue_key']=other['api_key']
        self.save()
        self.report['workspace']=workspace['id']
        self.report['scope']='only the two explicitly allowlisted disposable seed hosts'
        self.save()
        self.check('bootstrap_complete',True)

    def inspect(self):
        client=Client(self.config['origin'],self.state['workspace_key'])
        nodes=client.call('/api/nodes')
        expected=set(self.config['allowed_hosts'])
        self.check('actual_nodes_allowlisted',len(nodes)==2 and {n['host'] for n in nodes}==expected)
        self.state['nodes']=[n['id'] for n in nodes]
        self.save()
        for node in nodes:
            client.call('/api/nodes/'+node['id']+'/discover',{})
        request={'nodes':self.state['nodes'],'methods':['WIREGUARD','SSH_REMOTE_FORWARD','HYSTERIA2',
            'VMESS_TCP_TLS','WATERWALL_H_HTTP2_TLS'],'profile':'NORMAL','purpose':'tcp_egress',
            'objective':'latency','recommend_count':5,'recommend_encrypted_only':True}
        limit_path='/api/workspaces/'+self.state['workspace']
        self.owner.call(limit_path,{'limits':{'max_daily_candidate_units':9}},method='PATCH')
        quote=client.call('/api/mesh/estimate',request)
        self.check('quota_quote_10_above_9',quote['candidate_units']==10 and not quote['within_budget'])
        count_before=len(client.call('/api/mesh/campaigns'))
        client.call('/api/mesh/campaigns',request,expected=429)
        self.check('over_budget_created_no_job',len(client.call('/api/mesh/campaigns'))==count_before)
        self.owner.call(limit_path,{'limits':{'max_daily_candidate_units':500}},method='PATCH')
        self.state['campaign_request']=request
        self.save()

    def start(self):
        client=Client(self.config['origin'],self.state['workspace_key'])
        request=self.state['campaign_request']
        quote=client.call('/api/mesh/estimate',request)
        self.check('actual_quote_10',quote['candidate_units']==10 and quote['within_budget'])
        payload={**request,'estimate_fingerprint':quote['fingerprint']}
        result=client.call('/api/mesh/campaigns',payload,expected=202)
        self.state['campaign']=result['id']
        self.report['campaign']=result['id']
        self.save()
        client.call('/api/mesh/campaigns',payload,expected=409)
        self.check('stale_confirmation_cannot_duplicate',True)

    def budget_low(self):
        self.owner.call('/api/workspaces/'+self.state['workspace'],
                        {'limits':{'max_daily_candidate_units':9}},method='PATCH')
        self.check('ui_budget_low_set',True)

    def budget_restore(self):
        self.owner.call('/api/workspaces/'+self.state['workspace'],
                        {'limits':{'max_daily_candidate_units':500}},method='PATCH')
        self.check('ui_budget_restored',True)
        client=Client(self.config['origin'],self.state['workspace_key'])
        self.state['pre_ui_fingerprint']=client.call('/api/mesh/estimate',self.state['campaign_request'])['fingerprint']
        self.save()

    def adopt(self):
        from core.models import Job
        client=Client(self.config['origin'],self.state['workspace_key'])
        history=client.call('/api/mesh/campaigns')
        self.check('ui_started_one_actual_campaign',len(history)==1)
        self.state['campaign']=history[0]['id']
        self.report['campaign']=history[0]['id']
        with self.factory()() as session:
            job=session.get(Job,self.state['campaign'])
            self.check('ui_campaign_parameters_persisted',job.payload['candidate_units']==10
                and job.payload['objective']=='latency' and job.payload['recommend_encrypted_only'] is True)
        self.save()
        client.call('/api/mesh/campaigns',{**self.state['campaign_request'],
                    'estimate_fingerprint':self.state['pre_ui_fingerprint']},expected=409)
        self.check('actual_stale_estimate_cannot_duplicate_ui_job',True)

    def queue(self):
        from core.models import Job, ResourceAllocation, Deployment
        from orchestrator.remote_nodes import node_access
        client=Client(self.config['origin'],self.state['queue_key'])
        existing=client.call('/api/nodes')
        if not existing:
            seed=self.factory(self.config['seed_workspace'])
            for index,identity in enumerate(self.config['seed_nodes']):
                with seed() as session:
                    endpoint,credentials=node_access(session,identity)
                if endpoint['host'] not in self.config['allowed_hosts']:
                    raise ValueError('refusing a non-allowlisted target')
                node=client.call('/api/nodes',{'name':'Queue node '+str(index),'host':endpoint['host'],
                    'ssh_port':endpoint['port'],'ssh_username':endpoint['ssh_username'],
                    'host_key_fingerprint':endpoint['host_key_fingerprint'],
                    'password' if credentials['auth_method']=='PASSWORD' else 'private_key':credentials['secret']},expected=201)
                client.call('/api/nodes/'+node['id']+'/discover',{})
            existing=client.call('/api/nodes')
        result=client.call('/benchmarks',{'node_a':{'node_id':existing[0]['id']},
            'node_b':{'node_id':existing[1]['id']},'methods':['WIREGUARD'],'profile':'NORMAL','max_parallel':1})
        self.state['queue_job']=result['job_id']
        self.save()
        queued=client.call('/benchmarks/'+result['job_id'])
        self.check('second_tenant_waits_durably_without_worker',queued['state']=='QUEUED')
        factory=self.factory()
        deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            with factory() as session:
                campaign=session.get(Job,self.state['campaign'])
                child_id=next((r['job_id'] for r in campaign.payload['routes'] if r['job_id']
                               and session.get(Job,r['job_id']).state=='RUNNING'),None)
                active=session.query(ResourceAllocation).join(Deployment).filter(
                    Deployment.desired_state['job_id'].as_string()==child_id,
                    ResourceAllocation.kind!='temp',
                    ResourceAllocation.released_at.is_(None)).count() if child_id else 0
            if active:
                self.state['interrupted_child']=child_id
                self.report['restart_boundary']={'child':child_id,'active_owned_allocations':active}
                self.save()
                self.check('ready_for_controller_restart',True)
                return
            time.sleep(1)
        raise AssertionError('no owned in-flight candidate found for restart drill')

    def drill_prepare(self):
        from core.operations import METRICS, numeric
        client=Client(self.config['origin'],self.state['workspace_key'])
        primary=client.call('/api/mesh/campaigns/'+self.state['campaign'])
        self.check('initial_five_method_bidirectional_receipts',primary['state']=='PASS'
            and len(primary['routes'])==2
            and all(len(r['results'])==5 and r['recommendation']['qualified']==5 for r in primary['routes']))
        self.state['primary_campaign']=self.state['campaign']
        self.report['primary_campaign']={'id':primary['id'],'state':primary['state'],
            'routes':[{'qualified':r['recommendation']['qualified'],'selected':r['recommendation']['selected'],
                       'results':[{'candidate':row['candidate'],'status':row['status'],
                                   'metrics':{k:numeric(row['metrics'].get(k)) for k in METRICS},
                                   'data_plane_ok':row['metrics'].get('data_plane_ok') is True,
                                   'recovery_ok':row['metrics'].get('recovery_ok') is True}
                                  for row in r['results']]} for r in primary['routes']]}
        self.state['initial_queue_job']=self.state.get('queue_job')
        queued=Client(self.config['origin'],self.state['queue_key'])
        deadline=time.monotonic()+180
        while self.state.get('queue_job') and time.monotonic()<deadline:
            if queued.call('/benchmarks/'+self.state['queue_job'])['state'] not in {'QUEUED','RUNNING'}:
                break
            time.sleep(1)
        result=client.call('/api/mesh/campaigns',{'nodes':self.state['nodes'],
            'directions':[{'source':self.state['nodes'][0],'destination':self.state['nodes'][1]}],
            'methods':['WIREGUARD'],'profile':'DEEP','recommend_count':1,'purpose':'tcp_egress',
            'objective':'stability','recommend_encrypted_only':True},expected=202)
        self.state['campaign']=result['id']
        self.report['restart_drill_campaign']=result['id']
        self.save()
        self.queue()

    def status(self):
        client=Client(self.config['origin'],self.state['workspace_key'])
        result=client.call('/api/mesh/campaigns/'+self.state['campaign'])
        safe={'id':result['id'],'state':result['state'],'progress':result['progress'],
              'routes':[{'source':r['source'],'destination':r['destination'],'state':r['state'],
                         'samples':len(r['results']),'qualified':r['recommendation']['qualified'],
                         'selected':r['recommendation']['selected']} for r in result['routes']]}
        self.report['campaign_status']=safe
        self.save()
        print(json.dumps(safe),flush=True)

    def recovery(self):
        from core.models import Deployment, Job, ResourceAllocation
        client=Client(self.config['origin'],self.state['workspace_key'])
        queued=Client(self.config['origin'],self.state['queue_key'])
        factory=self.factory()
        deadline=time.monotonic()+600
        while time.monotonic()<deadline:
            campaign=client.call('/api/mesh/campaigns/'+self.state['campaign'])
            job=queued.call('/benchmarks/'+self.state['queue_job'])
            if campaign['state'] not in {'RUNNING','QUEUED'} and job['state'] not in {'RUNNING','QUEUED'}:
                break
            time.sleep(3)
        self.check('restarted_mesh_resumes_with_new_child',campaign['state']=='PASS'
            and campaign['routes'][0]['job_id']!=self.state['interrupted_child']
            and campaign['routes'][0]['recommendation']['qualified']==1)
        self.check('queued_other_tenant_dispatches_after_restart',job['state']=='PASS')
        with factory() as session:
            child=session.get(Job,self.state['interrupted_child'])
            active=session.query(ResourceAllocation).join(Deployment).filter(
                Deployment.desired_state['job_id'].as_string()==child.id,
                ResourceAllocation.released_at.is_(None)).count()
            self.check('interrupted_child_owned_allocations_released',child.state=='INTERRUPTED' and active==0)
        proof=json.loads((self.directory/'restart-root-proof.json').read_text())
        self.check('controller_pid_changed_and_health_returned',proof['health_recovered']
            and proof['before_pid']!=proof['after_pid'])
        self.report['restart']={k:proof[k] for k in ('live_owned_resources','health_recovered','started_at')}
        self.save()

    def legacy_prepare(self):
        from core.models import Deployment, ResourceAllocation
        client=Client(self.config['origin'],self.state['queue_key'])
        nodes=client.call('/api/nodes')
        result=client.call('/benchmarks',{'node_a':{'node_id':nodes[0]['id']},
            'node_b':{'node_id':nodes[1]['id']},'methods':['WIREGUARD'],'profile':'DEEP','max_parallel':1})
        self.state['standalone_drill_job']=result['job_id']
        self.save()
        deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            with self.factory(self.state['queue_workspace'])() as session:
                active=session.query(ResourceAllocation).join(Deployment).filter(
                    Deployment.desired_state['job_id'].as_string()==result['job_id'],
                    ResourceAllocation.kind!='temp',ResourceAllocation.released_at.is_(None)).count()
            if active:
                self.check('standalone_ready_for_controller_restart',True)
                return
            time.sleep(1)
        raise AssertionError('standalone did not reach its owned live boundary')

    def legacy_verify(self):
        from core.models import Deployment, Job, ResourceAllocation
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            with self.factory(self.state['queue_workspace'])() as session:
                job=session.get(Job,self.state['standalone_drill_job'])
                active=session.query(ResourceAllocation).join(Deployment).filter(
                    Deployment.desired_state['job_id'].as_string()==job.id,
                    ResourceAllocation.released_at.is_(None)).count()
                okay=job.state=='INTERRUPTED' and active==0
            if okay:
                self.check('standalone_interrupted_once_and_owned_resources_released',True)
                return
            time.sleep(2)
        raise AssertionError('standalone interrupted cleanup did not finish')

    def agent(self):
        from urllib.parse import urlsplit
        from plan_executor import executor as bodies
        from orchestrator.remote_nodes import NodeRemote
        client=Client(self.config['origin'],self.state['workspace_key'])
        hub=self.config['hub_url']
        self.check('verified_https_hub_configured',hub.startswith('https://'))
        nodes=client.call('/api/nodes')
        target=next(n for n in nodes if n['host']!=urlsplit(hub).hostname)
        node_id=target['id']
        endpoint,credentials=self.access(self.factory(),node_id)
        remote=NodeRemote(endpoint,credentials).connect()
        bundle_path='/root/tp-commercial-agent-'+secrets.token_hex(12)+'.json'
        try:
            bundle=client.call('/api/nodes/'+node_id+'/agent',{})
            self.state['agent_node']=node_id
            self.report['agent']={'ca_sha256':hashlib.sha256(bundle['ca'].encode()).hexdigest(),
                                  'cross_server':True}
            self.save()
            def install(value):
                bodies.write_remote_text(remote,bundle_path,json.dumps(value),'0600')
                remote.run('bash /opt/tunnelpannel/scripts/agent-install.sh '+shlex.quote(bundle_path),root=True)
                remote.run('rm -- '+shlex.quote(bundle_path),root=True)
            def fresh(after=0):
                deadline=time.monotonic()+100
                while time.monotonic()<deadline:
                    status=client.call('/api/nodes/'+node_id+'/agent')
                    if status.get('fresh') and status.get('last_seen',0)>after:
                        return status
                    time.sleep(2)
                raise AssertionError('cross-server telemetry did not become fresh')
            install(bundle)
            status=fresh()
            self.check('actual_unprivileged_linux_agent_reports',status['report']['os']=='linux')
            security=json.loads(remote.run("python3 - <<'PY'\nimport json,subprocess\n"
                "pid=subprocess.check_output(['systemctl','show','tunnelpannel-agent','--property=MainPID','--value'],text=True).strip()\n"
                "uid=next(line.split()[1] for line in open('/proc/'+pid+'/status') if line.startswith('Uid:'))\n"
                "dynamic=subprocess.check_output(['systemctl','show','tunnelpannel-agent','--property=DynamicUser','--value'],text=True).strip()\n"
                "protection=subprocess.check_output(['systemctl','show','tunnelpannel-agent','--property=ProtectSystem','--value'],text=True).strip()\n"
                "print(json.dumps({'nonroot':int(uid)>0,'dynamic':dynamic=='yes','strict':protection=='strict'}))\nPY",root=True)['stdout'])
            self.check('agent_dynamic_user_and_filesystem_protection',all(security.values()))
            remote.run('systemctl stop tunnelpannel-agent',root=True)
            program="""import json,sys,time,socket,ssl,tempfile
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
sys.path.insert(0,'/opt/tunnelpannel')
from agent.telemetry import collect,send
b=json.loads(Path('/etc/tunnelpannel-agent/bundle.json').read_text())
r=collect(time.time_ns());checks={}
checks['accepted']=send(b,r)['accepted']
try:send(b,r)
except HTTPError as e:checks['replay_denied']=e.code==409
try:send(b,{**r,'sequence':r['sequence']+1,'command':'id'})
except HTTPError as e:checks['commands_denied']=e.code==400
url=urlsplit(b['hub_url'])
with tempfile.TemporaryDirectory() as directory:
 for name in ('certificate','private_key','ca'):
  Path(directory,name).write_text(b[name])
 for label,wrong_ca,no_client,hostname in [('wrong_ca',True,False,url.hostname),('missing_client',False,True,url.hostname),('wrong_hostname',False,False,'invalid.example')]:
  context=ssl.create_default_context(cafile=None if wrong_ca else directory+'/ca')
  if not no_client:context.load_cert_chain(directory+'/certificate',directory+'/private_key')
  try:
   with socket.create_connection((url.hostname,url.port),timeout=5) as sock:
    with context.wrap_socket(sock,server_hostname=hostname) as channel:
     channel.sendall(b'POST /v1/telemetry HTTP/1.0\\r\\nContent-Length: 2\\r\\n\\r\\n{}')
     result=channel.recv(100)
     checks[label+'_denied']=not result.startswith(b'HTTP/1.0 200')
  except OSError:checks[label+'_denied']=True
assert all(checks.values()),checks
print(json.dumps(checks))
"""
            result=json.loads(remote.run('python3 - <<\'PY\'\n'+program+'\nPY',root=True)['stdout'])
            self.check('cross_server_mtls_trust_hostname_client_replay_command_gates',all(result.values()))
            client.call('/api/nodes/'+node_id+'/agent',method='DELETE')
            denied="import json,sys,time;from pathlib import Path;from urllib.error import HTTPError;sys.path.insert(0,'/opt/tunnelpannel');from agent.telemetry import collect,send\nb=json.loads(Path('/etc/tunnelpannel-agent/bundle.json').read_text())\ntry:send(b,collect(time.time_ns()))\nexcept HTTPError as e:assert e.code==401;print('REVOKED')\nelse:raise AssertionError('revoked certificate accepted')"
            self.check('actual_revoked_certificate_denied',remote.run('python3 - <<\'PY\'\n'+denied+'\nPY',root=True)['stdout'].strip()=='REVOKED')
            replacement=client.call('/api/nodes/'+node_id+'/agent',{})
            self.check('rotation_preserves_installation_ca',replacement['ca']==bundle['ca']
                and replacement['certificate']!=bundle['certificate'])
            install(replacement)
            status=fresh()
            a_id=next(n['id'] for n in nodes if n['id']!=node_id)
            a_endpoint,a_credentials=self.access(self.factory(),a_id)
            controller=NodeRemote(a_endpoint,a_credentials).connect()
            try:
                controller.run('systemctl restart tunnelpannel-agent-hub',root=True)
            finally:
                controller.close()
            before=status['last_seen']
            remote.run('systemctl restart tunnelpannel-agent',root=True)
            status=fresh(before)
            self.check('hub_and_client_restart_keep_rotated_identity',status['fresh'] and not status['revoked'])
            self.report['agent'].update(last_seen=status['last_seen'],
                report_fields=sorted(status['report']),checks=result)
            self.save()
        finally:
            remote.run('rm -f -- '+shlex.quote(bundle_path),root=True,check=False)
            remote.close()

    def factory(self, workspace=None):
        from core.workspaces import WorkspaceRegistry
        return WorkspaceRegistry(os.environ['TP_WORKSPACES_DIR'])._factory(workspace or self.state['workspace'])

    def operations(self):
        import hmac
        from core.models import Deployment, ResourceAllocation
        from core.operations import OperationsStore
        from core.subscriptions import SubscriptionStore
        from core.workspaces import WorkspaceRegistry
        from orchestrator.mesh_routes import route_job, route_private
        from orchestrator.remote_nodes import NodeRemote
        client=Client(self.config['origin'],self.state['workspace_key'])
        factory=self.factory()
        campaign=client.call('/api/mesh/campaigns/'+self.state['primary_campaign'])
        self.state.setdefault('qa_routes',[])
        for index,route in enumerate(campaign['routes']):
            if len(self.state['qa_routes'])<=index:
                result=client.call('/api/mesh/routes',{'campaign_id':campaign['id'],'route_id':route['id'],
                    'methods':['WIREGUARD','SSH_REMOTE_FORWARD'] if index==0 else ['WIREGUARD'],
                    'mode':'balance' if index==0 else 'failover'},expected=202)
                self.state['qa_routes'].append(result['id'])
                self.save()
            deadline=time.monotonic()+240
            while time.monotonic()<deadline:
                observed=client.call('/api/mesh/routes/'+self.state['qa_routes'][index])
                if observed['state'] not in {'APPLYING','QUEUED'}:
                    break
                time.sleep(2)
            self.check('actual_warm_route_'+str(index),observed['state']=='COMMITTED' and observed.get('observed'))
        route_id=self.state['qa_routes'][0]
        with factory() as session:
            runtime=route_private(session,route_job(session,route_id))
            source=route_job(session,route_id).payload['source']
            rows=session.query(ResourceAllocation).join(Deployment).filter(
                Deployment.desired_state['job_id'].as_string()==route_id,
                Deployment.desired_state['candidate'].as_string()=='SSH_REMOTE_FORWARD',
                ResourceAllocation.kind=='service',ResourceAllocation.node_id==source,
                ResourceAllocation.released_at.is_(None)).all()
            services=[row.key for row in rows]
        self.check('failover_targets_only_owned_test_member_services',bool(services)
            and all(name.startswith(('tpmesh-','tpbench-','netauto-ssh-')) for name in services))
        endpoint,credentials=self.access(factory,source)
        remote=NodeRemote(endpoint,credentials).connect()
        stable=lambda config:hashlib.sha256(json.dumps({key:config[key]
            for key in ('listen_host','listen_port','username','password')},sort_keys=True).encode()).hexdigest()
        before_entry=stable(runtime['config'])
        def observation(predicate, timeout=90):
            deadline=time.monotonic()+timeout
            while time.monotonic()<deadline:
                result=client.call('/api/mesh/routes/'+route_id)
                if result.get('observed') and predicate(result['runtime']):
                    return result
                time.sleep(2)
            raise AssertionError('owned gateway did not reach the required real observation')
        program="""import asyncio,importlib.util,json,sys
from pathlib import Path
p=Path(sys.argv[1]);c=json.loads(p.read_text())
spec=importlib.util.spec_from_file_location('gateway',p.with_name('gateway.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
proxy={'host':c['listen_host'],'port':c['listen_port'],'username':c['username'],'password':c['password']}
target=next(u['probe'] for u in c['upstreams'] if u['id']=='WIREGUARD')
async def one():
 r,w=await m.socks_connect(proxy,target['host'],target['port'])
 try:
  w.write(b'GET / HTTP/1.0\\r\\nHost: owned-health.local\\r\\nConnection: close\\r\\n\\r\\n');await w.drain()
  headers=await asyncio.wait_for(r.readuntil(b'\\r\\n\\r\\n'),15)
  body=await asyncio.wait_for(r.readexactly(len(target['nonce'].encode())),15)
  assert headers.startswith((b'HTTP/1.0 200',b'HTTP/1.1 200')) and body==target['nonce'].encode()
  await asyncio.sleep(.2)
 finally:w.close();await w.wait_closed()
async def main():await asyncio.gather(*(one() for _ in range(20)))
asyncio.run(main());print('20_NONCE_RECEIPTS')
"""
        def data():
            command='python3 - '+shlex.quote(runtime['directory']+'/config.json')+" <<'PY'\n"+program+'\nPY'
            return remote.run(command,root=True,timeout=90)['stdout'].strip()=='20_NONCE_RECEIPTS'
        try:
            observed=observation(lambda r:all(r['healthy'].values()))
            pid=observed['runtime']['worker_pid']
            before_counts=observed['runtime']['connections_by_upstream']
            self.check('stable_entry_parallel_data_nonce_receipts',data())
            observed=observation(lambda r:all(r['connections_by_upstream'][m]>before_counts.get(m,0)
                for m in ('WIREGUARD','SSH_REMOTE_FORWARD')))
            self.check('actual_connection_distribution_across_two_methods',True)
            client.call('/api/operations/policy',{'enabled':True,'interval_s':60},method='PUT')
            store=OperationsStore(factory)
            store.record(route_id,observed)
            client.call('/api/mesh/routes/'+route_id+'/policy',{'mode':'failover','pin':'SSH_REMOTE_FORWARD'},method='PUT')
            observation(lambda r:r['mode']=='failover' and r['active']=='SSH_REMOTE_FORWARD')
            stopped=[]
            started=time.monotonic()
            try:
                for service in services:
                    remote.run('systemctl stop '+shlex.quote(service+'.service'),root=True)
                    stopped.append(service)
                observed=observation(lambda r:not r['healthy']['SSH_REMOTE_FORWARD'] and r['active']=='WIREGUARD')
                self.check('actual_member_outage_switches_new_connections',data())
                self.report['failover']={'detection_and_new_connections_s':round(time.monotonic()-started,3),
                    'parallel_nonce_receipts':20,'existing_sessions':'client reconnect required'}
                store.record(route_id,observed)
            finally:
                for service in stopped:
                    remote.run('systemctl start '+shlex.quote(service+'.service'),root=True)
            observation(lambda r:all(r['healthy'].values()))
            client.call('/api/mesh/routes/'+route_id+'/policy',{'mode':'balance','pin':None},method='PUT')
            observed=observation(lambda r:r['mode']=='balance' and all(r['healthy'].values()))
            with factory() as session:
                current=route_private(session,route_job(session,route_id))['config']
            self.check('mode_and_failover_preserve_entry_and_worker',stable(current)==before_entry
                and observed['runtime']['worker_pid']==pid)
            self.check('restored_balance_data_receipts',data())
            store.record(route_id,observed)
        finally:
            remote.close()
        # Exercise installed signature/idempotency and real HTTP entitlements.
        registry=WorkspaceRegistry(os.environ['TP_WORKSPACES_DIR'])
        signing=secrets.token_urlsafe(48)
        billing=SubscriptionStore(registry,webhook_secret=signing)
        def event(paid,grace):
            current=billing.status(self.state['workspace'])
            raw=json.dumps({'event_id':'acceptance-'+secrets.token_hex(12),'workspace_id':self.state['workspace'],
                'revision':current['revision']+1,'plan':'starter','state':'past_due',
                'paid_through':paid,'grace_until':grace,'mode':'sandbox'}).encode()
            timestamp=str(int(time.time()))
            signature=hmac.new(signing.encode(),timestamp.encode()+b'.'+raw,hashlib.sha256).hexdigest()
            first=billing.apply_event(raw,timestamp,signature)
            duplicate=billing.apply_event(raw,timestamp,signature)
            self.check('installed_signed_events_idempotent',first['applied'] and duplicate['duplicate'])
        event(time.time()-10,time.time()+60)
        self.check('actual_grace_keeps_entitlements',client.call('/api/billing/status')['state']=='past_due')
        event(time.time()-100,time.time()-10)
        self.check('actual_expiry_blocks_new_paid_work',client.call('/api/billing/status')['state']=='expired')
        client.call('/api/mesh/campaigns',self.state['campaign_request'],expected=402)
        time.sleep(8)
        self.check('default_expiry_preserves_running_groups',all(
            client.call('/api/mesh/routes/'+identity)['state']=='COMMITTED' for identity in self.state['qa_routes']))
        support=client.call('/api/operations/support')
        raw=json.dumps(support)
        forbidden=[self.config['owner_token'],self.state['workspace_key']]
        forbidden += [a['password'] for a in self.state['accounts'].values()]
        for identity in self.state['nodes']:
            _,secret=self.access(factory,identity)
            forbidden.append(secret['secret'])
        self.check('support_export_after_expiry_excludes_live_credentials',
            all(value not in raw for value in forbidden) and support['schema']=='tunnelpannel-support-v1')
        events=client.call('/api/operations/events')
        self.check('actual_transition_history_contains_degraded_and_restored',
            {'UP','DEGRADED'} <= {row['health'] for row in events})
        self.report['support']={'sha256':hashlib.sha256(raw.encode()).hexdigest(),
            'sample_count':len(support['samples']),'observation_count':len(support['observations']),
            'transition_count':len(events)}
        self.owner.call('/api/billing/workspaces/'+self.state['workspace']+'/policy',{'stop_on_expiry':True})
        deadline=time.monotonic()+240
        while time.monotonic()<deadline:
            if all(client.call('/api/mesh/routes/'+identity)['state']=='STOPPED' for identity in self.state['qa_routes']):
                break
            time.sleep(3)
        else:raise AssertionError('explicit tenant expiry cleanup did not complete')
        with factory() as session:
            count=session.query(ResourceAllocation).join(Deployment).filter(
                Deployment.desired_state['job_id'].as_string().in_(self.state['qa_routes']),
                ResourceAllocation.released_at.is_(None)).count()
        self.check('explicit_expiry_cleanup_releases_only_qa_routes',count==0)
        self.owner.call('/api/billing/workspaces/'+self.state['workspace']+'/policy',{'stop_on_expiry':False})
        self.owner.call('/api/billing/workspaces/'+self.state['workspace']+'/sandbox-grant',{'plan':'starter'})
        self.owner.call('/api/billing/workspaces/'+self.state['workspace']+'/sandbox-cancel',{})
        self.check('actual_owner_cancellation_blocks_new_work',client.call('/api/billing/status')['state']=='cancelled')
        client.call('/api/mesh/campaigns',self.state['campaign_request'],expected=402)
        self.owner.call('/api/billing/workspaces/'+self.state['workspace']+'/sandbox-grant',{'plan':'starter'})
        self.check('actual_renewal_restores_entitlements',client.call('/api/billing/status')['can_start_work'])
        with self.factory(self.config['seed_workspace'])() as session:
            from core.models import Job
            originals=session.query(Job).filter_by(kind='mesh_route',state='COMMITTED').all()
            self.check('expiry_preserves_original_twelve_members',len(originals)==2
                and sorted(len(job.payload['methods']) for job in originals)==[5,7])
        self.save()

    def access(self, factory, node_id):
        from orchestrator.remote_nodes import node_access
        with factory() as session:
            endpoint,credentials=node_access(session,node_id)
        if endpoint['host'] not in self.config['allowed_hosts']:
            raise ValueError('refusing a non-allowlisted SSH target')
        return endpoint,credentials

    def keys(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from orchestrator.remote_nodes import NodeRemote
        client=Client(self.config['origin'],self.state['workspace_key'])
        factory=self.factory()
        seeds=self.factory(self.config['seed_workspace'])
        seed_access={}
        for identity in self.config['seed_nodes']:
            endpoint,credentials=self.access(seeds,identity)
            seed_access[endpoint['host']]=credentials
        self.state.setdefault('foreign_key_lines',{})
        for node_id in self.state['nodes']:
            endpoint,old=self.access(factory,node_id)
            if node_id not in self.state['foreign_key_lines']:
                public=Ed25519PrivateKey.generate().public_key().public_bytes(
                    serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()
                foreign=public+' tp-commercial-foreign-'+secrets.token_hex(12)
                self.state['foreign_key_lines'][node_id]=foreign
                self.save()
                remote=NodeRemote(endpoint,old).connect()
                try:
                    program=("from pathlib import Path; import os; p=Path('/root/.ssh/authorized_keys'); "
                             "assert not p.is_symlink(); "
                             "f=p.open('ab'); f.write("+repr((foreign+'\n').encode())+"); f.close(); os.chmod(p,0o600)")
                    remote.run('python3 -c '+shlex.quote(program),root=True)
                finally:
                    remote.close()
            foreign=self.state['foreign_key_lines'][node_id]
            first=client.call('/api/nodes/'+node_id+'/managed-key',{})
            _,current=self.access(factory,node_id)
            self.check('managed_bootstrap_'+node_id[:8],first['password_retained'] is False and current['auth_method']=='KEY')
            previous_line=current['managed_public_line']
            client.call('/api/nodes/'+node_id+'/managed-key',{})
            _,current=self.access(factory,node_id)
            remote=NodeRemote(endpoint,current).connect()
            try:
                raw=remote.run('cat /root/.ssh/authorized_keys',root=True)['stdout']
                self.check('managed_rotation_preserves_foreign_'+node_id[:8],
                    previous_line not in raw and current['managed_public_line'] in raw and foreign in raw)
                self.check('managed_real_root_access_'+node_id[:8],remote.run('id -u',root=True)['stdout'].strip()=='0')
            finally:
                remote.close()
            previous_line=current['managed_public_line']
            replacement=seed_access[endpoint['host']]
            body={('password' if replacement['auth_method']=='PASSWORD' else 'private_key'):replacement['secret']}
            client.call('/api/nodes/'+node_id+'/managed-key/revoke',body)
            _,current=self.access(factory,node_id)
            remote=NodeRemote(endpoint,current).connect()
            try:
                raw=remote.run('cat /root/.ssh/authorized_keys',root=True)['stdout']
                self.check('managed_revocation_verified_replacement_'+node_id[:8],
                    previous_line not in raw and foreign in raw and not current.get('managed_public_line'))
            finally:
                remote.close()
            client.call('/api/nodes/'+node_id+'/managed-key',{})
        crashed=subprocess.run([sys.executable,__file__,'--config',str(self.directory/'private-config.json'),
                                '--stage','crash-key'],timeout=120)
        self.check('managed_crash_boundary_injected',crashed.returncode==91)
        from core.models import Job
        deadline=time.monotonic()+100
        while time.monotonic()<deadline:
            with factory() as session:
                pending=session.query(Job).filter_by(kind='node_key',state='APPLYING').count()
            if not pending:
                break
            time.sleep(2)
        self.check('managed_recovery_drained_owned_pending_keys',pending==0)
        node_id=self.state['nodes'][0]
        endpoint,current=self.access(factory,node_id)
        remote=NodeRemote(endpoint,current).connect()
        try:
            raw=remote.run('cat /root/.ssh/authorized_keys',root=True)['stdout']
            self.check('managed_recovery_preserves_current_and_foreign',
                current['managed_public_line'] in raw and self.state['foreign_key_lines'][node_id] in raw
                and len([line for line in raw.splitlines() if ' tp-managed-' in line])==1)
            self.report['key_file_sha256_after_tests']=hashlib.sha256(raw.encode()).hexdigest()
            self.save()
        finally:
            remote.close()

    def crash_key(self):
        import orchestrator.node_keys as keys
        node_id=self.state['nodes'][0]
        factory=self.factory()
        _,old=self.access(factory,node_id)
        original=keys.NodeRemote
        class CrashBeforeVerification(original):
            def connect(self):
                if self.credentials['secret']!=old['secret']:
                    raise SystemExit(91)
                return super().connect()
        keys.NodeRemote=CrashBeforeVerification
        keys.provision_managed_key(factory,node_id)

    def finish(self):
        from orchestrator.remote_nodes import NodeRemote
        # Remove only exact canaries created by keys(); real managed/foreign keys survive.
        for node_id,line in self.state.get('foreign_key_lines',{}).items():
            endpoint,credentials=self.access(self.factory(),node_id)
            remote=NodeRemote(endpoint,credentials).connect()
            try:
                program=("import os,tempfile;from pathlib import Path\n"
                    "p=Path('/root/.ssh/authorized_keys');assert not p.is_symlink() and not p.parent.is_symlink()\n"
                    "lines=p.read_text().splitlines();target="+repr(line)+"\n"
                    "kept=[s for s in lines if s!=target]\n"
                    "fd,name=tempfile.mkstemp(dir=p.parent,prefix='.tp-canary-cleanup-');os.fchmod(fd,0o600)\n"
                    "with os.fdopen(fd,'w') as f:f.write('\\n'.join(kept)+'\\n');f.flush();os.fsync(f.fileno())\n"
                    "os.replace(name,p);assert target not in p.read_text().splitlines();print('EXACT_CANARY_REMOVED')")
                self.check('exact_foreign_canary_cleanup_'+node_id[:8],remote.run(
                    "python3 - <<'PY'\n"+program+'\nPY',root=True)['stdout'].strip()=='EXACT_CANARY_REMOVED')
                self.check('current_managed_access_survives_canary_cleanup_'+node_id[:8],
                    remote.run('id -u',root=True)['stdout'].strip()=='0')
            finally:remote.close()
        context_path=self.directory/'private-legacy-context.json'
        context=json.loads(context_path.read_text())
        if not self.state.get('demo_key_rotated'):
            old=Client(self.config['origin'],context['key'])
            result=self.owner.call('/api/workspaces/'+self.config['seed_workspace']+'/rotate-key',{})
            context['key']=result['api_key']
            fd=os.open(context_path,os.O_WRONLY|os.O_TRUNC,0o600)
            with os.fdopen(fd,'w') as stream:json.dump(context,stream)
            old.call('/api/nodes',expected=401)
            self.state['demo_key_rotated']=True
            self.check('predictable_demo_api_key_revoked',True)
        demo=Client(self.config['origin'],context['key'])
        self.check('rotated_demo_api_access',len(demo.call('/api/nodes'))==2)
        for label,workspace in [('demo',self.config['seed_workspace']),('owner','system')]:
            if label+'_account' not in self.state:
                account={'email':label+'-'+secrets.token_hex(8)+'@tunnelpannel.invalid',
                         'password':secrets.token_urlsafe(30)}
                invite=self.owner.call('/api/accounts/invitations',{'workspace_id':workspace,
                    'email':account['email'],'role':'SUPER_ADMIN'},expected=201)
                Client(self.config['origin']).call('/auth/register',{'invitation':invite['token'],**account},expected=201)
                self.state[label+'_account']=account
                self.save()
            account_client=Client(self.config['origin'])
            account_client.login(self.state[label+'_account'])
            self.check(label+'_handoff_account_scoped',account_client.call('/api/whoami')['workspace_id']==workspace)
        demo.call('/api/operations/policy',{'enabled':True,'interval_s':60},method='PUT')
        self.report.setdefault('original_groups_monitor_started_at',time.time())
        # Repeat replay rejection after restarting the actual hub with a persisted sequence.
        if self.state.get('agent_node'):
            client=Client(self.config['origin'],self.state['workspace_key'])
            report=client.call('/api/nodes/'+self.state['agent_node']+'/agent')['report']
            endpoint,credentials=self.access(self.factory(),self.state['agent_node'])
            remote=NodeRemote(endpoint,credentials).connect()
            try:
                program=("import sys,json;from pathlib import Path;from urllib.error import HTTPError\n"
                    "sys.path.insert(0,'/opt/tunnelpannel');from agent.telemetry import send\n"
                    "b=json.loads(Path('/etc/tunnelpannel-agent/bundle.json').read_text())\n"
                    "try:send(b,"+repr(report)+")\n"
                    "except HTTPError as e:assert e.code==409;print('PERSISTENT_REPLAY_DENIED')\n"
                    "else:raise AssertionError('replay after hub restart accepted')")
                self.check('actual_hub_restart_retains_replay_gate',remote.run(
                    "python3 - <<'PY'\n"+program+'\nPY',root=True)['stdout'].strip()=='PERSISTENT_REPLAY_DENIED')
            finally:remote.close()
        self.save()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--stage',choices=['bootstrap','inspect','start','status','keys','crash-key',
                                         'budget-low','budget-restore','adopt','queue','drill-prepare',
                                         'recovery','legacy-prepare','legacy-verify','agent','operations','finish'],required=True)
    args=parser.parse_args()
    if args.config.stat().st_mode & 0o077:
        raise SystemExit('acceptance config must be private (mode600)')
    acceptance=Acceptance(args.config)
    getattr(acceptance,args.stage.replace('-','_'))()


if __name__=='__main__':
    main()
