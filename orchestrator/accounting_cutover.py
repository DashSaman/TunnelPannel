"""Executed over pinned SSH with private PARAMS; stdout contains no credentials."""
import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import time

from orchestrator.accounting_migration import validate_idle
from orchestrator.mesh_gateway import socks_connect

os.umask(0o077)
p=globals()['PARAMS']  # injected by the privileged controller, never a public request
directory=Path(p['directory']);route=p['route_id']
assert re.fullmatch(r'[0-9a-f]{32}',route) and directory==Path('/var/lib/tunnelpannel/mesh')/route/'gateway'
assert re.fullmatch(r'tpmesh-[0-9]+-0-gateway',p['service'])
base=Path(p['rescue_base']);assert base.is_absolute() and str(base).startswith('/root/tp-') and '..' not in base.parts
base.mkdir(mode=0o700,exist_ok=True);route_rescue=base/('route-'+route);route_rescue.mkdir(mode=0o700,exist_ok=True)
assert re.fullmatch(r'[0-9a-f]{32}',p['attempt_id'])
rescue=route_rescue/p['attempt_id'];rescue.mkdir(mode=0o700)
config_path=directory/'config.json';state_path=directory/'state.json'
assert not directory.is_symlink() and not config_path.is_symlink()
def run(*args):return subprocess.check_output(args,text=True).strip()
def pid():return int(run('systemctl','show',p['service'],'-p','MainPID','--value'))
def member_workers():
 units=[line.split()[0] for line in run('systemctl','list-units','--type=service','--state=running','--plain','--no-legend').splitlines()]
 return {unit:run('systemctl','show',unit,'-p','MainPID','--value') for unit in units
         if unit.startswith(('tp-','tpmesh-')) and unit!=p['service']+'.service'}
workers_before=member_workers()
links_before={v['ifname']:v['ifindex'] for v in json.loads(run('ip','-j','link','show'))}
if json.loads(config_path.read_text())==p['new_config']:
 # Recover a lost source response or controller metadata commit without another restart.
 for name,source in p['files'].items():
  path=directory/('gateway.py' if name=='mesh_gateway.py' else name)
  assert path.read_text()==source,'pending source artifact drift requires investigation'
 state=json.loads(state_path.read_text());worker=pid()
 assert state['worker_pid']==worker and 0<=time.time()-state['updated_at']<8
 assert state.get('monthly_accounting_version')==1 and all(state['healthy'].values())
 async def recovered_receipt():
  old=p['old_config'];target=old['upstreams'][0]['probe']
  reader,writer=await socks_connect({'host':old['listen_host'],'port':old['listen_port'],'username':old['username'],'password':old['password']},target['host'],target['port'])
  try:
   writer.write(b'GET / HTTP/1.0\r\nHost: owned-migration.local\r\nConnection: close\r\n\r\n');await writer.drain()
   header=await reader.readuntil(b'\r\n\r\n');body=await reader.readexactly(len(target['nonce'].encode()))
   assert header.startswith((b'HTTP/1.0 200',b'HTTP/1.1 200')) and hmac.compare_digest(body,target['nonce'].encode())
  finally:writer.close();await writer.wait_closed()
 asyncio.run(asyncio.wait_for(recovered_receipt(),10))
 previous=[]
 for path in route_rescue.glob('*/cutover.json'):
  record=json.loads(path.read_text())
  if record.get('status')=='PASS' and record.get('new_worker_pid')==worker:previous.append(record['counting_started_at'])
 report={'status':'PASS','recovered_existing_cutover':True,'old_worker_pid':p['expected_pid'],'new_worker_pid':worker,
         'counting_started_at':min(previous) if previous else p['started_at'],'start_timestamp_estimated':not bool(previous),
         'source_config_sha256':hashlib.sha256(config_path.read_bytes()).hexdigest(),'member_workers_restarted':0,
         'entry_credentials_and_settings_preserved':True,'probe_successes':1,'maximum_observed_success_gap_s':None}
 (rescue/'cutover.json').write_text(json.dumps(report,indent=2));print(json.dumps(report));raise SystemExit(0)
assert hashlib.sha256(config_path.read_bytes()).hexdigest()==p['expected_sha']
assert json.loads(config_path.read_text())==p['old_config']
assert pid()==p['expected_pid']
assert (directory/'gateway.py').as_posix().encode() in Path('/proc/'+str(pid())+'/cmdline').read_bytes()
for name in ['gateway.py','monthly_client.py','config.json','state.json']:
 source=directory/name
 if source.exists():
  assert source.is_file() and not source.is_symlink();shutil.copy2(source,rescue/name)
usage=Path(p['new_config']['usage_path']);assert usage==Path('/var/lib/tunnelpannel/route-usage')/(route+'.sqlite3')
if usage.exists():
 assert not usage.is_symlink()
 with sqlite3.connect(usage.as_uri()+'?mode=ro',uri=True) as live:
  with sqlite3.connect(rescue/'usage-before.sqlite3') as copy:live.backup(copy)
(rescue/'service-before.txt').write_text(run('systemctl','cat',p['service']))
(rescue/'new-config-private.json').write_text(json.dumps(p['new_config']))
for name,source in p['files'].items():compile(source,name,'exec')
deadline=time.monotonic()+45;last_update=None;idle_samples=0
while time.monotonic()<deadline:
 assert pid()==p['expected_pid'] and hashlib.sha256(config_path.read_bytes()).hexdigest()==p['expected_sha']
 state=json.loads(state_path.read_text())
 try:validate_idle(state,p['old_config'],p['expected_pid'],time.time())
 except ValueError:idle_samples=0
 else:
  if state['updated_at']!=last_update:
   idle_samples+=1;last_update=state['updated_at']
  if idle_samples>=2:break
 time.sleep(.2)
else:raise RuntimeError('gateway did not become safely idle; no cutover performed')
usage.parent.mkdir(mode=0o700,exist_ok=True)
def atomic(path,text):
 target=path.with_name(path.name+'.accounting-new')
 with target.open('x',encoding='utf8',newline='\n') as file:
  file.write(text);file.flush();os.fsync(file.fileno())
 target.chmod(0o600);os.replace(target,path)
samples=[];stop_sampling=False;cutover_started=False;started_at=None;usage_baseline={'upload':0,'download':0}
async def sample():
 old=p['old_config'];target=old['upstreams'][0]['probe'];writer=None;begin=time.monotonic()
 try:
  async def exercise():
   nonlocal writer
   reader,writer=await socks_connect({'host':old['listen_host'],'port':old['listen_port'],'username':old['username'],'password':old['password']},target['host'],target['port'])
   writer.write(b'GET / HTTP/1.0\r\nHost: owned-migration.local\r\nConnection: close\r\n\r\n');await writer.drain()
   header=await reader.readuntil(b'\r\n\r\n');body=await reader.readexactly(len(target['nonce'].encode()))
   assert header.startswith((b'HTTP/1.0 200',b'HTTP/1.1 200')) and hmac.compare_digest(body,target['nonce'].encode())
  await asyncio.wait_for(exercise(),.6);ok=True
 except (OSError,AssertionError,asyncio.TimeoutError,asyncio.IncompleteReadError):ok=False
 finally:
  if writer:
   writer.close()
   try:await writer.wait_closed()
   except OSError:pass
 samples.append({'at':time.monotonic(),'ok':ok,'elapsed':time.monotonic()-begin})
async def monitor():
 while not stop_sampling:
  await sample();await asyncio.sleep(.05)
def switch():
 global cutover_started,started_at,usage_baseline
 assert pid()==p['expected_pid'] and hashlib.sha256(config_path.read_bytes()).hexdigest()==p['expected_sha']
 cutover_started=True
 subprocess.run(['systemctl','stop',p['service']],check=True,timeout=15)
 assert pid()==0
 if usage.exists():
  with sqlite3.connect(usage.as_uri()+'?mode=ro',uri=True) as db:
   assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
   values=db.execute('SELECT upload,download FROM usage WHERE id=1').fetchone()
   usage_baseline={'upload':values[0],'download':values[1]}
 (rescue/'usage-baseline.json').write_text(json.dumps(usage_baseline))
 atomic(directory/'gateway.py',p['files']['mesh_gateway.py'])
 atomic(directory/'monthly_client.py',p['files']['monthly_client.py'])
 atomic(config_path,json.dumps(p['new_config']))
 started_at=time.time()
 subprocess.run(['systemctl','start',p['service']],check=True,timeout=15)
def rollback():
 subprocess.run(['systemctl','stop',p['service']],check=True,timeout=15)
 for name in ['gateway.py','monthly_client.py','config.json']:
  previous=rescue/name
  if previous.exists():atomic(directory/name,previous.read_text())
  elif name=='monthly_client.py' and (directory/name).exists():
   assert (directory/name).read_text()==p['files'][name];(directory/name).unlink()
 subprocess.run(['systemctl','start',p['service']],check=True,timeout=15)
async def execute():
 global stop_sampling
 task=asyncio.create_task(monitor())
 try:
  while len(samples)<3:await asyncio.sleep(.05)
  assert all(s['ok'] for s in samples),'entry preflight failed'
  await asyncio.to_thread(switch)
  end=time.monotonic()+25
  while time.monotonic()<end:
   state=json.loads(state_path.read_text())
   if state.get('worker_pid')==pid() and state.get('monthly_accounting_version')==1 and all(state.get('healthy',{}).values()) and state.get('monthly',{}).get('callback_available') is True:
    break
   await asyncio.sleep(.2)
  else:raise RuntimeError('new gateway accounting/health did not become ready')
  assert json.loads(config_path.read_text())==p['new_config']
  await asyncio.sleep(.5)
  assert len(samples)>=3 and all(s['ok'] for s in samples[-3:])
 finally:
  stop_sampling=True;await task
report={}
try:
 asyncio.run(execute())
 assert member_workers()==workers_before,'an underlying tunnel worker changed'
 assert {v['ifname']:v['ifindex'] for v in json.loads(run('ip','-j','link','show'))}==links_before,'existing interfaces changed'
 passed=[s['at'] for s in samples if s['ok']]
 gaps=[b-a for a,b in zip(passed,passed[1:])]
 report={'status':'PASS','counting_started_at':started_at,'old_worker_pid':p['expected_pid'],'new_worker_pid':pid(),
         'source_config_sha256':hashlib.sha256(config_path.read_bytes()).hexdigest(),
         'member_workers_restarted':0,'member_worker_identities_preserved':True,'interfaces_preserved':True,
         'source_usage_baseline':usage_baseline,'entry_credentials_and_settings_preserved':True,
         'before_idle_samples':idle_samples,'sample_interval_s':.05,'sample_timeout_s':.6,
         'probe_successes':len(passed),'probe_failures':sum(not s['ok'] for s in samples),
         'maximum_observed_success_gap_s':max(gaps,default=0),'existing_tcp_session_survival_claimed':False}
except Exception as error:
 status='FAILED_BEFORE_CUTOVER'
 if cutover_started:
  try:rollback();status='FAILED_ROLLED_BACK'
  except Exception:status='FAILED_ROLLBACK_REQUIRES_INSPECTION'
 report={'status':status,'error_type':type(error).__name__,'error':str(error),'worker_pid':pid()}
finally:
 (rescue/'samples.json').write_text(json.dumps(samples))
 (rescue/'cutover.json').write_text(json.dumps(report,indent=2))
 print(json.dumps(report))
