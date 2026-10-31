"""Real isolated API/container acceptance; only newly owned fixture resources."""
import argparse
import json
import subprocess
import time
import uuid

suffix=uuid.uuid4().hex[:10]
volume='tehnet-controller-qa-data-'+suffix
name='tehnet-controller-qa-'+suffix
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--image',required=True)
image=parser.parse_args().image
label='com.tehnet.codex.task=control-plane-recovery-20261031'
env=['-e','DATABASE_URL=sqlite:////data/tunnelpannel.db','-e','TP_WORKSPACES_DIR=/data/workspaces',
     '-e','TP_CONTROL_PLANE_ONLY=1','-e','TP_CONTROLLER_EXCLUDED_HOSTS=91.107.138.246',
     '-e','TP_RETIRED_NODE_HOSTS=65.109.209.194,65.109.213.64',
     '-e','TP_SECRET_KEY=local-owned-fixture-key-only-20261031',
     '-e','TP_PUBLIC_ORIGIN=https://tehnet.ir','-e','FORWARDED_ALLOW_IPS=127.0.0.1',
     '-e','TP_BILLING_MODE=manual','-e','TP_TEST_WORKERS=1']
def run(args, text=None):
    p=subprocess.run(['docker',*args],input=text,capture_output=True,text=True)
    if p.returncode:
        raise RuntimeError(p.stdout+p.stderr)
    return p.stdout
created=False
try:
    run(['volume','create','--label',label,volume]);created=True
    run(['run','--rm','--network','none','--user','0','-v',volume+':/data',image,
         'python','-c',"import os;os.chown('/data',10001,10001);os.chmod('/data',0o700)"])
    result=run(['run','--rm','-i','--network','none','-v',volume+':/data',*env,image,
                'python','scripts/control_plane_admin.py'],json.dumps({'username':'fixture_owner','password':'fixture-owner-only-123'}))
    print(result.strip())
    run(['run','-d','--name',name,'--label',label,'--network','none','--read-only',
         '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','128',
         '--memory','512m','--cpus','0.5','--tmpfs','/tmp:rw,noexec,nosuid,size=64m,uid=10001,gid=10001,mode=700',
         '-v',volume+':/data',*env,image])
    probe="import urllib.request;assert urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3).status==200"
    for index in range(30):
        try:
            run(['exec',name,'python','-c',probe]);break
        except RuntimeError:
            time.sleep(0.5)
    else:
        raise RuntimeError(run(['logs','--tail','40',name]))
    acceptance=r'''
import urllib.request,urllib.error,http.cookiejar,http.cookies,json,os,shutil
opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf=None
cookie=''
def call(path,body=None,method=None,expected=200,use_csrf=True):
 global cookie
 h={'Host':'tehnet.ir','Origin':'https://tehnet.ir','X-Forwarded-Proto':'https','Content-Type':'application/json'}
 if cookie:h['Cookie']=cookie
 if csrf and use_csrf:h['X-CSRF-Token']=csrf
 request=urllib.request.Request('http://127.0.0.1:8080'+path,data=json.dumps(body).encode() if body is not None else None,headers=h,method=method)
 try:r=opener.open(request,timeout=20)
 except urllib.error.HTTPError as error:r=error
 with r:
  if r.headers.get('Set-Cookie'):
   jar=http.cookies.SimpleCookie();jar.load(r.headers['Set-Cookie'])
   if 'tp_session' in jar:
    assert jar['tp_session']['secure'] and jar['tp_session']['httponly']
    cookie='tp_session='+jar['tp_session'].value
  data=json.load(r)
  assert r.status==expected,(path,r.status,expected,sorted(data) if isinstance(data,dict) else 'array')
  return data
login=call('/auth/login',{'username':'fixture_owner','password':'fixture-owner-only-123'})
csrf=login['csrf']
assert call('/api/whoami')['role']=='SUPER_ADMIN'
assert call('/api/deployment')['management_only'] is True
from pathlib import Path
assert not Path('/app/.git').exists()
call('/api/workspaces',{'name':'no-csrf'},expected=403,use_csrf=False)
workspace=call('/api/workspaces',{'name':'Persistent fixture customer'},expected=201)
call('/api/accounts',{'workspace_id':workspace['id'],'username':'fixture_customer','password':'fixture-customer-only-123','role':'SUPER_ADMIN'},expected=201)
assert any(w['id']==workspace['id'] for w in call('/api/workspaces'))
assert os.getuid()==10001
assert all(shutil.which(tool) is None for tool in ('ip','ping','iperf3','wg','nft'))
print(json.dumps({'status':'PASS','health_login_owner_and_user_creation':True,'cookie_csrf_refusal':True,'manual_billing':True,'uid':os.getuid(),'tunnel_utilities_absent':True,'workspace':workspace['id']}))
'''
    result=run(['exec','-i',name,'python','-'],acceptance)
    print(result.strip())
    previous=json.loads(result)['workspace']
    run(['restart',name])
    for index in range(30):
        try:run(['exec',name,'python','-c',probe]);break
        except RuntimeError:time.sleep(0.5)
    verify="import sqlite3;db=sqlite3.connect('/data/workspaces/registry.db');assert db.execute('SELECT count(*) FROM workspaces WHERE id=?',("+repr(previous)+",)).fetchone()[0]==1;print('durable_restart=PASS')"
    print(run(['exec',name,'python','-c',verify]).strip())
    config=json.loads(run(['inspect',name]))[0]['HostConfig']
    assert config['ReadonlyRootfs'] and not config['Privileged'] and config['CapDrop']==['ALL']
    print(run(['stats','--no-stream','--format','{{.MemUsage}} {{.CPUPerc}}',name]).strip())
finally:
    try:
        raw=run(['inspect','--format','{{index .Config.Labels "com.tehnet.codex.task"}}',name]).strip()
        if raw==label.split('=',1)[1]:run(['rm','-f',name])
    except RuntimeError:pass
    if created:
        raw=run(['volume','inspect','--format','{{index .Labels "com.tehnet.codex.task"}}',volume]).strip()
        if raw==label.split('=',1)[1]:run(['volume','rm',volume])
