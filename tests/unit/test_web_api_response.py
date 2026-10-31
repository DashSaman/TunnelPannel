"""Exercise the deployed browser transport with real HTTP Response objects."""
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('language', ['fa', 'en'])
def test_proxy_html_and_invalid_json_become_safe_actionable_errors(language):
    node = shutil.which('node')
    if not node:
        pytest.skip('Node.js required for browser transport regression')
    code = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
let next=()=>new Response(JSON.stringify({principal:null,csrf:''}),{headers:{'Content-Type':'application/json'}});
const context={URL,Headers,Response,window:{location:{origin:'https://tehnet.ir'}},
document:{documentElement:{lang:process.argv[1]},currentScript:{src:'https://tehnet.ir/tunnels/assets/auth.js'},querySelectorAll:()=>[]},
fetch:async()=>next(),addEventListener:()=>{}};
vm.runInNewContext(fs.readFileSync(process.argv[2],'utf8'),context);
(async()=>{
 const a=context.window.TPAuth;await a.ready;
 for(const status of [502,503,504,200]){
  next=()=>new Response('<!DOCTYPE html><p>private upstream detail</p>',{status,headers:{'Content-Type':'text/html'}});
  let error;try{await a.request('/billing/plans')}catch(e){error=e}
  assert(error,'HTML must fail in shared transport before every page attempts JSON');
  assert.equal(error.code,status===200?'INVALID_API_RESPONSE':'CONTROLLER_UNAVAILABLE');
  assert.equal(error.status,status);assert(!error.message.includes('<')&&!error.message.includes('Unexpected token'));
  assert(!error.message.includes('private upstream detail'));
  assert(error.message.includes(process.argv[1]==='fa'?'مدیریت':'management'));
 }
 next=()=>new Response('{broken',{headers:{'Content-Type':'application/json'}});
 await assert.rejects(async()=>a.readJSON(await a.request('/api/nodes')),e=>e.code==='INVALID_API_RESPONSE');
 next=()=>new Response(JSON.stringify({detail:'Invalid credentials'}),{status:401,headers:{'Content-Type':'application/json; charset=utf-8'}});
 const rejected=await a.request('/auth/login');assert.equal(rejected.status,401);
 assert.equal((await a.readJSON(rejected)).detail,'Invalid credentials');
 next=()=>new Response(JSON.stringify({detail:'controller unavailable'}),{status:503,headers:{'Content-Type':'application/problem+json'}});
 assert.equal((await a.readJSON(await a.request('/api/nodes'))).detail,'controller unavailable');
 next=()=>new Response(null,{status:204});assert.equal(await a.readJSON(await a.request('/auth/logout')),null);
})().catch(e=>{console.error(e);process.exitCode=1});
'''
    result = subprocess.run([node, '-e', code, language, str(ROOT/'apps/web/auth.js')],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_static_gateway_uses_json_for_its_own_upstream_failures(tmp_path):
    from scripts.container_web_gateway import package
    output = tmp_path/'gateway'
    package(ROOT, output, '/tunnels', 'https://tehnet.ir', 21100, 21001,
            'nginx:stable-alpine@sha256:'+'a'*64)
    nginx = (output/'nginx.conf').read_text()
    assert 'error_page 502 503 504 =503 @controller_unavailable;' in nginx
    assert 'location @controller_unavailable' in nginx
    assert 'default_type application/json;' in nginx
    assert '"code":"CONTROLLER_UNAVAILABLE"' in nginx
    # Auth/validation errors from the real API must retain their status/body.
    assert 'proxy_intercept_errors on;' not in nginx
