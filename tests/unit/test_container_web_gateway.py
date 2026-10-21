"""A public subpath gateway preserves auth scope without running the controller."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
IMAGE = 'nginx:stable-alpine@sha256:' + 'a' * 64


def test_package_namespaces_pages_assets_and_inline_code(tmp_path):
    from scripts.container_web_gateway import package
    out = tmp_path / 'gateway'
    package(ROOT, out, '/tunnels', 'https://tehnet.ir', 21100, 21001, IMAGE)
    for page in ('portal', 'mesh', 'ranking', 'topology'):
        body = (out / 'public' / (page + '.html')).read_text(encoding='utf8')
        assert 'src="/assets/' not in body and 'href="/mesh' not in body
        assert '/tunnels/assets/auth.js' in body
        assert '<script>' not in body and '<style>' not in body
    assert (out / 'public/assets/mesh-inline-0.js').is_file()
    for name in ('theme.css','tehnet-vazirmatn.woff2'):
        assert (out/'public/assets'/name).read_bytes()==(ROOT/'apps/web'/name).read_bytes()
    assert '/tunnels/assets/theme.css' in (out/'public/portal.html').read_text(encoding='utf8')
    portal = (out / 'public/assets/portal.js').read_text(encoding='utf8')
    assert "TPAuth.url('/mesh?campaign='" in portal
    assert "TPAuth.url('/portal')" in portal
    manifest = json.loads((out / 'manifest.json').read_text())
    assert manifest['controller_on_gateway'] is False
    assert all('\\' not in name for name in manifest['files'])
    with pytest.raises(FileExistsError):
        package(ROOT, out, '/tunnels', 'https://tehnet.ir', 21100, 21001, IMAGE)


def test_managed_services_ship_in_real_static_bundle_and_mesh_bootstrap(tmp_path):
    from scripts.container_web_gateway import package
    out = tmp_path / 'services-gateway'
    package(ROOT, out, '/tunnels', 'https://tehnet.ir', 21100, 21001, IMAGE)
    asset = out / 'public/assets/mesh-services.js'
    assert asset.is_file()
    assert asset.read_bytes() == (ROOT / 'apps/web/mesh-services.js').read_bytes()
    body = (out / 'public/mesh.html').read_text(encoding='utf8')
    assert '/tunnels/assets/mesh-services.js' in body and 'id="services"' in body
    bootstrap = (out / 'public/assets/mesh-inline-0.js').read_text(encoding='utf8')
    assert 'TPServices.bindServices' in bootstrap


def test_managed_service_browser_asset_uses_exact_public_whitelist():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.web.web_api import create_web_router
    app = FastAPI()
    app.include_router(create_web_router(None))
    client = TestClient(app)
    response = client.get('/assets/mesh-services.js')
    assert response.status_code == 200
    assert 'javascript' in response.headers['content-type']
    assert response.headers['x-content-type-options'] == 'nosniff'
    assert client.get('/assets/service_forward_node_helper.py').status_code == 404


def test_container_only_binds_loopback_and_preserves_https_cookie_scope(tmp_path):
    from scripts.container_web_gateway import package
    out = tmp_path / 'gateway'
    package(ROOT, out, '/tunnels', 'https://tehnet.ir', 21100, 21001, IMAGE)
    nginx = (out / 'nginx.conf').read_text()
    assert 'listen 127.0.0.1:21100;' in nginx
    assert 'proxy_pass http://127.0.0.1:21001;' in nginx
    assert 'proxy_set_header X-Forwarded-Proto https;' in nginx
    assert 'proxy_cookie_path / /tunnels/;' in nginx
    assert 'proxy_cookie_flags tp_session secure httponly samesite=strict;' in nginx
    assert 'proxy_request_buffering off;' in nginx and 'access_log off;' in nginx
    assert 'if ($http_x_forwarded_proto != "https")' in nginx
    assert 'script-src \'self\'' in nginx and "script-src 'self' 'unsafe-inline'" not in nginx
    compose = (out / 'compose.yaml').read_text()
    assert IMAGE in compose and 'read_only: true' in compose
    assert '127.0.0.1:21100' in compose and 'mem_limit: 96m' in compose
    assert 'cap_drop: [ALL]' in compose and 'no-new-privileges:true' in compose
    assert all(s not in compose for s in ('uvicorn', 'sqlite', 'docker.sock', 'ssh.key'))
    host = (out / 'host-location.conf').read_text()
    assert 'location ^~ /tunnels/' in host and 'proxy_set_header X-Forwarded-Proto $scheme;' in host


@pytest.mark.parametrize('prefix,origin', [('//evil','https://tehnet.ir'),('/a/../b','https://tehnet.ir'),('/tunnels','http://tehnet.ir'),('/tunnels','https://u:p@tehnet.ir'),('/tunnels','https://tehnet.ir/path')])
def test_public_configuration_rejects_ambiguous_paths_and_origins(tmp_path,prefix,origin):
    from scripts.container_web_gateway import package
    with pytest.raises(ValueError):
        package(ROOT,tmp_path/'gateway',prefix,origin,21100,21001,IMAGE)


@pytest.mark.parametrize('base', ['', '/tunnels'])
def test_shared_auth_transports_stay_under_script_base_and_refuse_token_escape(base):
    node=shutil.which('node')
    if not node:
        pytest.skip('Node.js required for browser transport regression')
    code=r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const base=process.argv[1],calls=[];
const context={URL,Headers,window:{location:{origin:'https://tehnet.ir'}},
document:{currentScript:{src:'https://tehnet.ir'+base+'/assets/auth.js'},querySelectorAll:()=>[]},
fetch:async(path,options)=>{calls.push(path);return{ok:true,json:async()=>({principal:null,csrf:''})}},addEventListener:()=>{}};
vm.runInNewContext(fs.readFileSync(process.argv[2],'utf8'),context);
(async()=>{const a=context.window.TPAuth;await a.ready;assert.equal(calls[0],base+'/auth/session');a.setKey('test-only-marker');await a.request('/api/nodes');assert.equal(calls.at(-1),base+'/api/nodes');assert.equal(a.url('/mesh?campaign=abc'),base+'/mesh?campaign=abc');for(const p of ['https://evil.invalid/','//evil.invalid/','/../outside','/\\evil.invalid/']){let rejected=false;try{await a.request(p)}catch{rejected=true}assert(rejected,'unsafe path '+p)}assert.equal(calls.length,2)})().catch(e=>{console.error(e);process.exitCode=1});
'''
    result=subprocess.run([node,'-e',code,base,str(ROOT/'apps/web/auth.js')],capture_output=True,text=True)
    assert result.returncode==0,result.stdout+result.stderr
