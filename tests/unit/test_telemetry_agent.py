import json
import pytest
from fastapi import HTTPException

pytestmark = pytest.mark.unit_portable


@pytest.fixture
def identity(tmp_path, monkeypatch):
    from core.workspaces import WorkspaceRegistry
    from core.agent_identity import AgentIdentityStore
    from core.models import Node
    monkeypatch.setenv('TP_SECRET_KEY','telemetry-only-test-installation')
    registry=WorkspaceRegistry(tmp_path/'registry')
    workspace=registry.create('Customer')
    with registry._factory(workspace['id'])() as session:
        session.add(Node(id='a'*32,name='Node',host='8.8.8.8'))
        session.commit()
    return AgentIdentityStore(registry, clock=lambda:1800000000.), registry, workspace


def report(sequence=1, **changes):
    return json.dumps({'version':1, 'sequence':sequence, 'sent_at':1800000000.,
        'os':'linux','arch':'amd64', 'uptime_s':10.,'load1':0.5,
        'memory_total_bytes':1024,'memory_available_bytes':512, **changes}).encode()


def test_certificate_bound_reports_reject_replay_revocation_and_arbitrary_commands(identity):
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    store, registry, workspace=identity
    bundle=store.issue(workspace['id'],'a'*32)
    cert=x509.load_pem_x509_certificate(bundle['certificate'].encode()).public_bytes(Encoding.DER)
    assert store.accept_report(cert,report())['accepted']
    for raw in [report(),report(2,command='whoami'),report(2,uptime_s=True),report(2,load1=float('nan')),b'x'*16385]:
        with pytest.raises(HTTPException): store.accept_report(cert,raw)
    assert store.accept_report(cert,report(2))['accepted']
    store.revoke(workspace['id'],'a'*32)
    with pytest.raises(HTTPException): store.accept_report(cert,report(3))
    assert store.status(workspace['id'],'a'*32)['revoked']
    # An issue request cannot choose another tenant's node.
    other=registry.create('Other')
    with pytest.raises(HTTPException): store.issue(other['id'],'a'*32)


def test_agent_rotation_and_disabled_workspace_cannot_accept_telemetry(identity):
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    store, registry, workspace=identity
    old=store.issue(workspace['id'],'a'*32)
    old_cert=x509.load_pem_x509_certificate(old['certificate'].encode()).public_bytes(Encoding.DER)
    new=store.issue(workspace['id'],'a'*32)
    new_cert=x509.load_pem_x509_certificate(new['certificate'].encode()).public_bytes(Encoding.DER)
    with pytest.raises(HTTPException): store.accept_report(old_cert,report())
    registry.disable(workspace['id'])
    with pytest.raises(HTTPException): store.accept_report(new_cert,report())


def test_real_mutual_tls_handshake_hostname_trust_and_revocation(identity, tmp_path):
    import ssl
    import threading
    import time
    from urllib.error import HTTPError, URLError
    from urllib.request import HTTPSHandler, ProxyHandler, build_opener
    from agent.hub import create_hub
    from agent.telemetry import send
    store, _, workspace=identity
    store.clock=time.time
    bundle=store.issue(workspace['id'],'a'*32)
    server=create_hub(('127.0.0.1',0),store,'127.0.0.1')
    worker=threading.Thread(target=server.serve_forever,daemon=True)
    worker.start()
    url='https://127.0.0.1:'+str(server.server_port)
    data=json.loads(report(sent_at=time.time()))
    try:
        assert send(bundle,data,url)['accepted']
        with pytest.raises(HTTPError) as duplicate:
            send(bundle,data,url)
        assert duplicate.value.code==409
        ca=tmp_path/'ca.pem'
        ca.write_text(bundle['ca'])
        # Trusted server without a client certificate is still rejected in TLS.
        opener=build_opener(ProxyHandler({}),HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))))
        with pytest.raises((OSError,URLError)):
            opener.open(url+'/v1/telemetry',data=b'{}',timeout=3)
        with pytest.raises((OSError,URLError)):
            send(bundle,{**data,'sequence':2},url.replace('127.0.0.1','localhost'))
        store.revoke(workspace['id'],'a'*32)
        with pytest.raises(HTTPError) as revoked:
            send(bundle,{**data,'sequence':2},url)
        assert revoked.value.code==401
    finally:
        server.shutdown()
        worker.join(3)
        server.server_close()


def test_real_ipv6_mutual_tls_loopback(identity):
    import socket
    import threading
    import time
    from agent.hub import create_hub
    from agent.telemetry import send
    if not socket.has_ipv6:
        pytest.skip('IPv6 runtime unavailable')
    try:
        with socket.socket(socket.AF_INET6) as probe:
            probe.bind(('::1',0))
    except OSError:
        pytest.skip('IPv6 loopback unavailable')
    store,_,workspace=identity
    store.clock=time.time
    bundle=store.issue(workspace['id'],'a'*32)
    server=create_hub(('::1',0),store,'::1')
    worker=threading.Thread(target=server.serve_forever,daemon=True)
    worker.start()
    try:
        assert send(bundle,json.loads(report(sent_at=time.time())),
                    'https://[::1]:'+str(server.server_port))['accepted']
    finally:
        server.shutdown()
        worker.join(3)
        server.server_close()
