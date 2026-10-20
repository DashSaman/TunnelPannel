import pytest

from core.monthly_usage import MonthlyUsage
from orchestrator.mesh_gateway import TrafficLedger
from orchestrator.monthly_client import MonthlyClient

pytestmark = pytest.mark.unit_portable


def setup(tmp_path, quota=1000):
    pool = MonthlyUsage(tmp_path/'central.db', clock=lambda:1000)
    pool.grant('customer', quota, 4000, expected_revision=0, actor='owner')
    token = pool.register_route('customer', 'route')
    ledger = TrafficLedger(tmp_path/'source.db')
    return pool, token, ledger


def test_local_route_and_shared_credit_are_debited_atomically_and_survive_restart(tmp_path):
    pool, token, ledger = setup(tmp_path)
    rpc = lambda body: pool.exchange(token, **body)
    client = MonthlyClient(ledger, {'url':'https://example.invalid/quota/credits','token':token}, rpc=rpc)
    assert client.ensure()
    assert ledger.charge('download', 700, 800, monthly=client) == 700
    assert ledger.charge('upload', 700, 800, monthly=client) == 100
    client.tick()
    assert pool.status('customer')['used_bytes'] == 800
    restarted = MonthlyClient(ledger, client.config, rpc=rpc)
    assert restarted.ensure()  # recovers/fences old grant and returns unused200
    assert ledger.charge('download', 700, 0, monthly=restarted) == 200
    restarted.tick()
    assert pool.status('customer')['used_bytes'] == 1000
    assert ledger.snapshot()['total_bytes'] == 1000
    assert not restarted.ensure()


def test_lost_reservation_response_replays_pending_identity_after_restart(tmp_path):
    pool, token, ledger = setup(tmp_path)
    def lost(body):
        answer = pool.exchange(token, **body)
        if body.get('request_id'):
            raise ConnectionError('lost response after durable central grant')
        return answer
    client = MonthlyClient(ledger, {'url':'https://example.invalid/quota/credits','token':token}, rpc=lost)
    with pytest.raises(ConnectionError):
        client.ensure()
    assert pool.status('customer')['held_bytes'] == 1000
    recovered = MonthlyClient(ledger, client.config, rpc=lambda body:pool.exchange(token, **body))
    assert recovered.ensure()
    assert ledger.charge('upload', 2000, 0, monthly=recovered) == 1000
    recovered.tick()
    assert pool.status('customer')['used_bytes'] == 1000


def test_expired_offline_credit_and_idle_return_do_not_bypass_quota(tmp_path):
    pool, token, ledger = setup(tmp_path)
    clock = [0]
    client = MonthlyClient(ledger, {'url':'https://example.invalid/quota/credits','token':token},
                           rpc=lambda body:pool.exchange(token, **body), monotonic=lambda:clock[0])
    assert client.ensure()
    assert ledger.charge('upload', 100, 0, monthly=client) == 100
    clock[0] = 20
    assert ledger.charge('upload', 1, 0, monthly=client) == 0
    client.tick()
    assert pool.status('customer')['held_bytes'] == 0
    assert pool.status('customer')['available_bytes'] == 900


def test_callback_rejects_unverified_or_credential_bearing_urls(tmp_path):
    _, token, ledger = setup(tmp_path)
    for url in ('http://example.invalid/quota/credits','https://user:pass@example.invalid/quota/credits',
                'https://example.invalid/quota/credits?token=secret'):
        with pytest.raises(ValueError):
            MonthlyClient(ledger, {'url':url,'token':token})


def test_two_source_relays_cross_credit_boundaries_without_dropping_payload(tmp_path, monkeypatch):
    import asyncio
    from orchestrator.mesh_gateway import TrafficController
    monkeypatch.setattr('orchestrator.monthly_client.MAX_CREDIT', 1024)
    pool = MonthlyUsage(tmp_path/'pool.db', clock=lambda:1000)
    pool.grant('customer', 4097, 4000, expected_revision=0, actor='owner')
    writers, clients, controllers = [], [], []
    class Writer:
        def __init__(self): self.data = bytearray()
        def write(self, data): self.data.extend(data)
        async def drain(self): await asyncio.sleep(0)
    for source in ('a','b'):
        token = pool.register_route('customer', source)
        ledger = TrafficLedger(tmp_path/(source+'.db'))
        client = MonthlyClient(ledger, {'url':'https://example.invalid/quota/credits','token':token},
                               rpc=lambda body, token=token:pool.exchange(token, **body))
        clients.append(client)
        writers.append(Writer())
        controllers.append(TrafficController(ledger, lambda:{}, monthly=client))
    async def run():
        return await asyncio.gather(*(c.relay(b'x'*10000,w,'download') for c,w in zip(controllers,writers)),
                                    return_exceptions=True)
    outcomes = asyncio.run(run())
    assert all(isinstance(value, ConnectionError) for value in outcomes)
    assert sum(len(w.data) for w in writers) == 4097
    for client in clients: client.tick()
    assert pool.status('customer')['used_bytes'] == 4097
    assert sum(c.ledger.snapshot()['total_bytes'] for c in controllers) == 4097


def test_period_change_between_status_and_reservation_does_not_strand_pending_request(tmp_path):
    pool, token, ledger = setup(tmp_path)
    changed = [False]
    def rpc(body):
        answer = pool.exchange(token, **body)
        if not body and not changed[0]:
            pool.grant('customer', 2000, 5000, expected_revision=1, actor='owner', new_period=True)
            changed[0] = True
        return answer
    client = MonthlyClient(ledger, {'url':'https://example.invalid/quota/credits','token':token}, rpc=rpc)
    assert client.ensure() is False
    assert client.ensure() is True
    assert ledger.charge('upload', 3000, 0, monthly=client) == 2000
    client.tick()
    assert pool.status('customer')['used_bytes'] == 2000


def test_http_callback_identifies_the_real_service_and_tracks_contact_without_claiming_idle_success(tmp_path, monkeypatch):
    import io
    pool, token, ledger = setup(tmp_path)
    class Opener:
        def open(self, request, timeout):
            if request.get_header('User-agent') != 'TehNet-TunnelPannel-Gateway/1.0':
                raise ConnectionError('unidentified automated client rejected by front door')
            assert request.get_header('Accept') == 'application/json'
            return io.BytesIO(b'{"ttl_s":0,"period_id":null}')
    monkeypatch.setattr('orchestrator.monthly_client.build_opener',lambda *args:Opener())
    client=MonthlyClient(ledger,{'url':'https://example.invalid/quota/credits','token':token})
    assert client.snapshot()['callback_available'] is None
    client.tick()  # no request was made; idle tick cannot claim reachability
    assert client.snapshot()['callback_available'] is None
    assert client.ensure() is False
    assert client.snapshot()['callback_available'] is True
    def offline(body): raise ConnectionError('fixture transport outage')
    client.rpc=offline
    with pytest.raises(ConnectionError):client.ensure()
    client.tick()
    assert client.snapshot()['callback_available'] is False
