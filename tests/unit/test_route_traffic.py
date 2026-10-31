import asyncio
import json

import pytest

pytestmark = pytest.mark.unit_portable


def test_ledger_exact_shared_quota_restart_and_no_reset(tmp_path):
    from orchestrator.mesh_gateway import TrafficLedger
    path = tmp_path / 'usage.sqlite3'
    first = TrafficLedger(path)
    assert first.charge('upload', 70, 100) == 70
    second = TrafficLedger(path)
    assert second.charge('download', 70, 100) == 30
    assert first.charge('upload', 1, 100) == 0
    assert first.snapshot() == {'upload_bytes': 70, 'download_bytes': 30, 'total_bytes': 100}
    assert second.charge('upload', 10, 200) == 10
    assert TrafficLedger(path).snapshot()['total_bytes'] == 110


def test_invalid_traffic_limits_fail_closed():
    from orchestrator.mesh_gateway import validate_traffic
    for changes in ({'rate_mbps': -1}, {'rate_mbps': float('nan')}, {'quota_bytes': True},
                    {'quota_bytes': -1}, {'max_connections': 0}, {'max_connections': 10001},
                    {'unknown': 1}):
        with pytest.raises(ValueError):
            validate_traffic(changes)
    assert validate_traffic({}) == {'rate_mbps': 0, 'quota_bytes': 0, 'max_connections': 256}


def test_unreadable_or_corrupt_ledger_never_resets(tmp_path):
    from orchestrator.mesh_gateway import TrafficLedger
    path = tmp_path / 'usage.sqlite3'
    path.write_bytes(b'corrupt billing state')
    with pytest.raises(Exception):
        TrafficLedger(path)
    assert path.read_bytes() == b'corrupt billing state'


def test_actual_relay_shapes_payload_and_stops_at_quota(tmp_path):
    from orchestrator.mesh_gateway import TrafficController, TrafficLedger, serve_socks, direct_connect, socks_connect
    async def exercise():
        received = bytearray()
        async def sink(reader, writer):
            try:
                while data := await reader.read(65536):
                    received.extend(data)
            finally:
                writer.close()
        origin = await asyncio.start_server(sink, '127.0.0.1', 0)
        config = {'rate_mbps': .08, 'quota_bytes': 12000, 'max_connections': 2}
        traffic = TrafficController(TrafficLedger(tmp_path / 'usage.sqlite3'), lambda: config)
        async def handler(reader, writer):
            await serve_socks(reader, writer, direct_connect, 'u', 'password', traffic=traffic)
        gateway = await asyncio.start_server(handler, '127.0.0.1', 0)
        try:
            endpoint = {'host': '127.0.0.1', 'port': gateway.sockets[0].getsockname()[1],
                        'username': 'u', 'password': 'password'}
            reader, writer = await socks_connect(endpoint, '127.0.0.1', origin.sockets[0].getsockname()[1])
            started = asyncio.get_running_loop().time()
            writer.write(b'x' * 20000)
            await writer.drain()
            assert await asyncio.wait_for(reader.read(), 5) == b''
            assert asyncio.get_running_loop().time() - started >= 1.0
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(.05)
            assert len(received) == 12000
            assert traffic.ledger.snapshot()['total_bytes'] == 12000
        finally:
            gateway.close(); origin.close()
            await gateway.wait_closed(); await origin.wait_closed()
    asyncio.run(exercise())


def test_live_gateway_advertises_capability_and_persistent_usage(tmp_path):
    from orchestrator.mesh_gateway import Gateway
    config = {'username': 'u', 'password': 'long-test-password', 'upstreams': [{'id': 'a'}],
              'traffic': {'rate_mbps': 5, 'quota_bytes': 1000, 'max_connections': 2}}
    gateway = Gateway(config, tmp_path / 'state.json')
    gateway.traffic.ledger.charge('upload', 10, 1000)
    gateway.write_state()
    state = json.loads((tmp_path / 'state.json').read_text())
    assert state['traffic_control_version'] == 1
    assert state['traffic']['used']['total_bytes'] == 10
    assert state['traffic']['limits']['rate_mbps'] == 5


def test_concurrent_connections_share_one_hard_byte_allowance(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from orchestrator.mesh_gateway import TrafficLedger
    path = tmp_path / 'usage.sqlite3'
    TrafficLedger(path)
    def debit(_):
        return TrafficLedger(path).charge('upload', 700, 1000)
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(debit, range(20))) == 1000
    assert TrafficLedger(path).snapshot()['total_bytes'] == 1000


def test_customer_zero_policy_cannot_bypass_owner_ceiling():
    from core.traffic import bounded_traffic
    from fastapi import HTTPException
    limits = {'max_route_mbps': 10, 'max_route_bytes': 1000, 'max_route_connections': 2}
    assert bounded_traffic({'max_connections': 2}, limits) == {'rate_mbps': 10, 'quota_bytes': 1000, 'max_connections': 2}
    with pytest.raises(HTTPException) as error:
        bounded_traffic({'rate_mbps': 20, 'max_connections': 2}, limits)
    assert error.value.status_code == 403
