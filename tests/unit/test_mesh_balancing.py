"""Concurrent real TCP streams must share healthy upstreams and release load."""
import asyncio
import json

import pytest

pytestmark = pytest.mark.unit_portable


@pytest.mark.parametrize('mode,weights,expected', [
    ('failover', [1, 1], [8, 0]),
    ('balance', [1, 1], [4, 4]),
    ('balance', [3, 1], [6, 2]),
])
def test_parallel_streams_follow_mode_weights_and_release_reservations(tmp_path, mode, weights, expected):
    from orchestrator.mesh_gateway import Gateway, direct_connect, serve_socks, socks_connect
    async def exercise():
        accepted = [0, 0]
        async def echo(reader, writer):
            try:
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
        origin = await asyncio.start_server(echo, '127.0.0.1', 0)
        origin_port = origin.sockets[0].getsockname()[1]
        servers, streams = [], []
        for index in range(2):
            async def upstream(reader, writer, index=index):
                accepted[index] += 1
                await serve_socks(reader, writer, direct_connect, 'u', 'p')
            servers.append(await asyncio.start_server(upstream, '127.0.0.1', 0))
        config = {'mode': mode, 'listen_port': 0, 'username': 'client',
            'password': 'unit-test-gateway-password', 'upstreams': [
                {'id': str(i), 'host': '127.0.0.1', 'port': server.sockets[0].getsockname()[1],
                 'username': 'u', 'password': 'p', 'weight': weights[i]}
                for i, server in enumerate(servers)]}
        gateway = Gateway(config, tmp_path/'state.json')
        gateway.policy.update({'0': True, '1': True}, now=0)
        gateway.policy.update({'0': True, '1': True}, now=1)
        await gateway.start_listener()
        stable = {'host': '127.0.0.1', 'port': gateway.server.sockets[0].getsockname()[1],
                  'username': config['username'], 'password': config['password']}
        try:
            for index in range(8):
                reader, writer = await socks_connect(stable, '127.0.0.1', origin_port)
                streams.append((reader, writer))
            payloads = [(str(index).encode()+bytes(65535)) for index in range(8)]
            async def transfer(stream, payload):
                reader, writer = stream
                writer.write(payload)
                await writer.drain()
                assert await reader.readexactly(len(payload)) == payload
            await asyncio.gather(*(transfer(stream, payload) for stream,payload in zip(streams,payloads)))
            assert accepted == expected
            gateway.write_state()
            state = json.loads((tmp_path/'state.json').read_text())
            assert state['mode'] == mode
            assert [state['active_connections'][str(i)] for i in range(2)] == expected
            assert [state['connections_by_upstream'][str(i)] for i in range(2)] == expected
        finally:
            for _, writer in streams:
                writer.close()
                await writer.wait_closed()
            for _ in range(100):
                if not sum(gateway.active_connections.values()): break
                await asyncio.sleep(.01)
            assert sum(gateway.active_connections.values()) == 0
            for server in [gateway.server, *servers, origin]:
                server.close()
                await server.wait_closed()
    asyncio.run(exercise())


def test_cancelled_connection_setup_releases_reserved_capacity(tmp_path, monkeypatch):
    from orchestrator.mesh_gateway import Gateway
    async def exercise():
        entered = asyncio.Event()
        async def blocked(*args):
            entered.set()
            await asyncio.Event().wait()
        monkeypatch.setattr('orchestrator.mesh_gateway.socks_connect', blocked)
        gateway = Gateway({'mode': 'balance', 'username': 'u', 'password': 'unit-test-long-password',
            'upstreams': [{'id': 'a', 'host': '127.0.0.1', 'port': 1}]}, tmp_path/'state')
        gateway.policy.healthy['a'] = True
        task = asyncio.create_task(gateway.connect('127.0.0.1', 2))
        await entered.wait()
        assert gateway.active_connections['a'] == 1
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
        assert gateway.active_connections['a'] == 0
    asyncio.run(exercise())


def test_quality_weights_use_measurements_and_bound_extreme_values():
    from orchestrator.mesh_campaign import quality_weights
    rows = [{'candidate': 'fast', 'metrics': {'throughput_mbps': 100, 'jitter': 0, 'loss_pct': 0}},
            {'candidate': 'slow', 'metrics': {'throughput_mbps': 50, 'jitter': 0, 'loss_pct': 0}},
            {'candidate': 'jittery', 'metrics': {'throughput_mbps': 100, 'jitter': 30, 'loss_pct': 0}},
            {'candidate': 'lossy', 'metrics': {'throughput_mbps': 100, 'jitter': 0, 'loss_pct': 10}},
            {'candidate': 'invalid', 'metrics': {'throughput_mbps': float('nan')}}]
    weights = quality_weights(rows)
    assert weights['fast'] == 100 and weights['slow'] == 50
    assert weights['jittery'] < weights['slow'] < weights['lossy'] < weights['fast']
    assert weights['invalid'] == 1


def test_live_probe_degradation_reduces_weight_and_pin_only_uses_healthy_member(tmp_path):
    from orchestrator.mesh_gateway import Gateway
    gateway = Gateway({'mode': 'balance', 'username': 'u', 'password': 'unit-test-long-password',
        'upstreams': [{'id': i, 'host': '127.0.0.1', 'port': 1, 'weight': 10, 'baseline_rtt_ms': 5}
                      for i in ['a', 'b']]}, tmp_path/'state')
    gateway.policy.healthy = {'a': True, 'b': True}
    for _ in range(4):
        gateway.record_probes({'a': {'ok': True, 'latency_ms': 5}, 'b': {'ok': True, 'latency_ms': 100}})
    assert gateway.effective_weight('a') > gateway.effective_weight('b')
    assert gateway.connection_order()[0] == 'a'
    gateway.policy.pin = 'b'
    assert gateway.connection_order()[0] == 'b'
    gateway.policy.healthy['b'] = False
    assert gateway.connection_order() == ['a']


def test_failed_setup_tries_another_healthy_member_without_leaking_load(tmp_path, monkeypatch):
    from orchestrator.mesh_gateway import Gateway
    async def exercise():
        calls = []
        async def connect(upstream, *args):
            calls.append(upstream['id'])
            if upstream['id'] == 'a':
                raise ConnectionError('unit setup failure')
            return object(), object()
        monkeypatch.setattr('orchestrator.mesh_gateway.socks_connect', connect)
        gateway = Gateway({'mode': 'balance', 'username': 'u', 'password': 'unit-test-long-password',
            'upstreams': [{'id': i, 'host': '127.0.0.1', 'port': 1} for i in ['a', 'b']]}, tmp_path/'state')
        gateway.policy.healthy = {'a': True, 'b': True}
        await gateway.connect('127.0.0.1', 2)
        assert calls == ['a', 'b']
        assert gateway.active_connections == {'a': 0, 'b': 0}
        assert gateway.connections_by_upstream == {'a': 0, 'b': 1}
    asyncio.run(exercise())
