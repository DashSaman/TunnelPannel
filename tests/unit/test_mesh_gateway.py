"""Real local sockets test stable forwarding and data-plane failover."""
import asyncio
import json

import pytest

pytestmark = pytest.mark.unit_portable


def test_hysteresis_order_pin_and_restart_do_not_claim_unprobed_health():
    from orchestrator.mesh_gateway import RoutePolicy
    policy = RoutePolicy(['a', 'b', 'c'], failures=2, successes=2, hold_down=10)
    assert policy.update({'a': True, 'b': True, 'c': True}, now=0) is None
    assert policy.update({'a': True, 'b': True, 'c': True}, now=1) == 'a'
    assert policy.update({'a': False, 'b': True, 'c': True}, now=2) == 'a'
    assert policy.update({'a': False, 'b': True, 'c': True}, now=3) == 'b'
    assert policy.update({'a': True, 'b': True, 'c': True}, now=4) == 'b'
    assert policy.update({'a': True, 'b': True, 'c': True}, now=5) == 'b'
    assert policy.update({'a': True, 'b': True, 'c': True}, now=14) == 'a'
    policy.pin = 'c'
    assert policy.update({'a': True, 'b': True, 'c': True}, now=15) == 'c'
    restored = RoutePolicy(['a', 'b', 'c'], active='a')
    assert restored.update({'a': False, 'b': True, 'c': True}, now=0) is None


def test_authenticated_stable_socks_forwards_and_switches_between_real_upstreams(tmp_path):
    from orchestrator.mesh_gateway import Gateway, socks_connect

    async def exercise():
        async def echo(reader, writer):
            data = await reader.read(100)
            writer.write(data)
            await writer.drain()
            writer.close()

        origin = await asyncio.start_server(echo, '127.0.0.1', 0)
        port = origin.sockets[0].getsockname()[1]
        # Tiny genuine SOCKS upstreams forwarding to real local TCP connections.
        from orchestrator.mesh_gateway import serve_socks, direct_connect
        async def upstream(reader, writer):
            await serve_socks(reader, writer, direct_connect, 'up-user', 'up-pass')
        first = await asyncio.start_server(upstream, '127.0.0.1', 0)
        second = await asyncio.start_server(upstream, '127.0.0.1', 0)
        config = {'listen_host': '127.0.0.1', 'listen_port': 0,
                  'username': 'client', 'password': 'test-gateway-password',
                  'upstreams': [{'id': 'one', 'host': '127.0.0.1', 'port': first.sockets[0].getsockname()[1],
                                 'username': 'up-user', 'password': 'up-pass'},
                                {'id': 'two', 'host': '127.0.0.1', 'port': second.sockets[0].getsockname()[1],
                                 'username': 'up-user', 'password': 'up-pass'}]}
        gateway = Gateway(config, tmp_path / 'state.json')
        gateway.policy.update({'one': True, 'two': True}, now=0)
        gateway.policy.update({'one': True, 'two': True}, now=1)
        await gateway.start_listener()
        stable = {'host': '127.0.0.1', 'port': gateway.server.sockets[0].getsockname()[1],
                  'username': 'client', 'password': 'test-gateway-password'}
        async def roundtrip(nonce):
            reader, writer = await socks_connect(stable, '127.0.0.1', port)
            writer.write(nonce)
            await writer.drain()
            assert await reader.readexactly(len(nonce)) == nonce
            writer.close()
            await writer.wait_closed()
        await roundtrip(b'before-failure')
        first.close()
        await first.wait_closed()
        gateway.policy.update({'one': False, 'two': True}, now=2)
        gateway.policy.update({'one': False, 'two': True}, now=3)
        gateway.policy.update({'one': False, 'two': True}, now=4)
        assert gateway.policy.active == 'two'
        await roundtrip(b'after-failure-same-port')
        gateway.write_state()
        state = json.loads((tmp_path / 'state.json').read_text())
        assert state['active'] == 'two'
        assert 'test-gateway-password' not in json.dumps(state)
        for server in (gateway.server, second, origin):
            server.close()
            await server.wait_closed()
    asyncio.run(exercise())


@pytest.mark.parametrize('rejection', ['method', 'password', 'command'])
def test_rejected_socks_handshake_closes_without_starting_relays(rejection):
    from orchestrator.mesh_gateway import serve_socks

    async def exercise():
        completed = asyncio.get_running_loop().create_future()
        async def forbidden_connect(host, port):
            raise AssertionError('a rejected handshake reached the destination')
        async def handler(reader, writer):
            try:
                await serve_socks(reader, writer, forbidden_connect, 'u', 'p')
                completed.set_result(None)
            except Exception as error:
                completed.set_result(error)
        server = await asyncio.start_server(handler, '127.0.0.1', 0)
        reader, writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
        try:
            writer.write(b'\x05\x01\x00' if rejection == 'method' else b'\x05\x01\x02')
            await writer.drain()
            assert await reader.readexactly(2) == (b'\x05\xff' if rejection == 'method' else b'\x05\x02')
            if rejection != 'method':
                writer.write(b'\x01\x01u\x01' + (b'x' if rejection == 'password' else b'p'))
                await writer.drain()
                assert await reader.readexactly(2) == (b'\x01\x01' if rejection == 'password' else b'\x01\x00')
                if rejection == 'command':
                    writer.write(b'\x05\x03\x00\x01' + bytes(6))
                    await writer.drain()
                    assert await reader.readexactly(10) == b'\x05\x07\x00\x01' + bytes(6)
            assert await asyncio.wait_for(reader.read(), 1) == b''
            assert await asyncio.wait_for(completed, 1) is None
        finally:
            writer.close()
            await writer.wait_closed()
            server.close()
            await server.wait_closed()
    asyncio.run(exercise())
