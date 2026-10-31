"""Actual local TCP/SOCKS traffic; the new relay must not own a debit ledger."""
import asyncio
from contextlib import asynccontextmanager, suppress
import json
import os
import socket

import pytest

pytestmark = pytest.mark.unit_portable


def unused_port():
    with socket.socket() as candidate:
        candidate.bind(('127.0.0.1', 0))
        return candidate.getsockname()[1]


def configuration(upstream_port=25000, target_port=25001, **changes):
    return {
        'schema': 1, 'id': 'e' * 32, 'route_id': 'a' * 32, 'revision': 1,
        'listen_host': '127.0.0.1', 'listen_port': unused_port(),
        'target_host': '127.0.0.1', 'target_port': target_port,
        'source_cidrs': [], 'allow_public': False, 'max_connections': 4,
        'connect_timeout_s': 1, 'idle_timeout_s': 1,
        'upstream': {'host': '127.0.0.1', 'port': upstream_port,
                     'username': 'stable', 'password': 'private-stable-password'},
        **changes,
    }


def test_runtime_only_accepts_authenticated_owned_loopback_upstream_and_bounded_config():
    from orchestrator.service_forward_runtime import validate_runtime, client_allowed
    assert validate_runtime(configuration())['upstream']['host'] == '127.0.0.1'
    for change in (
        {'upstream': {'host': '192.0.2.1', 'port': 25000, 'username': 'u', 'password': 'x' * 32}},
        {'upstream': {'host': 'localhost', 'port': 25000, 'username': 'u', 'password': 'x' * 32}},
        {'upstream': {'host': '127.0.0.1', 'port': True, 'username': 'u', 'password': 'x' * 32}},
        {'upstream': {'host': '127.0.0.1', 'port': 25000}},
        {'upstream': {'host': '127.0.0.1', 'port': 25000, 'username': 'u', 'password': ''}},
        {'listen_port': 22}, {'listen_port': True}, {'max_connections': 0},
        {'connect_timeout_s': float('nan')}, {'idle_timeout_s': float('inf')},
        {'target_host': '169.254.169.254'}, {'target_host': 'example.com'},
        {'monthly': {'token': 'second-accounting-client-forbidden'}},
        {'listen_host': '0.0.0.0'}, {'allow_public': 'true'},
    ):
        with pytest.raises(ValueError):
            validate_runtime(configuration(**change))
    assert client_allowed('::ffff:192.0.2.5', ['192.0.2.0/24'])
    assert not client_allowed('192.0.3.5', ['192.0.2.0/24'])
    assert client_allowed('127.0.0.1', []) and client_allowed('::1', [])
    assert not client_allowed('192.0.2.5', [])


@asynccontextmanager
async def live_stack(tmp_path, *, quota=None, response=None, server_first=False):
    from orchestrator.mesh_gateway import Gateway, direct_connect, serve_socks
    from orchestrator.service_forward_runtime import ForwardRelay
    tasks, relays = set(), []
    target_uploads = []

    async def origin_handler(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        try:
            data = await reader.read(1) if server_first else await reader.read()
            target_uploads.append(data)
            writer.write(data[::-1] if response is None else response)
            await writer.drain()
        except (OSError, asyncio.CancelledError):
            pass
        finally:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()
            tasks.discard(task)

    async def upstream_handler(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        try:
            await serve_socks(reader, writer, direct_connect, 'exit', 'exit-password')
        finally:
            tasks.discard(task)

    origin = await asyncio.start_server(origin_handler, '127.0.0.1', 0)
    upstream = await asyncio.start_server(upstream_handler, '127.0.0.1', 0)
    cfg = {'listen_host': '127.0.0.1', 'listen_port': 0,
           'username': 'stable', 'password': 'private-stable-password',
           'usage_path': str(tmp_path / 'existing-route.sqlite3'),
           'upstreams': [{'id': 'one', 'host': '127.0.0.1',
                          'port': upstream.sockets[0].getsockname()[1],
                          'username': 'exit', 'password': 'exit-password'}]}
    gateway = Gateway(cfg, tmp_path / 'existing-state.json')
    gateway.policy.update({'one': True}, now=0)
    gateway.policy.update({'one': True}, now=1)
    await gateway.start_listener()
    pool, monthly = None, None
    clock = [0]
    if quota is not None:
        from core.monthly_usage import MonthlyUsage
        from orchestrator.monthly_client import MonthlyClient
        pool = MonthlyUsage(tmp_path / 'existing-central.sqlite3', clock=lambda: 1000)
        pool.grant('customer', quota, 4000, expected_revision=0, actor='owner')
        token = pool.register_route('customer', 'existing-route')
        monthly = MonthlyClient(gateway.traffic.ledger,
            {'url': 'https://fixture.invalid/quota/credits', 'token': token},
            rpc=lambda body: pool.exchange(token, **body), monotonic=lambda: clock[0])
        assert monthly.ensure()
        gateway.traffic.monthly = gateway.monthly = monthly
    value = configuration(gateway.server.sockets[0].getsockname()[1], origin.sockets[0].getsockname()[1])

    async def new_relay(**changes):
        config = {**value, 'id': str(len(relays) + 1) * 32, 'listen_port': unused_port(), **changes}
        relay = ForwardRelay(config)
        await relay.start()
        relays.append(relay)
        return relay

    try:
        yield dict(gateway=gateway, config=value, relay=new_relay, pool=pool,
                   monthly=monthly, clock=clock, target_uploads=target_uploads)
    finally:
        for relay in relays:
            await relay.close()
        for server in (gateway.server, upstream, origin):
            server.close()
            await server.wait_closed()
        pending = set(tasks) | set(gateway._connections)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)


async def exchange(port, payload):
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    try:
        writer.write(payload)
        await writer.drain()
        writer.write_eof()
        return await asyncio.wait_for(reader.read(), 3)
    except ConnectionResetError:
        return b''
    finally:
        writer.close()
        with suppress(OSError):
            await writer.wait_closed()


def test_real_relay_preserves_binary_half_close_and_uses_parent_gateway(tmp_path):
    async def run():
        async with live_stack(tmp_path) as stack:
            relay = await stack['relay']()
            body = bytes(range(256)) * 256
            assert await exchange(relay.config['listen_port'], body) == body[::-1]
            # TCP EOF may arrive before wait_closed/finally completes in the server.
            # Await the actual bounded cleanup, not an arbitrary timing sleep.
            await asyncio.wait_for(asyncio.gather(*tuple(relay.tasks)), 2)
            assert stack['target_uploads'] == [body]
            assert stack['gateway'].traffic.ledger.snapshot()['total_bytes'] == len(body) * 2
            status = relay.snapshot()
            assert status['connections_total'] == 1 and status['active_connections'] == 0
            assert 'private-' not in json.dumps(status)
            assert 'upstream' not in status and 'password' not in status
    asyncio.run(run())


def test_real_relay_rejects_acl_and_bad_auth_without_direct_destination_fallback(tmp_path):
    async def run():
        async with live_stack(tmp_path) as stack:
            denied = await stack['relay'](source_cidrs=['192.0.2.0/24'])
            assert await exchange(denied.config['listen_port'], b'denied') == b''
            assert denied.snapshot()['rejected_connections'] == 1
            invalid = await stack['relay'](upstream={**stack['config']['upstream'], 'password': 'wrong-password-is-long'})
            assert await exchange(invalid.config['listen_port'], b'never-direct') == b''
            assert invalid.snapshot()['connect_failures'] == 1
            assert stack['target_uploads'] == []
            assert stack['gateway'].traffic.ledger.snapshot()['total_bytes'] == 0
    asyncio.run(run())


def test_concurrent_forwards_and_direct_socks_share_exactly_one_debit(tmp_path):
    from orchestrator.mesh_gateway import socks_connect
    async def run():
        async with live_stack(tmp_path, quota=100000) as stack:
            first, second = await stack['relay'](), await stack['relay']()
            payloads = [b'a' * 1024, b'b' * 2048, b'c' * 3072]
            async def direct():
                reader, writer = await socks_connect(stack['config']['upstream'], '127.0.0.1', stack['config']['target_port'])
                try:
                    writer.write(payloads[2])
                    await writer.drain()
                    writer.write_eof()
                    return await asyncio.wait_for(reader.read(), 3)
                finally:
                    writer.close()
                    await writer.wait_closed()
            results = await asyncio.gather(exchange(first.config['listen_port'], payloads[0]),
                                           exchange(second.config['listen_port'], payloads[1]), direct())
            assert results == [value[::-1] for value in payloads]
            stack['monthly'].tick()
            expected = sum(map(len, payloads)) * 2
            assert stack['pool'].status('customer')['used_bytes'] == expected
            assert stack['gateway'].traffic.ledger.snapshot()['total_bytes'] == expected
            assert not hasattr(first, 'monthly') and not hasattr(second, 'ledger')
    asyncio.run(run())


def test_forward_cap_and_offline_expired_credit_fail_closed_without_usage_reset(tmp_path):
    async def run():
        async with live_stack(tmp_path, quota=4097, response=b'x' * 65536) as stack:
            first, second = await stack['relay'](), await stack['relay']()
            replies = await asyncio.gather(exchange(first.config['listen_port'], b'1'),
                                           exchange(second.config['listen_port'], b'2'))
            stack['monthly'].tick()
            before = stack['gateway'].traffic.ledger.snapshot()['total_bytes']
            assert before == 4097
            assert sum(map(len, replies)) + sum(map(len, stack['target_uploads'])) == 4097
            assert stack['pool'].status('customer')['used_bytes'] == 4097
            def offline(body):
                raise ConnectionError('private fixture outage')
            stack['monthly'].rpc = offline
            stack['clock'][0] = 20
            await first.close()
            restarted = await stack['relay']()
            assert await exchange(restarted.config['listen_port'], b'no-credit') == b''
            assert await exchange(second.config['listen_port'], b'no-credit') == b''
            assert stack['gateway'].traffic.ledger.snapshot()['total_bytes'] == before
    asyncio.run(run())


def test_relay_idle_limit_and_close_leave_no_accepted_socket_tasks(tmp_path):
    async def run():
        async with live_stack(tmp_path) as stack:
            relay = await stack['relay'](max_connections=1, idle_timeout_s=0.1)
            reader, writer = await asyncio.open_connection('127.0.0.1', relay.config['listen_port'])
            try:
                assert await asyncio.wait_for(reader.read(), 2) == b''
                await relay.close()
                assert relay.snapshot()['active_connections'] == 0
                assert not relay.tasks
            finally:
                writer.close()
                await writer.wait_closed()
    asyncio.run(run())


def test_relay_concurrency_refusal_and_shutdown_do_not_wait_for_idle_timeout(tmp_path):
    async def run():
        async with live_stack(tmp_path) as stack:
            relay = await stack['relay'](max_connections=1, idle_timeout_s=30)
            reader, writer = await asyncio.open_connection('127.0.0.1', relay.config['listen_port'])
            try:
                assert await exchange(relay.config['listen_port'], b'excess') == b''
                assert relay.snapshot()['active_connections'] == 1
                assert relay.snapshot()['rejected_connections'] == 1
                await asyncio.wait_for(relay.close(), 2)
                assert await asyncio.wait_for(reader.read(), 1) == b''
                assert not relay.tasks and not relay.snapshot()['listening']
            finally:
                writer.close()
                await writer.wait_closed()
    asyncio.run(run())


def test_runtime_refuses_occupied_exact_port_without_moving_or_closing_foreign_listener():
    from orchestrator.service_forward_runtime import ForwardRelay
    async def run():
        async def foreign(reader, writer):
            writer.write(b'foreign-preserved')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(foreign, '127.0.0.1', 0)
        port = server.sockets[0].getsockname()[1]
        relay = ForwardRelay(configuration(listen_port=port))
        try:
            with pytest.raises(OSError):
                await relay.start()
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            try:
                assert await reader.read() == b'foreign-preserved'
                assert relay.config['listen_port'] == port and not relay.snapshot()['listening']
            finally:
                writer.close()
                await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()
            await relay.close()
    asyncio.run(run())


def test_standalone_runtime_stops_listening_if_its_owned_status_cannot_be_written(tmp_path, monkeypatch):
    from orchestrator.service_forward_runtime import run
    def unavailable(*args):
        raise OSError('private fixture disk failure')
    monkeypatch.setattr('orchestrator.service_forward_runtime.atomic_json', unavailable)
    config = configuration()
    async def exercise():
        task = asyncio.create_task(run(config, tmp_path / 'status.json'))
        try:
            # Shield distinguishes a real reporter failure from an exception
            # raised only during wait_for's timeout/cancellation cleanup.
            with pytest.raises(OSError, match='private fixture disk failure'):
                await asyncio.wait_for(asyncio.shield(task), 1)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        with pytest.raises(OSError):
            await asyncio.open_connection('127.0.0.1', config['listen_port'])
    asyncio.run(exercise())


@pytest.mark.skipif(os.name != 'posix', reason='Linux deployment TCP TIME_WAIT restart contract')
def test_owned_relay_rebinds_after_server_first_eof_without_changing_its_port(tmp_path):
    from orchestrator.service_forward_runtime import ForwardRelay
    async def run():
        async with live_stack(tmp_path, server_first=True) as stack:
            relay = await stack['relay']()
            reader, writer = await asyncio.open_connection('127.0.0.1', relay.config['listen_port'])
            writer.write(b'x'); await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(1), 2) == b'x'
            # The service sends FIN while the client remains open. Closing the
            # client afterwards leaves the source port in TIME_WAIT on Linux.
            assert await asyncio.wait_for(reader.read(), 2) == b''
            assert not writer.is_closing()
            writer.close(); await writer.wait_closed()
            await asyncio.wait_for(asyncio.gather(*tuple(relay.tasks)), 2)
            await relay.close()
            replacement = ForwardRelay(dict(relay.config))
            try:
                await replacement.start()
                assert replacement.config['listen_port'] == relay.config['listen_port']
            finally:
                await replacement.close()
    asyncio.run(run())
