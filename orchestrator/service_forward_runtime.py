"""Bounded fixed-target TCP relay; the existing SOCKS gateway owns all billing.

Standalone copies include first-party mesh_gateway.py/service_forward_protocol.py.
No direct destination connection, monthly credit client or payload log lives here.
"""
from __future__ import annotations

import asyncio
from contextlib import suppress
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import time

if __package__:
    from .mesh_gateway import atomic_json, socks_connect
    from .service_forward_protocol import (
        canonical_address, client_allowed, literal_address, normalize_cidrs, validate_exposure,
    )
else:
    from mesh_gateway import atomic_json, socks_connect
    from service_forward_protocol import (
        canonical_address, client_allowed, literal_address, normalize_cidrs, validate_exposure,
    )


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('bounded integer required')
    return value


def timeout(value, maximum):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0.1 <= value <= maximum:
        raise ValueError('bounded finite timeout required')
    return float(value)


def validate_runtime(config):
    required = {'schema', 'id', 'route_id', 'revision', 'listen_host', 'listen_port',
                'target_host', 'target_port', 'source_cidrs', 'allow_public', 'upstream'}
    defaults = {'max_connections': 256, 'connect_timeout_s': 10, 'idle_timeout_s': 300}
    if not isinstance(config, dict) or required - config.keys() or config.keys() - required - defaults.keys():
        raise ValueError('invalid service runtime configuration')
    result = {**defaults, **config}
    integer(result['schema'], 1, 1)
    for field in ('id', 'route_id'):
        if not isinstance(result[field], str) or not re.fullmatch(r'[0-9a-f]{32}', result[field]):
            raise ValueError('opaque service and route identities required')
    result['revision'] = integer(result['revision'], 1, 2**31 - 1)
    result['listen_host'] = canonical_address(result['listen_host'])
    result['target_host'] = canonical_address(result['target_host'], target=True)
    result['listen_port'] = integer(result['listen_port'], 1024, 65535)
    result['target_port'] = integer(result['target_port'], 1, 65535)
    result['max_connections'] = integer(result['max_connections'], 1, 10000)
    result['connect_timeout_s'] = timeout(result['connect_timeout_s'], 30)
    result['idle_timeout_s'] = timeout(result['idle_timeout_s'], 3600)
    result['source_cidrs'] = normalize_cidrs(result['source_cidrs'])
    validate_exposure(result['listen_host'], result['allow_public'], result['source_cidrs'])
    upstream = result['upstream']
    if not isinstance(upstream, dict) or set(upstream) != {'host', 'port', 'username', 'password'}:
        raise ValueError('one authenticated loopback upstream required')
    upstream = dict(upstream)
    upstream['host'] = canonical_address(upstream['host'])
    if not literal_address(upstream['host']).is_loopback:
        raise ValueError('upstream must be the owned local gateway')
    upstream['port'] = integer(upstream['port'], 1024, 65535)
    if upstream['port'] == result['listen_port']:
        raise ValueError('service cannot bind its own upstream port')
    for field, minimum in (('username', 1), ('password', 16)):
        value = upstream[field]
        if not isinstance(value, str):
            raise ValueError('bounded authenticated credentials required')
        try:
            length = len(value.encode('utf-8'))
        except UnicodeError:
            raise ValueError('valid credential encoding required') from None
        if not minimum <= length <= 255:
            raise ValueError('bounded authenticated credentials required')
    result['upstream'] = upstream
    return result


async def close_writer(writer):
    if writer is not None:
        writer.close()
        with suppress(OSError, asyncio.TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), 1)


class ForwardRelay:
    def __init__(self, config, state_path=None):
        self.config = validate_runtime(config)
        encoded = json.dumps(self.config, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        self.config_sha256 = hashlib.sha256(encoded).hexdigest()
        self.state_path = Path(state_path) if state_path else None
        self.server, self.reporter = None, None
        self.tasks = set()
        self.closing = False
        self.connections_total = self.rejected_connections = self.connect_failures = 0
        self.started_at = None

    async def start(self):
        if self.server is not None:
            raise RuntimeError('service listener already started')
        self.closing = False
        self.server = await asyncio.start_server(self.handle, self.config['listen_host'],
            # Rebind our stopped listener after accepted TCP sessions enter
            # TIME_WAIT. SO_REUSEPORT stays off; a live foreign listener still
            # fails bind and is also refused by controller/source ownership checks.
            self.config['listen_port'], limit=65536, reuse_address=os.name == 'posix', backlog=128)
        self.started_at = time.time()
        if self.state_path:
            self.reporter = asyncio.create_task(self.report())

    def snapshot(self):
        return {'id': self.config['id'], 'route_id': self.config['route_id'],
                'revision': self.config['revision'], 'config_sha256': self.config_sha256,
                'worker_pid': os.getpid(), 'updated_at': time.time(), 'started_at': self.started_at,
                'listening': bool(self.server and self.server.is_serving()),
                'active_connections': len(self.tasks), 'connections_total': self.connections_total,
                'rejected_connections': self.rejected_connections, 'connect_failures': self.connect_failures,
                'accounting': 'inherited existing route gateway; no independent debit',
                'target_health': 'not asserted by listener status'}

    async def report(self):
        while True:
            atomic_json(self.state_path, self.snapshot())
            await asyncio.sleep(1)

    async def handle(self, reader, writer):
        peer = writer.get_extra_info('peername')
        if (self.closing or not peer or not client_allowed(peer[0], self.config['source_cidrs'])
                or len(self.tasks) >= self.config['max_connections']):
            self.rejected_connections += 1
            await close_writer(writer)
            return
        task = asyncio.current_task()
        self.tasks.add(task)
        self.connections_total += 1
        remote = None
        pipes = []
        try:
            try:
                remote_reader, remote = await asyncio.wait_for(socks_connect(self.config['upstream'],
                    self.config['target_host'], self.config['target_port']), self.config['connect_timeout_s'])
            except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                self.connect_failures += 1
                return

            async def pipe(source, destination):
                while True:
                    data = await asyncio.wait_for(source.read(65536), self.config['idle_timeout_s'])
                    if not data:
                        if destination.can_write_eof():
                            destination.write_eof()
                            await asyncio.wait_for(destination.drain(), self.config['idle_timeout_s'])
                        return
                    destination.write(data)
                    await asyncio.wait_for(destination.drain(), self.config['idle_timeout_s'])

            pipes = [asyncio.create_task(pipe(reader, remote)),
                     asyncio.create_task(pipe(remote_reader, writer))]
            await asyncio.gather(*pipes)
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass  # No raw exception, target credentials or customer payload in logs/status.
        finally:
            for pipe in pipes:
                pipe.cancel()
            if pipes:
                await asyncio.gather(*pipes, return_exceptions=True)
            await close_writer(remote)
            await close_writer(writer)
            self.tasks.discard(task)

    async def close(self):
        self.closing = True
        server, self.server = self.server, None
        if server:
            server.close()
        pending = list(self.tasks)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        # Python3.12+ waits for accepted transports as well as the listener;
        # cancel/close handlers before waiting for the server to finish.
        if server:
            await server.wait_closed()
        if self.reporter:
            self.reporter.cancel()
            await asyncio.gather(self.reporter, return_exceptions=True)
            self.reporter = None
        if self.state_path:
            atomic_json(self.state_path, self.snapshot())


async def run(config, state_path):
    relay = ForwardRelay(config, state_path)
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in (signal.SIGTERM, signal.SIGINT):
        with suppress(NotImplementedError):
            loop.add_signal_handler(name, stopped.set)
    waiter = None
    try:
        await relay.start()
        waiter = asyncio.create_task(stopped.wait())
        done, _ = await asyncio.wait((waiter, relay.reporter), return_when=asyncio.FIRST_COMPLETED)
        if relay.reporter in done:
            # A stale/unwritable identity record cannot accompany a live service.
            await relay.reporter
    finally:
        if waiter:
            waiter.cancel()
            await asyncio.gather(waiter, return_exceptions=True)
        await relay.close()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--state', required=True)
    args = parser.parse_args()
    try:
        value = json.loads(Path(args.config).read_text(encoding='utf-8'))
        asyncio.run(run(value, args.state))
    except (OSError, ValueError):
        raise SystemExit('service runtime unavailable; inspect owned resources') from None
