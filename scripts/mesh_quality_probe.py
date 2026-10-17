"""Opt-in bounded TCP receipt load through an existing owned warm SOCKS entry.

Reads a private gateway config, never changes it or stops a member. The target
is an existing member's owned nonce health origin. Measures short-request quality,
not bulk throughput, public exit identity, Internet availability or an SLA.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import sys
import time
from contextlib import suppress
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.catalog import CATALOG
from orchestrator.mesh_gateway import socks_connect


def distribution(values):
    values = sorted(values)
    if not values:
        return {'samples':0, 'p50':None, 'p95':None, 'max':None}
    return {'samples':len(values), 'p50':round(values[math.ceil(len(values)*.5)-1], 3),
            'p95':round(values[math.ceil(len(values)*.95)-1], 3), 'max':round(values[-1], 3)}


def runtime(path):
    try:
        value = json.loads(path.with_name('state.json').read_text(encoding='utf8'))
        fresh = 0 <= time.time()-value['updated_at'] < 30
        counts = {k:v for k,v in value['connections_by_upstream'].items()
                  if k in CATALOG.identities and type(v) is int and v >= 0}
        health = {k:v for k,v in value['healthy'].items() if k in CATALOG.identities and type(v) is bool}
        return {'fresh':fresh, 'worker_pid':value.get('worker_pid'), 'counts':counts, 'healthy':health}
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return {'fresh':False, 'worker_pid':None, 'counts':{}, 'healthy':{}}


def resources():
    try:
        ticks = list(map(int, Path('/proc/stat').read_text().splitlines()[0].split()[1:9]))
        memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
        return (sum(ticks), ticks[3]+ticks[4]), int(memory['MemAvailable'].split()[0])/1024
    except (OSError, ValueError, KeyError, IndexError):
        return None, None


async def run_probe(path, *, levels, rounds, interval, timeout=15):
    if (not levels or len(levels) > 8 or any(type(n) is not int or not 1 <= n <= 64 for n in levels)
            or type(rounds) is not int or not 1 <= rounds <= 3600 or sum(levels)*rounds > 50000
            or not math.isfinite(interval) or not 0 <= interval <= 3600
            or not math.isfinite(timeout) or not .1 <= timeout <= 60):
        raise ValueError('probe workload exceeds bounded limits')
    path = Path(path)
    raw = path.read_bytes()
    config = json.loads(raw)
    proxy = {key:config['listen_'+key] for key in ('host', 'port')}
    proxy.update({key:config[key] for key in ('username', 'password')})
    target = next(u['probe'] for u in config['upstreams'] if u.get('probe', {}).get('nonce'))
    nonce = target['nonce'].encode()
    if not 1 <= len(nonce) <= 4096:
        raise ValueError('owned health nonce must be 1..4096 bytes')
    started, wall = time.monotonic(), time.time()
    before = runtime(path)
    ticks, _ = resources()
    cpu, ram, phases = [], [], []

    async def request():
        writer = None
        began = time.monotonic()
        latency = None
        try:
            async def exchange():
                nonlocal writer, latency
                reader, writer = await socks_connect(proxy, target['host'], target['port'])
                writer.write(b'GET / HTTP/1.0\r\nHost: owned-health.local\r\nConnection: close\r\n\r\n')
                await writer.drain()
                headers = await reader.readuntil(b'\r\n\r\n')
                if not headers.startswith((b'HTTP/1.0 200 ', b'HTTP/1.1 200 ')):
                    raise ConnectionError('health origin rejected request')
                body = await reader.readexactly(len(nonce))
                if body != nonce:
                    raise ValueError('health receipt mismatch')
                latency = (time.monotonic()-began)*1000
                await asyncio.sleep(.15)  # keep concurrent sessions overlapping.
            await asyncio.wait_for(exchange(), timeout)
            return True, latency
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            return False, None
        finally:
            if writer is not None:
                writer.close()
                with suppress(Exception):
                    await asyncio.wait_for(writer.wait_closed(), 2)

    for level in levels:
        phase_start = time.monotonic()
        times, failures = [], 0
        for index in range(rounds):
            results = await asyncio.gather(*(request() for _ in range(level)))
            times.extend(value for ok, value in results if ok)
            failures += sum(not ok for ok, _ in results)
            next_ticks, available = resources()
            if ticks and next_ticks and next_ticks[0] > ticks[0]:
                cpu.append(100*(1-(next_ticks[1]-ticks[1])/(next_ticks[0]-ticks[0])))
            ticks = next_ticks
            if available is not None:
                ram.append(available)
            if index+1 < rounds:
                await asyncio.sleep(interval)
        phases.append({'concurrency':level, 'rounds':rounds, 'attempts':level*rounds,
                       'successes':len(times), 'failures':failures,
                       'latency_ms':distribution(times), 'elapsed_s':round(time.monotonic()-phase_start, 3)})
    after = runtime(path)
    total = sum(p['attempts'] for p in phases)
    successes = sum(p['successes'] for p in phases)
    unchanged = hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(raw).digest()
    same_worker = before['worker_pid'] is not None and before['worker_pid'] == after['worker_pid']
    deltas = {key:value-before['counts'].get(key,0) for key,value in after['counts'].items()
              if same_worker and value >= before['counts'].get(key,0)}
    return {'schema':'tunnelpannel-mesh-quality-v1', 'started_at':wall, 'finished_at':time.time(),
            'elapsed_s':round(time.monotonic()-started,3),
            'status':'PASS' if successes == total and unchanged else 'FAILED',
            'attempts':total, 'successes':successes, 'loss_pct':100*(total-successes)/total,
            'phases':phases, 'config_unchanged':unchanged, 'same_gateway_worker':same_worker,
            'gateway_observation_fresh':after['fresh'], 'healthy_members':sum(after['healthy'].values()),
            'total_members':len(after['healthy']), 'connections_by_upstream_delta':deltas,
            'host_cpu_pct':distribution(cpu), 'host_min_available_ram_mb':min(ram, default=None),
            'scope':'bounded short TCP nonce requests through existing warm entry; latency excludes deliberate150ms hold; not throughput, public exit proof, ICMP or SLA'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True, help='private owned gateway config.json')
    parser.add_argument('--levels', default='1,8,32,64', help='up to8 comma-separated concurrency levels,1..64')
    parser.add_argument('--rounds', type=int, default=5)
    parser.add_argument('--interval', type=float, default=1)
    parser.add_argument('--timeout', type=float, default=15)
    parser.add_argument('--output', type=Path, required=True, help='allowlisted report destination')
    args = parser.parse_args()
    try:
        levels = [int(n) for n in args.levels.split(',')]
        result = asyncio.run(run_probe(args.config, levels=levels, rounds=args.rounds,
                                      interval=args.interval, timeout=args.timeout))
        args.output.write_text(json.dumps(result, indent=2, allow_nan=False)+'\n', encoding='utf8')
        print(json.dumps({'status':result['status'], 'attempts':result['attempts'], 'successes':result['successes']}))
        return 0 if result['status'] == 'PASS' else 1
    except (OSError, ValueError, KeyError, StopIteration):
        print('probe refused: check private config, bounded arguments and output permissions', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
