import asyncio
import json

import pytest

pytestmark = pytest.mark.unit_portable


@pytest.mark.parametrize('valid', [True, False])
def test_quality_probe_checks_real_nonce_and_reports_loss_without_credentials(tmp_path, valid):
    from orchestrator.mesh_gateway import direct_connect, serve_socks
    from scripts.mesh_quality_probe import run_probe

    async def exercise():
        async def origin(reader, writer):
            await reader.readuntil(b'\r\n\r\n')
            writer.write(b'HTTP/1.0 200 OK\r\n\r\n'+(b'owned-nonce' if valid else b'wrong-nonce'))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        async def proxy(reader, writer):
            await serve_socks(reader, writer, direct_connect, 'test-user', 'SECRET_CANARY')
        server = await asyncio.start_server(origin, '127.0.0.1', 0)
        socks = await asyncio.start_server(proxy, '127.0.0.1', 0)
        config = tmp_path/'config.json'
        config.write_text(json.dumps({'listen_host':'127.0.0.1',
            'listen_port':socks.sockets[0].getsockname()[1], 'username':'test-user', 'password':'SECRET_CANARY',
            'upstreams':[{'id':'WIREGUARD','probe':{'host':'127.0.0.1',
                'port':server.sockets[0].getsockname()[1], 'nonce':'owned-nonce'}}]}))
        try:
            result = await run_probe(config, levels=[1,4], rounds=2, interval=0, timeout=1)
            assert result['status'] == ('PASS' if valid else 'FAILED')
            assert result['attempts'] == 10
            assert result['successes'] == (10 if valid else 0)
            assert result['loss_pct'] == (0 if valid else 100)
            assert result['config_unchanged'] is True
            assert 'SECRET_CANARY' not in json.dumps(result)
            assert 'owned-nonce' not in json.dumps(result)
            assert '127.0.0.1' not in json.dumps(result)
        finally:
            socks.close(); server.close()
            await socks.wait_closed(); await server.wait_closed()
    asyncio.run(exercise())


def test_quality_probe_rejects_unbounded_work_before_connecting(tmp_path):
    from scripts.mesh_quality_probe import run_probe
    with pytest.raises(ValueError):
        asyncio.run(run_probe(tmp_path/'missing.json', levels=[1000], rounds=1, interval=0, timeout=1))
