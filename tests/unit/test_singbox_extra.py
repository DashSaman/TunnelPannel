import pytest
from uuid import uuid4

pytestmark = pytest.mark.unit_portable


@pytest.mark.parametrize('method', ['VMESS_TCP_TLS', 'VMESS_WS_TLS', 'ANYTLS', 'NAIVE_HTTPS'])
def test_protocols_authenticate_both_sides_and_verify_owned_tls(method):
    from engines.singbox_extra import paired_configs
    client, server = paired_configs(method, '203.0.113.4', 24000, 22000,
        {'server': {'enabled': True, 'certificate_path': '/owned/cert', 'key_path': '/owned/key'},
         'client': {'enabled': True, 'server_name': 'owned-cover.test', 'certificate_path': '/owned/ca'}},
        'random-password', str(uuid4()), 'ss-key', 25000)
    inbound, outbound = server['inbounds'][0], client['outbounds'][0]
    assert inbound['type'] == outbound['type']
    assert inbound['users']
    assert outbound['tls']['certificate_path'] == '/owned/ca'
    assert not outbound['tls'].get('insecure')
    assert client['route']['final'] == outbound['tag']
    if method.startswith('VMESS'):
        assert inbound['users'][0]['alterId'] == outbound['alter_id'] == 0


def test_shadowtls_is_composed_with_aead_and_owned_cover_only():
    from engines.singbox_extra import paired_configs
    client, server = paired_configs('SHADOWTLS3_SS2022', '203.0.113.4', 24000, 22000,
        {'server': {}, 'client': {'enabled': True, 'certificate_path': '/owned/ca'}},
        'random-password', 'unused', 'ss-key', 25000)
    assert server['inbounds'][0]['strict_mode'] is True
    assert server['inbounds'][0]['handshake'] == {'server': '127.0.0.1', 'server_port': 25000}
    assert server['inbounds'][0]['detour'] == server['inbounds'][1]['tag']
    assert client['outbounds'][0]['detour'] == client['outbounds'][1]['tag']
    assert client['outbounds'][0]['method'] == '2022-blake3-aes-128-gcm'
