import pytest

pytestmark = pytest.mark.unit_portable


def test_owned_ca_patch_is_explicit_fail_closed_and_preserves_peer_verification():
    from engines.waterwall_h import patch_owned_ca
    original = 'static bool loadCaCertificates(SSL_CTX *ssl_ctx)\n{\n    BIO_free(bio);\n    return true;\n}\nSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);\n'
    patched = patch_owned_ca(original)
    assert 'TP_WATERWALL_CA_FILE' in patched
    assert 'SSL_VERIFY_PEER' in patched
    assert 'BIO_new_file' in patched
    assert 'loaded > 0' in patched
    assert patch_owned_ca(patched) == patched
    with pytest.raises(ValueError):
        patch_owned_ca('unexpected source')


@pytest.mark.parametrize('method', ['WATERWALL_H_WS_TLS', 'WATERWALL_H_HTTP2_TLS', 'WATERWALL_H_REALITY',
                                    'WATERWALL_H_VLESS_REALITY'])
def test_paired_recipes_are_strict_tls_and_have_no_loopback_transport_shortcut(method):
    from engines.waterwall_h import paired_configs
    client, server = paired_configs(method, '198.51.100.9', 24321, 24322, 24323,
        '/owned/cert.pem', '/owned/key.pem', 'test-auth-secret', 'test-salt', 24324)
    clients = client['nodes']
    assert all(node['settings']['verify'] is True for node in clients if node['type'] in {'TlsClient', 'RealityClient'})
    tcp = next(node for node in clients if node['name'] == 'transport-out')
    assert tcp['settings']['address'] == '198.51.100.9'
    assert tcp['settings']['port'] == 24321
    assert server['nodes'][0]['settings']['port'] == 24321
