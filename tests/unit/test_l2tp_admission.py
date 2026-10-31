import pytest

from plan_executor import executor


def test_named_lns_admits_only_the_configured_peer(monkeypatch):
    monkeypatch.setattr(executor, 'free_port', lambda *args: 27000)
    files = []
    class Remote:
        def run(self, command, **kwargs):
            return {'code': 1 if 'ss -H -lun' in command else 0, 'stdout': '', 'stderr': ''}
    for name in ('install_strongswan', 'install_packages', 'allow_firewall_port',
                 'append_managed_chap_secret', 'remove_services'):
        monkeypatch.setattr(executor, name, lambda *a, **kw: None)
    monkeypatch.setattr(executor, 'write_remote_text', lambda r, path, text, mode: files.append((path, text)))
    def stop(*args): raise RuntimeError('stop before daemon startup')
    monkeypatch.setattr(executor, 'oneshot_service', stop)
    with pytest.raises(RuntimeError, match='stop before daemon startup'):
        executor.deploy_l2tp_ipsec({'id': 123456789}, {'id': 3, 'initiator': 'A'},
            {'source_ip_a': '198.51.100.1', 'source_ip_b': '198.51.100.2',
             'tunnel_cidr': '10.246.30.0/30', 'tunnel_ip_a': '10.246.30.1/30',
             'tunnel_ip_b': '10.246.30.2/30'}, Remote(), Remote(), {}, {})
    config = next(text for path, text in files if path.endswith('xl2tpd.conf') and '[lns ' in text)
    assert 'lac = 198.51.100.1' in config
    server_options = next(text for path, text in files if path.endswith('ppp.options') and '\nname netauto-l2tp' in text)
    assert '\nlock\n' not in server_options
