import shlex
from urllib.parse import parse_qs,urlsplit


def test_ssh_transport_disables_nested_socks_tls_on_both_ends(monkeypatch):
    from engines.gost_pair import deploy_gost_proxy_pair
    from plan_executor import executor as bodies
    commands=[]
    monkeypatch.setattr(bodies,'install_gost',lambda remote:None)
    monkeypatch.setattr(bodies,'free_port',lambda remote,*args:23017)
    monkeypatch.setattr(bodies,'allow_firewall_port',lambda *args:None)
    monkeypatch.setattr(bodies,'wait_listener',lambda *args:None)
    monkeypatch.setattr(bodies,'persistent_service',lambda remote,name,command:commands.append(command))
    artifact=deploy_gost_proxy_pair('GOST_SSH',{'id':1234},{'id':1},{},object(),object(),{}, {'host':'192.0.2.2'})
    urls=[arg for command in commands for arg in shlex.split(command) if arg.startswith('socks5+ssh://')]
    assert len(urls)==2
    assert all(parse_qs(urlsplit(url).query).get('notls')==['true'] for url in urls)
    assert artifact['transport']=='socks5+ssh'
