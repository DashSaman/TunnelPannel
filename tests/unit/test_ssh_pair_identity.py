"""SSH carrier setup must not restart or weaken the management SSH daemon."""
from types import SimpleNamespace


def test_pair_identity_uses_pinned_sidecar_and_preserves_management_auth(monkeypatch):
    from plan_executor import executor
    class Key:
        def get_name(self): return "ssh-ed25519"
        def get_base64(self): return "verified-host-public-key"
    class Remote:
        endpoint = {"id": "b", "ssh_username": "root"}
        client = SimpleNamespace(get_transport=lambda: SimpleNamespace(get_remote_server_key=lambda: Key()))
        def __init__(self): self.commands=[]; self.files={}
        def run(self, command, **kwargs):
            self.commands.append(command)
            return {"code":0,"stdout":"ssh-ed25519 temporary-pair-public-key","stderr":""}
    a,b=Remote(),Remote()
    monkeypatch.setattr(executor,"install_packages",lambda *v:None)
    monkeypatch.setattr(executor,"free_port",lambda *v:21015)
    monkeypatch.setattr(executor,"wait_listener",lambda *v:None)
    monkeypatch.setattr(executor,"persistent_service",lambda r,n,c,*v: r.run(c))
    monkeypatch.setattr(executor,"write_remote_text",lambda r,p,c,**kw: r.files.update({p:c}))
    identity=executor.prepare_ssh_identity(a,b,{"host":"192.0.2.5","port":22,"ssh_username":"root"},"netauto-ssh-123456789-2")
    assert identity["port"] == 21015
    assert "verified-host-public-key" in a.files[identity["known_hosts"]]
    assert not any("ssh-keyscan" in cmd for cmd in a.commands)
    assert not any("systemctl restart ssh" in cmd or "sshd_config.d" in cmd for cmd in b.commands)
    assert not any('"$home/.ssh/authorized_keys"' in cmd for cmd in b.commands)
