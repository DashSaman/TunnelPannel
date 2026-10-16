import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytestmark = pytest.mark.unit_portable


def public(tag='a'*32):
    key = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    return 'restrict '+key+' tp-managed-'+tag


def test_exact_owned_line_changes_preserve_foreign_lines_and_reject_collision():
    from orchestrator.authorized_keys import rewrite
    line = public()
    foreign = b'# keep this\r\nssh-ed25519 SOMEONE_ELSE other\r\n'
    assert rewrite(foreign, add=line) == foreign+line.encode()+b'\n'
    assert rewrite(rewrite(foreign, add=line), add=line) == rewrite(foreign, add=line)
    assert rewrite(rewrite(foreign, add=line), remove=line) == foreign
    with pytest.raises(ValueError):
        rewrite(foreign, remove='ssh-ed25519 SOMEONE_ELSE other')
    with pytest.raises(ValueError):
        rewrite(line.replace('tp-managed-'+'a'*32,'foreign').encode(), add=line)


def test_failed_new_key_verification_keeps_old_encrypted_credential(tmp_path, monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from core.models import Base, Node, SecretReference
    from orchestrator.remote_nodes import encrypt_credentials
    from orchestrator.node_keys import provision_managed_key
    monkeypatch.setenv('TP_SECRET_KEY','test-only-installation-encryption')
    monkeypatch.setenv('TP_LOCK_DIR',str(tmp_path/'leases'))
    factory = sessionmaker(bind=create_engine('sqlite:///'+str(tmp_path/'keys.db')))
    Base.metadata.create_all(factory.kw['bind'])
    with factory() as session:
        secret = SecretReference(id='old', kind='ssh_password', ciphertext=encrypt_credentials(
            {'auth_method':'PASSWORD','secret':'OLD_CANARY','sudo_mode':'NOPASSWD'}))
        session.add_all([secret, Node(id='node', name='node', host='8.8.8.8', secret_ref='old',
                                      host_key_fingerprint='a'*64)])
        session.commit()
    changes=[]
    class Remote:
        def __init__(self, endpoint, credentials): self.credentials=credentials
        def connect(self):
            if self.credentials['auth_method']=='KEY': raise RuntimeError('NEW_CANARY')
            return self
        def run(self,*a,**kw): return {'stdout':'0\n','code':0}
        def close(self): pass
    monkeypatch.setattr('orchestrator.node_keys.NodeRemote', Remote)
    monkeypatch.setattr('orchestrator.node_keys.change_authorized_key', lambda remote,**kw:changes.append(kw))
    with pytest.raises(Exception) as error:
        provision_managed_key(factory,'node')
    assert 'CANARY' not in str(error.value)
    assert changes[0]['add'] == changes[-1]['remove']
    with factory() as session:
        assert session.get(Node,'node').secret_ref=='old'
        assert session.get(SecretReference,'old') is not None


@pytest.mark.skipif(__import__('os').name == 'nt', reason='POSIX file-descriptor ownership and symlink test')
def test_remote_helper_refuses_symlinks_and_preserves_foreign_content(tmp_path, monkeypatch):
    import os
    import pwd
    from types import SimpleNamespace
    from orchestrator.authorized_keys import update
    monkeypatch.setattr(pwd,'getpwnam',lambda name: SimpleNamespace(pw_dir=str(tmp_path),pw_uid=os.getuid(),pw_gid=os.getgid()))
    ssh = tmp_path/'.ssh'
    ssh.mkdir(mode=0o700)
    outside = tmp_path/'foreign'
    outside.write_text('keep foreign key\n')
    (ssh/'authorized_keys').symlink_to(outside)
    with pytest.raises(OSError):
        update('test',add=public())
    assert outside.read_text()=='keep foreign key\n'
    (ssh/'authorized_keys').unlink()
    (ssh/'authorized_keys').write_bytes(b'# foreign\r\n')
    line=public()
    update('test',add=line)
    update('test',remove=line)
    assert (ssh/'authorized_keys').read_bytes()==b'# foreign\r\n'
