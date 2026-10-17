"""Select a free entry without taking over someone else's service."""
from pathlib import Path

import pytest

from scripts import panel_port


def test_fresh_default_conflict_uses_port_manager_but_saved_or_explicit_refuse(monkeypatch):
    monkeypatch.setattr(panel_port,'owned_listener',lambda port:False)
    report = {'complete':True,'listeners':[{'proto':'TCP','port':8080},
                                          {'proto':'TCP','port':21000}],
              'reserved_ranges':{'TCP':[[21001,21005]]}}
    assert panel_port.select(report,8080,False) == 21006
    with pytest.raises(RuntimeError,match='occupied'):
        panel_port.select(report,8080,True)
    assert panel_port.select(report,21007,True) == 21007


def test_scan_failure_and_docker_port_refuse_and_own_listener_reruns(monkeypatch):
    monkeypatch.setattr(panel_port,'owned_listener',lambda port:port==8080)
    report = {'complete':True,'listeners':[{'proto':'TCP','port':8080}]}
    assert panel_port.select(report,8080,True) == 8080
    # A published container binding remains foreign, even if another owned
    # process has a socket with the same numerical port on a different address.
    report['listeners'].append({'proto':'TCP','port':8080,'source':'container'})
    with pytest.raises(RuntimeError):
        panel_port.select(report,8080,True)
    with pytest.raises(RuntimeError,match='incomplete'):
        panel_port.select({'complete':False},8080,False)


def test_owned_socket_requires_exact_systemd_pid_and_all_listener_inodes(tmp_path, monkeypatch):
    monkeypatch.setattr(panel_port,'PROC',tmp_path)
    monkeypatch.setattr(panel_port,'main_pid',lambda:123)
    (tmp_path/'123'/'fd').mkdir(parents=True)
    (tmp_path/'123'/'cgroup').write_text('0::/system.slice/tunnelpannel-api.service\n')
    (tmp_path/'net').mkdir()
    header = 'sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'
    row = '0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 888\n'
    for name in ['tcp','tcp6']:
        (tmp_path/'net'/name).write_text(header+(row if name=='tcp' else ''))
    # Mock symlink read rather than require Windows developer-mode privileges.
    (tmp_path/'123'/'fd'/'3').touch()
    monkeypatch.setattr(Path,'readlink',lambda self:Path('socket:[888]'))
    assert panel_port.owned_listener(8080)
    (tmp_path/'net'/'tcp6').write_text(header+row.replace('888','999'))
    assert not panel_port.owned_listener(8080)
