"""Run destructive lifecycle boundaries against disposable filesystem trees."""
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

import pytest
from tests.unit.test_installer import BASH

ROOT = Path(__file__).resolve().parents[2]


def harness(tmp_path, *, managed=False, unit=''):
    paths = {name: tmp_path / name for name in ('install', 'data', 'config', 'logs')}
    for path in paths.values():
        path.mkdir()
    if managed:
        (paths['config'] / '.managed-paths').write_text('TunnelPannel-managed-paths-v1\n')
    variables = '\n'.join(name + '=' + shlex.quote(paths[key].as_posix()) for name, key in
        [('INSTALL_DIR','install'),('DATA_DIR','data'),('CONF_DIR','config'),('LOG_DIR','logs')])
    setup = variables + '\nSERVICE=tunnelpannel-api\nREPO=https://github.com/DashSaman/TunnelPannel\n'
    setup += 'stat() { echo 0; }; systemctl() { printf "%s" ' + shlex.quote(unit) + '; };\n'
    return paths, setup


@pytest.mark.parametrize('name', ['install.sh', 'scripts/uninstall.sh'])
def test_foreign_nonempty_path_refused_before_mutation(tmp_path, name):
    paths, setup = harness(tmp_path)
    sentinel = paths['logs'] / 'foreign.log'
    sentinel.write_text('do not alter')
    source = (ROOT / name).read_text(encoding='utf8')
    guard = re.search(r'check_managed_paths\(\) \{.*?\n\}', source, re.S)
    assert guard, 'lifecycle ownership guard absent'
    result = subprocess.run([BASH, '-c', setup + guard[0] + '\ncheck_managed_paths'], capture_output=True, text=True)
    assert result.returncode != 0
    assert sentinel.read_text() == 'do not alter'
    assert 'ownership' in result.stderr.lower()


@pytest.mark.parametrize('managed', [False, True])
def test_empty_bootstrap_and_owned_retry_are_supported(tmp_path, managed):
    _, setup = harness(tmp_path, managed=managed)
    source = (ROOT/'install.sh').read_text(encoding='utf8')
    guard = re.search(r'check_managed_paths\(\) \{.*?\n\}', source, re.S)
    assert guard
    result = subprocess.run([BASH,'-c',setup+guard[0]+'\ncheck_managed_paths'],capture_output=True,text=True)
    assert result.returncode == 0, result.stderr


def test_uninstall_refuses_foreign_effective_unit_even_with_marker(tmp_path):
    paths, setup = harness(tmp_path, managed=True, unit='{ path=/usr/bin/foreign ; argv[]=/usr/bin/foreign ; }')
    source = (ROOT/'scripts/uninstall.sh').read_text(encoding='utf8')
    guard = re.search(r'check_managed_paths\(\) \{.*?\n\}', source, re.S)
    assert guard
    result=subprocess.run([BASH,'-c',setup+guard[0]+'\ncheck_managed_paths'],capture_output=True,text=True)
    assert result.returncode != 0
    assert paths['config'].is_dir()


def test_actual_uninstall_checks_before_stop_or_remove(tmp_path):
    paths, setup = harness(tmp_path)
    sentinel=paths['install']/'foreign'
    sentinel.write_text('keep')
    source=(ROOT/'scripts/uninstall.sh').read_text(encoding='utf8')
    for old,key in [('/opt/tunnelpannel','install'),('/var/lib/tunnelpannel','data'),('/etc/tunnelpannel','config'),('/var/log/tunnelpannel','logs')]:
        source=source.replace(old,paths[key].as_posix())
    source=source.replace('/etc/systemd/system', (tmp_path/'systemd').as_posix())
    source=source.replace('[[ $EUID -eq 0 ]]','true')
    called=tmp_path/'systemctl-called'
    source=setup+'systemctl() { printf "%s\\n" "$*" >> '+shlex.quote(called.as_posix())+'; };\n'+source
    result=subprocess.run([BASH,'-c',source],capture_output=True,text=True,env=os.environ)
    assert 'ownership' in result.stderr.lower(), (result.returncode, result.stdout, result.stderr)
    assert result.returncode != 0
    assert sentinel.read_text() == 'keep'
    assert not called.exists() or not re.search(r'^(stop|disable|daemon-reload)',called.read_text(),re.M)


def test_legacy_receipt_accepted_only_for_matching_paths(tmp_path):
    paths, setup=harness(tmp_path)
    (paths['install']/'.git').mkdir()
    (paths['install']/'apps'/'api').mkdir(parents=True)
    (paths['install']/'apps'/'api'/'main.py').touch()
    setup+='git() { echo https://github.com/DashSaman/TunnelPannel.git; };\n'
    receipt={'product':'TunnelPannel','install_path':paths['install'].as_posix(),
             'data_path':paths['data'].as_posix(),'config_path':(paths['config']/'tunnelpannel.env').as_posix(),
             'services':['tunnelpannel-api']}
    path=paths['data']/'install-receipt.json'
    path.write_text(json.dumps(receipt))
    source=(ROOT/'install.sh').read_text(encoding='utf8')
    guard=re.search(r'check_managed_paths\(\) \{.*?\n\}',source,re.S)
    assert guard
    # Python is selected explicitly for Git Bash on Windows as well.
    import sys
    setup+='python3() { '+shlex.quote(Path(sys.executable).as_posix())+' "$@"; };\n'
    result=subprocess.run([BASH,'-c',setup+guard[0]+'\ncheck_managed_paths'],capture_output=True,text=True)
    assert result.returncode == 0,result.stderr
    receipt['data_path']='/foreign'
    path.write_text(json.dumps(receipt))
    result=subprocess.run([BASH,'-c',setup+guard[0]+'\ncheck_managed_paths'],capture_output=True,text=True)
    assert result.returncode != 0
