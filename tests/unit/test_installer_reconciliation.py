"""Execute the installer's real shell sections against disposable Git repos."""
import os
import pathlib
import re
import shlex
import subprocess
import pytest

from tests.unit.test_installer import BASH

ROOT = pathlib.Path(__file__).resolve().parents[2]


def test_rerun_installs_the_fetched_branch_head(tmp_path):
    env = {**os.environ, "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@local",
           "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@local"}
    upstream = tmp_path / "upstream"
    installed = tmp_path / "installed"
    upstream.mkdir()
    def git(*args, cwd=upstream):
        return subprocess.run(["git", *args], cwd=cwd, env=env, check=True,
                              capture_output=True, text=True).stdout.strip()
    git("init", "-q", "--initial-branch=main")
    git("commit", "--allow-empty", "-qm", "old")
    git("clone", "-q", upstream.as_posix(), installed.as_posix())
    git("commit", "--allow-empty", "-qm", "new")
    expected = git("rev-parse", "HEAD")
    source = (ROOT / "install.sh").read_text(encoding="utf-8")
    resolver = re.search(r"resolve_tp_version\(\) \{.*?\n\}", source, re.S).group()
    section = source.split('STAGE="fetch-source"', 1)[1].split('STAGE="config"', 1)[0]
    code = "\n".join(["set -Eeuo pipefail", "note() { :; }", "die() { exit 1; }",
                        "INSTALL_DIR=" + shlex.quote(installed.as_posix()),
                        "REPO=" + shlex.quote(upstream.as_posix()),
                        "TUNNELPANNEL_VERSION=main", resolver, section])
    result = subprocess.run([BASH, "-c", code], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert git("rev-parse", "HEAD", cwd=installed) == expected


def test_first_run_tokens_do_not_enter_persistent_install_log(tmp_path):
    source = (ROOT / "install.sh").read_text(encoding="utf-8")
    log = tmp_path / "install.log"
    block = re.search(r'if \[\[ "\$SHOW_TOKENS" == "1" \]\]; then.*?\nfi', source, re.S).group()
    redirection = source[source.index('exec > >(tee'):source.index('STAGE="preflight"')]
    # Preserve the operator's original stdout, as the real installer does.
    code = "\n".join(["exec 3>&1", "LOG_FILE=" + shlex.quote(log.as_posix()),
                        redirection, "SHOW_TOKENS=1", "V_TOKEN=secret-viewer",
                        "O_TOKEN=secret-operator", "A_TOKEN=secret-admin", block])
    result = subprocess.run([BASH, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "secret-admin" in result.stdout
    assert "secret-admin" not in log.read_text(encoding="utf-8")
    assert "secret-operator" not in log.read_text(encoding="utf-8")


@pytest.mark.parametrize("override,expected", [(None, "21011"), ("21012", "21012")])
def test_saved_port_survives_rerun_and_explicit_changes_are_persisted(tmp_path, override, expected):
    config = tmp_path / "tunnelpannel.env"
    config.write_text("TP_SECRET_KEY=unchanged\nTUNNELPANNEL_PORT=21011\n", encoding="utf-8")
    source = (ROOT / "install.sh").read_text(encoding="utf-8")
    section = source.split('STAGE="config"', 1)[1].split('STAGE="python-env"', 1)[0]
    code = "\n".join(["set -Eeuo pipefail", "note() { :; }", "die() { exit 1; }",
                        'INSTALL_DIR=unused', 'python3() { echo "$3"; }',
                        "CONF_DIR=" + shlex.quote(tmp_path.as_posix()), "PORT=8080",
                        "DATA_DIR=" + shlex.quote(tmp_path.as_posix()),
                        ("TUNNELPANNEL_PORT="+override) if override else "unset TUNNELPANNEL_PORT",
                        section, 'echo "$PORT"', '. "$CONF_DIR/tunnelpannel.env"',
                        'echo "$TUNNELPANNEL_PORT"'])
    result = subprocess.run([BASH, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-2:] == [expected, expected]
    assert "TP_SECRET_KEY=unchanged" in config.read_text(encoding="utf-8")
    assert 'TP_LOCK_DIR=' + tmp_path.as_posix() + '/leases' in config.read_text(encoding='utf-8')


def test_bootstrap_tokens_are_shown_before_a_later_install_failure(tmp_path):
    source = (ROOT / "install.sh").read_text(encoding="utf-8")
    section = source.split('STAGE="config"', 1)[1].split('STAGE="python-env"', 1)[0]
    code = "\n".join(["set -Eeuo pipefail", "exec 3>&1", "note() { :; }", "die() { exit 1; }",
                       'INSTALL_DIR=unused', 'python3() { echo "$3"; }',
                       "chown() { :; }", "CONF_DIR=" + shlex.quote(tmp_path.as_posix()),
                       "DATA_DIR=" + shlex.quote(tmp_path.as_posix()), "PORT=8080",
                       "unset TUNNELPANNEL_PORT", section, "false"])
    result = subprocess.run([BASH, "-c", code], capture_output=True, text=True)
    assert result.returncode != 0
    assert "FIRST-RUN RBAC TOKENS" in result.stdout
