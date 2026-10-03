"""Installer gate tests (P13 final gate items 4+5) — table-driven.

Extracts the REAL case-pattern and version resolver from install.sh and
exercises them in bash, so the tests can never drift from the script.
"""
import pathlib
import re
import shlex
import subprocess

import pytest

pytestmark = pytest.mark.unit_portable

INSTALL = pathlib.Path(__file__).resolve().parents[2] / "install.sh"
SRC = INSTALL.read_text(encoding="utf-8")
NL = chr(10)

def _bash() -> str:
    """Resolve a bash that actually behaves like POSIX bash.

    On Windows the first 'bash' on PATH may be WSL's launcher (breaks
    argv semantics and Windows paths); prefer Git-for-Windows bash there.
    """
    import os
    import shutil
    if os.name == "nt":
        for cand in (r"C:\Program Files\Gitinash.exe",
                     r"C:\Program Files (x86)\Gitinash.exe"):
            if os.path.exists(cand):
                return cand
    found = shutil.which("bash")
    assert found, "bash not available"
    return found


BASH = _bash()



def _pattern() -> str:
    head = re.escape('case "$OS_ID:${OS_VERSION_ID%%.*}" in')
    m = re.search(head + NL + r"\s*([^\n)]+?)\)", SRC)
    assert m, "OS gate pattern not found in install.sh"
    return m.group(1).strip().rstrip(";").strip()


def os_allowed(distro: str, version_id: str) -> bool:
    code = NL.join([
        "OS_ID=" + shlex.quote(distro),
        "OS_VERSION_ID=" + shlex.quote(version_id),
        'case "$OS_ID:${OS_VERSION_ID%%.*}" in',
        "  " + _pattern() + ") echo accept;;",
        "  *) echo reject;;",
        "esac",
    ])
    out = subprocess.run([BASH, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return out.stdout.strip().splitlines()[-1] == "accept"


class TestOSGateTable:
    # (distro, version, expected) — exactly what CI/real testing covers
    TABLE = [
        ("ubuntu", "22.04", True),      # intended LTS
        ("ubuntu", "24.04", True),      # CI-verified (ubuntu-latest = 24.04)
        ("debian", "12", True),         # Debian stable — intended support
        ("debian", "11", False),        # oldstable — NOT tested, rejected
        ("debian", "13", False),        # not yet tested, rejected
        ("ubuntu", "20.04", False),     # older LTS, not supported
        ("ubuntu", "25.10", False),     # interim release, not supported
        ("fedora", "40", False),
        ("centos", "9", False),
        ("alpine", "3.20", False),
        ("arch", "rolling", False),
    ]

    @pytest.mark.parametrize("distro,version,expected", TABLE)
    def test_os_pair(self, distro, version, expected):
        assert os_allowed(distro, version) is expected

    def test_gate_documents_the_supported_set_inline(self):
        assert "exactly what CI/real testing covers" in SRC

    def test_reject_message_lists_only_supported_targets(self):
        assert "Ubuntu 22.04/24.04, Debian 12" in SRC
        assert "Debian 11/12" not in SRC


class TestVersionResolution:
    @pytest.fixture(scope="class")
    def resolver(self):
        m = re.search(r"resolve_tp_version\(\) \{.*?\n\}", SRC, re.S)
        assert m, "resolve_tp_version not found in install.sh"
        return m.group(0)

    def run_resolver(self, resolver, env: dict, install_dir=".") -> str:
        env_text = "".join(
            "export %s=%s;" % (k, shlex.quote(str(v))) + NL
            for k, v in env.items())
        tail = ('INSTALL_DIR=' + shlex.quote(str(install_dir)) + NL +
                'echo "$(resolve_tp_version)"')
        out = subprocess.run([BASH, "-c", resolver + NL + env_text + tail],
                             capture_output=True, text=True)
        assert out.returncode == 0, out.stderr
        return out.stdout.strip().splitlines()[-1]

    def test_explicit_tag_wins(self, resolver):
        assert self.run_resolver(resolver, {"TUNNELPANNEL_VERSION": "v1.2.3"}) == "v1.2.3"

    def test_explicit_main_wins(self, resolver):
        assert self.run_resolver(resolver, {"TUNNELPANNEL_VERSION": "main"}) == "main"

    def test_development_channel_defaults_to_main(self, resolver):
        assert self.run_resolver(resolver, {}) == "main"

    def test_stable_channel_resolves_latest_tag(self, resolver, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
               "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
        import os
        env = {**os.environ, **env}
        for cmd in (["git", "init", "-q"],
                    ["git", "commit", "--allow-empty", "-m", "x", "-q"],
                    ["git", "tag", "v1.0.0"],
                    ["git", "commit", "--allow-empty", "-m", "y", "-q"],
                    ["git", "tag", "v1.1.0"]):
            subprocess.run(cmd, cwd=repo, check=True, capture_output=True, env=env)
        got = self.run_resolver(resolver, {"TP_RELEASE_CHANNEL": "stable"},
                                install_dir=repo.as_posix())
        assert got == "v1.1.0"

    def test_stable_channel_without_tags_falls_back_to_main(self, resolver, tmp_path):
        repo = tmp_path / "empty"
        repo.mkdir()
        got = self.run_resolver(resolver, {"TP_RELEASE_CHANNEL": "stable"},
                                install_dir=repo.as_posix())
        assert got == "main"

    def test_default_is_NOT_prematurely_stable(self):
        # P15 rule: the channel default must stay 'development' until the
        # production release deliberately flips it.
        assert "TP_RELEASE_CHANNEL:-development" in SRC
