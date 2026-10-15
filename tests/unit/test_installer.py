"""Exercise the actual package-manager dispatch and version resolver in bash."""
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



class TestPackageManagerDispatch:
    @pytest.mark.parametrize("manager", ["apt-get", "dnf", "yum", "zypper", "pacman", "apk"])
    def test_selected_manager_installs_runtime_without_other_managers(self, manager):
        start = SRC.index('if command -v apt-get')
        end = SRC.index("\npython3 -c", start)
        dispatch = SRC[start:end]
        stubs = [
            'command() { [[ "$1" == -v && "$2" == ' + shlex.quote(manager) + ' ]]; }',
            'die() { echo "$*" >&2; exit 42; }',
        ]
        for tool in ["apt-get", "dnf", "yum", "zypper", "pacman", "apk"]:
            stubs.append(tool + '() { echo "' + tool + ' $*" >&2; }')
        out = subprocess.run([BASH, "-c", NL.join(stubs) + NL + dispatch],
                             capture_output=True, text=True)
        assert out.returncode == 0, out.stderr
        assert manager + " " in out.stderr
        assert "python" in out.stderr and "openssl" in out.stderr
        for other in {"apt-get", "dnf", "yum", "zypper", "pacman", "apk"} - {manager}:
            assert other + " " not in out.stderr

    def test_unknown_manager_fails_before_source_or_credentials_are_changed(self):
        start = SRC.index('if command -v apt-get')
        dispatch = SRC[start:SRC.index("\npython3 -c", start)]
        out = subprocess.run([BASH, "-c", 'command() { return 1; }; '
                              'die() { echo "$*" >&2; exit 42; };' + NL + dispatch],
                             capture_output=True, text=True)
        assert out.returncode == 42
        assert "unsupported distribution" in out.stderr

    def test_systemd_and_python_requirements_are_explicit(self):
        assert '[[ -d /run/systemd/system ]]' in SRC
        assert 'sys.version_info >= (3,10)' in SRC
        assert "Other paths are not a test claim" in SRC


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
