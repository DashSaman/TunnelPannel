from plan_executor import executor


def test_installed_dependencies_do_not_repeat_apt_updates():
    calls = []
    class Remote:
        def run(self, command, **kwargs):
            calls.append(command)
            return {'code': 0, 'stdout': '', 'stderr': ''}
    executor.install_packages(Remote(), ['openssl', 'ca-certificates'])
    assert not any('apt-get update' in command for command in calls)
