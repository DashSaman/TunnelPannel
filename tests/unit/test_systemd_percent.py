from plan_executor import executor


def test_url_escapes_survive_systemd_specifier_expansion():
    commands = []
    class Remote:
        def run(self, command, **kwargs):
            commands.append(command)
            return {'code': 0, 'stdout': '', 'stderr': ''}
    executor.persistent_service(Remote(), 'netauto-test', "exec gost -L 'socks5+quic://host:23000?certFile=%2Fetc%2Fcert.pem'")
    assert 'certFile=%%2Fetc%%2Fcert.pem' in commands[0]
