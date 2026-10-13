def test_legacy_body_port_roles_use_canonical_ranges_and_reservations():
    from plan_executor.executor import free_port
    class Remote:
        endpoint = {"id": "test-node"}
        def run(self, cmd, **kwargs):
            return {"code": 0, "stdout": "tcp LISTEN 0 128 0.0.0.0:21000 0.0.0.0:*\n", "stderr": ""}
    remote = Remote()
    first = free_port(remote, "tcp", 60000)
    second = free_port(remote, "tcp", 60000)
    assert 21000 <= first <= 25999
    assert second != first
    assert first != 21000
