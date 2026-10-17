def test_legacy_body_port_roles_use_canonical_ranges_and_reservations(monkeypatch):
    from plan_executor.executor import free_port
    from orchestrator import host_inventory
    monkeypatch.setattr(host_inventory, 'scan', lambda remote, **kw: {
        'schema':1,'complete':True,'listeners':[{'proto':'TCP','port':21000},
                                             {'proto':'TCP','port':21001,'source':'container'}],
        'reserved_ranges':{'TCP':[[21002,21004]]}})
    class Remote:
        endpoint = {"id": "test-node"}
        def run(self, cmd, **kwargs):
            return {"code": 0, "stdout": "tcp LISTEN 0 128 0.0.0.0:21000 0.0.0.0:*\n", "stderr": ""}
    remote = Remote()
    first = free_port(remote, "tcp", 60000)
    second = free_port(remote, "tcp", 60000)
    assert 21000 <= first <= 25999
    assert second != first
    assert first == 21005


def test_allocator_fails_before_reservation_on_unknown_container_inventory(monkeypatch):
    import pytest
    from plan_executor.executor import free_port
    monkeypatch.setattr('orchestrator.host_inventory.scan',lambda *a,**kw: {
        'complete':False,'listeners':[], 'errors':['docker_ports']})
    class Remote:
        endpoint = {'id':'a'}
        def run(self,*args,**kwargs):
            return {'code':0,'stdout':''}
    remote = Remote()
    with pytest.raises(RuntimeError,match='incomplete'):
        free_port(remote,'tcp',21000)
    assert not getattr(remote,'reserved_ports',set())
