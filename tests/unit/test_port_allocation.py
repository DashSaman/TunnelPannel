"""Allocations in one request must not collide with each other."""
from deploy.engine.mtf import portmgr


def test_multiple_roles_receive_distinct_free_ports(tmp_path, monkeypatch):
    monkeypatch.setattr(portmgr, "ALLOC_FILE", str(tmp_path / "allocations.json"))
    monkeypatch.setattr(portmgr.state, "event", lambda *args: None)
    report = {"sides": {"a": {"listeners": [{"proto": "TCP", "port": 21000}]},
                        "b": {"listeners": []}}}
    result = portmgr.assign("owned-run", {"server": "tcp", "client": "tcp"}, ["a", "b"], report)
    assert result["ok"]
    assert result["ports"]["server"] == 21001
    assert result["ports"]["client"] == 21002
