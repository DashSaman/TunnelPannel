"""Partial configuration and cleanup must retain durable physical ownership."""
from orchestrator.benchmarking import Candidate
import pytest


def test_failed_configuration_cleanup_removes_only_its_recorded_resources():
    from orchestrator.pair_runtime import RealPairAdapter
    from orchestrator.remote_journal import RemoteJournal
    class Remote:
        deadline = None
        def __init__(self): self.commands = []
        def run(self, cmd, **kwargs):
            self.commands.append(cmd)
            return {"code": 0 if "test ! -e" in cmd else 1, "stdout": "", "stderr": ""}
        def close(self): pass
    r = Remote()
    recorded = []
    journal = RemoteJournal(r, 123456789, 7, "a", lambda *v: recorded.append(v))
    journal.observe("cat > /etc/systemd/system/netauto-frp-123456789-7-server.service <<'EOF'\nunit\nEOF")
    journal.observe("cat > /etc/systemd/system/unrelated.service <<'EOF'\nunit\nEOF")
    assert any(v[1] == "service" for v in recorded)
    assert all("unrelated" not in str(v) for v in recorded)
    adapter = RealPairAdapter(Candidate("frp", "tcp", "FRP_TCP", "forwarder", "COMPATIBLE"),
                              [], "QUICK", 123456789, 7)
    adapter.remotes = [r]
    adapter.journals = [journal]
    adapter.rollback()
    assert any("systemctl stop" in c and "netauto-frp-123456789-7-server.service" in c for c in r.commands)
    assert all("unrelated" not in c for c in r.commands)


def test_journal_cleanup_is_attempted_when_primary_teardown_raises(monkeypatch):
    from orchestrator.pair_runtime import RealPairAdapter
    from plan_executor import executor
    calls = []
    class Remote:
        def close(self): pass
    class Journal:
        def cleanup(self): calls.append("journal cleanup")
    def broken(*args): raise RuntimeError("primary teardown failed")
    monkeypatch.setattr(executor, "rollback_artifact", broken)
    adapter = RealPairAdapter(Candidate("vti", "default", "VTI", "vpn", "COMPATIBLE"), [], "QUICK", 123456789, 7)
    adapter.artifact = {"method": "VTI"}
    adapter.remotes = [Remote(), Remote()]
    adapter.journals = [Journal()]
    with pytest.raises(RuntimeError):
        adapter.rollback()
    assert calls == ["journal cleanup"]


@pytest.mark.parametrize('state,code,should_fail',[('inactive',4,False),('active',0,True)])
def test_transient_cleanup_handles_expiry_but_rejects_running_process(state,code,should_fail):
    from orchestrator.pair_runtime import RealPairAdapter
    class Remote:
        def run(self,command,**kwargs):
            if command.startswith('systemctl stop '):
                if kwargs.get('check',True):raise RuntimeError('Unit not loaded')
                return {'code':5,'stdout':'','stderr':'Unit not loaded'}
            return {'code':code,'stdout':state,'stderr':''}
        def close(self):pass
    remote=Remote()
    adapter=RealPairAdapter(Candidate('gre','default','GRE','kernel','COMPATIBLE'),[],
        'DEEP',123456789,8)
    adapter.remotes=[remote]
    adapter.extra_services=[(remote,'tpbench-123456789-8-iperf')]
    if should_fail:
        with pytest.raises(RuntimeError):adapter.rollback()
    else:adapter.rollback()
