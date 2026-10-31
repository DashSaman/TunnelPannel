import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.models import Base, Node
from engines.adapters import ProbeResult
from orchestrator.benchmarking import Candidate
from orchestrator.benchmarking.runner import BenchmarkRunner

pytestmark = pytest.mark.unit_portable


def test_dependency_preparation_runs_before_timed_candidate_configuration(tmp_path):
    engine = create_engine('sqlite:///' + str(tmp_path / 'preflight.db'))
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    stages = []
    class Adapter:
        def configure(self): stages.append('configure')
        def start(self): pass
        def probe(self): return ProbeResult(True, 'unit fixture')
        def metrics(self): return {}
        def rollback(self): stages.append('cleanup')
    def adapters(candidate): return Adapter()
    adapters.prepare = lambda candidates, cancelled: stages.append('prepare')
    with factory() as session:
        session.add_all([Node(id='a', name='a', host='8.8.8.8'), Node(id='b', name='b', host='1.1.1.1')])
        session.commit()
        runner = BenchmarkRunner(session, 'a', 'b', 'QUICK', adapters,
            [Candidate('wireguard', 'default', 'WIREGUARD', 'VPN', 'COMPATIBLE')], max_parallel=1)
        runner.run()
    assert stages == ['prepare', 'configure', 'cleanup']
