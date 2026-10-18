from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from core.models import Base, BenchmarkRun, Job
from orchestrator.mesh_reconcile import reconcile_benchmark


def test_recovered_worker_finalizes_only_its_interrupted_run():
    engine=create_engine('sqlite://',poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory=sessionmaker(bind=engine)
    with factory() as session:
        active=BenchmarkRun(node_a='a',node_b='b',profile='QUICK',state='RUNNING')
        completed=BenchmarkRun(node_a='a',node_b='b',profile='QUICK',state='PASS')
        session.add_all([active,completed]);session.flush()
        job=Job(kind='benchmark',state='RUNNING',payload={'_run_id':active.id})
        other=Job(kind='benchmark',state='PASS',payload={'_run_id':completed.id})
        session.add_all([job,other]);session.commit()
        identities=(job.id,other.id,active.id,completed.id)
    reconcile_benchmark(factory,identities[0])
    reconcile_benchmark(factory,identities[1])
    with factory() as session:
        assert session.get(BenchmarkRun,identities[2]).state=='INTERRUPTED'
        assert session.get(BenchmarkRun,identities[2]).finished_at is not None
        assert session.get(BenchmarkRun,identities[3]).state=='PASS'
