import threading
import pytest

pytestmark = pytest.mark.unit_portable


def test_slots_bound_before_thread_creation_and_release_on_failure(monkeypatch, tmp_path):
    from orchestrator.worker_slots import dispatch
    monkeypatch.setenv('TP_LOCK_DIR', str(tmp_path))
    monkeypatch.setenv('TP_TEST_WORKERS', '1')
    started, release, done = threading.Event(), threading.Event(), threading.Event()
    def work():
        started.set()
        release.wait(5)
        done.set()
    assert dispatch(work, 'one')
    assert started.wait(2)
    assert not dispatch(lambda: pytest.fail('cannot run'), 'two')
    release.set()
    assert done.wait(2)


def test_mesh_leaves_durable_queue_when_worker_slots_full(monkeypatch):
    from orchestrator.mesh_service import CampaignService
    import orchestrator.worker_slots as slots
    monkeypatch.setattr(slots, 'dispatch', lambda *args: False)
    service = CampaignService()
    class Factory:
        kw = {'bind': type('Engine', (), {'url':'sqlite:///isolated.db'})()}
    monkeypatch.setattr(service, 'run', lambda *args: pytest.fail('must stay queued'))
    service.kick(Factory(), 'id')
    assert not service._threads
