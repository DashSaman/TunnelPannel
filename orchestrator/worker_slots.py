"""A process-safe bounded pool; queued rows wait in SQLite, never in threads."""
import os
import threading

from orchestrator.host_lease import HostLease


def dispatch(work, name):
    try:
        count = max(1, min(4, int(os.environ.get('TP_TEST_WORKERS', '2'))))
    except ValueError:
        count = 2
    for index in range(count):
        lease = HostLease({'host': 'global-test-worker:' + str(index)})
        if not lease.acquire(0):
            continue
        def run(owned=lease):
            try:
                work()
            finally:
                owned.release()
        try:
            threading.Thread(target=run, daemon=True, name=name).start()
        except BaseException:
            lease.release()
            raise
        return True
    return False
