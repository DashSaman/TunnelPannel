"""Heavy source builds are preparation, never tunnel performance measurements."""
import concurrent.futures
import time

from orchestrator.host_lease import HostLease
from orchestrator.remote_nodes import NodeRemote


def prepare_engines(access, candidates, cancelled):
    from engines.waterwall_h import METHODS, install
    targets = [candidate for candidate in candidates if candidate.legacy_method_id in METHODS or candidate.legacy_method_id == 'AMNEZIAWG']
    if not targets or cancelled():
        return
    leases = sorted([HostLease(endpoint) for endpoint, _ in access], key=lambda lease: lease.key)
    acquired = []
    try:
        for lease in leases:
            deadline = time.monotonic() + 1800
            while not lease.acquire(.25):
                if cancelled():
                    return
                if time.monotonic() > deadline:
                    raise TimeoutError('host busy during dependency preparation')
            acquired.append(lease)
        def provision(item):
            endpoint, credentials = item
            remote = NodeRemote(endpoint, credentials).connect()
            try:
                if not cancelled():
                    from orchestrator.host_inventory import scan, require_safe
                    require_safe(scan(remote), 'ENGINE_PREPARATION')
                    if any(c.legacy_method_id in METHODS for c in targets):
                        install(remote)
                    if any(c.legacy_method_id == 'AMNEZIAWG' for c in targets):
                        from engines.amneziawg import install as install_awg
                        install_awg(remote)
            finally:
                remote.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            for future in [executor.submit(provision, item) for item in access]:
                future.result()
    except Exception as error:
        for candidate in targets:
            candidate.status = 'BLOCKED'
            candidate.reason = 'pinned engine preparation failed (' + type(error).__name__ + '); see owned build log'
    finally:
        for lease in reversed(acquired):
            lease.release()
