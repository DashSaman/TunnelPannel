"""Restart cleanup uses only the durable physical ownership ledger."""
from core.models import Deployment, ResourceAllocation
from orchestrator.host_lease import HostLease
from orchestrator.remote_journal import RemoteJournal
from orchestrator.remote_nodes import NodeRemote, node_access


def reconcile_benchmark(factory, job_id):
    # The campaign lease proves the former worker no longer owns this job.
    # A child job stores the run ID; deployments identify the run via samples
    # only indirectly, so persist the job ID on each benchmark deployment.
    with factory() as session:
        deployments = [d for d in session.query(Deployment).all()
                       if d.desired_state.get("job_id") == job_id]
        for deployment in deployments:
            resources = session.query(ResourceAllocation).filter_by(
                deployment_id=deployment.id, released_at=None).all()
            node_ids = sorted({r.node_id for r in resources if r.node_id})
            access = [node_access(session, node_id) for node_id in node_ids]
            leases = sorted([HostLease(endpoint) for endpoint, _ in access], key=lambda lease: lease.key)
            acquired, remotes = [], []
            try:
                for lease in leases:
                    if not lease.acquire(120):
                        raise RuntimeError("host busy during restart reconciliation")
                    acquired.append(lease)
                for endpoint, credentials in access:
                    remote = NodeRemote(endpoint, credentials).connect()
                    remotes.append(remote)
                    journal = RemoteJournal(remote, 0, 0, endpoint['id'], lambda *args: None)
                    buckets = {"service": journal.units, "path": journal.paths,
                               "interface": journal.interfaces, "auth_marker": journal.auth_markers,
                               "cleanup_command": journal.cleanup_commands, "firewall_rule": journal.firewall_rules}
                    for row in resources:
                        if row.node_id == endpoint['id'] and row.kind in buckets:
                            buckets[row.kind].add(row.key)
                    journal.cleanup()
                from orchestrator.resources import ResourceManager
                ResourceManager(session).release_deployment(deployment.id)
                deployment.state = "ROLLED_BACK"
                session.commit()
            finally:
                for remote in remotes:
                    remote.close()
                for lease in reversed(acquired):
                    lease.release()
