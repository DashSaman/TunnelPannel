"""Customer objectives affect measured ranking without weakening receipt gates."""
import pytest

from orchestrator.mesh_campaign import recommendations

pytestmark = pytest.mark.unit_portable


def sample(method, **changes):
    metrics = {'setup_ok':True, 'data_plane_ok':True, 'recovery_ok':True, 'cleanup':'released 3',
               'rtt_avg':10., 'rtt_p95':12., 'jitter':1., 'loss_pct':0., 'throughput_mbps':100.,
               'reconnect_s':1., 'stability_ratio':1., 'rtt_basis':'http_request', **changes}
    return {'candidate':method, 'status':'PASS', 'receipt':True, 'metrics':metrics}


def test_objectives_choose_latency_or_capacity_from_the_same_actual_receipts():
    rows = [sample('WIREGUARD', rtt_avg=5., throughput_mbps=20., reconnect_s=20., stability_ratio=.7),
            sample('SSH_REMOTE_FORWARD', rtt_avg=200., throughput_mbps=900., jitter=20., reconnect_s=1.)]
    assert recommendations(rows, count=1, objective='latency')['selected'] == ['WIREGUARD']
    assert recommendations(rows, count=1, objective='throughput')['selected'] == ['SSH_REMOTE_FORWARD']
    assert recommendations(rows, count=1, objective='stability')['selected'] == ['SSH_REMOTE_FORWARD']


def test_objective_keeps_diversity_and_encrypted_recommendations_are_not_padded():
    rows = [sample('GRE', throughput_mbps=1000.), sample('IP6GRE', throughput_mbps=990.),
            sample('WIREGUARD', throughput_mbps=20.)]
    assert recommendations(rows, count=2, objective='throughput')['selected'] == ['GRE','WIREGUARD']
    result = recommendations(rows, count=5, objective='latency', encrypted_only=True)
    assert result['selected'] == ['WIREGUARD'] and result['shortfall'] == 4
    assert all(row['reason'] for row in result['excluded'])
    assert result['ranked'][0]['encryption'] == 'protocol_encrypted'


def test_boolean_measurement_is_not_a_numeric_receipt():
    result = recommendations([sample('WIREGUARD', rtt_avg=True)], count=1)
    assert result['selected'] == [] and result['qualified'] == 0
