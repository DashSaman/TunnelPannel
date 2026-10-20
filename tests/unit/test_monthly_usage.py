from concurrent.futures import ThreadPoolExecutor

import pytest

from core.monthly_usage import MonthlyUsage

pytestmark = pytest.mark.unit_portable


@pytest.fixture
def pool(tmp_path):
    return MonthlyUsage(tmp_path / 'quota.db', clock=lambda: 1000)


def test_two_sources_share_one_atomic_allowance_and_retries_do_not_multiply(pool):
    period = pool.grant('customer', 1000, 4000, expected_revision=0, actor='owner')
    first = pool.register_route('customer', 'route-a')
    second = pool.register_route('customer', 'route-b')
    def reserve(item):
        token, request = item
        return pool.exchange(token, request_id=request, amount=700, period_id=period['id'])
    with ThreadPoolExecutor(max_workers=2) as executor:
        a, b = list(executor.map(reserve, [(first, 'a'), (second, 'b')]))
    assert a['amount'] + b['amount'] == 1000
    assert reserve((first, 'a'))['grant_id'] == a['grant_id']
    assert pool.status('customer')['held_bytes'] == 1000
    assert pool.status('other')['period'] is None


def test_fenced_return_monotonic_reports_topup_and_history(pool):
    p = pool.grant('customer', 100, 4000, expected_revision=0, actor='owner')
    token = pool.register_route('customer', 'route')
    a = pool.exchange(token, request_id='a', amount=100, period_id=p['id'])
    pool.exchange(token, grant_id=a['grant_id'], upload=20, download=30)
    state = pool.status('customer')
    assert (state['used_bytes'], state['held_bytes'], state['available_bytes']) == (50, 50, 0)
    with pytest.raises(ValueError):
        pool.exchange(token, grant_id=a['grant_id'], upload=19, download=30)
    with pytest.raises(ValueError):
        pool.grant('customer', 99, 4000, expected_revision=1, actor='owner')
    pool.exchange(token, grant_id=a['grant_id'], upload=20, download=30, close=True)
    assert pool.status('customer')['available_bytes'] == 50
    pool.grant('customer', 200, 5000, expected_revision=1, actor='owner')
    assert pool.status('customer')['used_bytes'] == 50
    assert len(pool.status('customer')['history']) == 2
    assert MonthlyUsage(pool.path, clock=lambda:1000).status('customer')['used_bytes'] == 50


def test_expiry_revocation_and_foreign_grants_fail_closed(pool):
    p = pool.grant('customer', 100, 1001, expected_revision=0, actor='owner')
    token = pool.register_route('customer', 'route')
    other = pool.register_route('customer', 'other')
    a = pool.exchange(token, request_id='a', amount=100, period_id=p['id'])
    with pytest.raises(ValueError):
        pool.exchange(other, grant_id=a['grant_id'], upload=1)
    expired = MonthlyUsage(pool.path, clock=lambda:1002)
    assert expired.exchange(token, grant_id=a['grant_id'])['ttl_s'] == 0
    assert expired.status('customer')['held_bytes'] == 100  # never refund on timeout alone
    assert expired.exchange(token, request_id='b', amount=1, period_id=p['id'])['rejected'] is True
    pool.retire_route('route', {a['grant_id']: (10, 0)})  # caller must prove worker fenced
    with pytest.raises(PermissionError):
        pool.exchange(token, request_id='c', amount=1, period_id=p['id'])
    assert pool.status('customer')['used_bytes'] == 10
