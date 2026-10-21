import pytest
from orchestrator.benchmarking import rtt_stats

pytestmark = pytest.mark.unit_portable


def test_jitter_preserves_time_order_instead_of_sorting_away_variation():
    result = rtt_stats([1.0, 100.0, 1.0, 100.0])
    assert result["jitter"] == 99.0
    assert result["rtt_p50"] == 50.5


def test_http_measurement_uses_remote_curl_network_clock_and_verifies_body():
    from orchestrator.pair_metrics import latency_script
    script = latency_script("curl -fsS http://127.0.0.1:12345/", "owned-nonce", 5)
    assert "%{time_total}" in script
    assert "owned-nonce" in script
    assert "subprocess.run" in script
    assert "http_request" in script
