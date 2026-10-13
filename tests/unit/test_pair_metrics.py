import pytest


def test_iperf_errors_are_not_zero_speed_success():
    from orchestrator.pair_metrics import parse_iperf
    with pytest.raises(RuntimeError, match='refused'):
        parse_iperf({'error': 'connection refused'})
    with pytest.raises(RuntimeError):
        parse_iperf({'end': {}})


def test_iperf_preserves_actual_received_bytes_and_elapsed_time():
    from orchestrator.pair_metrics import parse_iperf
    receipt = parse_iperf({'end': {'sum_received': {'bytes': 123456, 'seconds': 10,
                                                 'bits_per_second': 98764.8}}})
    assert receipt == {'verified_bytes': 123456, 'elapsed_s': 10, 'throughput_mbps': .0987648}


def test_whole_node_cpu_uses_counter_delta_and_reports_memory_scope():
    from orchestrator.pair_metrics import resource_usage
    metrics = resource_usage({'total': 1000, 'idle': 500, 'ram_mb': 400},
                             {'total': 1100, 'idle': 560, 'ram_mb': 450})
    assert metrics == {'cpu_pct': 40.0, 'ram_mb': 450}
    with pytest.raises(RuntimeError):
        resource_usage({'total': 1000}, {'total': 1000})
