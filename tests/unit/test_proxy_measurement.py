import pytest


@pytest.mark.parametrize("output", ["200\t1048576\t1000000\t1.048576", "200\\t1048576\\t1000000\\t1.048576"])
def test_proxy_measurement_accepts_curl_tab_output(monkeypatch, output):
    from plan_executor import executor
    class Remote:
        def run(self, command, **kw):
            return {"code": 0, "stdout": output, "stderr": ""}
    monkeypatch.setattr(executor, "free_port", lambda *a: 21017)
    monkeypatch.setattr(executor, "install_packages", lambda *a: None)
    data = executor.proxy_throughput_test(Remote(), Remote(), 21016, "test-owned", 1)
    assert data["http_code"] == 200
    assert data["size_mb"] == 1
