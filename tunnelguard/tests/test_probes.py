"""Unit tests — probe engine, scoring, settings validation."""
import socket
import threading
import time

from tfd import probes


class TestTcpProbe:
    def test_tcp_probe_open_port(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        port = srv.getsockname()[1]
        t = threading.Thread(target=lambda: (srv.accept()[0].close(), srv.close()),
                             daemon=True)
        t.start()
        res = probes.tcp_cycle("127.0.0.1", port, timeout_s=1.5)
        srv.close()
        assert res["ok"] is True
        assert res["rtt_ms"] is not None and res["rtt_ms"] >= 0

    def test_tcp_probe_closed_port(self):
        res = probes.tcp_cycle("127.0.0.1", 1, timeout_s=0.6)
        assert res["ok"] is False
        assert res["loss_pct"] == 100.0

    def test_tcp_probe_bind_source(self):
        res = probes.tcp_cycle("127.0.0.1", 1, source="127.0.0.1", timeout_s=0.6)
        # bind succeeded but connection refused -> still a failed probe, not bind error
        assert res["ok"] is False


SCORING_S = {
    "weight_loss": 40, "weight_latency": 30, "weight_jitter": 20,
    "weight_stability": 10, "rtt_reference_ms": 300, "jitter_reference_ms": 50,
}


class TestScoring:
    S = SCORING_S

    def test_perfect(self):
        sc = probes.score_sample(10.0, 0.0, 2.0, self.S, 0)
        assert sc > 90

    def test_dead(self):
        sc = probes.score_sample(None, 100.0, None, self.S, 0)
        assert sc < 15

    def test_high_latency_ranking(self):
        good = probes.score_sample(20.0, 0.0, 2.0, self.S, 0)
        bad = probes.score_sample(280.0, 0.0, 40.0, self.S, 0)
        assert good - bad > 30

    def test_stability_penalty(self):
        a = probes.score_sample(20.0, 0.0, 2.0, self.S, 0)
        b = probes.score_sample(20.0, 0.0, 2.0, self.S, 3)
        assert a > b


class TestWindowStats:
    def test_stats_from_rows(self):
        now = time.time()
        rows = [
            {"ts": now - 30, "rtt_ms": 20.0, "loss_pct": 0, "jitter_ms": 2, "ok": 1},
            {"ts": now - 20, "rtt_ms": 22.0, "loss_pct": 0, "jitter_ms": 3, "ok": 1},
            {"ts": now - 10, "rtt_ms": None, "loss_pct": 100, "jitter_ms": None, "ok": 0},
        ]
        s = dict(SCORING_S, loss_threshold_pct=50)
        out = probes.stats_from_rows(rows, s)
        assert out["n"] == 3
        assert 20 < out["rtt_ms"] < 23       # avg of the two good samples (20,22)
        assert out["loss_pct"] < 50          # (0+0+100)/3 = 33.3
        assert out["ok"] is True

    def test_empty_rows(self):
        s = dict(SCORING_S, loss_threshold_pct=50)
        out = probes.stats_from_rows([], s)
        assert out["n"] == 0 and out["ok"] is False and out["score"] == 0.0


class TestSettingsValidation:
    def test_bad_values(self):
        problems = probes.validate_settings_numbers({
            "probe_interval_s": 0, "fail_threshold": 0, "cooldown_s": 1,
            "loss_threshold_pct": 1, "weight_loss": 40, "weight_latency": 30,
            "weight_jitter": 20, "weight_stability": 5,
        })
        assert len(problems) == 5  # + weights sum = 95

    def test_good_values(self):
        assert probes.validate_settings_numbers({
            "probe_interval_s": 3, "fail_threshold": 3, "cooldown_s": 60,
            "loss_threshold_pct": 50, "weight_loss": 40, "weight_latency": 30,
            "weight_jitter": 20, "weight_stability": 10,
        }) == []
