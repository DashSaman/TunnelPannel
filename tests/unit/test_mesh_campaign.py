import pytest
from fastapi import HTTPException

pytestmark = pytest.mark.unit_portable


def sample(method, **overrides):
    metrics = {"setup_ok": True, "data_plane_ok": True, "recovery_ok": True,
               "throughput_mbps": 50, "rtt_avg": 10, "rtt_p95": 12,
               "jitter": 1, "loss_pct": 0, "reconnect_s": 2, "stability_ratio": 1,
               "rtt_basis": "http_request", "cleanup": "released 5"}
    metrics.update(overrides)
    return {"candidate": method, "status": "PASS", "metrics": metrics, "receipt": True}


def test_three_nodes_produce_all_six_directed_routes_and_reject_duplicate_physical_nodes():
    from orchestrator.mesh_campaign import directed_routes
    assert set(directed_routes(["ir", "de", "us"])) == {
        ("ir", "de"), ("ir", "us"), ("de", "ir"), ("de", "us"), ("us", "ir"), ("us", "de")}
    with pytest.raises(ValueError):
        directed_routes(["ir", "ir"])


def test_top_five_prefers_distinct_carriers_without_inventing_results():
    from orchestrator.mesh_campaign import recommendations
    rows = [sample(m) for m in ["GRE", "GRETAP", "IPIP", "WIREGUARD", "HAJSAMAN_WG", "SIT_6IN4", "VLESS_REALITY"]]
    result = recommendations(rows, count=5)
    assert len(result["selected"]) == 5
    assert "WIREGUARD" in result["selected"] and "VLESS_REALITY" in result["selected"]
    assert not {"GRE", "GRETAP"} <= set(result["selected"])
    assert not {"HAJSAMAN_WG", "SIT_6IN4"} <= set(result["selected"])
    assert len(recommendations(rows[:1], count=5)["selected"]) == 1


@pytest.mark.parametrize("changes", [{"receipt": False}, {"status": "FAILED"},
    {"metrics": {"recovery_ok": False}}, {"metrics": {"cleanup": "ORPHANED: interface"}},
    {"metrics": {"throughput_mbps": 0}}, {"metrics": {"rtt_avg": float('nan')}},
    {"metrics": {"rtt_basis": None}}])
def test_unproven_or_failed_methods_cannot_be_recommended(changes):
    from orchestrator.mesh_campaign import recommendations
    row = sample("WIREGUARD", **changes.get("metrics", {}))
    row.update({k: v for k, v in changes.items() if k != "metrics"})
    assert recommendations([row])["selected"] == []


def test_manual_selection_preserves_order_more_than_five_and_checks_limits():
    from orchestrator.mesh_campaign import select_methods
    rows = [sample(m) for m in ["GRE", "IPIP", "WIREGUARD", "SIT_6IN4", "VLESS_REALITY", "GOST_GRPC"]]
    ordered = [r["candidate"] for r in reversed(rows)]
    assert select_methods(rows, ordered, 10) == ordered
    for bad, limit in [(["missing"], 10), (["GRE", "GRE"], 10), (ordered, 5)]:
        with pytest.raises(HTTPException):
            select_methods(rows, bad, limit)
