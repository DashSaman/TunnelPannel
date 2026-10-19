"""Read the curated installed expansion receipt; never promote other profiles."""
from __future__ import annotations

import json
import math
from pathlib import Path
import re

EVIDENCE_PATH = "docs/evidence/commercial/tehnet-expansion-installed.json"
METHODS = {"BACKHAUL_TCP", "AMNEZIAWG", "IP4IN6"}


def accepted_methods(evidence: dict) -> set[str]:
    campaign = evidence.get("campaign", {})
    rows = campaign.get("results", [])
    expected = {(method, direction) for method in METHODS for direction in ("A_to_B", "B_to_A")}
    observed = {(row.get("method"), row.get("direction")) for row in rows}
    valid = (
        evidence.get("status") == "PASS"
        and campaign.get("profile") == "NORMAL"
        and campaign.get("outcomes") == campaign.get("passed") == 6
        and len(rows) == 6 and observed == expected
    )
    for row in rows:
        metrics = row.get("metrics", {})
        valid = valid and row.get("status") == "PASS" and row.get("receipt") is True
        valid = valid and all(metrics.get(key) is True for key in (
            "setup_ok", "data_plane_ok", "recovery_ok"))
        valid = valid and metrics.get("samples", 0) >= 30
        valid = valid and bool(re.fullmatch(r"released [1-9][0-9]*", metrics.get("cleanup", "")))
        throughput = metrics.get("throughput_mbps", 0)
        valid = valid and isinstance(throughput, (int, float)) and math.isfinite(throughput) and throughput > 0
    if not valid:
        raise ValueError("Installed expansion evidence is incomplete; cannot promote verification")
    return METHODS.copy()


def load_accepted(root: Path) -> set[str]:
    return accepted_methods(json.loads((root / EVIDENCE_PATH).read_text(encoding="utf-8")))
