"""Keep generated verification labels tied to complete installed receipts."""
import copy
import json
from pathlib import Path

import pytest

from scripts.accepted_expansion_receipts import accepted_methods


EVIDENCE = Path(__file__).resolve().parents[2] / "docs/evidence/commercial/tehnet-expansion-installed.json"


def test_installed_receipts_cover_only_three_expansion_profiles():
    assert accepted_methods(json.loads(EVIDENCE.read_text(encoding="utf-8"))) == {
        "BACKHAUL_TCP", "AMNEZIAWG", "IP4IN6",
    }


@pytest.mark.parametrize("change", ["missing_direction", "missing_receipt", "cleanup_failed", "no_data"])
def test_incomplete_receipts_cannot_promote_verification(change):
    evidence = copy.deepcopy(json.loads(EVIDENCE.read_text(encoding="utf-8")))
    if change == "missing_direction":
        evidence["campaign"]["results"].pop()
    elif change == "missing_receipt":
        evidence["campaign"]["results"][0]["receipt"] = False
    elif change == "cleanup_failed":
        evidence["campaign"]["results"][0]["metrics"]["cleanup"] = "failed"
    else:
        evidence["campaign"]["results"][0]["metrics"]["data_plane_ok"] = False
    with pytest.raises(ValueError):
        accepted_methods(evidence)
