"""Method registry loader — the exact 77 methods from TunnelPannel + kernel base."""
import json
import os
from dataclasses import dataclass, field

BASE = "/opt/multitunnel"
REG_PATH = os.environ.get("MTF_REGISTRY", os.path.join(BASE, "engine", "methods_registry.json"))
# NOTE: the registry JSON already contains the user-requested tunnels:
#   HEDIOUM_POOL_SOCKS, HEDIOUM_TUN, HAJSAMAN_SIT/WG/FULL, PAQET_RAW_KCP/SOCKS5


@dataclass
class Method:
    id: str
    name_fa: str
    name_en: str
    family_fa: str
    family_en: str
    set: str
    cls: str            # kernel | userspace | kernel+userspace
    binary: str
    default_port: int | None = None
    note: str | None = None

    @classmethod
    def from_dict(cls, d):
        return cls(
            id=d["id"], name_fa=d["name_fa"], name_en=d["name_en"],
            family_fa=d["family_fa"], family_en=d["family_en"],
            set=d["set"], cls=d["class"], binary=d["binary"],
            default_port=d.get("default_port"), note=d.get("note"),
        )


def load_registry() -> list[Method]:
    with open(REG_PATH, encoding="utf-8") as f:
        reg = json.load(f)
    return [Method.from_dict(m) for m in reg["methods"]]


def families(methods: list[Method]) -> list[str]:
    seen = []
    for m in methods:
        if m.set not in seen:
            seen.append(m.set)
    return seen
