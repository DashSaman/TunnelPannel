"""Canonical package/dependency service (P5 §9).

One implementation of "install this engine's packages on that distro" —
engines declare package names per package-manager family and never invoke
apt/dnf/yum/zypper/pacman/apk themselves.

Distro support honesty: only managers with a real detection path are
claimed; unsupported distros return BLOCKED rather than guessing.
"""
from __future__ import annotations

from dataclasses import dataclass

# package-manager by (distro id family) — detection via /etc/os-release ID_LIKE/ID
_MANAGER_BY_DISTRO = {
    "debian": "apt", "ubuntu": "apt",
    "rhel": "dnf", "fedora": "dnf", "rocky": "dnf", "almalinux": "dnf", "centos": "dnf",
    "suse": "zypper", "opensuse": "zypper",
    "arch": "pacman", "manjaro": "pacman",
    "alpine": "apk",
}

_INSTALL = {
    "apt":    lambda pkgs: f"apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {' '.join(pkgs)}",
    "dnf":    lambda pkgs: f"dnf install -y {' '.join(pkgs)}",
    "yum":    lambda pkgs: f"yum install -y {' '.join(pkgs)}",
    "zypper": lambda pkgs: f"zypper --non-interactive install {' '.join(pkgs)}",
    "pacman": lambda pkgs: f"pacman --noconfirm -S {' '.join(pkgs)}",
    "apk":    lambda pkgs: f"apk add --no-cache {' '.join(pkgs)}",
}


@dataclass
class PackageSpec:
    """Engine package requirements; names may differ per manager family."""
    engine: str
    # canonical name first; overrides per manager when names differ
    packages: list[str]
    overrides: dict[str, list[str]] | None = None   # {"apt": [...], "apk": [...]}


class PackageService:
    """Single authority for OS package installation commands."""

    def __init__(self, executor):
        self.executor = executor

    def detect_manager(self) -> str | None:
        rc, out = self.executor.run(
            "cat /etc/os-release 2>/dev/null | grep -E '^(ID|ID_LIKE)=' | head -2")
        if rc != 0:
            return None
        ids: list[str] = []
        for line in out.splitlines():
            value = line.split("=", 1)[1].strip('"').lower()
            ids.extend(x.strip() for x in value.split() if x.strip())
        for distro in ids:
            if distro in _MANAGER_BY_DISTRO:
                return _MANAGER_BY_DISTRO[distro]
        return None

    def install_command(self, spec: PackageSpec, manager: str) -> str | None:
        if manager not in _INSTALL:
            return None
        pkgs = (spec.overrides or {}).get(manager, spec.packages)
        return _INSTALL[manager](pkgs)

    def ensure(self, spec: PackageSpec) -> tuple[str, str]:
        """Idempotent best-effort install; returns (status, detail).
        status: INSTALLED | ALREADY_PRESENT | BLOCKED | FAILED"""
        manager = self.detect_manager()
        if manager is None:
            return "BLOCKED", "unsupported distribution (no known package manager)"
        check = " && ".join(f"command -v {p}" for p in spec.packages)
        rc, _ = self.executor.run(check)
        if rc == 0:
            return "ALREADY_PRESENT", manager
        cmd = self.install_command(spec, manager)
        if cmd is None:
            return "BLOCKED", f"no install recipe for manager {manager}"
        rc, out = self.executor.run(cmd, timeout=600)
        return ("INSTALLED" if rc == 0 else "FAILED"), out[-300:]
