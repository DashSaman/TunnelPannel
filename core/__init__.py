"""Canonical core package — single source of truth (ADR-001).

models : canonical ORM entities (Node, Engine, Chain, Deployment, …)
catalog : engine/profile identity + legacy method-ID aliases (P1.7/P2)
"""
from core import catalog, models  # noqa: F401
