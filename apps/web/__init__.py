"""Ranking web UI (P7) — operator workflow page + selection persistence.

Served by apps.web.web_api; talks to the benchmark API. Selection is an
explicit, separate action from deployment (§37): ticking rows only
records operator intent for future FailoverGroups (P10).
"""
