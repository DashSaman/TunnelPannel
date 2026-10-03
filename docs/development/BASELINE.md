# Test Baseline — P0

- **Commit:** `84d2dd8e26c0e333633050ff30b458df8f558b75` (`main`, `v3 Neon Ops UI`)
- **Date:** 2026-10-03
- **Environment:** Windows 10 x64 dev machine, Python 3.12.10, project venv `.venv`.
  Several suites target a Linux/containerized runtime (`mtf-panel` Docker, `/opt/multitunnel/engine`) and are recorded as BLOCKED here, not FAIL.

## Results summary

| Suite | Command (canonical) | Result |
|---|---|---|
| tunnelguard | `cd tunnelguard && python -m pytest` | **89 PASS / 11 FAIL** |
| backend | `cd backend && APP_SECRET_KEY=… JWT_SECRET_KEY=… DATABASE_URL=… REDIS_URL=… python -m pytest app/tests` | **1 PASS / 0 FAIL** |
| root | `PYTHONPATH=backend APP_SECRET_KEY=… JWT_SECRET_KEY=… DATABASE_URL=… REDIS_URL=… python -m pytest tests` | **5 PASS / 3 FAIL** |
| deploy (82-method harness) | `deploy/tests/run_all_tests.py` (inside `mtf-panel` container) | **BLOCKED** (needs Linux Docker host with the panel image) |

Totals at baseline: **95 PASS / 14 FAIL / 1 suite BLOCKED**.

## Failure detail

### tunnelguard — 11 FAIL (all environmental, win32)
All 11 failures are `AttributeError: module 'os' has no attribute 'geteuid'` raised from
`tfd/engines/*` precheck code paths (`os.geteuid()` is POSIX-only; this run is on Windows):

- `tests/test_hajsaman.py` — 3 tests (precheck CLI cases)
- `tests/test_hedioum.py` — 3 tests (precheck / standalone `up`)
- `tests/test_paqet.py` — 5 tests (precheck / root-check / `up`)

Expected verdict: these pass on a Linux host. They are code paths worth making
`hasattr(os, "geteuid")`-safe only if cross-platform testing is a goal (decision for P5, not a baseline regression).

### root `tests/test_release_assets.py` — 3 FAIL (pre-existing at HEAD, doc-content assertions)
1. `test_agent_guide_is_comprehensive` — `AGENTS.md` lacks the required marker `Production safety`.
2. `test_bilingual_readmes_cross_link` — `README.md` does not reference `README.fa.md`
   (repo currently ships `README.md` + `README-fa.md` + `README.fa.md` — inconsistent naming).
3. `test_gitignore_blocks_runtime_secrets` — `.gitignore` lacks `/backups` entry.

These assert documentation/release hygiene and were failing before any of our changes.

### backend — collection requires env vars
`backend/app/config.py` declares required settings (`app_secret_key`, `jwt_secret_key`,
`database_url`, `redis_url`) with no defaults; tests can only collect when these are provided.
Recorded as an audit finding (config ergonomics), not fixed at baseline.

## Dependency finding (blocks a single shared venv)

`tunnelguard/requirements.txt` pins `fastapi==0.115.6`; `backend/requirements.txt` pins
`fastapi==0.116.1` → `pip install -r both` = `ResolutionImpossible`.

Baseline procedure used: install tunnelguard pins first → run tunnelguard suite (results above
are with its own pins) → overlay backend requirements (fastapi bumps to 0.116.x) → run
backend + root suites.

## Static checks

No linter/formatter configuration exists in the repo at baseline (no ruff/flake8/black/pyproject
beyond dependency pins). Adding CI static checks is a P13 task.

## Rule

No later phase may silently reduce this baseline. Any test that passed here must keep passing
(or be consciously migrated with an explicit ledger entry).
