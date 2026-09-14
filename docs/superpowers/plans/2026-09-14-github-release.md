# TunnelPannel GitHub Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish the complete NetAuto/TunnelPannel source safely with bilingual documentation and a one-line bootstrap installer.

**Architecture:** Work only in an isolated Git worktree created from the production repository. Add release-only docs/tests/installer, validate secrets and Compose without touching the running production stack, then push the verified Git history to the empty private GitHub repository as `main`.

**Tech Stack:** Bash, Docker Compose, FastAPI/Python, Nginx, PostgreSQL, Redis, Git/GitHub.

**Spec:** `docs/superpowers/specs/2026-09-14-github-release-design.md`

## Global Constraints
- Production checkout `/opt/network-automation` must remain operational and unmodified except for pre-existing changes.
- Never commit `.env`, backups, dumps, keys, certificates, logs, databases, or runtime volumes.
- Preserve all existing tracked project source and Git history.
- Keep GitHub repository private and document authenticated install flow.

---

### Task 1: Release guard tests
**Files:** Create `tests/test_release_assets.py`; preserve current `tests/test_imports.py` changes.
- [ ] Add tests for README language links, required env keys, installer collision guard, no credential-bearing remote URL, and 77 executor methods.
- [ ] Run the release test and verify it fails before the new assets exist.

### Task 2: Installer and environment template
**Files:** Create `install.sh`; modify `.env.example`; modify `.gitignore` if required.
- [ ] Add `BOT_INTERNAL_API_KEY` to the example environment.
- [ ] Implement root/sudo check, OS prerequisites, Docker bootstrap, repository acquisition, collision detection, secret generation, Compose validation, controlled stack startup, and final health output.
- [ ] Ensure GitHub tokens are accepted only through environment/header use and never written to the repository remote URL.
- [ ] Run the release tests until green and run `bash -n install.sh`.

### Task 3: Complete bilingual documentation
**Files:** Replace `README.md`; create `README.fa.md`; replace `README-fa.md` with compatibility redirect text.
- [ ] Document architecture, services, 77 tunnel methods, security model, prerequisites, private/public one-line installation, manual install, configuration, reverse proxy, backup/restore/update/uninstall, health checks, project structure, and troubleshooting.
- [ ] Keep English and Persian instructions technically equivalent.
- [ ] Re-run release tests.

### Task 4: Verification and publication
**Files:** No production file changes; Git metadata only in release worktree.
- [ ] Run unit/release tests and syntax checks.
- [ ] Validate `docker compose config` using a temporary generated env file without starting production services.
- [ ] Re-run tracked-file and Git-history secret scans.
- [ ] Record production `docker ps` state and verify it was not altered.
- [ ] Commit release changes, configure clean GitHub remote, push `release/tunnelpannel` to `main`, and verify repository contents from GitHub.
