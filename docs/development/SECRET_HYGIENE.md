# SECRET HYGIENE — status, rotation duties, history-cleanup procedure (P1.3)

## Current state

- **HEAD is clean of credentials** (post-P0 redaction): the server root password
  (`AGENT.md`, `deploy/AGENT.md`) and the panel bootstrap password (`worklog.md`) were
  removed; a repo-wide grep for both values returns zero matches.
- `.gitignore` now also blocks `/backups`, `*.key`, `*.pem`, `*.dump`.
- `.env.example` files contain only `CHANGE_ME` placeholders.

## OPERATOR_ACTION_REQUIRED (owner, not agent)

1. **Rotate the exposed server root password** (test node) — it is in git history.
2. **Rotate the panel admin/bootstrap password** on `tun.softarg.ir` — same reason.
3. Rotate the GitHub token if it ever matched the one leaked in chat (AGENT.md note).
4. Decide policy for tracked infrastructure IPs / domain (currently operational context in
   agent docs; optionally scrub or move to an untracked ops file).

None of these block development; work continues on non-secret areas.

## History-cleanup procedure (documented, NOT auto-executed)

Do **not** rewrite history automatically. If the owner decides to scrub:

```bash
# 1. Coordinate a maintenance window (all clones/forks become divergent).
# 2. Back up the repo (mirror clone):
git clone --mirror https://github.com/DashSaman/TunnelPannel.git backup.git
# 3. Rewrite history with git-filter-repo (safer than filter-branch):
pip install git-filter-repo
git filter-repo --replace-text <(printf '123456@Saman==>REDACTED\nfaZPTs6GVYoW==>REDACTED\n')
#    (use the actual secret strings; never echo them into logs)
# 4. Force-push all branches/tags, then on GitHub: invalidate cached views/PRs,
#    and rotate credentials REGARDLESS (history may be forked/cached already).
git push --force --mirror origin
```

Rotation is mandatory either way — history cleanup alone is insufficient protection.

## Standing rules for this repo

- Never print secret values in logs, commits, docs, test output, or chat.
- New credentials go to `.env` (gitignored) or encrypted storage — never tracked files.
- Secret scanning joins CI in P13 (T-P13-001).
