# TunnelPannel GitHub Release Design

## Goal
Publish the current TehranNetwork/NetAuto production source to `DashSaman/TunnelPannel` without exposing runtime secrets or disturbing the running control server, and make a fresh installation possible from one command.

## Source of truth
- Production checkout: `/opt/network-automation`
- Release worktree: `/opt/TunnelPannel-release`
- Target repository: `DashSaman/TunnelPannel`
- Preserve existing Git history and all tracked source components.
- Include the two current uncommitted test-only changes from production.

## Safety constraints
- Never stop, restart, rebuild, or reconfigure the production `netauto-*` containers during release preparation.
- Never add `.env`, database dumps, backup archives, private keys, certificates, runtime logs, or persistent data to Git.
- Test Compose configuration statically and use a distinct project name for any disposable runtime test.
- Keep the repository private; installation documentation must support authenticated GitHub access.

## Release changes
1. Replace the starter README with a complete English README and add `README.fa.md` as the canonical Persian README while retaining `README-fa.md` as a compatibility pointer.
2. Add a root `install.sh` that can bootstrap Docker when missing, acquire the repository safely, generate strong local secrets, validate Compose, and start only this stack.
3. Harden `.env.example` so every environment variable required by the application is documented, including `BOT_INTERNAL_API_KEY`.
4. Add release tests that validate repository hygiene, installer safety guards, documentation links, environment completeness, and the 77-method execution catalog.
5. Push the release branch to the empty GitHub repository as `main` only after all verification passes.

## Installer behavior
- Supported host target: Ubuntu 22.04/24.04 and Debian 12-class systems with root/sudo.
- Default install directory: `/opt/tunnelpannel`; configurable with `INSTALL_DIR`.
- Refuse to proceed if unrelated `netauto-*` containers already exist, unless the target directory is already this installation and `ALLOW_EXISTING_NETAUTO=1` is explicitly set.
- Use existing Docker when available; install Docker Engine only when absent.
- Generate cryptographically random app/JWT/database/Redis/admin/bot-internal secrets without storing GitHub credentials in `.git/config`.
- Bind the web UI to localhost by default (`127.0.0.1:18080`) so exposure requires an explicit reverse proxy.

## Verification
- Python unit/release tests.
- `docker compose config` with generated throwaway environment values.
- Secret/path audit across tracked files and Git history.
- Confirm production container state is unchanged before and after release work.
