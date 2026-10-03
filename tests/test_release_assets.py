import ast
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ReleaseAssetTests(unittest.TestCase):
    def test_executor_catalog_has_77_methods(self):
        tree = ast.parse((ROOT / "plan_executor/executor.py").read_text())
        supported = None
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "SUPPORTED"
                for target in node.targets
            ):
                supported = ast.literal_eval(node.value)
                break
        self.assertIsNotNone(supported)
        self.assertEqual(77, len(supported))
        self.assertIn("WIREGUARD", supported)
        self.assertIn("GRE", supported)
        self.assertIn("VLESS_XHTTP_REALITY", supported)

    def test_environment_template_documents_required_bot_key(self):
        env = (ROOT / ".env.example").read_text()
        self.assertRegex(env, r"(?m)^BOT_INTERNAL_API_KEY=")

    def test_bilingual_readmes_cross_link(self):
        english = (ROOT / "README.md").read_text()
        persian = (ROOT / "README.fa.md").read_text()
        self.assertIn("README.fa.md", english)
        self.assertIn("README.md", persian)
        self.assertIn("77", english)
        self.assertTrue("77" in persian or "۷۷" in persian)
        self.assertIn("export-production-state.sh", english)
        self.assertIn("restore-production-state.sh", english)

    def test_root_installer_has_safety_and_public_repo_support(self):
        installer = (ROOT / "install.sh").read_text()
        # canonical installer contract (P13): public repo (no token),
        # generated secrets, localhost bind, version-aware, idempotent,
        # honest distro gate, migrations + real health check
        for marker in [
            "DashSaman/TunnelPannel",
            "openssl rand",
            "127.0.0.1",
            "TUNNELPANNEL_VERSION",
            "alembic",
            "unsupported distribution",
            "/health",
        ]:
            self.assertIn(marker, installer)
        self.assertIn("set -Eeuo pipefail", installer)
        self.assertNotIn("GITHUB_TOKEN=", installer)
        self.assertNotRegex(
            installer,
            re.compile(r"https://[^\n]*\$\{?GITHUB_TOKEN\}?@github\.com"),
        )

    def test_gitignore_blocks_runtime_secrets(self):
        ignore = (ROOT / ".gitignore").read_text()
        for marker in [".env", "/backups", "*.key", "*.pem", "*.dump"]:
            self.assertIn(marker, ignore)

    def test_agent_guide_is_comprehensive(self):
        agents = (ROOT / "AGENTS.md").read_text()
        for marker in [
            "Production safety",
            "Source of truth",
            "Verification",
            "77",
            "plan_executor/executor.py",
            "export-production-state.sh",
            "restore-production-state.sh",
        ]:
            self.assertIn(marker, agents)

    def test_state_recovery_helpers_exist(self):
        export_script = (ROOT / "scripts/export-production-state.sh").read_text()
        restore_script = (ROOT / "scripts/restore-production-state.sh").read_text()
        for marker in ["DR_PASSPHRASE", "pg_dump", "app_data", "openssl enc -aes-256-cbc"]:
            self.assertIn(marker, export_script)
        self.assertNotIn("cp .env", export_script)
        for marker in ["DR_PASSPHRASE", "pg_restore", "RESTORE_TUNNELPANNEL", "APP_SECRET_KEY"]:
            self.assertIn(marker, restore_script)


if __name__ == "__main__":
    unittest.main()
