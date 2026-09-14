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

    def test_root_installer_has_safety_and_private_repo_support(self):
        installer = (ROOT / "install.sh").read_text()
        required_markers = [
            "ALLOW_EXISTING_NETAUTO",
            "GITHUB_TOKEN",
            "docker compose --env-file .env config",
            "openssl rand",
            "127.0.0.1",
            "DashSaman/TunnelPannel",
        ]
        for marker in required_markers:
            self.assertIn(marker, installer)
        self.assertNotRegex(
            installer,
            re.compile(r"https://[^\n]*\$\{?GITHUB_TOKEN\}?@github\.com"),
        )

    def test_gitignore_blocks_runtime_secrets(self):
        ignore = (ROOT / ".gitignore").read_text()
        for marker in [".env", "/backups", "*.key", "*.pem", "*.dump"]:
            self.assertIn(marker, ignore)


if __name__ == "__main__":
    unittest.main()
