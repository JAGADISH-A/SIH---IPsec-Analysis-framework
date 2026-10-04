"""Tests for reading backend configuration from a gitignored ``.env``.

The properties worth pinning are not the parsing trivia. They are that a real
environment variable beats the file, that the file cannot configure anything
outside the AI service, and that no value is ever echoed.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from correlation.ai.dotenv import (
    AI_ENV_KEYS,
    load_backend_env,
    parse_env_file,
)


def write(root: Path, text: str) -> Path:
    path = root / ".env"
    path.write_text(text, encoding="utf-8")
    return path


class TestParsing(unittest.TestCase):
    def test_comments_blanks_and_export_are_handled(self):
        parsed = parse_env_file(
            "\n"
            "# a comment\n"
            "  # an indented comment\n"
            "export A=1\n"
            "B=2\n"
        )
        self.assertEqual(parsed, {"A": "1", "B": "2"})

    def test_quotes_are_stripped_and_inner_hash_is_kept(self):
        parsed = parse_env_file(
            'A="two"\n' "B='three'\n" "C=has # a value fragment\n"
        )
        self.assertEqual(parsed, {"A": "two", "B": "three", "C": "has # a value fragment"})

    def test_an_empty_value_is_kept_but_meaningless(self):
        self.assertEqual(parse_env_file("A=\n"), {"A": ""})

    def test_a_line_without_equals_is_skipped_not_fatal(self):
        self.assertEqual(parse_env_file("garbage\nA=1\n"), {"A": "1"})

    def test_later_assignment_wins(self):
        self.assertEqual(parse_env_file("A=1\nA=2\n"), {"A": "2"})


class TestLoading(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_allowed_keys_are_applied(self):
        write(self.root, "GEMINI_API_KEY=secret\nGEMINI_MODEL=gemini-3.8-flash\n")
        env = {}
        applied = load_backend_env(root=self.root, environ=env)
        self.assertEqual(env["GEMINI_API_KEY"], "secret")
        self.assertEqual(env["GEMINI_MODEL"], "gemini-3.8-flash")
        self.assertIn("GEMINI_API_KEY", applied)

    def test_a_real_environment_variable_wins_over_the_file(self):
        write(self.root, "GEMINI_MODEL=from-file\n")
        env = {"GEMINI_MODEL": "from-environment"}
        load_backend_env(root=self.root, environ=env)
        self.assertEqual(env["GEMINI_MODEL"], "from-environment")

    def test_a_blank_file_value_does_not_erase_a_real_key(self):
        write(self.root, "GEMINI_API_KEY=\n")
        env = {"GEMINI_API_KEY": "real-key"}
        load_backend_env(root=self.root, environ=env)
        self.assertEqual(env["GEMINI_API_KEY"], "real-key")

    def test_a_blank_file_value_configures_nothing(self):
        write(self.root, "GEMINI_API_KEY=\n")
        env = {}
        applied = load_backend_env(root=self.root, environ=env)
        self.assertNotIn("GEMINI_API_KEY", env)
        self.assertEqual(applied, [])

    def test_keys_outside_the_ai_service_are_not_applied(self):
        write(
            self.root,
            "SIHAPI_PORT=9999\n"
            "GEMINI_MODEL=m\n"
            "GEMINI_UNLISTED_SECRET=leak\n",
        )
        env = {}
        load_backend_env(root=self.root, environ=env)
        self.assertNotIn("SIHAPI_PORT", env)
        self.assertNotIn("GEMINI_UNLISTED_SECRET", env)
        self.assertIn("GEMINI_MODEL", env)

    def test_the_closed_key_list_cannot_be_widened_by_prefix(self):
        for key in AI_ENV_KEYS:
            self.assertNotIn("*", key)
            self.assertTrue(key.isupper())

    def test_a_missing_file_is_not_an_error(self):
        empty = self.root / "nested"
        empty.mkdir()
        env = {}
        self.assertEqual(load_backend_env(root=empty / "deeper", environ=env), [])
        self.assertEqual(env, {})

    def test_only_key_names_are_returned_never_values(self):
        write(self.root, "GEMINI_API_KEY=super-secret-value\n")
        env = {}
        applied = load_backend_env(root=self.root, environ=env)
        self.assertNotIn("super-secret-value", " ".join(applied))

    def test_the_search_stops_at_the_first_env_file(self):
        write(self.root, "GEMINI_MODEL=outer\n")
        inner = self.root / "a"
        inner.mkdir()
        write(inner, "GEMINI_MODEL=inner\n")
        env = {}
        load_backend_env(root=inner, environ=env)
        self.assertEqual(env["GEMINI_MODEL"], "inner")


class TestRepositoryEnvFile(unittest.TestCase):
    """The committed repository state must never carry a usable key."""

    def test_the_repo_env_file_has_no_populated_gemini_key(self):
        path = Path(__file__).resolve().parents[1] / ".env"
        if not path.is_file():
            self.skipTest("no local .env in this checkout")
        values = parse_env_file(path.read_text(encoding="utf-8"))
        self.assertEqual(
            values.get("GEMINI_API_KEY", ""),
            "",
            "the local .env must not contain a real key",
        )

    def test_the_env_file_is_gitignored(self):
        import subprocess

        repo = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            ["git", "check-ignore", ".env"],
            cwd=repo,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.returncode, 0, ".env must be gitignored or the key can leak"
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()