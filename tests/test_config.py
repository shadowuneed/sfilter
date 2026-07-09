from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from app.config import _api_keys_from_env, _bool_env, _first_env, _optional_env, _split_env, get_settings


class ConfigTests(unittest.TestCase):
    def test_split_env_accepts_commas_semicolons_and_newlines(self) -> None:
        with patch.dict(os.environ, {"ITEMS": "one, two;three\nfour"}, clear=False):
            self.assertEqual(_split_env("ITEMS"), ["one", "two", "three", "four"])

    def test_split_env_accepts_json_list(self) -> None:
        with patch.dict(os.environ, {"ITEMS": '["one", "two"]'}, clear=False):
            self.assertEqual(_split_env("ITEMS"), ["one", "two"])

    def test_api_keys_are_cleaned_from_render_style_values(self) -> None:
        with patch.dict(
            os.environ,
            {
                "GEMINI_API_KEYS": '"Bearer key-one", key-two',
                "GEMINI_API_KEY": "key-two",
                "GOOGLE_API_KEY": "Authorization: Bearer key-three",
            },
            clear=False,
        ):
            self.assertEqual(
                _api_keys_from_env(("GEMINI_API_KEYS", "GEMINI_API_KEY", "GOOGLE_API_KEY")),
                ["key-one", "key-two", "key-three"],
            )

    def test_optional_env_treats_blank_as_none(self) -> None:
        with patch.dict(os.environ, {"ADMIN_TOKEN": "   "}, clear=False):
            self.assertIsNone(_optional_env("ADMIN_TOKEN"))

    def test_bool_env_parses_common_true_values(self) -> None:
        with patch.dict(os.environ, {"AUTH_REQUIRED": "yes"}, clear=False):
            self.assertTrue(_bool_env("AUTH_REQUIRED", False))

    def test_database_url_is_read_from_environment(self) -> None:
        url = "postgresql://user:secret@db.example.com:5432/postgres"
        with patch.dict(os.environ, {"DATABASE_URL": url}, clear=False):
            self.assertEqual(get_settings().database_url, url)

    @patch("app.config._load_dotenv", lambda: None)
    def test_require_postgres_blocks_sqlite_fallback(self) -> None:
        with patch.dict(os.environ, {"REQUIRE_POSTGRES": "true"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "DATABASE_URL"):
                get_settings()

    def test_kz_proxy_alias_is_read(self) -> None:
        with patch.dict(os.environ, {"KZ_HTTP_PROXY": "socks5://proxy.kz:1080"}, clear=False):
            name, value = _first_env(("KZ_PROXY_URL", "KZ_HTTP_PROXY", "KZ_HTTPS_PROXY", "KZ_PROXY"))

        self.assertEqual(name, "KZ_HTTP_PROXY")
        self.assertEqual(value, "socks5://proxy.kz:1080")

    @patch("app.config._load_dotenv", lambda: None)
    def test_kz_proxy_is_soft_by_default(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("REQUIRE_KZ_PROXY", None)
            self.assertFalse(get_settings().require_kz_proxy)

    @patch("app.config._load_dotenv", lambda: None)
    def test_scan_tuning_is_read_from_environment(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SCAN_CONCURRENCY": "4",
                "CANDIDATE_TIMEOUT_SECONDS": "30",
                "SCREENSHOT_TIMEOUT_SECONDS": "8",
                "SCREENSHOT_SETTLE_MS": "250",
                "SCREENSHOT_CONCURRENCY": "2",
                "BROWSER_SCREENSHOTS_ENABLED": "false",
                "SCREENSHOT_FALLBACK_ENABLED": "true",
                "RESUME_ACTIVE_RUNS": "true",
                "FAST_EVIDENCE_MODE": "true",
            },
            clear=False,
        ):
            settings = get_settings()

        self.assertEqual(settings.scan_concurrency, 4)
        self.assertEqual(settings.candidate_timeout_seconds, 30)
        self.assertEqual(settings.screenshot_timeout_seconds, 8)
        self.assertEqual(settings.screenshot_settle_ms, 250)
        self.assertEqual(settings.screenshot_concurrency, 2)
        self.assertFalse(settings.browser_screenshots_enabled)
        self.assertTrue(settings.screenshot_fallback_enabled)
        self.assertTrue(settings.resume_active_runs)
        self.assertTrue(settings.fast_evidence_mode)

    @patch("app.config._load_dotenv", lambda: None)
    def test_user_search_defaults_avoid_gemini_fallback(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SEARCH_PAGES_ENABLED", None)
            os.environ.pop("GEMINI_USER_SEARCH_FALLBACK", None)
            settings = get_settings()

        self.assertTrue(settings.search_pages_enabled)
        self.assertFalse(settings.gemini_user_search_fallback)

    @patch("app.config._load_dotenv", lambda: None)
    def test_search_page_delay_is_read_from_environment(self) -> None:
        with patch.dict(os.environ, {"SEARCH_PAGE_DELAY_SECONDS": "1.5"}, clear=False):
            settings = get_settings()

        self.assertEqual(settings.search_page_delay_seconds, 1.5)

    @patch("app.config._load_dotenv", lambda: None)
    def test_candidate_limit_has_production_floor(self) -> None:
        with patch.dict(os.environ, {"MAX_CANDIDATES_PER_RUN": "15"}, clear=True):
            settings = get_settings()

        self.assertEqual(settings.max_candidates_per_run, 15000)


if __name__ == "__main__":
    unittest.main()
