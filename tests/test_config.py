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


if __name__ == "__main__":
    unittest.main()
