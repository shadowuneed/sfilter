from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from app.config import _bool_env, _optional_env, _split_env, get_settings


class ConfigTests(unittest.TestCase):
    def test_split_env_accepts_commas_semicolons_and_newlines(self) -> None:
        with patch.dict(os.environ, {"ITEMS": "one, two;three\nfour"}, clear=False):
            self.assertEqual(_split_env("ITEMS"), ["one", "two", "three", "four"])

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


if __name__ == "__main__":
    unittest.main()
