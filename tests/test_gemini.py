from __future__ import annotations

import unittest

from app.config import Settings
from app.services.gemini import GeminiClient


def client_for(keys: list[str]) -> GeminiClient:
    return GeminiClient(Settings(gemini_api_keys=keys), db=None)  # type: ignore[arg-type]


class GeminiConfigTests(unittest.TestCase):
    def test_non_aiza_auth_key_shape_is_allowed(self) -> None:
        client = client_for(["gsk_live_abcdefghijklmnopqrstuvwxyz1234567890"])

        self.assertTrue(client.key_format_ok)
        self.assertEqual(client.key_format_warnings, [])

    def test_wrapped_key_shape_warns(self) -> None:
        client = client_for(['"Bearer gsk_live_abcdefghijklmnopqrstuvwxyz1234567890"'])

        self.assertFalse(client.key_format_ok)
        self.assertTrue(any("quotes" in warning for warning in client.key_format_warnings))
        self.assertTrue(any("Bearer" in warning for warning in client.key_format_warnings))


if __name__ == "__main__":
    unittest.main()
