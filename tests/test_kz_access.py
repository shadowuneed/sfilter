from __future__ import annotations

import unittest

from app.services.kz_access import country_from_payload


class KzAccessTests(unittest.TestCase):
    def test_country_from_payload_accepts_country(self) -> None:
        self.assertEqual(country_from_payload({"country": "kz"}), "KZ")

    def test_country_from_payload_accepts_country_code_alias(self) -> None:
        self.assertEqual(country_from_payload({"countryCode": "KZ"}), "KZ")
        self.assertEqual(country_from_payload({"country_code": "kz"}), "KZ")

    def test_country_from_payload_returns_none_when_missing(self) -> None:
        self.assertIsNone(country_from_payload({"ip": "203.0.113.10"}))


if __name__ == "__main__":
    unittest.main()
