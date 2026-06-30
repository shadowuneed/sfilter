from __future__ import annotations

import unittest

from app.services.domains import extract_domain, find_domains, registered_domain, suspicious_tld


class DomainTests(unittest.TestCase):
    def test_extract_domain_normalizes_host(self) -> None:
        self.assertEqual(extract_domain("https://www.Example.COM:443/path?q=1"), "example.com")

    def test_registered_domain_handles_second_level_suffix(self) -> None:
        self.assertEqual(registered_domain("login.payments.example.com.kz"), "example.com.kz")

    def test_find_domains_skips_ip_addresses(self) -> None:
        self.assertEqual(find_domains("open 127.0.0.1 and casino-test.xyz"), ["casino-test.xyz"])

    def test_suspicious_tld_detects_common_throwaway_zone(self) -> None:
        self.assertTrue(suspicious_tld("mirror-entry.lol"))


if __name__ == "__main__":
    unittest.main()
