from __future__ import annotations

import unittest

from app.services.domains import (
    extract_domain,
    find_domains,
    is_candidate_domain,
    is_candidate_url,
    is_public_domain,
    registered_domain,
    suspicious_tld,
)


class DomainTests(unittest.TestCase):
    def test_extract_domain_normalizes_host(self) -> None:
        self.assertEqual(extract_domain("https://www.Example.COM:443/path?q=1"), "example.com")

    def test_registered_domain_handles_second_level_suffix(self) -> None:
        self.assertEqual(registered_domain("login.payments.example.com.kz"), "example.com.kz")

    def test_find_domains_skips_ip_addresses(self) -> None:
        self.assertEqual(find_domains("open 127.0.0.1 and casino-test.xyz"), ["casino-test.xyz"])

    def test_suspicious_tld_detects_common_throwaway_zone(self) -> None:
        self.assertTrue(suspicious_tld("mirror-entry.lol"))

    def test_google_grounding_redirect_is_not_candidate(self) -> None:
        url = "https://vertexaisearch.cloud.google.com/grounding-api-redirect/AUZIYQFQ5a8vLPgWCmaJ1NFNqsqdmXsf0"

        self.assertTrue(is_public_domain("vertexaisearch.cloud.google.com"))
        self.assertFalse(is_candidate_domain("vertexaisearch.cloud.google.com"))
        self.assertFalse(is_candidate_url(url))

    def test_regular_suspicious_domain_is_candidate(self) -> None:
        self.assertTrue(is_candidate_domain("mirror-entry.lol"))
        self.assertTrue(is_candidate_url("https://mirror-entry.lol/login"))


if __name__ == "__main__":
    unittest.main()
