from __future__ import annotations

import unittest

from app.services.investigator import Investigator


GROUNDING_REDIRECT = (
    "https://vertexaisearch.cloud.google.com/grounding-api-redirect/"
    "AUZIYQFQ5a8vLPgWCmaJ1NFNqsqdmXsf0-g_DszycTTnICT4kppcu8kDJNV7YIS7Wr_OoiRu5iDXFm2ryilKBIYmoI5Z"
)


class InvestigatorCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.investigator = object.__new__(Investigator)

    def test_rejects_google_grounding_redirect_as_candidate(self) -> None:
        candidate = self.investigator._candidate_from_item(
            {
                "url": GROUNDING_REDIRECT,
                "domain": "vertexaisearch.cloud.google.com",
                "category": "suspicious",
            },
            default_sources=[],
        )

        self.assertIsNone(candidate)

    def test_uses_real_domain_when_url_is_grounding_redirect(self) -> None:
        candidate = self.investigator._candidate_from_item(
            {
                "url": GROUNDING_REDIRECT,
                "domain": "mirror-entry.lol",
                "category": "casino",
                "source_urls": [GROUNDING_REDIRECT, "https://public-report.kz/case"],
            },
            default_sources=[],
        )

        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.domain, "mirror-entry.lol")
        self.assertEqual(candidate.url, "https://mirror-entry.lol")
        self.assertEqual(candidate.source_urls, ["https://public-report.kz/case"])

    def test_feed_parser_extracts_csv_and_hosts_domains(self) -> None:
        csv_tokens = self.investigator._feed_tokens(
            '# comment\n"2026-06-30","https://bad-login.example/home.php","online"\n',
            "csv",
        )
        hosts_tokens = self.investigator._feed_tokens(
            "0.0.0.0 casino-mirror.example\n||bonus-slot.example^\n",
            "hosts_file",
        )

        self.assertIn("https://bad-login.example/home.php", csv_tokens)
        self.assertNotIn("home.php", csv_tokens)
        self.assertIn("casino-mirror.example", hosts_tokens)
        self.assertIn("bonus-slot.example", hosts_tokens)


if __name__ == "__main__":
    unittest.main()
