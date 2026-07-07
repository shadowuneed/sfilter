from __future__ import annotations

import asyncio
import unittest

from app.config import Settings
from app.services.evidence import EvidenceResult
from app.services.investigator import Candidate, Investigator
from app.services.screenshots import ScreenshotResult


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

    def test_unwraps_google_search_redirect_to_direct_candidate(self) -> None:
        candidate = self.investigator._candidate_from_item(
            {
                "url": "https://www.google.com/url?q=https%3A%2F%2Fpinco4.aktif.kz%2F&sa=U",
                "category": "suspicious",
                "search_query": "online casino Kazakhstan",
            },
            default_sources=[],
        )

        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.domain, "pinco4.aktif.kz")
        self.assertEqual(candidate.url, "https://pinco4.aktif.kz")
        self.assertEqual(candidate.category, "casino")

    def test_grounding_source_extracts_direct_site_not_review_platform(self) -> None:
        candidates = self.investigator._candidates_from_grounding_sources(
            [
                {
                    "url": "https://www.scamadviser.com/check-website/top.45minut.kz",
                    "title": "top.45minut.kz online casino Kazakhstan",
                }
            ],
            "online casino Kazakhstan",
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].domain, "top.45minut.kz")
        self.assertEqual(candidates[0].url, "https://top.45minut.kz")
        self.assertEqual(candidates[0].category, "casino")

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

    def test_known_domains_are_dropped_from_auto_discovery(self) -> None:
        class FakeDb:
            def __init__(self) -> None:
                self.logs = []

            def known_domains(self) -> set[str]:
                return {"mycasino.kz"}

            def add_log(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
                self.logs.append((args, kwargs))

        class FakeGemini:
            available = False

        self.investigator.settings = Settings(osint_feeds_enabled=False, osint_candidate_pool_size=10)
        self.investigator.db = FakeDb()
        self.investigator.gemini = FakeGemini()

        candidates = asyncio.run(self.investigator._discover_candidates(1, "mycasino.kz", 1))

        self.assertFalse(any(candidate.domain == "mycasino.kz" for candidate in candidates))
        self.assertEqual(candidates, [])
        last_log = self.investigator.db.logs[-1][0]
        self.assertEqual(last_log[3]["skipped_known"], 1)

    def test_bootstrap_adds_verification_candidates_when_discovery_is_empty(self) -> None:
        self.investigator.settings = Settings(seed_queries=["казино зеркало рабочий вход"])

        candidates = self.investigator._discover_from_bootstrap(None, 3)

        self.assertEqual(len(candidates), 3)
        self.assertTrue(all(candidate.why.startswith("Bootstrap-кандидат") for candidate in candidates))

    def test_build_finding_skips_active_http_site_without_html_content(self) -> None:
        class FakeDb:
            def __init__(self) -> None:
                self.logs = []

            def add_log(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
                self.logs.append((args, kwargs))

        class FakeEvidence:
            async def collect(self, url: str, run_id: int) -> EvidenceResult:
                return EvidenceResult(
                    requested_url=url,
                    final_url="http://no-ssl.example",
                    domain="no-ssl.example",
                    status_code=200,
                    active=True,
                    response_time_ms=95,
                    page_size_bytes=512,
                    dns={"records": ["203.0.113.10"], "mx_records": []},
                    tls={"valid": False, "error": "no certificate"},
                )

        class FakeScreenshots:
            async def capture(self, url: str, run_id: int, **kwargs) -> ScreenshotResult:  # noqa: ANN003
                return ScreenshotResult(path=None, error="browser blocked")

        class FakeContentAI:
            def analyze(self, url: str, evidence: EvidenceResult) -> dict:
                return {"signals": [], "risk_delta": 0}

        class FakeClassifier:
            def classify(self, url: str, evidence: EvidenceResult, content_ai: dict | None = None) -> dict:
                return {"available": False}

        self.investigator.settings = Settings()
        self.investigator.db = FakeDb()
        self.investigator.evidence = FakeEvidence()
        self.investigator.screenshots = FakeScreenshots()
        self.investigator.content_ai = FakeContentAI()
        self.investigator.cyberscan = FakeClassifier()
        self.investigator.ml = FakeClassifier()

        finding = asyncio.run(
            self.investigator._build_finding(
                1,
                Candidate(
                    url="https://no-ssl.example",
                    domain="no-ssl.example",
                    category="suspicious",
                    why="unit test",
                ),
                None,
                True,
            )
        )

        self.assertTrue(finding["_skip"])
        self.assertEqual(finding["status_code"], 200)
        self.assertIn("пустышку", finding["_skip_reason"])


if __name__ == "__main__":
    unittest.main()
