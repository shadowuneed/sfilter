from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.config import Settings
from app.services.content_intelligence import ContentIntelligence
from app.services.evidence import EvidenceResult


class ContentIntelligenceTests(unittest.TestCase):
    def test_detects_casino_and_form_signals(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            evidence_dir = Path(temp_dir)
            html_path = evidence_dir / "run_1_casino.html"
            html_path.write_text(
                """
                <html>
                  <head><meta http-equiv="refresh" content="0;url=/go"></head>
                  <body>
                    <h1>Online casino slots roulette free spins 1xbet</h1>
                    <iframe src="https://tracker.example/frame"></iframe>
                    <form action="https://pay.example/login">
                      <input type="password" name="password">
                      <input type="hidden" name="token">
                    </form>
                  </body>
                </html>
                """,
                encoding="utf-8",
            )
            evidence = EvidenceResult(
                requested_url="https://casino-bonus.example",
                final_url="https://casino-bonus.example",
                domain="casino-bonus.example",
                html_path=f"evidence/{html_path.name}",
                dns={"records": ["203.0.113.10"], "mx_records": []},
                tls={"valid": True, "expires_in_days": 30},
                domain_info={"age_days": 5},
            )

            result = ContentIntelligence(Settings(evidence_dir=evidence_dir)).analyze(evidence.final_url or "", evidence)

        self.assertEqual(result["category_hint"], "online_casino")
        self.assertGreaterEqual(result["features"]["casino_keywords_count"], 3)
        self.assertEqual(result["features"]["num_password_forms"], 1)
        self.assertEqual(result["features"]["has_meta_refresh"], 1)
        self.assertTrue(result["signals"])

    def test_official_kaspi_domain_is_not_casino_or_phishing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            evidence_dir = Path(temp_dir)
            html_path = evidence_dir / "run_1_kaspi.html"
            html_path.write_text(
                """
                <html>
                  <body>
                    <h1>Kaspi.kz</h1>
                    <p>Официальный сервис банка: платежи, переводы, магазин, login для клиентов.</p>
                    <form action="/login"><input type="password" name="password"></form>
                  </body>
                </html>
                """,
                encoding="utf-8",
            )
            evidence = EvidenceResult(
                requested_url="https://kaspi.kz",
                final_url="https://kaspi.kz",
                domain="kaspi.kz",
                html_path=f"evidence/{html_path.name}",
                page_size_bytes=8000,
                dns={"records": ["203.0.113.10"], "mx_records": ["mail.kaspi.kz"]},
                tls={"valid": True, "expires_in_days": 90},
                domain_info={"age_days": 7000},
            )

            result = ContentIntelligence(Settings(evidence_dir=evidence_dir)).analyze(evidence.final_url or "", evidence)

        self.assertEqual(result["category_hint"], "legit")
        self.assertTrue(result["domain_policy"]["trusted"])
        self.assertNotEqual(result["category_hint"], "online_casino")

    def test_fake_kaspi_login_domain_is_phishing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            evidence_dir = Path(temp_dir)
            html_path = evidence_dir / "run_1_fake_kaspi.html"
            html_path.write_text(
                """
                <html>
                  <body>
                    <h1>Kaspi verification</h1>
                    <p>Подтвердите аккаунт Kaspi и карту.</p>
                    <form action="https://collector.example/submit">
                      <input type="password" name="password">
                      <input name="card">
                    </form>
                  </body>
                </html>
                """,
                encoding="utf-8",
            )
            evidence = EvidenceResult(
                requested_url="https://kaspi-login.example",
                final_url="https://kaspi-login.example",
                domain="kaspi-login.example",
                html_path=f"evidence/{html_path.name}",
                page_size_bytes=9000,
                dns={"records": ["203.0.113.11"], "mx_records": []},
                tls={"valid": True, "expires_in_days": 30},
                domain_info={"age_days": 2},
            )

            result = ContentIntelligence(Settings(evidence_dir=evidence_dir)).analyze(evidence.final_url or "", evidence)

        self.assertEqual(result["category_hint"], "phishing")
        self.assertIn("kaspi", result["brand_impersonation"])

    def test_betting_without_casino_product_is_separate_review_category(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            evidence_dir = Path(temp_dir)
            html_path = evidence_dir / "run_1_bookmaker.html"
            html_path.write_text(
                """
                <html><body>
                  <h1>Sports betting bookmaker</h1>
                  <p>Линия ставок, коэффициенты, экспресс и ставки на спорт.</p>
                </body></html>
                """,
                encoding="utf-8",
            )
            evidence = EvidenceResult(
                requested_url="https://bookmaker-review.example",
                final_url="https://bookmaker-review.example",
                domain="bookmaker-review.example",
                html_path=f"evidence/{html_path.name}",
                page_size_bytes=9000,
            )

            result = ContentIntelligence(Settings(evidence_dir=evidence_dir)).analyze(evidence.final_url or "", evidence)

        self.assertEqual(result["category_hint"], "sports_betting_review")
        self.assertNotEqual(result["category_hint"], "online_casino")

    def test_empty_or_parked_site_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            evidence_dir = Path(temp_dir)
            html_path = evidence_dir / "run_1_parked.html"
            html_path.write_text("<html><body>Domain is for sale</body></html>", encoding="utf-8")
            evidence = EvidenceResult(
                requested_url="https://parked.example",
                final_url="https://parked.example",
                domain="parked.example",
                html_path=f"evidence/{html_path.name}",
                page_size_bytes=1200,
            )

            result = ContentIntelligence(Settings(evidence_dir=evidence_dir)).analyze(evidence.final_url or "", evidence)

        self.assertEqual(result["category_hint"], "empty_or_parked")
        self.assertTrue(result["site_quality"]["is_empty_or_parked"])

    def test_blocked_page_is_detected_even_with_casino_words(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            evidence_dir = Path(temp_dir)
            html_path = evidence_dir / "run_1_blocked.html"
            html_path.write_text(
                "<html><body><h1>Access to this site is blocked</h1><p>casino slots roulette</p></body></html>",
                encoding="utf-8",
            )
            evidence = EvidenceResult(
                requested_url="https://blocked-casino.example",
                final_url="https://blocked-casino.example",
                domain="blocked-casino.example",
                html_path=f"evidence/{html_path.name}",
                page_size_bytes=3000,
            )

            result = ContentIntelligence(Settings(evidence_dir=evidence_dir)).analyze(evidence.final_url or "", evidence)

        self.assertEqual(result["category_hint"], "blocked_or_unreachable")
        self.assertTrue(result["site_quality"]["is_blocked_or_restricted"])


if __name__ == "__main__":
    unittest.main()
