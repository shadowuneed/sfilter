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
                    <h1>Online casino bonus free spins 1xbet</h1>
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

        self.assertEqual(result["category_hint"], "casino")
        self.assertGreaterEqual(result["features"]["casino_keywords_count"], 3)
        self.assertEqual(result["features"]["num_password_forms"], 1)
        self.assertEqual(result["features"]["has_meta_refresh"], 1)
        self.assertTrue(result["signals"])


if __name__ == "__main__":
    unittest.main()
