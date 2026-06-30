from __future__ import annotations

import unittest

from app.services.evidence import score_finding


class ScoringTests(unittest.TestCase):
    def test_pipe_separated_category_counts_as_casino(self) -> None:
        risk, verdict, reasons = score_finding(
            category="betting|gambling",
            active=True,
            status_code=200,
            keyword_hits=["bonus", "casino"],
            has_sources=True,
            domain="mirror-entry.lol",
            mirror_group="brand",
        )

        self.assertGreaterEqual(risk, 80)
        self.assertEqual(verdict, "suspected_fraud_or_illegal")
        self.assertTrue(any("казино" in reason.lower() for reason in reasons))

    def test_low_signal_inactive_domain_stays_low(self) -> None:
        risk, verdict, reasons = score_finding(
            category="unknown",
            active=False,
            status_code=None,
            keyword_hits=[],
            has_sources=False,
            domain="example.org",
            mirror_group=None,
        )

        self.assertLess(risk, 40)
        self.assertEqual(verdict, "low_signal")
        self.assertEqual(reasons, [])


if __name__ == "__main__":
    unittest.main()
