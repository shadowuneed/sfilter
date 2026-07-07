from __future__ import annotations

import unittest

from app.services.evidence import score_finding
from app.services.evidence import EvidenceResult
from app.services.investigator import Investigator


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

    def test_technical_signals_use_ssl_as_risk_metadata_not_legitimacy(self) -> None:
        evidence = EvidenceResult(
            requested_url="https://fresh-risk.example",
            final_url="https://fresh-risk.example",
            domain="fresh-risk.example",
            status_code=200,
            active=True,
            dns={"records": ["203.0.113.10"], "mx_records": []},
            tls={"valid": True, "issuer": "Let's Encrypt", "expires_in_days": 90},
            domain_info={"age_days": 4, "registrar": "Example Privacy Registrar", "privacy": True},
        )

        delta, reasons = Investigator._technical_risk_signals(evidence)

        self.assertGreater(delta, 0)
        self.assertTrue(any("молодой" in reason.lower() for reason in reasons))
        self.assertFalse(any("легитим" in reason.lower() for reason in reasons))

    def test_confident_legit_ml_reduces_risk(self) -> None:
        self.assertLess(
            Investigator._ml_risk_delta({"available": True, "label": "legit", "confidence": 0.86}),
            0,
        )

    def test_suspicious_ml_increases_risk(self) -> None:
        self.assertGreater(
            Investigator._ml_risk_delta({"available": True, "label": "phishing", "confidence": 0.86}),
            0,
        )

    def test_trusted_domain_policy_caps_non_phishing_risk(self) -> None:
        capped = Investigator._apply_policy_caps(
            95,
            "online_casino",
            {
                "domain_policy": {"trusted": True, "reason": "официальный домен Kaspi"},
                "credential_risk": False,
            },
        )

        self.assertLessEqual(capped, 35)

    def test_sports_betting_review_is_capped_below_illegal_verdict(self) -> None:
        capped = Investigator._apply_policy_caps(
            95,
            "sports_betting_review",
            {"domain_policy": {"trusted": False}, "credential_risk": False},
        )

        self.assertLessEqual(capped, 72)


if __name__ == "__main__":
    unittest.main()
