from __future__ import annotations

import unittest

from app.config import Settings
from app.services.evidence import EvidenceResult
from app.services.ml_classifier import DomainMLClassifier


class DomainMLClassifierTests(unittest.TestCase):
    def test_bundled_model_predicts_from_evidence(self) -> None:
        classifier = DomainMLClassifier(Settings())
        evidence = EvidenceResult(
            requested_url="https://example.com",
            final_url="https://example.com/login",
            domain="example.com",
            status_code=200,
            active=True,
            title="Secure account login",
            description="Verify account password",
            text_excerpt="login verify account password",
            response_time_ms=120,
            page_size_bytes=4096,
            redirect_count=0,
            dns={"records": ["93.184.216.34"], "mx_records": []},
            tls={"valid": True, "issuer": "Let's Encrypt", "subject": "example.com", "expires_in_days": 80},
            domain_info={"age_days": 1200, "registrar": "Example Registrar"},
        )

        result = classifier.classify("https://example.com/login", evidence)

        self.assertTrue(result["available"])
        self.assertEqual(result["feature_count"], 34)
        self.assertIn(result["label"], classifier.status().classes)
        self.assertGreaterEqual(result["confidence"], 0)
        self.assertIn("probabilities", result)


if __name__ == "__main__":
    unittest.main()
