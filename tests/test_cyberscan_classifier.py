from __future__ import annotations

import unittest

from app.config import Settings
from app.services.cyberscan_classifier import CyberScanClassifier
from app.services.evidence import EvidenceResult


class CyberScanClassifierTests(unittest.TestCase):
    def test_bundled_cyberscan_model_predicts_from_content_features(self) -> None:
        classifier = CyberScanClassifier(Settings())
        evidence = EvidenceResult(
            requested_url="https://login-bonus.example",
            final_url="https://login-bonus.example",
            domain="login-bonus.example",
            status_code=200,
            active=True,
        )
        content_ai = {
            "features": {
                "url_length": 27,
                "num_dots": 1,
                "num_hyphens": 1,
                "num_digits": 0,
                "has_ip": 0,
                "subdomain_count": 0,
                "suspicious_tld": 0,
                "path_length": 0,
                "num_query_params": 0,
                "special_chars_count": 0,
                "has_dns": 1,
                "has_mx": 0,
                "num_ip_addresses": 1,
                "num_ns_servers": 0,
                "domain_age_days": 3,
                "is_private_whois": 0,
                "days_to_expiry": 90,
                "ssl_valid": 1,
                "ssl_days_until_expiry": 60,
                "num_forms": 1,
                "num_password_forms": 1,
                "num_external_scripts": 2,
                "num_external_resources": 3,
                "scam_word_count": 4,
                "has_brand_impersonation": 1,
                "num_suspicious_patterns": 2,
                "num_iframes": 1,
                "has_meta_refresh": 0,
                "has_redirect": 1,
                "num_hidden_elements": 3,
                "num_external_links": 7,
                "casino_keywords_count": 5,
                "has_casino_in_url": 1,
                "casino_confidence_score": 0.8,
            }
        }

        result = classifier.classify("https://login-bonus.example", evidence, content_ai)

        self.assertTrue(result["available"], result.get("error"))
        self.assertEqual(result["feature_count"], 34)
        self.assertIn(result["label"], {"legit", "suspicious"})
        self.assertIn("suspicious_probability", result)
        self.assertGreaterEqual(result["suspicious_probability"], 0)


if __name__ == "__main__":
    unittest.main()
