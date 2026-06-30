from __future__ import annotations

import os
import unittest

from fastapi.testclient import TestClient

os.environ["DATABASE_URL"] = ""
os.environ.setdefault("DATABASE_PATH", "data/test_api_auth.db")

from app import main


def set_auth(*, required: bool = True, token: str | None = "test-secret") -> None:
    object.__setattr__(main.settings, "auth_required", required)
    object.__setattr__(main.settings, "admin_token", token)


def set_kz_proxy(*, required: bool = True, url: str | None = "http://proxy.kz:8080") -> None:
    object.__setattr__(main.settings, "require_kz_proxy", required)
    object.__setattr__(main.settings, "kz_proxy_url", url)


class ApiAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        set_auth(required=True, token="test-secret")
        set_kz_proxy(required=True, url="http://proxy.kz:8080")
        self.client = TestClient(main.app)

    def tearDown(self) -> None:
        set_auth(required=True, token=None)
        set_kz_proxy(required=True, url=None)

    def test_health_is_public(self) -> None:
        response = self.client.get("/api/health")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["auth_required"])

    def test_protected_api_rejects_missing_token(self) -> None:
        response = self.client.get("/api/runs")

        self.assertEqual(response.status_code, 401)

    def test_manual_check_rejects_missing_token(self) -> None:
        response = self.client.post("/api/manual-check", json={"target": "example.com"})

        self.assertEqual(response.status_code, 401)

    def test_protected_api_accepts_bearer_token(self) -> None:
        response = self.client.get("/api/runs", headers={"Authorization": "Bearer test-secret"})

        self.assertEqual(response.status_code, 200)
        self.assertIn("runs", response.json())

    def test_missing_server_token_blocks_protected_api(self) -> None:
        set_auth(required=True, token=None)

        response = self.client.get("/api/runs", headers={"Authorization": "Bearer anything"})

        self.assertEqual(response.status_code, 503)

    def test_missing_kz_proxy_blocks_launch(self) -> None:
        set_kz_proxy(required=True, url=None)

        response = self.client.post(
            "/api/runs",
            headers={"Authorization": "Bearer test-secret"},
            json={"max_candidates": 1, "take_screenshots": False},
        )

        self.assertEqual(response.status_code, 503)
        self.assertIn("Kazakhstan proxy is required", response.text)

    def test_missing_kz_proxy_is_allowed_when_not_required(self) -> None:
        set_kz_proxy(required=False, url=None)

        main._ensure_kz_proxy_ready()


if __name__ == "__main__":
    unittest.main()
