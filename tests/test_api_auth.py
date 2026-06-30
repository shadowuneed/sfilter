from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from app import main


def set_auth(*, required: bool = True, token: str | None = "test-secret") -> None:
    object.__setattr__(main.settings, "auth_required", required)
    object.__setattr__(main.settings, "admin_token", token)


class ApiAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        set_auth(required=True, token="test-secret")
        self.client = TestClient(main.app)

    def tearDown(self) -> None:
        set_auth(required=True, token=None)

    def test_health_is_public(self) -> None:
        response = self.client.get("/api/health")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["auth_required"])

    def test_protected_api_rejects_missing_token(self) -> None:
        response = self.client.get("/api/runs")

        self.assertEqual(response.status_code, 401)

    def test_protected_api_accepts_bearer_token(self) -> None:
        response = self.client.get("/api/runs", headers={"Authorization": "Bearer test-secret"})

        self.assertEqual(response.status_code, 200)
        self.assertIn("runs", response.json())

    def test_missing_server_token_blocks_protected_api(self) -> None:
        set_auth(required=True, token=None)

        response = self.client.get("/api/runs", headers={"Authorization": "Bearer anything"})

        self.assertEqual(response.status_code, 503)


if __name__ == "__main__":
    unittest.main()
