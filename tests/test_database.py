from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app.database import Database


class DatabaseBackendTests(unittest.TestCase):
    def test_postgres_url_selects_postgres_backend_and_redacts_label(self) -> None:
        db = Database("postgres://user:secret@db.example.com:5432/appdb")

        self.assertEqual(db.backend, "postgres")
        self.assertIn("[redacted]@db.example.com:5432", db.label)
        self.assertNotIn("secret", db.label)

    def test_path_selects_sqlite_backend(self) -> None:
        db = Database("data/test.db")

        self.assertEqual(db.backend, "sqlite")
        self.assertEqual(db.label, "data\\test.db" if "\\" in db.label else "data/test.db")

    def test_supabase_url_gets_required_sslmode(self) -> None:
        db = Database("postgresql://user:secret@aws-1.pooler.supabase.com:6543/postgres")

        self.assertIn("sslmode=require", db.dsn)
        self.assertNotIn("secret", db.label)

    def test_explicit_sslmode_is_preserved(self) -> None:
        db = Database("postgresql://user:secret@aws-1.pooler.supabase.com:6543/postgres?sslmode=verify-full")

        self.assertIn("sslmode=verify-full", db.dsn)

    def test_finding_insert_values_store_active_as_integer(self) -> None:
        db = Database("data/test.db")

        columns, values = db._finding_insert_values(
            1,
            {
                "url": "https://example.com",
                "normalized_domain": "example.com",
                "risk_score": 70,
                "active": True,
            },
        )

        active_index = columns.index("active")
        self.assertEqual(values[active_index], 1)
        self.assertIs(type(values[active_index]), int)

    def test_case_lookup_is_direct_and_finding_history_is_limited(self) -> None:
        with TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "argus.db")
            db.init()
            run_id = db.create_run(seed_query="test", max_candidates=3, take_screenshots=False)
            for index in range(3):
                db.insert_finding(
                    run_id,
                    {
                        "url": f"https://example.com/path-{index}",
                        "final_url": f"https://example.com/path-{index}",
                        "domain": "example.com",
                        "normalized_domain": "example.com",
                        "title": f"Example {index}",
                        "category": "phishing",
                        "verdict": "high",
                        "risk_score": 70 + index,
                        "active": True,
                        "status_code": 200,
                    },
                )

            case = db.get_case(1)
            self.assertIsNotNone(case)
            self.assertEqual(case["normalized_domain"], "example.com")
            self.assertEqual(case["finding_total"], 3)

            history = db.list_case_findings(1, limit=2)
            self.assertEqual(len(history), 2)
            self.assertEqual([item["title"] for item in history], ["Example 2", "Example 1"])

    def test_active_http_finding_without_html_stays_in_registry_after_backfill(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "argus.db"
            db = Database(path)
            db.init()
            run_id = db.create_run(seed_query="no ssl", max_candidates=1, take_screenshots=True)
            db.insert_finding(
                run_id,
                {
                    "url": "http://no-ssl.example",
                    "final_url": "http://no-ssl.example",
                    "domain": "no-ssl.example",
                    "normalized_domain": "no-ssl.example",
                    "title": None,
                    "category": "suspicious",
                    "verdict": "suspicious",
                    "risk_score": 72,
                    "active": True,
                    "status_code": 200,
                    "html_path": None,
                    "screenshot_path": None,
                },
            )

            reopened = Database(path)
            reopened.init()
            cases = reopened.list_cases(archived=False)

            self.assertEqual(len(cases), 1)
            self.assertEqual(cases[0]["normalized_domain"], "no-ssl.example")

    def test_registry_lists_latest_seen_cases_first(self) -> None:
        with TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "argus.db")
            db.init()
            run_id = db.create_run(seed_query="order", max_candidates=2, take_screenshots=False)
            db.insert_finding(
                run_id,
                {
                    "url": "https://older-risk.example",
                    "final_url": "https://older-risk.example",
                    "domain": "older-risk.example",
                    "normalized_domain": "older-risk.example",
                    "title": "Older high risk",
                    "category": "phishing",
                    "verdict": "high",
                    "risk_score": 99,
                    "active": True,
                    "status_code": 200,
                },
            )
            db.insert_finding(
                run_id,
                {
                    "url": "https://latest.example",
                    "final_url": "https://latest.example",
                    "domain": "latest.example",
                    "normalized_domain": "latest.example",
                    "title": "Latest lower risk",
                    "category": "suspicious",
                    "verdict": "suspicious",
                    "risk_score": 55,
                    "active": True,
                    "status_code": 200,
                },
            )
            with db.connect() as conn:
                conn.execute(
                    "UPDATE cases SET saved=1, last_seen=?, updated_at=? WHERE normalized_domain=?",
                    ("2026-07-02T00:00:00+00:00", "2026-07-02T00:00:00+00:00", "older-risk.example"),
                )
                conn.execute(
                    "UPDATE cases SET last_seen=?, updated_at=? WHERE normalized_domain=?",
                    ("2026-07-03T00:00:00+00:00", "2026-07-03T00:00:00+00:00", "latest.example"),
                )

            cases = db.list_cases(archived=False)

            self.assertEqual([case["normalized_domain"] for case in cases], ["latest.example", "older-risk.example"])

    def test_stale_running_runs_are_marked_interrupted_not_failed(self) -> None:
        with TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "argus.db")
            db.init()
            run_id = db.create_run(seed_query="test", max_candidates=1, take_screenshots=False)
            db.update_run(run_id, status="running")

            changed = db.mark_stale_runs_interrupted()
            run = db.get_run(run_id)

            self.assertEqual(changed, 1)
            assert run is not None
            self.assertEqual(run["status"], "interrupted")
            self.assertIn("прерван", run["error"])


if __name__ == "__main__":
    unittest.main()
