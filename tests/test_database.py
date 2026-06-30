from __future__ import annotations

import unittest

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


if __name__ == "__main__":
    unittest.main()
