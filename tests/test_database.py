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


if __name__ == "__main__":
    unittest.main()
