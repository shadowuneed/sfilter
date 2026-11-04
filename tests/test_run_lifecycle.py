from __future__ import annotations

import os
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

os.environ["DATABASE_URL"] = ""
os.environ.setdefault("DATABASE_PATH", "data/test_run_lifecycle.db")

from app import main
from app.database import Database, utc_now


class RunLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Database(Path(self.temp.name) / "runs.db")
        self.db.init()
        self.db_patch = patch.object(main, "db", self.db)
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        self.events_patch = patch.dict(main.cancel_events, {}, clear=True)
        self.events_patch.start()
        self.addCleanup(self.events_patch.stop)
        self.run_id = self.db.create_run("fixture", 100, True)
        self.db.update_run(self.run_id, status="running")

    def test_fast_worker_cancellation_is_not_reverted_to_canceling(self) -> None:
        event = Mock()
        event.set.side_effect = lambda: self.db.update_run(
            self.run_id, status="canceled", finished_at=utc_now()
        )
        main.cancel_events[self.run_id] = event

        main.cancel_run(self.run_id)

        self.assertEqual(self.db.get_run(self.run_id)["status"], "canceled")

    def test_cancellation_does_not_reopen_concurrently_completed_run(self) -> None:
        event = threading.Event()
        main.cancel_events[self.run_id] = event
        original_get_run = self.db.get_run
        first_read = True

        def completing_read(run_id: int):
            nonlocal first_read
            result = original_get_run(run_id)
            if first_read:
                first_read = False
                self.db.update_run(run_id, status="completed", finished_at=utc_now())
            return result

        with patch.object(self.db, "get_run", side_effect=completing_read):
            result = main.cancel_run(self.run_id)

        self.assertEqual(original_get_run(self.run_id)["status"], "completed")
        self.assertEqual(result["status"], "completed")
        self.assertFalse(event.is_set())

    def test_canceling_run_without_worker_gets_terminal_status(self) -> None:
        self.db.update_run(self.run_id, status="canceling")

        result = main.cancel_run(self.run_id)

        self.assertEqual(result["status"], "canceled")
        self.assertIsNotNone(self.db.get_run(self.run_id)["finished_at"])

    def test_unexpected_worker_exception_cannot_leave_active_run(self) -> None:
        main.cancel_events[self.run_id] = threading.Event()

        def broken_worker() -> None:
            raise RuntimeError("fixture failure")

        main._thread_entry(self.run_id, broken_worker, ())

        run = self.db.get_run(self.run_id)
        self.assertEqual(run["status"], "failed")
        self.assertIsNotNone(run["finished_at"])
        self.assertIn("RuntimeError", run["error"])
        self.assertNotIn(self.run_id, main.cancel_events)

    def test_worker_exit_after_stop_finalizes_cancellation(self) -> None:
        event = threading.Event()
        event.set()
        main.cancel_events[self.run_id] = event
        self.db.update_run(self.run_id, status="canceling")

        main._thread_entry(self.run_id, lambda: None, ())

        run = self.db.get_run(self.run_id)
        self.assertEqual(run["status"], "canceled")
        self.assertIsNotNone(run["finished_at"])


if __name__ == "__main__":
    unittest.main()
