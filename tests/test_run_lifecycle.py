from __future__ import annotations

import os
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

os.environ["DATABASE_URL"] = ""
os.environ.setdefault("DATABASE_PATH", "data/test_run_lifecycle.db")

from app import main
from app.database import Database, utc_now


class RunLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.db = Database(Path(temporary.name) / "runs.db")
        self.db.init()
        self.db_patch = patch.object(main, "db", self.db)
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        self.manager = Mock()
        self.manager.is_running.return_value = False
        self.manager.force_stop.return_value = False
        self.manager.stop_all.return_value = []
        self.manager.running_ids.return_value = []
        manager_patch = patch.object(main, "worker_manager", self.manager)
        manager_patch.start()
        self.addCleanup(manager_patch.stop)
        stop_intent_patch = patch.object(main, "_hard_stop_requested_run_ids", {})
        stop_intent_patch.start()
        self.addCleanup(stop_intent_patch.stop)
        repair_flag_patch = patch.object(main, "_allow_screenshot_repair", True)
        repair_flag_patch.start()
        self.addCleanup(repair_flag_patch.stop)
        repair_patch = patch.object(main, "_start_screenshot_repair", return_value=False)
        self.repair = repair_patch.start()
        self.addCleanup(repair_patch.stop)
        self.run_id = self.db.create_run("fixture", 100, True)
        self.db.update_run(self.run_id, status="running")

    def test_hard_stop_kills_before_database_transition_and_terminal_afterward(self) -> None:
        statuses_at_kill = []

        def kill(run_id: int) -> bool:
            statuses_at_kill.append(self.db.get_run(run_id)["status"])
            self.assertIsNone(self.db.get_run(run_id)["finished_at"])
            return True

        self.manager.force_stop.side_effect = kill
        result = main.cancel_run(self.run_id)
        self.assertEqual(statuses_at_kill, ["running"])
        self.assertEqual(result["status"], "canceled")
        self.assertTrue(result["force"])
        self.assertIsNotNone(self.db.get_run(self.run_id)["finished_at"])
        self.manager.force_stop.assert_called_once_with(self.run_id)

    def test_cancellation_does_not_reopen_concurrently_completed_run(self) -> None:
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
        self.manager.force_stop.assert_called_once_with(self.run_id)
        self.assertNotIn(self.run_id, main._hard_stop_requested_run_ids)

    def test_canceling_run_without_worker_gets_terminal_status(self) -> None:
        self.db.update_run(self.run_id, status="canceling")
        result = main.cancel_run(self.run_id)
        self.assertEqual(result["status"], "canceled")
        self.assertIsNotNone(self.db.get_run(self.run_id)["finished_at"])

    def test_failed_kill_does_not_claim_success_or_release_run(self) -> None:
        self.manager.force_stop.side_effect = TimeoutError("fixture process is still alive")
        with self.assertRaises(HTTPException) as error:
            main.cancel_run(self.run_id)
        self.assertEqual(error.exception.status_code, 503)
        self.assertEqual(self.db.get_run(self.run_id)["status"], "canceling")
        self.assertIsNone(self.db.get_run(self.run_id)["finished_at"])

    def test_stop_all_stops_background_repair_and_preserves_saved_findings(self) -> None:
        manual_id = self.db.create_run("manual fixture", 1, True)
        self.db.insert_finding(self.run_id, {
            "url": "https://fixture.example", "domain": "fixture.example",
            "normalized_domain": "fixture.example", "category": "casino",
            "risk_score": 90, "active": True, "status_code": 200,
        })
        running = {0, self.run_id, manual_id}

        def stop_all() -> list[int]:
            # Include repair worker 0, which has no runs-table row.
            self.assertEqual(self.db.get_run(self.run_id)["status"], "running")
            self.assertEqual(self.db.get_run(manual_id)["status"], "queued")
            stopped = list(running)
            running.clear()
            return stopped

        self.manager.stop_all.side_effect = stop_all
        result = main.cancel_all_runs()
        self.assertEqual(running, set())
        self.manager.stop_all.assert_called_once_with()
        self.assertCountEqual(result["run_ids"], [self.run_id, manual_id])
        self.assertEqual(result["stopped_count"], 2)
        self.assertEqual(self.db.count_findings(self.run_id), 1)
        self.assertTrue(all(self.db.get_run(item)["status"] == "canceled" for item in result["run_ids"]))

    def test_single_stop_kills_before_a_blocked_database_read(self) -> None:
        database_entered, release_database, killed = (threading.Event() for _ in range(3))
        original_get = self.db.get_run
        failures = []

        def delayed_get(run_id):
            database_entered.set()
            if not release_database.wait(3):
                raise TimeoutError("fixture database wait was not released")
            return original_get(run_id)

        def cancel():
            try:
                main.cancel_run(self.run_id)
            except Exception as exc:
                failures.append(type(exc).__name__)

        self.manager.force_stop.side_effect = lambda run_id: killed.set() or True
        with patch.object(self.db, "get_run", side_effect=delayed_get):
            request = threading.Thread(target=cancel)
            request.start()
            try:
                self.assertTrue(database_entered.wait(1))
                self.assertTrue(killed.is_set(), "Database latency delayed the actual process stop")
            finally:
                release_database.set()
                request.join(3)
        self.assertFalse(request.is_alive())
        self.assertEqual(failures, [])

    def test_stop_all_kills_before_a_blocked_database_read(self) -> None:
        database_entered, release_database, killed = (threading.Event() for _ in range(3))
        original_list = self.db.list_active_runs
        failures = []

        def delayed_list():
            database_entered.set()
            if not release_database.wait(3):
                raise TimeoutError("fixture database wait was not released")
            return original_list()

        def cancel():
            try:
                main.cancel_all_runs()
            except Exception as exc:
                failures.append(type(exc).__name__)

        self.manager.stop_all.side_effect = lambda: killed.set() or []
        with patch.object(self.db, "list_active_runs", side_effect=delayed_list):
            request = threading.Thread(target=cancel)
            request.start()
            try:
                self.assertTrue(database_entered.wait(1))
                self.assertTrue(killed.is_set(), "Database latency delayed all process stops")
            finally:
                release_database.set()
                request.join(3)
        self.assertFalse(request.is_alive())
        self.assertEqual(failures, [])

    def test_poll_database_wait_does_not_block_single_process_stop(self) -> None:
        database_entered, release_database, killed = (threading.Event() for _ in range(3))
        original_list = self.db.list_active_runs
        failures = []

        def delayed_list():
            if threading.current_thread().name == "fixture-blocked-poll":
                database_entered.set()
                if not release_database.wait(3):
                    raise TimeoutError("fixture poll wait was not released")
            return original_list()

        def poll():
            try:
                main.list_runs()
            except Exception as exc:
                failures.append(type(exc).__name__)

        def cancel():
            try:
                main.cancel_run(self.run_id)
            except Exception as exc:
                failures.append(type(exc).__name__)

        self.manager.force_stop.side_effect = lambda run_id: killed.set() or True
        with patch.object(self.db, "list_active_runs", side_effect=delayed_list):
            polling = threading.Thread(target=poll, name="fixture-blocked-poll")
            stopping = threading.Thread(target=cancel)
            polling.start()
            self.assertTrue(database_entered.wait(1))
            stopping.start()
            try:
                self.assertTrue(killed.wait(0.5), "An unrelated poll held the launch lock during a database read")
            finally:
                release_database.set()
                polling.join(3)
                stopping.join(3)
        self.assertFalse(polling.is_alive())
        self.assertFalse(stopping.is_alive())
        self.assertEqual(failures, [])

    def test_stale_poll_snapshot_does_not_interrupt_a_newly_registered_worker(self) -> None:
        self.db.update_run(self.run_id, status="queued")
        snapshot = [self.db.get_run(self.run_id)]

        def query_then_register():
            with main.run_launch_lock:
                self.manager.is_running.return_value = True
                self.db.update_run(self.run_id, status="running")
            return snapshot

        with patch.object(self.db, "list_active_runs", side_effect=query_then_register):
            main._reconcile_finished_runs()

        self.assertEqual(self.db.get_run(self.run_id)["status"], "running")
        self.assertIsNone(self.db.get_run(self.run_id)["finished_at"])

    def test_stale_poll_snapshot_does_not_reopen_a_completed_run(self) -> None:
        snapshot = [self.db.get_run(self.run_id)]

        def query_then_complete():
            self.db.update_run(self.run_id, status="completed", finished_at=utc_now())
            return snapshot

        with patch.object(self.db, "list_active_runs", side_effect=query_then_complete):
            main._reconcile_finished_runs()

        self.assertEqual(self.db.get_run(self.run_id)["status"], "completed")

    def test_callback_preserves_user_stop_intent_if_database_write_is_delayed(self) -> None:
        self.manager.force_stop.return_value = True
        with patch.object(self.db, "get_run", side_effect=ConnectionError("fixture unavailable database")):
            with self.assertRaises(ConnectionError):
                main.cancel_run(self.run_id)
        self.manager.force_stop.assert_called_once_with(self.run_id)

        main._worker_finished(self.run_id, exit_code=-9, force_stopped=True)

        self.assertEqual(self.db.get_run(self.run_id)["status"], "canceled")
        self.assertIsNone(self.db.get_run(self.run_id)["error"])
        self.assertNotIn(self.run_id, main._hard_stop_requested_run_ids)

    def test_stop_all_preserves_owned_intent_if_database_read_fails(self) -> None:
        self.manager.running_ids.return_value = [0, self.run_id]
        with patch.object(self.db, "list_active_runs", side_effect=ConnectionError("fixture database")):
            with self.assertRaises(ConnectionError):
                main.cancel_all_runs()
        self.manager.stop_all.assert_called_once_with()
        self.assertNotIn(0, main._hard_stop_requested_run_ids)

        main._worker_finished(self.run_id, exit_code=-9, force_stopped=True)

        self.assertEqual(self.db.get_run(self.run_id)["status"], "canceled")
        self.assertNotIn(self.run_id, main._hard_stop_requested_run_ids)

    def test_unknown_run_releases_stop_intent_after_404(self) -> None:
        unknown_id = self.run_id + 100
        with self.assertRaises(HTTPException) as error:
            main.cancel_run(unknown_id)
        self.assertEqual(error.exception.status_code, 404)
        self.assertNotIn(unknown_id, main._hard_stop_requested_run_ids)

    def test_stop_intent_memory_is_bounded_and_ignores_repair_worker(self) -> None:
        main._remember_stop_requests(range(main._STOP_INTENT_LIMIT + 20))
        self.assertLessEqual(len(main._hard_stop_requested_run_ids), main._STOP_INTENT_LIMIT)
        self.assertNotIn(0, main._hard_stop_requested_run_ids)
        self.assertNotIn(1, main._hard_stop_requested_run_ids)
        self.assertIn(main._STOP_INTENT_LIMIT + 19, main._hard_stop_requested_run_ids)

    def test_stop_all_failure_leaves_unconfirmed_runs_canceling(self) -> None:
        self.manager.stop_all.side_effect = TimeoutError("fixture")
        with self.assertRaises(HTTPException) as error:
            main.cancel_all_runs()
        self.assertEqual(error.exception.status_code, 503)
        self.assertEqual(self.db.get_run(self.run_id)["status"], "canceling")
        self.assertIsNone(self.db.get_run(self.run_id)["finished_at"])

    def test_unexpected_worker_exit_cannot_leave_active_run(self) -> None:
        main._worker_finished(self.run_id, exit_code=17, force_stopped=False)
        run = self.db.get_run(self.run_id)
        self.assertEqual(run["status"], "failed")
        self.assertIsNotNone(run["finished_at"])
        self.assertIn("17", run["error"])
        self.repair.assert_not_called()

    def test_worker_exit_after_stop_finalizes_cancellation_without_repair(self) -> None:
        self.db.update_run(self.run_id, status="canceling")
        main._worker_finished(self.run_id, exit_code=-9, force_stopped=True)
        self.assertEqual(self.db.get_run(self.run_id)["status"], "canceled")
        self.assertIsNotNone(self.db.get_run(self.run_id)["finished_at"])
        self.repair.assert_not_called()

    def test_failed_finalizer_is_recovered_on_poll_when_worker_is_gone(self) -> None:
        self.db.update_run(self.run_id, status="canceling")
        with patch.object(self.db, "update_active_run", side_effect=RuntimeError("temporary database failure")):
            main._worker_finished(self.run_id, exit_code=-9, force_stopped=True)
        self.assertEqual(self.db.get_run(self.run_id)["status"], "canceling")
        result = main.get_run(self.run_id)
        self.assertEqual(result["run"]["status"], "canceled")
        self.assertIsNotNone(result["run"]["finished_at"])

    def test_poll_does_not_interrupt_a_live_worker_even_if_old(self) -> None:
        self.db.update_run(self.run_id, started_at="2020-01-01T00:00:00+00:00")
        self.manager.is_running.return_value = True
        result = main.list_runs()
        self.assertEqual(result["runs"][0]["status"], "running")
        self.manager.force_stop.assert_not_called()

    def test_launch_failure_is_terminal_instead_of_permanently_queued(self) -> None:
        self.manager.start.side_effect = RuntimeError("process start failed")
        with patch.object(main, "_ensure_kz_proxy_ready"):
            with self.assertRaises(HTTPException) as error:
                main.create_run(main.RunRequest(seed_query="fixture", take_screenshots=False))
        self.assertEqual(error.exception.status_code, 503)
        failed = self.db.list_runs()[0]
        self.assertEqual(failed["status"], "failed")
        self.assertIsNotNone(failed["finished_at"])
        self.assertEqual(self.db.list_active_runs(), [])

    def test_launch_registers_worker_while_cancel_lock_is_held(self) -> None:
        observed_lock = []

        def start(run_id, settings, job):
            def competing_cancel_lock() -> None:
                acquired = main.run_launch_lock.acquire(blocking=False)
                observed_lock.append(acquired)
                if acquired:
                    main.run_launch_lock.release()

            competitor = threading.Thread(target=competing_cancel_lock)
            competitor.start()
            competitor.join(timeout=1)
            self.assertFalse(competitor.is_alive())
            self.assertEqual(self.db.get_run(run_id)["status"], "queued")
            self.assertEqual(job["run_id"], run_id)

        self.manager.start.side_effect = start
        with patch.object(main, "_ensure_kz_proxy_ready"):
            result = main.create_run(main.RunRequest(seed_query="fixture", take_screenshots=False))
        self.assertEqual(observed_lock, [False], "Cancel could enter before process registration")
        self.assertEqual(self.db.get_run(result["run_id"])["status"], "queued")

    def test_restart_finalizes_stop_request_without_resuming_it(self) -> None:
        self.db.update_run(self.run_id, status="canceling")
        with patch.object(main, "settings", replace(main.settings, resume_active_runs=True)):
            main.resume_active_runs_after_restart()
        self.assertEqual(self.db.get_run(self.run_id)["status"], "canceled")
        self.manager.start.assert_not_called()

    def test_failed_resume_worker_does_not_abort_api_startup(self) -> None:
        self.manager.start.side_effect = RuntimeError("fixture cold worker launch failure")
        with patch.object(main, "settings", replace(main.settings, resume_active_runs=True)):
            # Exercise the actual lifespan, as an uncaught HTTPException here
            # makes Uvicorn exit rather than returning a normal API error.
            with TestClient(main.app) as client:
                response = client.get("/api/health")
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.json()["ok"])
                self.assertEqual(self.db.get_run(self.run_id)["status"], "failed")
                self.assertIsNotNone(self.db.get_run(self.run_id)["finished_at"])

    def test_late_completed_callback_after_stop_does_not_restart_browser_repair(self) -> None:
        # A process can commit its completed row immediately before Stop takes
        # the launch lock, with its parent callback still waiting for that lock.
        self.db.update_run(self.run_id, status="completed", finished_at=utc_now())
        main.cancel_all_runs()

        main._worker_finished(self.run_id, exit_code=0, force_stopped=False)

        self.assertEqual(self.db.get_run(self.run_id)["status"], "completed")
        self.repair.assert_not_called()
        self.manager.start.assert_not_called()


if __name__ == "__main__":
    unittest.main()
