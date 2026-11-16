from __future__ import annotations

import asyncio
import io
import sqlite3
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, RLock
from unittest.mock import Mock

from app.config import Settings
from app.database import Database, DatabaseConnection
from app.services.investigator import Candidate, Investigator
from app.services.screenshots import ScreenshotResult


class InvestigatorScreenshotPipelineTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        connection = sqlite3.connect(":memory:", check_same_thread=False)
        connection.row_factory = sqlite3.Row
        self.addCleanup(connection.close)
        lock = RLock()

        @contextmanager
        def connect():
            with lock:
                try:
                    yield DatabaseConnection(connection, "sqlite")
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise

        self.db = Database(root / "pipeline.db")
        self.db.connect = connect
        self.db.init()
        self.run_id = self.db.create_run("casino", 2, True)
        self.investigator = object.__new__(Investigator)
        self.investigator.db = self.db
        self.investigator.settings = Settings(
            database_path=root / "pipeline.db",
            evidence_dir=root / "evidence",
            scan_concurrency=1,
            screenshot_concurrency=1,
            screenshot_timeout_seconds=5,
        )
        self.capture_started = asyncio.Event()
        self.release_capture = asyncio.Event()
        self.second_persisted = asyncio.Event()
        self.capture_canceled = asyncio.Event()
        self.capture_calls: list[str] = []
        self.active_captures = 0
        self.max_active_captures = 0
        self.cancel = Event()

        original_insert = self.db.insert_finding

        def insert(run_id: int, finding: dict) -> int:
            finding_id = original_insert(run_id, finding)
            if self.db.count_findings(run_id) >= 2:
                self.second_persisted.set()
            return finding_id

        self.db.insert_finding = insert

        async def discover(*args, **kwargs) -> list[Candidate]:  # noqa: ANN002, ANN003
            return [self.candidate(1), self.candidate(2)]

        async def mirrors(*args, **kwargs) -> list[dict]:  # noqa: ANN002, ANN003
            return []

        async def inspect(run_id: int, index: int, total: int, candidate: Candidate, *args, **kwargs) -> dict:  # noqa: ANN002, ANN003
            if candidate.domain.endswith("-2.example"):
                # The second persisted finding must overlap the first capture.
                await self.capture_started.wait()
            return self.finding(candidate)

        owner = self

        class ScreenshotBackend:
            async def capture(self, url: str, run_id: int, **kwargs) -> ScreenshotResult:  # noqa: ANN003
                owner.capture_calls.append(url)
                owner.active_captures += 1
                owner.max_active_captures = max(owner.max_active_captures, owner.active_captures)
                try:
                    if len(owner.capture_calls) == 1:
                        owner.capture_started.set()
                        try:
                            await owner.release_capture.wait()
                        except asyncio.CancelledError:
                            owner.capture_canceled.set()
                            raise
                    filename = f"finding-{len(owner.capture_calls)}.png"
                    path = owner.investigator.settings.screenshots_dir / filename
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"real fixture file")
                    return ScreenshotResult(path=f"evidence/screenshots/{filename}")
                finally:
                    owner.active_captures -= 1

        self.investigator._discover_candidates = discover
        self.investigator._discover_mirrors = mirrors
        self.investigator._inspect_candidate = inspect
        self.investigator.screenshots = ScreenshotBackend()

    @staticmethod
    def candidate(index: int) -> Candidate:
        domain = f"casino-{index}.example"
        return Candidate(url=f"https://{domain}", domain=domain, category="casino", why="fixture")

    @staticmethod
    def finding(candidate: Candidate) -> dict:
        return {
            "url": candidate.url,
            "final_url": candidate.url,
            "domain": candidate.domain,
            "normalized_domain": candidate.key(),
            "title": candidate.domain,
            "category": "casino",
            "verdict": "high",
            "risk_score": 90,
            "active": True,
            "status_code": 200,
            "evidence_json": {"screenshot_pending": True},
        }

    def start_run(self, target: int = 2) -> asyncio.Task:
        task = asyncio.create_task(self.investigator._run(self.run_id, "casino", target, True, self.cancel, "casino"))

        async def cleanup() -> None:
            self.release_capture.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

        self.addAsyncCleanup(cleanup)
        return task

    async def assert_search_overlaps_first_capture(self) -> None:
        await asyncio.wait_for(self.capture_started.wait(), 2)
        await asyncio.wait_for(self.second_persisted.wait(), 2)
        self.assertEqual(self.db.count_findings(self.run_id), 2)
        self.assertEqual(len(self.capture_calls), 1)
        self.assertEqual(self.active_captures, 1)
        self.assertEqual(self.db.get_run(self.run_id)["status"], "running")

    async def assert_completed_with_photos(self, task: asyncio.Task) -> None:
        self.release_capture.set()
        await asyncio.wait_for(asyncio.shield(task), 2)
        self.assertEqual(self.db.get_run(self.run_id)["status"], "completed")
        self.assertEqual(len(self.capture_calls), 2)
        self.assertEqual(self.max_active_captures, 1)
        self.assertTrue(all(item["screenshot_path"] for item in self.db.list_findings(self.run_id)))

    async def test_second_finding_persists_while_first_photo_is_held(self) -> None:
        task = self.start_run()
        await self.assert_search_overlaps_first_capture()
        self.assertFalse(task.done(), "The run must wait for its queued photos before completing")
        await self.assert_completed_with_photos(task)

    async def test_resumed_pending_photo_does_not_block_new_finding(self) -> None:
        self.db.insert_finding(self.run_id, self.finding(self.candidate(1)))
        self.db.update_run(self.run_id, finding_count=1)

        async def discover(*args, **kwargs) -> list[Candidate]:  # noqa: ANN002, ANN003
            return [self.candidate(2)]

        self.investigator._discover_candidates = discover
        task = self.start_run()
        await self.assert_search_overlaps_first_capture()
        await self.assert_completed_with_photos(task)

    async def test_same_consumer_does_not_block_second_discovery_pass(self) -> None:
        rounds: list[int] = []

        async def discover(*args, **kwargs) -> list[Candidate]:  # noqa: ANN002, ANN003
            round_index = kwargs["discovery_round"]
            rounds.append(round_index)
            return [self.candidate(round_index + 1)]

        self.investigator._discover_candidates = discover
        task = self.start_run()
        await self.assert_search_overlaps_first_capture()
        self.assertEqual(rounds, [0, 1])
        await self.assert_completed_with_photos(task)

    async def test_stop_cancels_active_photo_without_starting_next_photo(self) -> None:
        task = self.start_run()
        await self.assert_search_overlaps_first_capture()
        self.db.update_run(self.run_id, status="canceling")
        self.cancel.set()
        await asyncio.wait_for(asyncio.shield(task), 2)
        self.assertTrue(self.capture_canceled.is_set())
        self.assertEqual(len(self.capture_calls), 1)
        self.assertEqual(self.active_captures, 0)
        run = self.db.get_run(self.run_id)
        self.assertEqual(run["status"], "canceled")
        self.assertEqual(run["finding_count"], 2)
        findings = self.db.list_findings(self.run_id)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(item["evidence"]["screenshot_pending"] for item in findings))

    async def test_fatal_consumer_error_cancels_inflight_inspection_and_fails_run(self) -> None:
        second_inspection_started = asyncio.Event()
        second_inspection_canceled = asyncio.Event()

        async def inspect(run_id: int, index: int, total: int, candidate: Candidate, *args, **kwargs) -> dict:  # noqa: ANN002, ANN003
            if candidate.domain.endswith("-2.example"):
                second_inspection_started.set()
                try:
                    await asyncio.Future()
                finally:
                    second_inspection_canceled.set()
            return self.finding(candidate)

        self.investigator._inspect_candidate = inspect
        self.db.update_finding_screenshot = Mock(side_effect=RuntimeError("fixture screenshot persistence failed"))
        task = self.start_run()
        await asyncio.wait_for(self.capture_started.wait(), 2)
        await asyncio.wait_for(second_inspection_started.wait(), 2)
        self.release_capture.set()
        await asyncio.wait_for(asyncio.shield(task), 2)
        self.assertTrue(second_inspection_canceled.is_set())
        run = self.db.get_run(self.run_id)
        self.assertEqual(run["status"], "failed")
        self.assertIn("fixture screenshot persistence failed", run["error"])
        self.assertEqual(len(self.capture_calls), 1)

    async def test_fatal_consumer_error_while_draining_cannot_hang_completion(self) -> None:
        self.db.update_finding_screenshot = Mock(side_effect=RuntimeError("fixture final drain failed"))
        task = self.start_run()
        await self.assert_search_overlaps_first_capture()
        self.release_capture.set()
        await asyncio.wait_for(asyncio.shield(task), 2)
        run = self.db.get_run(self.run_id)
        self.assertEqual(run["status"], "failed")
        self.assertIn("fixture final drain failed", run["error"])
        self.assertEqual(len(self.capture_calls), 1)

    async def test_full_queue_bounds_discovery_and_fatal_consumer_wakes_blocked_enqueue(self) -> None:
        capacity_reached = asyncio.Event()
        inserted: list[int] = []
        original_insert = self.db.insert_finding

        def insert(run_id: int, finding: dict) -> int:
            finding_id = original_insert(run_id, finding)
            inserted.append(finding_id)
            if len(inserted) == 502:
                capacity_reached.set()
            return finding_id

        async def discover(*args, **kwargs) -> list[Candidate]:  # noqa: ANN002, ANN003
            return [self.candidate(index) for index in range(1, 504)]

        self.db.insert_finding = insert
        self.investigator._discover_candidates = discover
        self.db.update_finding_screenshot = Mock(side_effect=RuntimeError("fixture consumer failed with full queue"))
        # Keep real SQL/logging, omitting the hundreds of fixture log lines.
        with redirect_stdout(io.StringIO()):
            task = self.start_run(target=503)
            await asyncio.wait_for(self.capture_started.wait(), 2)
            await asyncio.wait_for(capacity_reached.wait(), 2)
            # One in flight, 500 queued, and one already persisted producer
            # waiting for a slot. A third extra finding must not be inspected.
            await asyncio.sleep(0.05)
            self.assertEqual(len(inserted), 502)
            self.assertEqual(len(self.capture_calls), 1)
            self.release_capture.set()
            await asyncio.wait_for(asyncio.shield(task), 2)
        self.assertEqual(self.db.get_run(self.run_id)["status"], "failed")
        self.assertIn("full queue", self.db.get_run(self.run_id)["error"])
        self.assertEqual(self.db.count_findings(self.run_id), 502)
        self.assertEqual(len(self.capture_calls), 1)

    async def test_normal_capture_error_is_recorded_and_later_photo_still_completes(self) -> None:
        original_capture = self.investigator.screenshots.capture

        async def capture(url: str, run_id: int, **kwargs) -> ScreenshotResult:  # noqa: ANN003
            if url.endswith("-1.example"):
                self.capture_calls.append(url)
                self.capture_started.set()
                raise RuntimeError("fixture browser navigation failed")
            return await original_capture(url, run_id, **kwargs)

        self.investigator.screenshots.capture = capture
        task = self.start_run()
        await asyncio.wait_for(asyncio.shield(task), 2)
        self.assertEqual(self.db.get_run(self.run_id)["status"], "completed")
        findings = {item["domain"]: item for item in self.db.list_findings(self.run_id)}
        self.assertIn("fixture browser navigation failed", findings["casino-1.example"]["evidence"]["screenshot_error"])
        self.assertIsNone(findings["casino-1.example"]["screenshot_path"])
        self.assertTrue(findings["casino-2.example"]["screenshot_path"])
        self.assertEqual(self.capture_calls, ["https://casino-1.example", "https://casino-2.example"])

    async def test_discovery_failure_cancels_active_photo_before_returning(self) -> None:
        async def mirrors(run_id: int, candidates: list[Candidate], search_mode: str) -> list[dict]:
            if candidates[0].domain.endswith("-2.example"):
                await self.capture_started.wait()
                raise RuntimeError("fixture discovery failed")
            return []

        self.investigator._discover_mirrors = mirrors
        task = self.start_run()
        await asyncio.wait_for(asyncio.shield(task), 2)
        self.assertEqual(self.db.get_run(self.run_id)["status"], "failed")
        self.assertTrue(self.capture_canceled.is_set())
        self.assertEqual(self.active_captures, 0)
        self.assertEqual(len(self.capture_calls), 1)

    async def test_stop_arriving_after_completion_does_not_rewrite_terminal_run(self) -> None:
        original_update = self.db.update_run

        def update(run_id: int, **fields) -> None:  # noqa: ANN003
            original_update(run_id, **fields)
            if fields.get("status") == "completed":
                self.cancel.set()

        self.db.update_run = update
        self.release_capture.set()
        task = self.start_run()
        await asyncio.wait_for(asyncio.shield(task), 2)
        self.assertTrue(self.cancel.is_set())
        self.assertEqual(self.db.get_run(self.run_id)["status"], "completed")
        self.assertEqual(len(self.capture_calls), 2)

    async def test_large_page_title_is_bounded_in_photo_metadata_and_preserved_in_database(self) -> None:
        original_inspect = self.investigator._inspect_candidate
        original_capture = self.investigator._capture_screenshot_with_stop
        page_title = "X" * 65536
        captured_metadata: list[dict] = []

        async def inspect(*args, **kwargs) -> dict:  # noqa: ANN002, ANN003
            finding = await original_inspect(*args, **kwargs)
            finding["title"] = page_title
            finding["evidence_json"]["page_content"] = "body kept outside the screenshot queue"
            return finding

        async def capture(run_id: int, finding_id: int, finding: dict, *args) -> bool:  # noqa: ANN002
            captured_metadata.append(finding)
            return await original_capture(run_id, finding_id, finding, *args)

        self.investigator._inspect_candidate = inspect
        self.investigator._capture_screenshot_with_stop = capture
        task = self.start_run()
        await self.assert_search_overlaps_first_capture()
        self.assertEqual(len(captured_metadata[0]["title"]), 1024)
        self.assertNotIn("evidence_json", captured_metadata[0])
        self.assertTrue(all(item["title"] == page_title for item in self.db.list_findings(self.run_id)))
        await self.assert_completed_with_photos(task)


if __name__ == "__main__":
    unittest.main()
