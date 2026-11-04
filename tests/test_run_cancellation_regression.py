from __future__ import annotations

import asyncio
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Thread
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from app.config import Settings
from app.database import Database
from app.services.investigator import Candidate, Investigator
from app.services.screenshots import ScreenshotResult, ScreenshotService


class RunScreenshotCancellationRegressionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.db = Database(root / "argus.db")
        self.db.init()
        self.run_id = self.db.create_run(seed_query="casino", max_candidates=3, take_screenshots=True)
        self.investigator = object.__new__(Investigator)
        self.investigator.db = self.db
        self.investigator.settings = Settings(
            database_path=root / "argus.db",
            evidence_dir=root / "evidence",
            scan_concurrency=3,
            screenshot_concurrency=1,
            screenshot_timeout_seconds=0.05,
        )
        self.inspected: list[int] = []
        self.capture_started = asyncio.Event()
        self.capture_calls: list[str] = []
        self.capture_cancellations: list[str] = []

    def configure_candidates(self, valid_indexes: set[int]) -> None:
        async def discover(*args, **kwargs) -> list[Candidate]:  # noqa: ANN002, ANN003
            return [
                Candidate(
                    url=f"https://casino-{index}.example",
                    domain=f"casino-{index}.example",
                    category="casino",
                    why="Regression fixture",
                )
                for index in range(1, 27)
            ]

        async def mirrors(*args, **kwargs) -> list[dict]:  # noqa: ANN002, ANN003
            return []

        async def inspect(
            current_run_id: int,
            index: int,
            total: int,
            candidate: Candidate,
            *args,
            **kwargs,
        ) -> dict:  # noqa: ANN002, ANN003
            self.inspected.append(index)
            if index not in valid_indexes:
                return {"_skip": True, "domain": candidate.domain, "_skip_reason": "fixture rejection"}
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

        self.investigator._discover_candidates = discover
        self.investigator._discover_mirrors = mirrors
        self.investigator._inspect_candidate = inspect

    def configure_screenshots(self) -> None:
        owner = self

        class ScreenshotBackend:
            async def capture(self, url: str, run_id: int, **kwargs) -> ScreenshotResult:  # noqa: ANN003
                owner.capture_calls.append(url)
                if url == "https://casino-1.example":
                    owner.capture_started.set()
                    try:
                        await asyncio.Future()
                    except asyncio.CancelledError:
                        owner.capture_cancellations.append(url)
                        raise
                    raise AssertionError("The hanging fixture cannot complete without cancellation")
                filename = f"{url.split('//', 1)[1]}.png"
                path = owner.investigator.settings.screenshots_dir / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fixture screenshot")
                return ScreenshotResult(path=f"evidence/screenshots/{filename}")

        self.investigator.screenshots = ScreenshotBackend()

    async def test_stop_during_first_screenshot_finishes_run_and_preserves_pending_findings(self) -> None:
        self.configure_candidates({1, 2})
        self.configure_screenshots()
        cancel_event = Event()
        run_task = asyncio.create_task(
            self.investigator._run(self.run_id, "casino", 3, True, cancel_event, "casino")
        )
        try:
            await asyncio.wait_for(self.capture_started.wait(), timeout=1.0)
            # Match the API's cancellation boundary while a real queued capture is active.
            self.db.update_run(self.run_id, status="canceling")
            cancel_event.set()
            await asyncio.wait_for(asyncio.shield(run_task), timeout=1.5)
        finally:
            if not run_task.done():
                run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)

        run = self.db.get_run(self.run_id)
        self.assertEqual(run["status"], "canceled")
        self.assertIsNotNone(run["finished_at"])
        self.assertEqual(run["candidate_count"], 24)
        self.assertEqual(run["finding_count"], 2)
        self.assertEqual(self.inspected, list(range(1, 25)))
        self.assertEqual(self.capture_calls, ["https://casino-1.example"])
        self.assertEqual(self.capture_cancellations, self.capture_calls)
        findings = self.db.list_findings(run_id=self.run_id)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(finding["screenshot_path"] is None for finding in findings))
        self.assertTrue(all(finding["evidence"]["screenshot_pending"] for finding in findings))

    async def test_hanging_screenshot_times_out_and_later_candidate_batch_reaches_target(self) -> None:
        self.configure_candidates({1, 25, 26})
        self.configure_screenshots()
        run_task = asyncio.create_task(
            self.investigator._run(self.run_id, "casino", 3, True, Event(), "casino")
        )
        try:
            await asyncio.wait_for(asyncio.shield(run_task), timeout=2.0)
        finally:
            if not run_task.done():
                run_task.cancel()
            await asyncio.gather(run_task, return_exceptions=True)

        run = self.db.get_run(self.run_id)
        self.assertEqual(run["status"], "completed")
        self.assertIsNotNone(run["finished_at"])
        self.assertEqual(run["candidate_count"], 26)
        self.assertEqual(run["finding_count"], 3)
        self.assertEqual(self.inspected, list(range(1, 27)))
        self.assertTrue(self.capture_cancellations)
        findings = {finding["domain"]: finding for finding in self.db.list_findings(run_id=self.run_id)}
        self.assertIsNone(findings["casino-1.example"]["screenshot_path"])
        self.assertTrue(findings["casino-1.example"]["evidence"]["screenshot_error"])
        self.assertTrue(findings["casino-25.example"]["screenshot_path"])
        self.assertTrue(findings["casino-26.example"]["screenshot_path"])

    async def test_synchronous_worker_returns_after_stop_with_hanging_browser_cleanup(self) -> None:
        self.configure_candidates({1, 2})
        self.investigator.settings = replace(
            self.investigator.settings,
            screenshot_timeout_seconds=5,
            screenshot_settle_ms=0,
            screenshot_fallback_enabled=False,
        )
        service = ScreenshotService(self.investigator.settings)
        self.investigator.screenshots = service
        reached = Event()
        cancel_event = Event()
        worker_errors: list[BaseException] = []
        worker_state: dict = {}

        async def hang(*args, **kwargs):  # noqa: ANN002, ANN003
            await worker_state["release"].wait()

        async def hanging_screenshot(*args, **kwargs):  # noqa: ANN002, ANN003
            worker_state["loop"] = asyncio.get_running_loop()
            worker_state["release"] = asyncio.Event()
            reached.set()
            await hang()

        page = Mock(goto=AsyncMock(), wait_for_load_state=AsyncMock())
        page.screenshot = AsyncMock(side_effect=hanging_screenshot)
        context = SimpleNamespace(new_page=AsyncMock(return_value=page), close=AsyncMock(side_effect=hang))
        browser = SimpleNamespace(new_context=AsyncMock(return_value=context), close=AsyncMock(side_effect=hang))
        playwright = SimpleNamespace(chromium=SimpleNamespace(launch=AsyncMock(return_value=browser)))
        manager = MagicMock()
        manager.start = AsyncMock(return_value=playwright)
        manager.__aexit__ = AsyncMock(side_effect=hang)

        def run_worker() -> None:
            try:
                self.investigator.run(self.run_id, "casino", 3, True, cancel_event, "casino")
            except BaseException as exc:
                worker_errors.append(exc)

        worker = Thread(target=run_worker, daemon=True)
        with patch("playwright.async_api.async_playwright", return_value=manager), patch(
            "app.services.screenshots._CLEANUP_TIMEOUT_SECONDS", 0.03
        ):
            worker.start()
            try:
                self.assertTrue(await asyncio.to_thread(reached.wait, 1.0), "Worker never reached browser capture")
                self.db.update_run(self.run_id, status="canceling")
                cancel_event.set()
                await asyncio.to_thread(worker.join, 1.5)
                self.assertFalse(worker.is_alive(), "asyncio.run shutdown kept the scan worker alive after Stop")
            finally:
                if worker.is_alive() and "loop" in worker_state:
                    worker_state["loop"].call_soon_threadsafe(worker_state["release"].set)
                    await asyncio.to_thread(worker.join, 1.0)

        self.assertEqual(worker_errors, [])
        run = self.db.get_run(self.run_id)
        self.assertEqual(run["status"], "canceled")
        self.assertIsNotNone(run["finished_at"])
        self.assertEqual(run["finding_count"], 2)
        self.assertEqual(self.inspected, list(range(1, 25)))
        page.screenshot.assert_awaited_once()
        context.close.assert_awaited_once()
        browser.close.assert_awaited_once()
        manager.__aexit__.assert_awaited_once()
        self.assertTrue(service._browser_slots.acquire(blocking=False), "Stopped worker leaked its browser slot")
        service._browser_slots.release()
        self.assertTrue(all(finding["evidence"]["screenshot_pending"] for finding in self.db.list_findings(run_id=self.run_id)))


if __name__ == "__main__":
    unittest.main()
