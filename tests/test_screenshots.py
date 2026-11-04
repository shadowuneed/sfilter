from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from app.config import Settings
from app.services.screenshots import BROWSER_SCREENSHOT_USER_AGENT, ScreenshotResult, ScreenshotService


class ScreenshotServiceTests(unittest.TestCase):
    def test_browser_screenshot_user_agent_is_not_service_bot(self) -> None:
        self.assertIn("Mozilla/5.0", BROWSER_SCREENSHOT_USER_AGENT)
        self.assertNotIn("Argus", BROWSER_SCREENSHOT_USER_AGENT)

    def test_browser_disabled_writes_fallback_png(self) -> None:
        with TemporaryDirectory() as tmp:
            settings = Settings(
                evidence_dir=Path(tmp) / "evidence",
                browser_screenshots_enabled=False,
                screenshot_fallback_enabled=True,
            )
            service = ScreenshotService(settings)

            result = asyncio.run(
                service.capture(
                    "https://example.com/login",
                    7,
                    title="Example",
                    html_path="evidence/example.html",
                    status_code=200,
                )
            )

            self.assertEqual(result.path, "evidence/screenshots/run_7_example.com.png")
            self.assertIsNotNone(result.error)
            self.assertTrue((settings.evidence_dir / "screenshots" / "run_7_example.com.png").exists())


class ScreenshotDeadlineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings = Settings(
            evidence_dir=Path(self.tmp.name) / "evidence",
            screenshot_timeout_seconds=0.08,
            screenshot_settle_ms=0,
            screenshot_fallback_enabled=False,
        )
        self.service = ScreenshotService(self.settings)
        self.service._capture_result = Mock(return_value=ScreenshotResult(path="evidence/test.png"))
        self.page = Mock(
            goto=AsyncMock(),
            wait_for_load_state=AsyncMock(),
            screenshot=AsyncMock(),
        )
        self.cdp = SimpleNamespace(send=AsyncMock())
        self.context = SimpleNamespace(
            new_page=AsyncMock(return_value=self.page),
            new_cdp_session=AsyncMock(return_value=self.cdp),
            close=AsyncMock(),
        )
        self.browser = SimpleNamespace(
            new_context=AsyncMock(return_value=self.context),
            close=AsyncMock(),
        )
        self.playwright = SimpleNamespace(chromium=SimpleNamespace(launch=AsyncMock(return_value=self.browser)))
        self.manager = MagicMock()
        self.manager.start = AsyncMock(return_value=self.playwright)
        self.manager.__aenter__ = AsyncMock(return_value=self.playwright)
        self.manager.__aexit__ = AsyncMock()
        self.playwright_patch = patch("playwright.async_api.async_playwright", return_value=self.manager)
        self.playwright_patch.start()
        self.addCleanup(self.playwright_patch.stop)
        self.cleanup_patch = patch("app.services.screenshots._CLEANUP_TIMEOUT_SECONDS", 0.02, create=True)
        self.cleanup_patch.start()
        self.addCleanup(self.cleanup_patch.stop)

    @staticmethod
    async def _hang(*args, **kwargs):
        await asyncio.Event().wait()

    async def _bounded_result(self, task: asyncio.Task):
        done, _ = await asyncio.wait({task}, timeout=0.35)
        if not done:
            # Keep the failing pre-fix test bounded even when its cleanup hangs.
            self.context.close.side_effect = None
            self.browser.close.side_effect = None
            self.manager.__aexit__.side_effect = None
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self.assertTrue(done, "Screenshot capture exceeded its total deadline or hung in cleanup")
        return task.result()

    def _assert_slot_released(self) -> None:
        self.assertTrue(self.service._browser_slots.acquire(blocking=False), "Screenshot slot leaked")
        self.service._browser_slots.release()

    async def test_cdp_fallback_obeys_total_deadline(self) -> None:
        self.page.screenshot.side_effect = RuntimeError("browser screenshot failed")
        self.cdp.send.side_effect = self._hang
        task = asyncio.create_task(self.service.capture("https://example.com", 7))

        result = await self._bounded_result(task)

        self.assertIsNone(result.path)
        self.assertIn("tim", result.error.lower())
        self.browser.close.assert_awaited()
        self.manager.__aexit__.assert_awaited()
        self._assert_slot_released()

    async def test_waiting_for_browser_slot_obeys_total_deadline(self) -> None:
        self.service._browser_slots.acquire()
        try:
            result = await self._bounded_result(asyncio.create_task(self.service.capture("https://example.com", 7)))
        finally:
            self.service._browser_slots.release()

        self.assertIsNone(result.path)
        self.assertIn("tim", result.error.lower())
        self.manager.start.assert_not_awaited()
        self._assert_slot_released()

    async def test_hanging_browser_launch_still_stops_driver_and_releases_slot(self) -> None:
        self.playwright.chromium.launch.side_effect = self._hang

        result = await self._bounded_result(asyncio.create_task(self.service.capture("https://example.com", 7)))

        self.assertIsNone(result.path)
        self.assertIn("tim", result.error.lower())
        self.manager.__aexit__.assert_awaited()
        self._assert_slot_released()

    async def test_hanging_close_cannot_prevent_success_or_leak_slot(self) -> None:
        self.context.close.side_effect = self._hang

        result = await self._bounded_result(asyncio.create_task(self.service.capture("https://example.com", 7)))

        self.assertEqual(result.path, "evidence/test.png")
        self.browser.close.assert_awaited()
        self.manager.__aexit__.assert_awaited()
        self._assert_slot_released()

    async def test_cancellation_is_not_blocked_by_hanging_close(self) -> None:
        reached = asyncio.Event()

        async def hanging_screenshot(*args, **kwargs):
            reached.set()
            await self._hang()

        self.page.screenshot.side_effect = hanging_screenshot
        self.context.close.side_effect = self._hang
        task = asyncio.create_task(self.service.capture("https://example.com", 7))
        await asyncio.wait_for(reached.wait(), timeout=0.2)
        task.cancel()

        with self.assertRaises(asyncio.CancelledError):
            await self._bounded_result(task)

        self.browser.close.assert_awaited()
        self.manager.__aexit__.assert_awaited()
        self._assert_slot_released()
        await asyncio.sleep(0)
        self.assertFalse(asyncio.all_tasks() - {asyncio.current_task()}, "Browser operation task leaked")

    async def test_hanging_driver_shutdown_does_not_block_capture_or_leak_slot(self) -> None:
        self.manager.__aexit__.side_effect = self._hang

        result = await self._bounded_result(asyncio.create_task(self.service.capture("https://example.com", 7)))

        self.assertEqual(result.path, "evidence/test.png")
        self._assert_slot_released()
        await asyncio.sleep(0)
        self.assertFalse(asyncio.all_tasks() - {asyncio.current_task()}, "Driver shutdown task leaked")

    async def test_cleanup_attempts_driver_shutdown_even_with_no_grace_remaining(self) -> None:
        with patch("app.services.screenshots._CLEANUP_TIMEOUT_SECONDS", 0):
            await self.service._cleanup_browser(self.context, self.browser, self.manager)

        self.manager.__aexit__.assert_awaited_once()
        self.context.close.assert_awaited_once()
        self.browser.close.assert_awaited_once()
        await asyncio.sleep(0)
        self.assertFalse(asyncio.all_tasks() - {asyncio.current_task()}, "Cleanup task leaked")


if __name__ == "__main__":
    unittest.main()
