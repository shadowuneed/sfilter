from __future__ import annotations

import asyncio
from dataclasses import replace
from io import BytesIO
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from PIL import Image
import psutil

from app.config import Settings
from app.services.process_cleanup import ScreenshotProcessScope, kill_processes, process_identity
from app.services.screenshots import ScreenshotService


def _spawn_sleep():
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
    return subprocess.Popen([sys.executable, "-B", "-c", "import time; time.sleep(60)"], **options)


def _spawn_tree(pid_file):
    script = (
        "import pathlib,subprocess,sys,time; "
        "p=subprocess.Popen([sys.executable,'-B','-c','import time; time.sleep(60)']); "
        "pathlib.Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(60)"
    )
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
    return subprocess.Popen([sys.executable, "-B", "-c", script, str(pid_file)], **options)


def _running(process):
    try:
        return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


def _cleanup_popen(process):
    if process.poll() is None:
        identity = process_identity(process.pid)
        children = []
        try:
            children = [process_identity(child) for child in identity.process.children(recursive=True)]
        except psutil.NoSuchProcess:
            pass
        kill_processes([identity, *children], timeout=0.5)
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=1)


def _wait(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


class ProcessScopeTests(unittest.TestCase):
    def test_owned_tree_is_killed_and_preexisting_child_survives(self):
        unrelated = _spawn_sleep()
        self.addCleanup(_cleanup_popen, unrelated)
        scope = ScreenshotProcessScope()
        with TemporaryDirectory() as directory:
            pid_file = Path(directory) / "descendant.txt"
            owned = _spawn_tree(pid_file)
            self.addCleanup(_cleanup_popen, owned)
            self.assertTrue(_wait(pid_file.exists))
            descendant = process_identity(int(pid_file.read_text()))
            self.addCleanup(kill_processes, [descendant], 0.5)
            scope.track()
            self.assertTrue(scope.cleanup(timeout=0.75))
            self.assertFalse(_running(descendant.process))
            owned.wait(timeout=1)
            self.assertIsNone(unrelated.poll())
            self.assertEqual(os.getpid(), scope._owner.pid)

    def test_stale_creation_time_and_current_parent_are_never_signalled(self):
        unrelated = _spawn_sleep()
        self.addCleanup(_cleanup_popen, unrelated)
        actual = process_identity(unrelated.pid)
        stale = replace(actual, created=actual.created + 100)
        with patch.object(actual.process, "kill", wraps=actual.process.kill) as kill:
            self.assertTrue(kill_processes([stale, process_identity(os.getpid())], timeout=0.1))
        kill.assert_not_called()
        self.assertIsNone(unrelated.poll())


class ScreenshotCleanupIntegrationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.settings = Settings(evidence_dir=self.root, screenshot_timeout_seconds=0.8,
                                 screenshot_settle_ms=0, screenshot_concurrency=1,
                                 screenshot_fallback_enabled=False)
        self.service = ScreenshotService(self.settings)
        buffer = BytesIO()
        Image.new("RGB", (80, 40), (20, 60, 180)).save(buffer, format="PNG")
        self.png = buffer.getvalue()
        self.owned = None
        self.descendant = None

    def configure_browser(self, spawn=False, hang_close=False):
        async def hang(*args, **kwargs):
            await asyncio.Future()

        async def screenshot(*args, **kwargs):
            Path(kwargs["path"]).write_bytes(self.png)

        page = SimpleNamespace(goto=AsyncMock(), wait_for_load_state=AsyncMock(),
                               screenshot=AsyncMock(side_effect=screenshot), set_default_timeout=lambda value: None)
        context = SimpleNamespace(new_page=AsyncMock(return_value=page), close=AsyncMock())
        browser = SimpleNamespace(new_context=AsyncMock(return_value=context), close=AsyncMock())
        playwright = SimpleNamespace(chromium=SimpleNamespace(launch=AsyncMock(return_value=browser)))
        manager = MagicMock()

        async def start():
            if spawn:
                pid_file = self.root / "browser-descendant.txt"
                self.owned = _spawn_tree(pid_file)
                self.addCleanup(_cleanup_popen, self.owned)
                deadline = asyncio.get_running_loop().time() + 0.5
                while not pid_file.exists() and asyncio.get_running_loop().time() < deadline:
                    await asyncio.sleep(0.01)
                if not pid_file.exists():
                    raise AssertionError("Fixture browser tree did not start")
                self.descendant = process_identity(int(pid_file.read_text()))
                self.addCleanup(kill_processes, [self.descendant], 0.5)
            return playwright

        manager.start = AsyncMock(side_effect=start)
        manager.__aexit__ = AsyncMock(side_effect=hang if hang_close else None)
        if hang_close:
            context.close.side_effect = hang
            browser.close.side_effect = hang
        self.manager, self.browser, self.context = manager, browser, context
        return manager

    async def test_hung_playwright_close_kills_real_owned_tree_and_keeps_captured_png(self):
        unrelated = _spawn_sleep()
        self.addCleanup(_cleanup_popen, unrelated)
        manager = self.configure_browser(spawn=True, hang_close=True)
        with patch("playwright.async_api.async_playwright", return_value=manager), \
                patch("app.services.screenshots._CLEANUP_TIMEOUT_SECONDS", 0.03):
            result = await asyncio.wait_for(self.service.capture("https://example.com", 7), 2.5)
        self.assertIsNotNone(result.path)
        output = self.root / "screenshots" / "run_7_example.com.png"
        self.assertEqual(output.read_bytes(), self.png)
        self.assertIsNotNone(self.owned)
        self.owned.wait(timeout=1)
        self.assertFalse(_running(self.descendant.process))
        self.assertIsNone(unrelated.poll())
        self.assertTrue(self.service._browser_slots.acquire(blocking=False))
        self.service._browser_slots.release()

    async def test_unconfirmed_cleanup_quarantines_slot_and_does_not_launch_another_browser(self):
        manager = self.configure_browser()
        guard = MagicMock()
        guard.cleanup.return_value = False
        with patch("playwright.async_api.async_playwright", return_value=manager), \
                patch("app.services.screenshots.ScreenshotProcessScope", return_value=guard):
            first = await self.service.capture("https://example.com", 7)
            second = await self.service.capture("https://another.example.com", 7)
        self.assertIsNotNone(first.path)
        self.assertIsNone(second.path)
        self.assertIn("cleanup", second.error.lower())
        self.assertEqual(manager.start.await_count, 1)
        self.assertFalse(self.service._browser_slots.acquire(blocking=False))
        self.assertEqual((self.root / "screenshots" / "run_7_example.com.png").read_bytes(), self.png)

    async def test_parallel_browser_configuration_does_not_claim_shared_descendants(self):
        self.service = ScreenshotService(replace(self.settings, screenshot_concurrency=2))
        manager = self.configure_browser()
        with patch("playwright.async_api.async_playwright", return_value=manager), \
                patch("app.services.screenshots.ScreenshotProcessScope") as guard:
            result = await self.service.capture("https://example.com", 7)
        self.assertIsNotNone(result.path)
        guard.assert_not_called()


if __name__ == "__main__":
    unittest.main()
