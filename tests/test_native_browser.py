from __future__ import annotations

import asyncio
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import MagicMock, patch

from PIL import Image

from app.config import Settings
from app.services.native_browser import NATIVE_READINESS_WARNING, capture_native, find_headless_shell


class NativeDiscoveryTests(unittest.TestCase):
    def test_only_matching_revision_headless_shell_is_selected(self):
        with TemporaryDirectory() as directory:
            root = Path(directory); package = root / "package"; cache = root / "cache"
            registry = package / "driver/package/browsers.json"
            registry.parent.mkdir(parents=True)
            registry.write_text(json.dumps({"browsers": [{"name": "chromium-headless-shell", "revision": "1234"}]}))
            executable = "chrome-headless-shell.exe" if sys.platform == "win32" else "chrome-headless-shell"
            old = cache / "chromium_headless_shell-1228/platform" / executable
            old.parent.mkdir(parents=True); old.touch(); old.chmod(0o755)
            full = cache / "chromium-1234/platform/chrome.exe"
            full.parent.mkdir(parents=True); full.touch(); full.chmod(0o755)
            self.assertIsNone(find_headless_shell(_package_root=package, _browser_roots=(cache,)))
            correct = cache / "chromium_headless_shell-1234/platform" / executable
            correct.parent.mkdir(parents=True); correct.touch(); correct.chmod(0o755)
            self.assertEqual(find_headless_shell(_package_root=package, _browser_roots=(cache,)), correct.resolve())


class _Process:
    pid = 424242

    def __init__(self, code=0):
        self.returncode = code
        self.killed = False

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


class NativeCaptureTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name); self.output = self.root / "capture.png"
        self.settings = Settings()
        self.scope = MagicMock()
        for target, value in [("find_headless_shell", self.root / "chrome-headless-shell"),
                              ("process_identity", MagicMock()), ("capture_owned_tree", []),
                              ("kill_processes", True)]:
            p = patch("app.services.native_browser." + target, return_value=value)
            p.start(); self.addCleanup(p.stop)

    async def capture(self, deadline=None, settings=None):
        return await capture_native(settings or self.settings, "https://example.com/", self.output,
                                    deadline if deadline is not None else asyncio.get_running_loop().time() + 3,
                                    self.scope, "fixture-agent")

    def completed(self, args, **kwargs):
        path = Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("--screenshot=")))
        Image.new("RGB", (1280, 720), (40, 90, 180)).save(path, format="PNG")
        return _Process()

    async def test_success_uses_native_argv_and_valid_new_png_with_honest_warning(self):
        with patch("app.services.native_browser.subprocess.Popen", side_effect=self.completed) as popen:
            result = await self.capture()
        self.assertTrue(result.captured); self.assertTrue(result.cleanup_confirmed)
        self.assertFalse(result.unavailable); self.assertEqual(result.error, NATIVE_READINESS_WARNING)
        args = popen.call_args.args[0]; options = popen.call_args.kwargs
        self.assertIn("--window-size=1280,720", args); self.assertIn("--timeout=20000", args)
        self.assertIn("--ignore-certificate-errors", args)
        self.assertIn("--virtual-time-budget=1800", args)
        self.assertFalse(options["shell"]); self.assertEqual(options["stdout"], subprocess.DEVNULL)
        self.assertEqual(options["stderr"], subprocess.DEVNULL)
        self.assertTrue(Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("--screenshot="))).is_absolute())
        profile = Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("--user-data-dir=")))
        self.assertFalse(profile.exists())
        with Image.open(self.output) as image:self.assertEqual(image.size, (1280, 720))

    async def test_unavailable_only_when_no_binary_and_never_launches_a_process(self):
        with patch("app.services.native_browser.find_headless_shell", return_value=None), \
                patch("app.services.native_browser.subprocess.Popen") as popen:
            result = await self.capture()
        self.assertTrue(result.unavailable); self.assertFalse(result.captured); popen.assert_not_called()

    async def test_existing_png_is_not_mistaken_for_a_failed_native_capture(self):
        Image.new("RGB", (1280, 720), (190, 30, 30)).save(self.output)
        original = self.output.read_bytes()
        with patch("app.services.native_browser.subprocess.Popen", return_value=_Process()):
            result = await self.capture()
        self.assertFalse(result.captured); self.assertFalse(result.unavailable)
        self.assertEqual(self.output.read_bytes(), original)

    async def test_wrong_size_or_nonzero_exit_does_not_publish_a_capture(self):
        for code, size in [(0, (20, 20)), (7, (1280, 720))]:
            def complete(args, **kwargs):
                path = Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("--screenshot=")))
                Image.new("RGB", size).save(path, format="PNG")
                return _Process(code)
            with self.subTest(code=code, size=size), \
                    patch("app.services.native_browser.subprocess.Popen", side_effect=complete):
                result = await self.capture()
                self.assertFalse(result.captured); self.assertFalse(self.output.exists())

    async def test_wall_deadline_kills_root_instead_of_trusting_soft_chrome_timeout(self):
        process = _Process(None)
        with patch("app.services.native_browser.subprocess.Popen", return_value=process):
            result = await self.capture(asyncio.get_running_loop().time() + 0.03)
        self.assertFalse(result.captured); self.assertFalse(result.unavailable)
        self.assertIn("wall-clock", result.error); self.assertTrue(process.killed)
        self.assertTrue(self.scope.track.called)

    async def test_cancel_is_preserved_even_when_cleanup_raises(self):
        process = _Process(None)
        with patch("app.services.native_browser.subprocess.Popen", return_value=process), \
                patch("app.services.native_browser.kill_processes", side_effect=OSError("fixture cleanup")):
            task = asyncio.create_task(self.capture())
            await asyncio.sleep(0.01); task.cancel()
            with self.assertRaises(asyncio.CancelledError):await task
        self.assertTrue(process.killed)

    async def test_uncertain_tree_cleanup_is_reported_even_for_a_valid_png(self):
        with patch("app.services.native_browser.subprocess.Popen", side_effect=self.completed), \
                patch("app.services.native_browser.kill_processes", return_value=False):
            result = await self.capture()
        self.assertTrue(result.captured); self.assertFalse(result.cleanup_confirmed)
        self.assertTrue(self.output.exists())

    async def test_launch_error_never_exposes_argv_or_becomes_unavailable(self):
        with patch("app.services.native_browser.subprocess.Popen", side_effect=OSError("fixture PRIVATE TOKEN URL")):
            result = await self.capture()
        self.assertFalse(result.unavailable); self.assertFalse(result.captured)
        self.assertNotIn("PRIVATE", result.error); self.assertIn("OSError", result.error)

    async def test_proxy_or_disabled_javascript_are_not_silently_ignored(self):
        for settings in [Settings(kz_proxy_url="http://fixture.invalid:3128"),
                         Settings(screenshot_javascript_enabled=False)]:
            with self.subTest(proxy=bool(settings.kz_proxy_url)), \
                    patch("app.services.native_browser.subprocess.Popen") as popen:
                result = await self.capture(settings=settings)
                self.assertFalse(result.captured); self.assertFalse(result.unavailable)
                popen.assert_not_called()


if __name__ == "__main__":unittest.main()
