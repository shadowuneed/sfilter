"""Opt-in capability proof on the actual installed shell, including Linux CI."""
from __future__ import annotations

import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import time
import unittest

from PIL import Image

from app.config import Settings
from app.services.native_browser import NATIVE_READINESS_WARNING, capture_native, find_headless_shell
from app.services.process_cleanup import ScreenshotProcessScope


@unittest.skipUnless(os.getenv("QALQAN_RUN_BROWSER_TESTS") == "1", "Opt-in real native Chromium capture")
class NativeBrowserIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_busy_browser_is_stopped_on_wall_deadline_and_cancellation(self):
        self.assertIsNotNone(find_headless_shell())
        parent_pid = os.getpid()
        busy_page = "data:text/html,<html><body><script>while(true){}</script></body></html>"
        with TemporaryDirectory() as directory:
            for cancel in (False, True):
                with self.subTest(cancel=cancel):
                    output = Path(directory) / f"busy-{cancel}.png"
                    output.write_bytes(b"previous artifact must not become a native success")
                    scope = ScreenshotProcessScope()
                    loop = asyncio.get_running_loop()
                    started = time.monotonic()
                    task = asyncio.create_task(capture_native(
                        Settings(), busy_page, output, loop.time() + (20 if cancel else 1), scope, "qalqan-test"))
                    try:
                        if cancel:
                            until = loop.time() + 3
                            while not scope._owned and loop.time() < until:
                                await asyncio.sleep(0.02)
                            self.assertTrue(scope._owned, "The real native process must start before cancellation")
                            task.cancel()
                            with self.assertRaises(asyncio.CancelledError):
                                await asyncio.wait_for(task, timeout=3)
                        else:
                            result = await asyncio.wait_for(task, timeout=4)
                            self.assertFalse(result.captured)
                            self.assertFalse(result.unavailable)
                            self.assertTrue(result.cleanup_confirmed)
                            self.assertIn("wall-clock", result.error)
                        self.assertLess(time.monotonic() - started, 4)
                        self.assertEqual(os.getpid(), parent_pid)
                        self.assertEqual(output.read_bytes(), b"previous artifact must not become a native success")
                    finally:
                        if not task.done():
                            task.cancel()
                            await asyncio.gather(task, return_exceptions=True)
                        self.assertTrue(scope.cleanup(timeout=1), "No native descendants may survive stop")

    async def test_native_shell_really_executes_javascript_and_captures_css_images(self):
        self.assertIsNotNone(find_headless_shell(), "Installed revision must provide a real headless-shell binary")
        requests = []
        resources = {
            "/": ("text/html", b'<html><head><link rel="stylesheet" href="/style.css"><script defer src="/app.js"></script></head><body>Loading...</body></html>'),
            "/style.css": ("text/css", b'body{margin:0;background:#999;color:white;font:24px Arial}main{padding:20px}img{display:block;border:8px solid #f3b83f}'),
            "/app.js": ("text/javascript", b'setTimeout(()=>{document.body.style.backgroundColor="#172d49";document.body.innerHTML=\'<main><h1>REAL JAVASCRIPT CONTENT</h1><img src="/image.svg" width="640" height="260"></main>\';fetch("/executed")},600)'),
            "/image.svg": ("image/svg+xml", b'<svg xmlns="http://www.w3.org/2000/svg" width="640" height="260"><rect width="640" height="260" fill="#20b8b4"/></svg>'),
            "/executed": ("text/plain", b"yes"),
        }
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                kind, body = resources.get(self.path, ("text/plain", b"not found"))
                self.send_response(200); self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            def log_message(self, *args):pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler); server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        with TemporaryDirectory() as directory:
            output = Path(directory) / "actual-native.png"
            scope = ScreenshotProcessScope()
            try:
                result = await capture_native(Settings(), f"http://127.0.0.1:{server.server_port}/", output,
                                              asyncio.get_running_loop().time() + 20, scope, "qalqan-test")
            finally:
                self.assertTrue(scope.cleanup(timeout=1), "No native browser descendants may survive")
            self.assertTrue(result.captured, result.error); self.assertTrue(result.cleanup_confirmed)
            self.assertFalse(result.unavailable); self.assertEqual(result.error, NATIVE_READINESS_WARNING)
            for path in ["/style.css", "/image.svg", "/executed"]:self.assertIn(path, requests)
            with Image.open(output).convert("RGB") as image:
                self.assertEqual(image.size, (1280, 720))
                self.assertEqual(image.getpixel((1200, 500)), (23, 45, 73))
                self.assertEqual(image.getpixel((50, 180)), (32, 184, 180))


if __name__ == "__main__":unittest.main()
