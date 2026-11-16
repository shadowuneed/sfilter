"""Opt-in real Chromium check: QALQAN_RUN_BROWSER_TESTS=1 python -m unittest discover -s tests -p test_screenshot_static_browser.py."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

from app.config import Settings
from app.services.screenshots import ScreenshotService


@unittest.skipUnless(os.getenv("QALQAN_RUN_BROWSER_TESTS") == "1", "Opt-in real Chromium rendering test")
class StaticBrowserRenderingTests(unittest.IsolatedAsyncioTestCase):
    async def test_static_browser_preserves_ssr_css_and_images_without_executing_page_scripts(self):
        requests = []
        resources = {
            "/": ("text/html", b'<!doctype html><html><head><link rel="stylesheet" href="/style.css"><script defer src="/run.js"></script></head><body><h1 id="heading">SERVER RENDERED CONTENT</h1><img src="/image.svg" width="640" height="260"></body></html>'),
            "/style.css": ("text/css", b'html,body{margin:0}body{background:#172d49;color:white;padding:24px;font:20px Arial}h1{font-size:32px;line-height:40px;margin:0 0 24px}img{display:block;border:8px solid #f3b83f}'),
            "/image.svg": ("image/svg+xml", b'<svg xmlns="http://www.w3.org/2000/svg" width="640" height="260"><rect width="640" height="260" fill="#20b8b4"/><circle cx="320" cy="130" r="90" fill="#f3d532"/><text x="170" y="140" font-size="36">CSS AND IMAGE</text></svg>'),
            "/run.js": ("text/javascript", b'document.body.style.backgroundColor="#7b2439";document.getElementById("heading").textContent="JAVASCRIPT EXECUTED";fetch("/executed");'),
            "/executed": ("text/plain", b"executed"),
        }

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                kind, body = resources.get(self.path, ("text/plain", b"not found"))
                self.send_response(200 if self.path in resources else 404)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        for javascript in (True, False):
            with self.subTest(javascript=javascript):
                requests.clear()
                settings = Settings(
                    evidence_dir=root / "evidence",
                    screenshot_timeout_seconds=10,
                    screenshot_settle_ms=100,
                    screenshot_fallback_enabled=False,
                    screenshot_javascript_enabled=javascript,
                )
                started = time.monotonic()
                result = await ScreenshotService(settings).capture(f"http://127.0.0.1:{server.server_port}/", 504)
                self.assertIsNotNone(result.path, result.error)
                self.assertIn("/style.css", requests)
                self.assertIn("/image.svg", requests)
                self.assertEqual("/executed" in requests, javascript)
                if javascript:
                    self.assertIsNone(result.error)
                else:
                    self.assertIn("JavaScript disabled", result.error)
                    self.assertNotIn("fallback evidence", result.error)
                from PIL import Image

                output = root / result.path
                with Image.open(output).convert("RGB") as image:
                    self.assertEqual(image.size, (1280, 720))
                    self.assertEqual(image.getpixel((5, 5)), (123, 36, 57) if javascript else (23, 45, 73))
                    self.assertEqual(image.getpixel((50, 120)), (32, 184, 180), "The external image and CSS layout must remain visible")
                artifact = Path(tempfile.gettempdir()) / f"qalqan-ssr-js-{javascript}-{uuid.uuid4().hex}.png"
                shutil.copy2(output, artifact)
                print(json.dumps({"javascript_enabled": javascript, "actual_png": str(artifact), "seconds": round(time.monotonic() - started, 3), "warning": result.error}))


if __name__ == "__main__":
    unittest.main()
