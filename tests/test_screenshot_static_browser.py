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
from app.services.screenshots import ScreenshotService, _VISIBLE_CONTENT_SCRIPT


@unittest.skipUnless(os.getenv("QALQAN_RUN_BROWSER_TESTS") == "1", "Opt-in real Chromium rendering test")
class StaticBrowserRenderingTests(unittest.IsolatedAsyncioTestCase):
    async def test_canvas_frame_is_retained_with_unconfirmed_readiness_warning(self):
        html = b'<!doctype html><html><body style="background:#172d49;color:white;margin:24px"><main><canvas id="canvas" width="640" height="260"></canvas><p>Frame</p></main><script>const context=document.getElementById("canvas").getContext("2d");context.fillStyle="#20b8b4";context.fillRect(0,0,640,260);context.fillStyle="#f3d532";context.beginPath();context.arc(320,130,90,0,Math.PI*2);context.fill();context.fillStyle="black";context.font="36px Arial";context.fillText("REAL CANVAS FRAME",120,140);</script></body></html>'

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)

            def log_message(self, *args):
                pass

        class UnconfirmedCanvasService(ScreenshotService):
            async def _wait_for_visible_content(self, page, deadline):
                # The real DOM heuristic cannot see canvas text or image pixels.
                self.content = await page.evaluate(_VISIBLE_CONTENT_SCRIPT)
                return self.content["ready"]

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        service = UnconfirmedCanvasService(Settings(
            evidence_dir=root / "evidence", screenshot_timeout_seconds=10,
            screenshot_settle_ms=100, screenshot_fallback_enabled=False,
            screenshot_freeze_after_render=True,
        ))
        result = await service.capture(f"http://127.0.0.1:{server.server_port}/", 506)
        self.assertFalse(service.content["ready"])
        self.assertIsNotNone(result.path, result.error)
        self.assertIn("Page content readiness was not confirmed; browser frame may be incomplete", result.error)
        self.assertNotIn("fallback evidence image", result.error)
        from PIL import Image

        output = root / result.path
        with Image.open(output).convert("RGB") as image:
            self.assertEqual(image.size, (1280, 720))
            self.assertEqual(image.getpixel((50, 50)), (32, 184, 180))
        artifact = Path(tempfile.gettempdir()) / f"qalqan-unconfirmed-canvas-{uuid.uuid4().hex}.png"
        shutil.copy2(output, artifact)
        print(json.dumps({"actual_unconfirmed_frame": str(artifact), "warning": result.error}))

    async def test_dynamic_content_renders_before_javascript_is_frozen(self):
        allow_render = threading.Event()
        resources = {
            "/": ("text/html", b'<!doctype html><html><head><link rel="stylesheet" href="/style.css"><script defer src="/run.js"></script></head><body><header>Logo and navigation text that must never qualify as rendered main content by itself.</header><main>Loading...<img src="/pixel.svg" width="160" height="100"><img src="/pixel.svg" width="160" height="100"></main><footer>Long footer content is outside the viewport and must not make a loading skeleton pass the screenshot readiness gate.</footer></body></html>'),
            "/style.css": ("text/css", b'body{background:#172d49;color:white;margin:0;font:20px Arial}header{padding:16px;background:#382b4b}main{padding:24px}h1{margin:0 0 12px}p{max-width:900px}img{border:6px solid #f3b83f;margin-right:20px}footer{position:absolute;top:2000px}'),
            "/image.svg": ("image/svg+xml", b'<svg xmlns="http://www.w3.org/2000/svg" width="240" height="120"><rect width="240" height="120" fill="#20b8b4"/><circle cx="120" cy="60" r="45" fill="#f3d532"/></svg>'),
            "/pixel.svg": ("image/svg+xml", b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><rect width="1" height="1" fill="#ffffff"/></svg>'),
            "/run.js": ("text/javascript", b'window.frameCounter=0;function animate(){const until=performance.now()+4;while(performance.now()<until){}window.frameCounter++;requestAnimationFrame(animate)}animate();setTimeout(()=>{const main=document.querySelector("main");main.textContent="";const h=document.createElement("h1");h.textContent="DYNAMIC CONTENT LOADED";const p=document.createElement("p");p.textContent="This actual visible content was mounted by JavaScript after the loading skeleton. Both external images and styles remain visible in the frozen browser screenshot.";main.append(h,p);for(let i=0;i<2;i++){const image=document.createElement("img");image.src="/image.svg";image.width=240;image.height=120;main.append(image)}},600);'),
        }
        resources["/run.js"] = ("text/javascript", resources["/run.js"][1].replace(b"setTimeout(()=>{", b'fetch("/release").then(()=>{').replace(b"},600);", b"});"))

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/release":
                    allow_render.wait(5)
                    self.send_response(204)
                    self.end_headers()
                    return
                kind, body = resources.get(self.path, ("text/plain", b"not found"))
                self.send_response(200 if self.path in resources else 404)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        class ObservedService(ScreenshotService):
            initial_content = None
            frozen_counters = None

            async def _wait_for_visible_content(self, page, deadline):
                await self._within_deadline(page.wait_for_function("Array.from(document.querySelectorAll('main img')).every(image => image.complete && image.naturalWidth > 0)"), deadline)
                self.initial_content = await page.evaluate(_VISIBLE_CONTENT_SCRIPT)
                allow_render.set()
                return await super()._wait_for_visible_content(page, deadline)

            async def _within_deadline(self, operation, deadline, **kwargs):
                frame = getattr(operation, "cr_frame", None)
                local_values = frame.f_locals if frame else {}
                freeze = local_values.get("method") == "Emulation.setScriptExecutionDisabled"
                client = local_values.get("self") if freeze else None
                result = await super()._within_deadline(operation, deadline, **kwargs)
                if freeze:
                    first = await client.send("Runtime.evaluate", {"expression": "window.frameCounter", "returnByValue": True})
                    import asyncio

                    await asyncio.sleep(0.2)
                    second = await client.send("Runtime.evaluate", {"expression": "window.frameCounter", "returnByValue": True})
                    self.frozen_counters = (first["result"]["value"], second["result"]["value"])
                return result

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        service = ObservedService(Settings(
            evidence_dir=root / "evidence", screenshot_timeout_seconds=10,
            screenshot_settle_ms=0, screenshot_fallback_enabled=False,
            screenshot_javascript_enabled=True, screenshot_freeze_after_render=True,
        ))
        started = time.monotonic()
        result = await service.capture(f"http://127.0.0.1:{server.server_port}/", 505)
        self.assertIsNotNone(result.path, result.error)
        self.assertFalse(service.initial_content["ready"], "Header and offscreen footer must not pass a loader")
        self.assertGreater(service.frozen_counters[0], 0, "JavaScript must execute and mount the content first")
        self.assertEqual(*service.frozen_counters, "Animation callbacks must stop before capture")
        self.assertIn("JavaScript was paused", result.error)
        self.assertNotIn("fallback evidence", result.error)
        from PIL import Image

        output = root / result.path
        with Image.open(output).convert("RGB") as image:
            self.assertEqual(image.size, (1280, 720))
            colors = {color: count for count, color in image.getcolors(1280 * 720)}
            self.assertGreater(colors.get((32, 184, 180), 0), 1000, "Loaded external images must be present")
        artifact = Path(tempfile.gettempdir()) / f"qalqan-frozen-content-{uuid.uuid4().hex}.png"
        shutil.copy2(output, artifact)
        print(json.dumps({"actual_frozen_png": str(artifact), "seconds": round(time.monotonic() - started, 3), "frame_counter": service.frozen_counters, "warning": result.error}))

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
