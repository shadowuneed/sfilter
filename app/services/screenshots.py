from __future__ import annotations

import base64
import asyncio
import importlib.util
import logging
import os
import re
import textwrap
import threading
from collections.abc import Awaitable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeVar

from app.config import Settings
from app.services.domains import extract_domain
from app.services.process_cleanup import ProcessCleanupError, ScreenshotProcessScope


BROWSER_SCREENSHOT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

_CLEANUP_TIMEOUT_SECONDS = 0.2
_LOGGER = logging.getLogger(__name__)
_Result = TypeVar("_Result")


_MINIMAL_PNG_BASE64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAFgwJ/"
    "l6wG6QAAAABJRU5ErkJggg=="
)


@dataclass
class ScreenshotResult:
    path: str | None
    error: str | None = None


class ScreenshotService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._browser_slots = threading.BoundedSemaphore(max(1, int(settings.screenshot_concurrency)))
        self._runtime_status_cache: dict[str, Any] | None = None
        self._process_cleanup_failed = False

    def runtime_status(self) -> dict[str, Any]:
        if self._runtime_status_cache is not None:
            return dict(self._runtime_status_cache)

        mode = "disabled"
        if self.settings.screenshots_enabled:
            if self.settings.browser_screenshots_enabled:
                mode = "browser-javascript" if self.settings.screenshot_javascript_enabled else "browser-static"
            elif self.settings.screenshot_fallback_enabled:
                mode = "fallback-evidence"
        status: dict[str, Any] = {
            "enabled": self.settings.screenshots_enabled,
            "browser_enabled": self.settings.browser_screenshots_enabled,
            "javascript_enabled": self.settings.screenshot_javascript_enabled,
            "capture_mode": mode,
            "fallback_enabled": self.settings.screenshot_fallback_enabled,
            "concurrency": self.settings.screenshot_concurrency,
            "dir": str(self.settings.screenshots_dir),
            "dir_exists": self.settings.screenshots_dir.exists(),
            "dir_writable": os.access(self.settings.screenshots_dir, os.W_OK),
            "playwright_browsers_path": os.environ.get("PLAYWRIGHT_BROWSERS_PATH"),
            "playwright_imported": False,
            "chromium_path": None,
            "chromium_exists": False,
            "error": None,
        }
        if not self.settings.browser_screenshots_enabled:
            status["error"] = "browser screenshots disabled; fallback evidence images are enabled"
            self._runtime_status_cache = dict(status)
            return status
        try:
            if importlib.util.find_spec("playwright") is None:
                raise ModuleNotFoundError("Playwright package is not installed")
            status["playwright_imported"] = True
            browser_roots: list[Path] = []
            configured_root = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
            if configured_root and configured_root != "0":
                browser_roots.append(Path(configured_root))
            local_app_data = os.environ.get("LOCALAPPDATA")
            if local_app_data:
                browser_roots.append(Path(local_app_data) / "ms-playwright")
            browser_roots.extend(
                [
                    Path.home() / ".cache" / "ms-playwright",
                    Path.home() / "Library" / "Caches" / "ms-playwright",
                ]
            )
            executable_names = {
                "chrome",
                "chrome.exe",
                "chrome-headless-shell",
                "chrome-headless-shell.exe",
            }
            chromium_path = next(
                (
                    candidate
                    for root in browser_roots
                    if root.exists()
                    for candidate in root.rglob("*")
                    if candidate.is_file() and candidate.name in executable_names
                ),
                None,
            )
            if chromium_path:
                status["chromium_path"] = str(chromium_path)
                status["chromium_exists"] = True
            else:
                status["error"] = "Chromium executable was not found in Playwright browser directories"
        except Exception as exc:  # noqa: BLE001
            status["error"] = f"{type(exc).__name__}: {exc}"
        self._runtime_status_cache = dict(status)
        return status

    async def capture(
        self,
        url: str,
        run_id: int,
        *,
        title: str | None = None,
        html_path: str | None = None,
        status_code: int | None = None,
    ) -> ScreenshotResult:
        if not self.settings.screenshots_enabled:
            return ScreenshotResult(path=None, error="screenshots disabled by configuration")
        if self._process_cleanup_failed:
            return ScreenshotResult(path=None, error="Browser process cleanup failed; restart the scan before another capture")

        domain = extract_domain(url) or "unknown"
        safe_domain = re.sub(r"[^a-zA-Z0-9_.-]+", "_", domain)[:80]
        self.settings.screenshots_dir.mkdir(parents=True, exist_ok=True)
        output = self.settings.screenshots_dir / f"run_{run_id}_{safe_domain}.png"
        rel_path = f"evidence/screenshots/{output.name}"

        if not self.settings.browser_screenshots_enabled:
            return self._fallback_result(
                output,
                rel_path,
                url=url,
                title=title,
                html_path=html_path,
                status_code=status_code,
                error="browser screenshots disabled by configuration",
            )

        try:
            from playwright.async_api import async_playwright
        except Exception as exc:  # noqa: BLE001
            return self._fallback_result(
                output,
                rel_path,
                url=url,
                title=title,
                html_path=html_path,
                status_code=status_code,
                error=f"Playwright is not installed or browsers are missing: {type(exc).__name__}: {exc}",
            )

        loop = asyncio.get_running_loop()
        timeout_seconds = max(0.01, float(self.settings.screenshot_timeout_seconds))
        deadline = loop.time() + timeout_seconds
        operation_deadline = deadline
        browser = None
        context = None
        manager = None
        acquired = False
        process_scope = None
        process_tracking_failed = False
        stage = "waiting for browser slot"
        try:
            while not self._browser_slots.acquire(blocking=False):
                await self._within_deadline(asyncio.sleep(0.2), operation_deadline)
            acquired = True
            if self.settings.screenshot_concurrency == 1:
                stage = "tracking browser processes"
                process_scope = ScreenshotProcessScope()
            manager = async_playwright()
            stage = "starting Playwright driver"
            playwright = await self._within_deadline(manager.start(), operation_deadline)
            if process_scope is not None:
                stage = "tracking browser processes"
                process_scope.track()
            stage = "launching Chromium"
            browser = await self._within_deadline(playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-extensions",
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-domain-reliability",
                    "--disable-default-apps",
                    "--disable-sync",
                    "--disable-site-isolation-trials",
                    "--disable-features=BackForwardCache,MediaRouter,OptimizationHints,Translate",
                    "--disk-cache-size=1",
                    "--media-cache-size=1",
                    "--js-flags=--max-old-space-size=64",
                    "--metrics-recording-only",
                    "--mute-audio",
                    "--no-first-run",
                    "--no-zygote",
                    "--renderer-process-limit=1",
                    "--disable-blink-features=AutomationControlled",
                ],
            ), operation_deadline)
            if process_scope is not None:
                stage = "tracking browser processes"
                process_scope.track()
            stage = "creating browser context"
            context = await self._within_deadline(browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 720},
                device_scale_factor=1,
                user_agent=BROWSER_SCREENSHOT_USER_AGENT,
                locale="ru-RU",
                timezone_id="Asia/Almaty",
                reduced_motion="reduce",
                java_script_enabled=self.settings.screenshot_javascript_enabled,
                proxy={"server": self.settings.kz_proxy_url} if self.settings.kz_proxy_url else None,
            ), operation_deadline)
            stage = "creating browser page"
            page = await self._within_deadline(context.new_page(), operation_deadline)
            # Navigation/readiness gets only part of the remaining total budget.
            # Slow ads or streaming responses must leave time to photograph the
            # actual viewport, even after an expensive cold browser launch.
            navigation_deadline = loop.time() + max(0.0, operation_deadline - loop.time()) * 0.55
            navigation_timeout_ms = max(1, int((navigation_deadline - loop.time()) * 1000))
            settle_ms = max(0, int(self.settings.screenshot_settle_ms))
            page.set_default_timeout(max(1, int((operation_deadline - loop.time()) * 1000)))
            navigation_error = None
            stage = "navigation commit"
            try:
                await self._within_deadline(
                    page.goto(url, wait_until="commit", timeout=navigation_timeout_ms), navigation_deadline,
                )
            except Exception as exc:  # noqa: BLE001
                navigation_error = exc
            stage = "document readiness"
            try:
                await self._within_deadline(
                    page.wait_for_load_state("domcontentloaded", timeout=max(1, int((navigation_deadline - loop.time()) * 1000))),
                    navigation_deadline,
                )
            except Exception:
                pass
            if settle_ms:
                stage = "settling browser viewport"
                settle_seconds = min(settle_ms / 1000, max(0.0, operation_deadline - loop.time()) * 0.1)
                await self._within_deadline(asyncio.sleep(settle_seconds), operation_deadline)
            stage = "capturing CDP browser PNG"
            try:
                capture_deadline = loop.time() + min(15.0, max(0.0, operation_deadline - loop.time()) * 0.75)
                # Capture the genuine rendered viewport without Playwright's
                # font-readiness/animation traversal holding a small container.
                client = await self._within_deadline(context.new_cdp_session(page), capture_deadline)
                capture = await self._within_deadline(client.send(
                    "Page.captureScreenshot",
                    {"format": "png", "fromSurface": True, "captureBeyondViewport": False, "optimizeForSpeed": True},
                ), capture_deadline)
                output.write_bytes(base64.b64decode(capture["data"]))
                result = self._capture_result(output, rel_path)
                if result.path or not self.settings.screenshot_fallback_enabled:
                    return self._with_browser_warnings(result, navigation_error)
                return self._fallback_result(
                    output,
                    rel_path,
                    url=url,
                    title=title,
                    html_path=html_path,
                    status_code=status_code,
                    error=result.error or "browser screenshot was not usable",
                )
            except Exception:  # noqa: BLE001
                try:
                    stage = "retrying browser PNG"
                    retry_deadline = loop.time() + min(5.0, max(0.0, operation_deadline - loop.time()) * 0.5)
                    await self._within_deadline(page.screenshot(
                        path=str(output),
                        full_page=False,
                        timeout=max(1, int((retry_deadline - loop.time()) * 1000)),
                        animations="disabled",
                        caret="hide",
                    ), retry_deadline)
                except Exception:  # noqa: BLE001
                    stage = "capturing CDP browser PNG"
                    client = await self._within_deadline(context.new_cdp_session(page), operation_deadline)
                    capture = await self._within_deadline(client.send(
                        "Page.captureScreenshot",
                        {"format": "png", "fromSurface": True, "captureBeyondViewport": False},
                    ), operation_deadline)
                    output.write_bytes(base64.b64decode(capture["data"]))
                result = self._capture_result(output, rel_path)
                if result.path or not self.settings.screenshot_fallback_enabled:
                    return self._with_browser_warnings(result, navigation_error)
                return self._fallback_result(
                    output,
                    rel_path,
                    url=url,
                    title=title,
                    html_path=html_path,
                    status_code=status_code,
                    error=result.error or "browser screenshot was not usable",
                )
        except Exception as exc:  # noqa: BLE001
            return self._fallback_result(
                output,
                rel_path,
                url=url,
                title=title,
                html_path=html_path,
                status_code=status_code,
                error=f"{stage}: {type(exc).__name__}: {exc}",
            )
        finally:
            if process_scope is not None:
                try:
                    process_scope.track()
                except ProcessCleanupError:
                    process_tracking_failed = True
            try:
                await self._cleanup_browser(context, browser, manager)
            finally:
                cleaned = not process_tracking_failed
                if process_scope is not None:
                    try:
                        cleaned = process_scope.cleanup(timeout=0.75) and cleaned
                    except Exception:
                        cleaned = False
                if acquired and cleaned:
                    self._browser_slots.release()
                elif acquired:
                    # Retain the slot: launching another Chromium on top of
                    # an unconfirmed old tree can exhaust a small container.
                    self._process_cleanup_failed = True
                    _LOGGER.error("Browser process cleanup failed; capture slot quarantined")

    async def _within_deadline(
        self,
        operation: Awaitable[_Result],
        deadline: float,
        *,
        start_before_timeout: bool = False,
    ) -> _Result:
        task = asyncio.ensure_future(operation)
        try:
            if start_before_timeout:
                # Driver shutdown must run far enough to request process stop,
                # even if earlier browser teardown used its remaining budget.
                await asyncio.sleep(0)
            remaining = max(0.0, deadline - asyncio.get_running_loop().time())
            if remaining:
                done, _ = await asyncio.wait({task}, timeout=remaining)
                if done:
                    return task.result()
            raise TimeoutError(
                f"screenshot timed out after {self.settings.screenshot_timeout_seconds:g} seconds"
            )
        finally:
            if not task.done():
                task.cancel()
                # Do not wait indefinitely for an unresponsive browser operation
                # to acknowledge cancellation. Driver shutdown runs separately.
            task.add_done_callback(self._consume_task_result)

    @staticmethod
    def _consume_task_result(task: asyncio.Future[Any]) -> None:
        if not task.cancelled():
            task.exception()

    async def _cleanup_browser(self, context: Any, browser: Any, manager: Any) -> None:
        closers = []
        closers.extend(resource.close for resource in (context, browser) if resource is not None)
        if manager is not None:
            closers.append(manager.__aexit__)
        canceled = False
        loop = asyncio.get_running_loop()
        # A fresh, shared grace period lets the driver terminate after a capture
        # timeout without turning one hung close into another unbounded wait.
        deadline = loop.time() + _CLEANUP_TIMEOUT_SECONDS
        for index, close in enumerate(closers):
            remaining = max(0.0, deadline - loop.time())
            close_budget = remaining / (len(closers) - index)
            try:
                await self._within_deadline(
                    close(), loop.time() + close_budget, start_before_timeout=True
                )
            except asyncio.CancelledError:
                canceled = True
            except Exception:  # noqa: BLE001
                pass
        if canceled:
            raise asyncio.CancelledError

    def _fallback_result(
        self,
        output: Path,
        rel_path: str,
        *,
        url: str,
        title: str | None,
        html_path: str | None,
        status_code: int | None,
        error: str,
    ) -> ScreenshotResult:
        if not self.settings.screenshot_fallback_enabled:
            return ScreenshotResult(path=None, error=error)
        try:
            self._write_fallback_image(
                output,
                url=url,
                title=title,
                html_path=html_path,
                status_code=status_code,
                error=error,
            )
            return ScreenshotResult(path=rel_path, error=f"{error}; fallback evidence image saved")
        except Exception as exc:  # noqa: BLE001
            return ScreenshotResult(path=None, error=f"{error}; fallback failed: {type(exc).__name__}: {exc}")

    @staticmethod
    def _write_fallback_image(
        output: Path,
        *,
        url: str,
        title: str | None,
        html_path: str | None,
        status_code: int | None,
        error: str,
    ) -> None:
        try:
            from PIL import Image, ImageDraw, ImageFont
        except Exception:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(base64.b64decode(_MINIMAL_PNG_BASE64))
            return

        width, height = 1280, 720
        image = Image.new("RGB", (width, height), "#101827")
        draw = ImageDraw.Draw(image)
        try:
            title_font = ImageFont.truetype("arial.ttf", 34)
            body_font = ImageFont.truetype("arial.ttf", 22)
            small_font = ImageFont.truetype("arial.ttf", 18)
        except Exception:
            title_font = body_font = small_font = ImageFont.load_default()

        draw.rectangle((0, 0, width, 84), fill="#172235")
        draw.text((42, 24), "Browser screenshot unavailable", fill="#e5eefb", font=title_font)
        draw.text((42, 112), "DOFilter saved a fallback evidence image instead of leaving a broken file.", fill="#b9c6d8", font=body_font)

        rows = [
            ("URL", url),
            ("Title", title or "not captured"),
            ("HTTP", str(status_code) if status_code else "unknown"),
            ("HTML evidence", html_path or "not saved"),
            ("Captured at", datetime.now(timezone.utc).replace(microsecond=0).isoformat()),
            ("Browser error", error),
        ]
        y = 170
        for label, value in rows:
            draw.text((42, y), label, fill="#60a5fa", font=small_font)
            y += 28
            for line in textwrap.wrap(str(value), width=98)[:5]:
                draw.text((42, y), line, fill="#f8fafc", font=body_font)
                y += 30
            y += 14
            if y > height - 70:
                break

        draw.rectangle((42, height - 58, width - 42, height - 30), outline="#334155", width=1)
        draw.text((56, height - 54), "Evidence file generated by DOFilter fallback renderer", fill="#94a3b8", font=small_font)
        output.parent.mkdir(parents=True, exist_ok=True)
        image.save(output, format="PNG")

    def _with_browser_warnings(self, result: ScreenshotResult, navigation_error: Exception | None) -> ScreenshotResult:
        if not result.path:
            return result
        warnings = [result.error] if result.error else []
        if not self.settings.screenshot_javascript_enabled:
            warnings.append("Browser screenshot captured with JavaScript disabled (HTML, CSS and images); dynamic content may be missing")
        if navigation_error:
            warnings.append(f"navigation warning: {type(navigation_error).__name__}: {navigation_error}")
        return ScreenshotResult(path=result.path, error="; ".join(warnings) or None)

    def _capture_result(self, output: Path, rel_path: str) -> ScreenshotResult:
        if self._looks_blank(output):
            try:
                output.unlink()
            except OSError:
                pass
            return ScreenshotResult(
                path=None,
                error="screenshot was blank; the site may block headless browsers, geo-filter traffic, or render empty content",
            )
        return ScreenshotResult(path=rel_path)

    @staticmethod
    def _looks_blank(path: Path) -> bool:
        try:
            from PIL import Image, ImageStat

            image = Image.open(path).convert("RGB")
            image.thumbnail((80, 80))
            extrema = image.getextrema()
            spread = max(high - low for low, high in extrema)
            means = ImageStat.Stat(image).mean
            return spread < 4 and (min(means) > 248 or max(means) < 7)
        except Exception:
            return False
