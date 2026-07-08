from __future__ import annotations

import base64
import asyncio
import os
import re
import textwrap
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import Settings
from app.services.domains import extract_domain


BROWSER_SCREENSHOT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

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

    def runtime_status(self) -> dict[str, Any]:
        status: dict[str, Any] = {
            "enabled": self.settings.screenshots_enabled,
            "browser_enabled": self.settings.browser_screenshots_enabled,
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
            return status
        try:
            from playwright.sync_api import sync_playwright

            status["playwright_imported"] = True
            with sync_playwright() as playwright:
                chromium_path = Path(playwright.chromium.executable_path)
                status["chromium_path"] = str(chromium_path)
                status["chromium_exists"] = chromium_path.exists()
        except Exception as exc:  # noqa: BLE001
            status["error"] = f"{type(exc).__name__}: {exc}"
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

        browser = None
        acquired = False
        try:
            while not self._browser_slots.acquire(blocking=False):
                await asyncio.sleep(0.2)
            acquired = True
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-extensions",
                        "--disable-background-networking",
                        "--disable-default-apps",
                        "--disable-sync",
                        "--metrics-recording-only",
                        "--mute-audio",
                        "--no-zygote",
                        "--renderer-process-limit=1",
                        "--disable-blink-features=AutomationControlled",
                    ],
                )
                context = await browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": 1280, "height": 720},
                    device_scale_factor=1,
                    user_agent=BROWSER_SCREENSHOT_USER_AGENT,
                    locale="ru-RU",
                    timezone_id="Asia/Almaty",
                    proxy={"server": self.settings.kz_proxy_url} if self.settings.kz_proxy_url else None,
                )
                page = await context.new_page()
                timeout_ms = max(4_000, int(self.settings.screenshot_timeout_seconds * 1000))
                settle_ms = max(0, int(self.settings.screenshot_settle_ms))
                page.set_default_timeout(timeout_ms)
                navigation_error = None
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms + 3_000)
                except Exception as exc:  # noqa: BLE001
                    navigation_error = exc
                    try:
                        await page.goto(url, wait_until="commit", timeout=max(3_000, timeout_ms // 2))
                    except Exception:
                        pass
                try:
                    await page.wait_for_load_state("networkidle", timeout=min(3_000, timeout_ms))
                except Exception:
                    pass
                if settle_ms:
                    await page.wait_for_timeout(settle_ms)
                try:
                    await page.screenshot(
                        path=str(output),
                        full_page=False,
                        timeout=timeout_ms,
                        animations="disabled",
                        caret="hide",
                    )
                    result = self._capture_result(output, rel_path)
                    if result.path or not self.settings.screenshot_fallback_enabled:
                        if result.path and navigation_error:
                            return ScreenshotResult(
                                path=result.path,
                                error=f"navigation warning: {type(navigation_error).__name__}: {navigation_error}",
                            )
                        return result
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
                        await page.screenshot(
                            path=str(output),
                            full_page=False,
                            timeout=max(3_000, timeout_ms // 2),
                            animations="disabled",
                            caret="hide",
                        )
                    except Exception:  # noqa: BLE001
                        client = await context.new_cdp_session(page)
                        capture = await client.send(
                            "Page.captureScreenshot",
                            {"format": "png", "fromSurface": True, "captureBeyondViewport": False},
                        )
                        output.write_bytes(base64.b64decode(capture["data"]))
                    result = self._capture_result(output, rel_path)
                    if result.path or not self.settings.screenshot_fallback_enabled:
                        if result.path and navigation_error:
                            return ScreenshotResult(
                                path=result.path,
                                error=f"navigation warning: {type(navigation_error).__name__}: {navigation_error}",
                            )
                        return result
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
                error=f"{type(exc).__name__}: {exc}",
            )
        finally:
            if browser:
                try:
                    await browser.close()
                except Exception:
                    pass
            if acquired:
                self._browser_slots.release()

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
