from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from pathlib import Path

from app.config import Settings
from app.services.domains import extract_domain


@dataclass
class ScreenshotResult:
    path: str | None
    error: str | None = None


class ScreenshotService:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def capture(self, url: str, run_id: int) -> ScreenshotResult:
        if not self.settings.screenshots_enabled:
            return ScreenshotResult(path=None, error="screenshots disabled by configuration")

        try:
            from playwright.async_api import async_playwright
        except Exception as exc:  # noqa: BLE001
            return ScreenshotResult(
                path=None,
                error=f"Playwright is not installed or browsers are missing: {type(exc).__name__}: {exc}",
            )

        domain = extract_domain(url) or "unknown"
        safe_domain = re.sub(r"[^a-zA-Z0-9_.-]+", "_", domain)[:80]
        output = self.settings.screenshots_dir / f"run_{run_id}_{safe_domain}.png"
        rel_path = f"evidence/screenshots/{output.name}"

        browser = None
        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(
                    headless=True,
                    args=["--disable-blink-features=AutomationControlled"],
                )
                context = await browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": 1365, "height": 900},
                    device_scale_factor=1,
                    user_agent=self.settings.user_agent,
                    locale="ru-RU",
                    timezone_id="Europe/Moscow",
                )
                page = await context.new_page()
                page.set_default_timeout(15_000)
                await page.goto(url, wait_until="domcontentloaded", timeout=25_000)
                try:
                    await page.wait_for_load_state("networkidle", timeout=10_000)
                except Exception:
                    pass
                await page.wait_for_timeout(2_000)
                try:
                    await page.screenshot(
                        path=str(output),
                        full_page=True,
                        timeout=15_000,
                        animations="disabled",
                        caret="hide",
                    )
                    return self._capture_result(output, rel_path)
                except Exception:  # noqa: BLE001
                    try:
                        await page.screenshot(
                            path=str(output),
                            full_page=False,
                            timeout=12_000,
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
                    return self._capture_result(output, rel_path)
        except Exception as exc:  # noqa: BLE001
            return ScreenshotResult(path=None, error=f"{type(exc).__name__}: {exc}")
        finally:
            if browser:
                try:
                    await browser.close()
                except Exception:
                    pass

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