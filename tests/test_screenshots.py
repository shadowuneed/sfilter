from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app.config import Settings
from app.services.screenshots import BROWSER_SCREENSHOT_USER_AGENT, ScreenshotService


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


if __name__ == "__main__":
    unittest.main()
