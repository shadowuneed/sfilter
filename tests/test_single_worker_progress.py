from __future__ import annotations

import asyncio
import base64
import sqlite3
import unittest
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from types import SimpleNamespace

from app.config import Settings
from app.database import Database, DatabaseConnection
from app.services.investigator import Candidate, Investigator
from app.services.screenshots import ScreenshotResult


class SingleWorkerProgressTests(unittest.IsolatedAsyncioTestCase):
    async def test_first_finding_and_png_are_saved_while_second_candidate_is_blocked(self) -> None:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        db = Database(root / "argus.db")
        # Exercise real SQL persistence without platform-dependent disk fsync delays.
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        self.addCleanup(connection.close)

        @contextmanager
        def fixture_connection():
            try:
                yield DatabaseConnection(connection, "sqlite")
                connection.commit()
            except Exception:
                connection.rollback()
                raise

        db.connect = fixture_connection
        db.init()
        run_id = db.create_run(seed_query="fixture", max_candidates=2, take_screenshots=True)
        investigator = object.__new__(Investigator)
        investigator.db = db
        investigator.settings = Settings(
            database_path=root / "argus.db",
            evidence_dir=root / "evidence",
            scan_concurrency=1,
            screenshot_concurrency=1,
        )
        candidates = [
            Candidate(url=f"https://casino-{index}.example", domain=f"casino-{index}.example", category="casino", why="Fixture")
            for index in (1, 2)
        ]
        second_started = asyncio.Event()
        release_second = asyncio.Event()
        inspected: list[str] = []
        captured: list[str] = []

        async def discover(*args, **kwargs) -> list[Candidate]:
            return candidates

        async def mirrors(*args, **kwargs) -> list[dict]:
            return []

        async def inspect(current_run_id, index, total, candidate, *args, **kwargs) -> dict:
            inspected.append(candidate.domain)
            if candidate is candidates[1]:
                second_started.set()
                await release_second.wait()
            return {
                "url": candidate.url,
                "final_url": candidate.url,
                "domain": candidate.domain,
                "normalized_domain": candidate.key(),
                "title": candidate.domain,
                "category": "casino",
                "verdict": "high",
                "risk_score": 90,
                "active": True,
                "status_code": 200,
                "evidence_json": {"screenshot_pending": True},
            }

        async def capture(url: str, current_run_id: int, **kwargs) -> ScreenshotResult:
            self.assertEqual(current_run_id, run_id)
            findings = db.list_findings(run_id=run_id)
            self.assertTrue(any(finding["final_url"] == url for finding in findings), "The finding must be committed before capture")
            captured.append(url)
            filename = f"{url.split('//', 1)[1]}.png"
            output = investigator.settings.screenshots_dir / filename
            output.parent.mkdir(parents=True, exist_ok=True)
            # A local PNG fixture replaces only the external browser boundary.
            output.write_bytes(base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAFgwJ/"
                "l6wG6QAAAABJRU5ErkJggg=="
            ))
            return ScreenshotResult(path=f"evidence/screenshots/{filename}")

        investigator._discover_candidates = discover
        investigator._discover_mirrors = mirrors
        investigator._inspect_candidate = inspect
        investigator.screenshots = SimpleNamespace(capture=capture)
        run_task = asyncio.create_task(investigator._run(run_id, "fixture", 2, True, Event(), "casino"))
        try:
            await asyncio.wait_for(second_started.wait(), timeout=2)
            self.assertFalse(release_second.is_set())
            self.assertFalse(run_task.done())
            first = db.list_findings(run_id=run_id)
            self.assertEqual(len(first), 1)
            self.assertEqual(first[0]["domain"], candidates[0].domain)
            self.assertEqual(captured, [candidates[0].url], "The first screenshot must not wait for candidate two")
            self.assertIsNotNone(first[0]["screenshot_path"])
            png = root / first[0]["screenshot_path"]
            self.assertTrue(png.is_file())
            self.assertTrue(png.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"))
            self.assertFalse(first[0]["evidence"]["screenshot_pending"])
            run = db.get_run(run_id)
            self.assertEqual(run["status"], "running")
            self.assertEqual(run["candidate_count"], 1)
            self.assertEqual(run["finding_count"], 1)
        finally:
            release_second.set()
            try:
                await asyncio.wait_for(asyncio.shield(run_task), timeout=2)
            finally:
                if not run_task.done():
                    run_task.cancel()
                await asyncio.gather(run_task, return_exceptions=True)

        self.assertEqual(inspected, [candidate.domain for candidate in candidates])
        self.assertEqual(captured, [candidate.url for candidate in candidates])
        self.assertEqual(db.get_run(run_id)["status"], "completed")
        self.assertEqual(db.count_findings(run_id), 2)
        self.assertTrue(all(finding["screenshot_path"] for finding in db.list_findings(run_id=run_id)))


if __name__ == "__main__":
    unittest.main()
