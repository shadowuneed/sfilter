from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event

from app.config import Settings
from app.database import Database
from app.services.investigator import Candidate, Investigator


class InvestigatorRunTargetTests(unittest.TestCase):
    def test_run_continues_to_second_discovery_pass_until_finding_target(self) -> None:
        with TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "argus.db")
            db.init()
            run_id = db.create_run(seed_query="онлайн казино", max_candidates=2, take_screenshots=False)
            investigator = object.__new__(Investigator)
            investigator.settings = Settings(
                database_path=Path(tmp) / "argus.db",
                scan_concurrency=1,
                screenshots_enabled=False,
            )
            investigator.db = db
            excluded_by_round: list[set[str]] = []

            async def discover(
                current_run_id: int,
                seed_query: str | None,
                max_candidates: int,
                search_mode: str = "auto",
                excluded_domains: set[str] | None = None,
                discovery_round: int = 0,
                use_groq: bool = True,
            ) -> list[Candidate]:
                self.assertEqual(current_run_id, run_id)
                excluded_by_round.append(set(excluded_domains or set()))
                domain = "alpha-casino.example" if discovery_round == 0 else "beta-casino.example"
                return [
                    Candidate(
                        url=f"https://{domain}",
                        domain=domain,
                        category="casino",
                        why="Search result",
                    )
                ]

            async def mirrors(*args, **kwargs) -> list[dict]:  # noqa: ANN002, ANN003
                return []

            async def inspect(
                current_run_id: int,
                index: int,
                total: int,
                candidate: Candidate,
                *args,
                **kwargs,
            ) -> dict:  # noqa: ANN002, ANN003
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
                }

            investigator._discover_candidates = discover
            investigator._discover_mirrors = mirrors
            investigator._inspect_candidate = inspect

            asyncio.run(investigator._run(run_id, "онлайн казино", 2, False, search_mode="auto"))

            run = db.get_run(run_id)
            self.assertIsNotNone(run)
            self.assertEqual(run["status"], "completed")
            self.assertEqual(db.count_findings(run_id), 2)
            self.assertEqual(run["candidate_count"], 2)
            self.assertEqual(excluded_by_round, [set(), {"alpha-casino.example"}])
            self.assertEqual(
                db.list_run_attempted_domains(run_id),
                {"alpha-casino.example", "beta-casino.example"},
            )

    def test_arbitrary_text_uses_search_pages_without_category_selector(self) -> None:
        self.assertTrue(Investigator._user_search_mode("подозрительные магазины Алматы", "auto"))

    def test_empty_pool_stays_active_until_manual_stop(self) -> None:
        with TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "argus.db")
            db.init()
            run_id = db.create_run(seed_query="онлайн казино", max_candidates=100, take_screenshots=False)
            investigator = object.__new__(Investigator)
            investigator.settings = Settings(
                database_path=Path(tmp) / "argus.db",
                screenshots_enabled=False,
            )
            investigator.db = db
            cancel_event = Event()

            async def discover(*args, **kwargs) -> list[Candidate]:  # noqa: ANN002, ANN003
                return []

            async def stop_during_wait(event: Event | None, delay_seconds: int) -> bool:
                self.assertEqual(db.get_run(run_id)["status"], "running")
                self.assertEqual(delay_seconds, 30)
                assert event is not None
                event.set()
                return True

            investigator._discover_candidates = discover
            investigator._wait_for_discovery_retry = stop_during_wait

            asyncio.run(investigator._run(run_id, "онлайн казино", 100, False, cancel_event, "auto"))

            self.assertEqual(db.get_run(run_id)["status"], "canceled")
            self.assertEqual(db.count_findings(run_id), 0)

    def test_later_discovery_round_reads_deeper_search_pages(self) -> None:
        investigator = object.__new__(Investigator)
        investigator.settings = Settings(search_result_pages=1, search_pages_enabled=True)
        page_indexes: list[int] = []

        class FakeDb:
            @staticmethod
            def add_log(*args, **kwargs) -> None:  # noqa: ANN002, ANN003
                return None

        def search_pages(*args, page_index: int = 0, **kwargs) -> list[Candidate]:  # noqa: ANN002, ANN003
            page_indexes.append(page_index)
            return []

        investigator.db = FakeDb()
        investigator._discover_from_search_pages = search_pages

        investigator._discover_with_user_search(
            1,
            "онлайн казино",
            discovery_limit=100,
            max_candidates=100,
            search_mode="casino",
            page_offset=20,
        )

        self.assertTrue(page_indexes)
        self.assertEqual(set(page_indexes), {20})

    def test_discovery_rotates_queries_before_advancing_page(self) -> None:
        investigator = object.__new__(Investigator)
        investigator.settings = Settings(osint_feeds_enabled=False, search_result_pages=10)
        investigator.groq = None
        schedule: list[tuple[int, int]] = []

        class FakeDb:
            @staticmethod
            def add_log(*args, **kwargs) -> None:  # noqa: ANN002, ANN003
                return None

            @staticmethod
            def known_domains() -> set[str]:
                return set()

        def user_search(
            run_id: int,
            seed_query: str | None,
            discovery_limit: int,
            max_candidates: int,
            search_mode: str = "auto",
            page_offset: int = 0,
            query_offset: int = 0,
        ) -> list[Candidate]:
            schedule.append((page_offset, query_offset))
            return []

        investigator.db = FakeDb()
        investigator._discover_with_user_search = user_search
        investigator._discover_from_bootstrap = lambda *args, **kwargs: []
        investigator._discover_from_algorithmic_mirrors = lambda *args, **kwargs: []

        for discovery_round in (0, 6, 12):
            asyncio.run(
                investigator._discover_candidates(
                    1,
                    "онлайн казино",
                    100,
                    "casino",
                    discovery_round=discovery_round,
                    use_groq=False,
                )
            )

        self.assertEqual(schedule, [(0, 0), (0, 6), (1, 0)])

    def test_later_round_refills_locally_without_repeating_web_search(self) -> None:
        investigator = object.__new__(Investigator)
        investigator.settings = Settings(osint_candidate_pool_size=5000, osint_feeds_enabled=False)
        investigator.groq = None
        algorithmic_limits: list[int] = []

        class FakeDb:
            @staticmethod
            def add_log(*args, **kwargs) -> None:  # noqa: ANN002, ANN003
                return None

            @staticmethod
            def known_domains() -> set[str]:
                return set()

        def fail_user_search(*args, **kwargs):  # noqa: ANN002, ANN003
            raise AssertionError("Intermediate pass must not repeat external search")

        def algorithmic_refill(seed_query, limit, excluded_domains, search_mode="auto"):  # noqa: ANN001
            algorithmic_limits.append(limit)
            return [
                Candidate(
                    url="https://new-casino-mirror.example",
                    domain="new-casino-mirror.example",
                    category="casino",
                    why="Algorithmic candidate for live verification",
                    search_query=seed_query,
                )
            ]

        investigator.db = FakeDb()
        investigator._discover_with_user_search = fail_user_search
        investigator._discover_from_bootstrap = lambda *args, **kwargs: []
        investigator._discover_from_algorithmic_mirrors = algorithmic_refill

        candidates = asyncio.run(
            investigator._discover_candidates(
                1,
                "онлайн казино",
                100,
                "casino",
                discovery_round=1,
                use_groq=False,
            )
        )

        self.assertEqual([candidate.domain for candidate in candidates], ["new-casino-mirror.example"])
        self.assertEqual(algorithmic_limits, [5000])

    def test_empty_discovery_backoff_is_bounded(self) -> None:
        self.assertEqual(Investigator._discovery_retry_delay(1), 30)
        self.assertEqual(Investigator._discovery_retry_delay(2), 60)
        self.assertEqual(Investigator._discovery_retry_delay(20), 300)


if __name__ == "__main__":
    unittest.main()
