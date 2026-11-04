from __future__ import annotations

import asyncio
import unittest
from threading import Event
from unittest.mock import AsyncMock, Mock, patch

import httpx

from app.config import Settings
from app.services.investigator import Investigator


SOURCE = {
    "name": "gambling_feed",
    "url": "https://feed.example/gambling.txt",
    "category": "casino",
    "parser": "hosts_file",
}


class FakeFeedClient:
    def __init__(self, get):
        self.get = get

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class DiscoveryCancellationRegressionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.investigator = object.__new__(Investigator)
        self.investigator.settings = Settings(osint_feeds=[])
        self.investigator.db = Mock()

    async def test_cancel_during_feed_download_returns_without_waiting_for_response(self) -> None:
        cancel = Event()
        entered = asyncio.Event()
        download_canceled = asyncio.Event()

        async def download(*args, **kwargs):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                download_canceled.set()

        with (
            patch.object(self.investigator, "_osint_sources", return_value=[SOURCE]),
            patch("app.services.investigator.httpx.AsyncClient", return_value=FakeFeedClient(download)),
        ):
            task = asyncio.create_task(self.investigator._discover_from_feeds(1, 100, "casino", cancel_event=cancel))
            await entered.wait()
            cancel.set()
            result = await asyncio.wait_for(task, timeout=0.4)

        self.assertEqual(result, [])
        self.assertTrue(download_canceled.is_set())

    async def test_cancel_during_feed_parsing_stops_consuming_the_source(self) -> None:
        cancel = Event()
        consumed = []

        def tokens(*args, **kwargs):
            for index in range(1_000):
                consumed.append(index)
                if index == 3:
                    cancel.set()
                yield f"casino-{index}.com"

        response = httpx.Response(200, request=httpx.Request("GET", SOURCE["url"]), text="unused")
        client = FakeFeedClient(AsyncMock(return_value=response))
        with (
            patch.object(self.investigator, "_osint_sources", return_value=[SOURCE]),
            patch.object(self.investigator, "_iter_feed_tokens", side_effect=tokens),
            patch("app.services.investigator.httpx.AsyncClient", return_value=client),
        ):
            result = await self.investigator._discover_from_feeds(1, 100, "casino", cancel_event=cancel)

        self.assertEqual(result, [])
        self.assertLessEqual(len(consumed), 4)

    async def test_total_download_deadline_moves_on_to_the_next_source(self) -> None:
        self.investigator.settings = Settings(osint_feeds=[], request_timeout_seconds=0.03)
        next_source = {**SOURCE, "name": "next_feed", "url": "https://feed.example/next.txt"}
        download_canceled = asyncio.Event()

        async def download(url):
            if url == SOURCE["url"]:
                try:
                    await asyncio.Event().wait()
                finally:
                    download_canceled.set()
            return httpx.Response(200, request=httpx.Request("GET", url), text="0.0.0.0 casino-safe.com\n")

        with (
            patch.object(self.investigator, "_osint_sources", return_value=[SOURCE, next_source]),
            patch("app.services.investigator.httpx.AsyncClient", return_value=FakeFeedClient(download)),
        ):
            result = await asyncio.wait_for(
                self.investigator._discover_from_feeds(1, 100, "casino"), timeout=0.4
            )

        self.assertTrue(download_canceled.is_set())
        self.assertEqual([candidate.domain for candidate in result], ["casino-safe.com"])

    def test_feed_windows_bound_work_and_visit_later_domains_on_later_passes(self) -> None:
        body = "".join(f"0.0.0.0 casino-{index}.com\n" for index in range(5))
        pages = [
            list(self.investigator._iter_feed_tokens(body, "hosts_file", page=page, line_limit=2))
            for page in range(4)
        ]

        self.assertEqual(pages[0], ["casino-0.com", "casino-1.com"])
        self.assertEqual(pages[1], ["casino-2.com", "casino-3.com"])
        self.assertEqual(pages[2], ["casino-4.com"])
        self.assertEqual(pages[3], pages[0])


if __name__ == "__main__":
    unittest.main()
