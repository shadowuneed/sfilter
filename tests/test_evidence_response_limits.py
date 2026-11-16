from __future__ import annotations

import hashlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import httpx

from app.config import Settings
from app.services.evidence import EvidenceCollector


BODY_LIMIT = 2 * 1024 * 1024
READ_CHUNK = 16 * 1024


class CountingBody(httpx.AsyncByteStream):
    def __init__(self, total_bytes: int, chunk_bytes: int = 8192):
        self.total_bytes = total_bytes
        self.chunk_bytes = chunk_bytes
        self.yielded_bytes = 0
        self.closed = False

    async def __aiter__(self):
        while self.yielded_bytes < self.total_bytes:
            count = min(self.chunk_bytes, self.total_bytes - self.yielded_bytes)
            self.yielded_bytes += count
            yield b"x" * count

    async def aclose(self) -> None:
        self.closed = True


class EvidenceResponseLimitTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        directory = Path(self.temporary.name)
        self.collector = EvidenceCollector(Settings(
            evidence_dir=directory, database_path=directory / "unused.db", fast_evidence_mode=True,
        ))
        self.real_client = httpx.AsyncClient

    def clients(self, handler):
        def factory(**kwargs):
            kwargs.pop("proxy", None)
            return self.real_client(transport=httpx.MockTransport(handler), **kwargs)
        return patch("app.services.evidence.httpx.AsyncClient", side_effect=factory)

    async def test_large_body_reads_only_bounded_prefix_and_closes_stream(self) -> None:
        body = CountingBody(32 * 1024 * 1024)

        def handler(request):
            return httpx.Response(200, headers={"content-type": "text/html"}, stream=body)

        with self.clients(handler), patch.object(self.collector, "_parse_html"):
            result = await self.collector.collect("https://fixture.example/", 1)

        self.assertLessEqual(body.yielded_bytes, BODY_LIMIT + READ_CHUNK)
        self.assertLess(body.yielded_bytes, body.total_bytes)
        self.assertTrue(body.closed)
        self.assertEqual(result.page_size_bytes, BODY_LIMIT)
        self.assertTrue(result.as_evidence()["response_body_truncated"])
        self.assertEqual(result.as_evidence()["response_body_limit_bytes"], BODY_LIMIT)
        self.assertTrue(result.active)

    async def test_small_html_preserves_text_hash_status_and_charset(self) -> None:
        html = "<html><title>Казино</title><body>Проверка страницы casino</body></html>"
        payload = html.encode("windows-1251")

        def handler(request):
            return httpx.Response(200, headers={"content-type": "text/html; charset=windows-1251"}, content=payload)

        with self.clients(handler):
            result = await self.collector.collect("https://fixture.example/", 2)

        self.assertEqual(result.title, "Казино")
        self.assertEqual(result.html_sha256, hashlib.sha256(html.encode("utf-8")).hexdigest())
        self.assertEqual(result.page_size_bytes, len(payload))
        self.assertEqual(result.status_code, 200)
        self.assertTrue(result.tls_verified_fetch)
        self.assertGreaterEqual(result.response_time_ms, 0)
        self.assertFalse(result.as_evidence()["response_body_truncated"])
        saved = Path(self.temporary.name) / Path(result.html_path).name
        self.assertEqual(saved.read_text(encoding="utf-8"), html)

    async def test_utf8_without_charset_and_http_error_are_preserved(self) -> None:
        html = "<html><title>Не найдено</title><body>Ошибка сайта</body></html>"

        def handler(request):
            return httpx.Response(404, content=html.encode("utf-8"))

        with self.clients(handler):
            result = await self.collector.collect("https://fixture.example/missing", 3)

        self.assertEqual(result.status_code, 404)
        self.assertFalse(result.active)
        self.assertEqual(result.title, "Не найдено")
        self.assertEqual(result.final_url, "https://fixture.example/missing")

    async def test_redirect_history_is_preserved_without_reading_large_redirect_body(self) -> None:
        redirect_body = CountingBody(32 * 1024 * 1024)

        def handler(request):
            if request.url.path == "/start":
                return httpx.Response(302, headers={"location": "/landing"}, stream=redirect_body)
            return httpx.Response(200, headers={"content-type": "text/html"}, content=b"<title>Landing</title>")

        with self.clients(handler):
            result = await self.collector.collect("https://fixture.example/start", 4)

        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.final_url, "https://fixture.example/landing")
        self.assertEqual(result.redirect_count, 1)
        self.assertEqual(result.redirect_chain, [{"status_code": 302, "url": "https://fixture.example/start"}])
        self.assertEqual(result.title, "Landing")
        self.assertTrue(redirect_body.closed)
        self.assertEqual(redirect_body.yielded_bytes, 0)

    async def test_exact_limit_body_is_not_marked_truncated(self) -> None:
        body = CountingBody(BODY_LIMIT)
        with self.clients(lambda request: httpx.Response(200, stream=body)), patch.object(self.collector, "_parse_html"):
            result = await self.collector.collect("https://fixture.example/", 5)
        self.assertEqual(result.page_size_bytes, BODY_LIMIT)
        self.assertFalse(result.as_evidence()["response_body_truncated"])
        self.assertTrue(body.closed)


if __name__ == "__main__":
    unittest.main()
