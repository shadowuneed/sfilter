from __future__ import annotations

import asyncio
import unittest

import httpx

from app.config import Settings
from app.services import investigator as investigator_module
from app.services.evidence import EvidenceResult
from app.services.investigator import Candidate, Investigator
from app.services.screenshots import ScreenshotResult


GROUNDING_REDIRECT = (
    "https://vertexaisearch.cloud.google.com/grounding-api-redirect/"
    "AUZIYQFQ5a8vLPgWCmaJ1NFNqsqdmXsf0-g_DszycTTnICT4kppcu8kDJNV7YIS7Wr_OoiRu5iDXFm2ryilKBIYmoI5Z"
)


class InvestigatorCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.investigator = object.__new__(Investigator)

    def test_rejects_google_grounding_redirect_as_candidate(self) -> None:
        candidate = self.investigator._candidate_from_item(
            {
                "url": GROUNDING_REDIRECT,
                "domain": "vertexaisearch.cloud.google.com",
                "category": "suspicious",
            },
            default_sources=[],
        )

        self.assertIsNone(candidate)

    def test_uses_real_domain_when_url_is_grounding_redirect(self) -> None:
        candidate = self.investigator._candidate_from_item(
            {
                "url": GROUNDING_REDIRECT,
                "domain": "mirror-entry.lol",
                "category": "casino",
                "source_urls": [GROUNDING_REDIRECT, "https://public-report.kz/case"],
            },
            default_sources=[],
        )

        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.domain, "mirror-entry.lol")
        self.assertEqual(candidate.url, "https://mirror-entry.lol")
        self.assertEqual(candidate.source_urls, ["https://public-report.kz/case"])

    def test_unwraps_google_search_redirect_to_direct_candidate(self) -> None:
        candidate = self.investigator._candidate_from_item(
            {
                "url": "https://www.google.com/url?q=https%3A%2F%2Fpinco4.aktif.kz%2F&sa=U",
                "category": "suspicious",
                "search_query": "online casino Kazakhstan",
            },
            default_sources=[],
        )

        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.domain, "pinco4.aktif.kz")
        self.assertEqual(candidate.url, "https://pinco4.aktif.kz")
        self.assertEqual(candidate.category, "casino")

    def test_grounding_source_extracts_direct_site_not_review_platform(self) -> None:
        candidates = self.investigator._candidates_from_grounding_sources(
            [
                {
                    "url": "https://www.scamadviser.com/check-website/top.45minut.kz",
                    "title": "top.45minut.kz online casino Kazakhstan",
                }
            ],
            "online casino Kazakhstan",
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].domain, "top.45minut.kz")
        self.assertEqual(candidates[0].url, "https://top.45minut.kz")
        self.assertEqual(candidates[0].category, "casino")

    def test_easy_money_grounding_source_is_treated_as_user_risk_search(self) -> None:
        candidates = self.investigator._candidates_from_grounding_sources(
            [
                {
                    "url": "https://fast-money.example/register",
                    "title": "Легкие деньги и быстрый заработок онлайн",
                }
            ],
            "легкие деньги",
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].domain, "fast-money.example")
        self.assertEqual(candidates[0].category, "scam")

    def test_grounding_source_rejects_informational_money_article(self) -> None:
        candidates = self.investigator._candidates_from_grounding_sources(
            [
                {
                    "url": "https://sky.pro/wiki/money/7-proverennyh-sposobov-kak-zarabatyvat-na-usdt-polnoe-rukovodstvo/",
                    "title": "7 проверенных способов как зарабатывать на USDT",
                }
            ],
            "легкие деньги",
        )

        self.assertEqual(candidates, [])

    def test_search_html_extracts_duckduckgo_redirect_target(self) -> None:
        html = """
        <html><body>
          <div class="result">
            <a class="result__a" href="/l/?uddg=https%3A%2F%2Fplay-slots.example%2Fregister">
              Онлайн казино слоты на деньги
            </a>
            <a href="/html/?q=online+casino">next</a>
          </div>
        </body></html>
        """

        candidates = self.investigator._candidates_from_search_html(
            query="онлайн казино",
            html=html,
            source_url="https://html.duckduckgo.com/html/?q=online+casino",
            engine="duckduckgo",
            limit=10,
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].domain, "play-slots.example")
        self.assertEqual(candidates[0].url, "https://play-slots.example/register")
        self.assertEqual(candidates[0].category, "casino")

    def test_search_html_rejects_unrelated_search_result(self) -> None:
        html = """
        <html><body>
          <div class="result">
            <a href="https://ordinary-news.example/story">Weather and local news</a>
          </div>
        </body></html>
        """

        candidates = self.investigator._candidates_from_search_html(
            query="онлайн казино",
            html=html,
            source_url="https://www.google.com/search?q=online+casino",
            engine="google",
            limit=10,
        )

        self.assertEqual(candidates, [])

    def test_search_html_rejects_informational_money_articles(self) -> None:
        html = """
        <html><body>
          <div class="result">
            <a href="https://www.bcc.kz/bcc-journal/investments_in_kazakhstan/">
              Куда инвестировать в Казахстане
            </a>
          </div>
          <div class="result">
            <a href="https://sky.pro/wiki/money/7-proverennyh-sposobov-kak-zarabatyvat-na-usdt-polnoe-rukovodstvo/">
              7 проверенных способов как зарабатывать на USDT
            </a>
          </div>
          <div class="result">
            <a href="https://finance.kz/news/legkie-dengi-i-bystryy-dohod/">
              Легкие деньги и быстрый доход: обзор новостей
            </a>
          </div>
        </body></html>
        """

        candidates = self.investigator._candidates_from_search_html(
            query="легкие деньги",
            html=html,
            source_url="https://www.google.com/search?q=легкие+деньги",
            engine="google",
            limit=10,
        )

        self.assertEqual(candidates, [])

    def test_search_html_keeps_direct_kz_casino_landing(self) -> None:
        html = """
        <html><body>
          <div class="result">
            <a href="https://top.45minut.kz/">
              Онлайн казино играть на деньги, регистрация и бонус
            </a>
          </div>
        </body></html>
        """

        candidates = self.investigator._candidates_from_search_html(
            query="онлайн казино",
            html=html,
            source_url="https://www.google.com/search?q=онлайн+казино",
            engine="google",
            limit=10,
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].domain, "top.45minut.kz")
        self.assertEqual(candidates[0].category, "casino")

    def test_search_html_keeps_short_kz_landing_from_casino_query(self) -> None:
        html = """
        <html><body>
          <div class="result">
            <a href="https://pinco4.aktif.kz/">pinco4.aktif.kz</a>
          </div>
        </body></html>
        """

        candidates = self.investigator._candidates_from_search_html(
            query="онлайн казино",
            html=html,
            source_url="https://www.google.com/search?q=онлайн+казино",
            engine="google",
            limit=10,
            search_mode="casino",
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].domain, "pinco4.aktif.kz")

    def test_search_html_rejects_casino_top_list_article(self) -> None:
        html = """
        <html><body>
          <div class="result">
            <a href="https://casino-rating.example/top-10-online-casino-kazakhstan">
              Топ 10 онлайн казино Казахстана: обзор и рейтинг
            </a>
          </div>
        </body></html>
        """

        candidates = self.investigator._candidates_from_search_html(
            query="онлайн казино",
            html=html,
            source_url="https://www.google.com/search?q=онлайн+казино",
            engine="google",
            limit=10,
        )

        self.assertEqual(candidates, [])

    def test_search_html_keeps_global_casino_results(self) -> None:
        html = """
        <html><body>
          <div class="result">
            <a href="https://mrbit.bg/bg">Mr Bit Casino Bulgaria</a>
          </div>
          <div class="result">
            <a href="https://palmsbet.com/bg/casino/slots">Palms Bet casino slots</a>
          </div>
        </body></html>
        """

        candidates = self.investigator._candidates_from_search_html(
            query="онлайн казино",
            html=html,
            source_url="https://www.google.com/search?q=онлайн+казино",
            engine="google",
            limit=10,
            search_mode="casino",
        )

        self.assertCountEqual([candidate.domain for candidate in candidates], ["mrbit.bg", "palmsbet.com"])

    def test_feed_parser_extracts_csv_and_hosts_domains(self) -> None:
        csv_tokens = self.investigator._feed_tokens(
            '# comment\n"2026-06-30","https://bad-login.example/home.php","online"\n',
            "csv",
        )
        hosts_tokens = self.investigator._feed_tokens(
            "0.0.0.0 casino-mirror.example\n||bonus-slot.example^\n",
            "hosts_file",
        )

        self.assertIn("https://bad-login.example/home.php", csv_tokens)
        self.assertNotIn("home.php", csv_tokens)
        self.assertIn("casino-mirror.example", hosts_tokens)
        self.assertIn("bonus-slot.example", hosts_tokens)

    def test_known_domains_are_dropped_from_auto_discovery(self) -> None:
        class FakeDb:
            def __init__(self) -> None:
                self.logs = []

            def known_domains(self) -> set[str]:
                return {"mycasino.kz"}

            def add_log(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
                self.logs.append((args, kwargs))

        class FakeGemini:
            available = False

        self.investigator.settings = Settings(
            osint_feeds_enabled=False,
            osint_candidate_pool_size=10,
            search_pages_enabled=False,
        )
        self.investigator.db = FakeDb()
        self.investigator.gemini = FakeGemini()

        candidates = asyncio.run(self.investigator._discover_candidates(1, "mycasino.kz", 1))

        self.assertFalse(any(candidate.domain == "mycasino.kz" for candidate in candidates))
        self.assertEqual(candidates, [])
        last_log = self.investigator.db.logs[-1][0]
        self.assertEqual(last_log[3]["skipped_known"], 1)

    def test_user_search_mode_does_not_start_from_feeds_or_bootstrap(self) -> None:
        class FakeDb:
            def __init__(self) -> None:
                self.logs = []

            def known_domains(self) -> set[str]:
                return set()

            def add_log(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
                self.logs.append((args, kwargs))

        class FakeGemini:
            available = False

        async def fail_feeds(*args, **kwargs):  # noqa: ANN002, ANN003
            raise AssertionError("OSINT feeds must not lead user-search discovery")

        def fail_bootstrap(*args, **kwargs):  # noqa: ANN002, ANN003
            raise AssertionError("Bootstrap candidates must not be mixed into user-search discovery")

        def fail_algorithmic(*args, **kwargs):  # noqa: ANN002, ANN003
            raise AssertionError("Algorithmic mirrors must not be mixed into user-search discovery")

        def fake_user_search(run_id, seed_query, discovery_limit, max_candidates, search_mode="auto"):  # noqa: ANN001
            return [
                Candidate(
                    url="https://live-casino.example",
                    domain="live-casino.example",
                    category="casino",
                    why="Search result",
                    search_query="онлайн казино Казахстан",
                )
            ]

        self.investigator.settings = Settings(osint_feeds_enabled=True, osint_candidate_pool_size=10)
        self.investigator.db = FakeDb()
        self.investigator.gemini = FakeGemini()
        self.investigator._discover_from_feeds = fail_feeds
        self.investigator._discover_from_bootstrap = fail_bootstrap
        self.investigator._discover_from_algorithmic_mirrors = fail_algorithmic
        self.investigator._discover_with_user_search = fake_user_search

        candidates = asyncio.run(self.investigator._discover_candidates(1, "онлайн казино", 1))

        self.assertEqual([candidate.domain for candidate in candidates], ["live-casino.example"])
        self.assertEqual(candidates[0].search_query, "онлайн казино Казахстан")

    def test_empty_casino_user_search_falls_back_to_bootstrap(self) -> None:
        class FakeDb:
            def __init__(self) -> None:
                self.logs = []

            def known_domains(self) -> set[str]:
                return set()

            def add_log(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
                self.logs.append((args, kwargs))

        class FakeGemini:
            available = False

        async def fail_feeds(*args, **kwargs):  # noqa: ANN002, ANN003
            raise AssertionError("OSINT feeds must not lead user-search discovery")

        def fake_user_search(run_id, seed_query, discovery_limit, max_candidates, search_mode="auto"):  # noqa: ANN001
            return []

        def fake_bootstrap(seed_query, limit, search_mode="auto"):  # noqa: ANN001
            return [
                Candidate(
                    url="https://pin-up.kz",
                    domain="pin-up.kz",
                    category="casino",
                    why="Fallback casino candidate",
                    search_query=seed_query,
                )
            ][:limit]

        self.investigator.settings = Settings(osint_feeds_enabled=True, osint_candidate_pool_size=10)
        self.investigator.db = FakeDb()
        self.investigator.gemini = FakeGemini()
        self.investigator._discover_from_feeds = fail_feeds
        self.investigator._discover_with_user_search = fake_user_search
        self.investigator._discover_from_bootstrap = fake_bootstrap

        candidates = asyncio.run(self.investigator._discover_candidates(1, "онлайн казино", 1, "casino"))

        self.assertEqual([candidate.domain for candidate in candidates], ["pin-up.kz"])

    def test_large_casino_user_search_refills_partial_results(self) -> None:
        class FakeDb:
            def __init__(self) -> None:
                self.logs = []

            def known_domains(self) -> set[str]:
                return set()

            def add_log(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
                self.logs.append((args, kwargs))

        class FakeGemini:
            available = False

        captured_bootstrap_limits: list[int] = []

        def fake_user_search(run_id, seed_query, discovery_limit, max_candidates, search_mode="auto"):  # noqa: ANN001
            return [
                Candidate(
                    url=f"https://casino-{index}.kz",
                    domain=f"casino-{index}.kz",
                    category="casino",
                    why="Search result",
                    search_query=seed_query,
                )
                for index in range(10)
            ]

        def fake_bootstrap(seed_query, limit, search_mode="auto"):  # noqa: ANN001
            captured_bootstrap_limits.append(limit)
            return []

        def fake_algorithmic(seed_query, limit, excluded_domains, search_mode="auto"):  # noqa: ANN001
            return []

        self.investigator.settings = Settings(osint_candidate_pool_size=700)
        self.investigator.db = FakeDb()
        self.investigator.gemini = FakeGemini()
        self.investigator._discover_with_user_search = fake_user_search
        self.investigator._discover_from_bootstrap = fake_bootstrap
        self.investigator._discover_from_algorithmic_mirrors = fake_algorithmic

        candidates = asyncio.run(self.investigator._discover_candidates(1, "онлайн казино", 100, "casino"))

        self.assertEqual(len(candidates), 10)
        self.assertEqual(captured_bootstrap_limits, [490])

    def test_casino_check_limit_overscans_candidates(self) -> None:
        self.investigator.settings = Settings(max_candidates_per_run=2000)

        limit = self.investigator._candidate_check_limit(100, 700, "casino")

        self.assertEqual(limit, 500)

    def test_user_search_filter_rejects_unrelated_suspicious_domain(self) -> None:
        candidate = Candidate(
            url="https://ordinary-news.example",
            domain="ordinary-news.example",
            category="suspicious",
            why="generic result",
            search_query="",
        )

        self.assertFalse(Investigator._candidate_matches_user_search(candidate, "онлайн казино"))

    def test_casino_mode_queries_do_not_include_easy_money(self) -> None:
        queries = Investigator._user_search_queries("онлайн казино", "casino")

        self.assertLessEqual(len(queries), 10)
        joined = " ".join(queries).lower()
        self.assertIn("онлайн казино", joined)
        self.assertIn("slots", joined)
        self.assertNotIn("ставки", joined)
        self.assertNotIn("букмекер", joined)
        self.assertNotIn("легкие деньги", joined)
        self.assertNotIn("usdt", joined)

    def test_casino_mode_rejects_betting_only_candidate(self) -> None:
        candidate = Candidate(
            url="https://bookmaker.example/sports",
            domain="bookmaker.example",
            category="betting",
            why="Спортивные ставки и букмекерская линия",
            search_query="онлайн казино",
        )

        self.assertFalse(Investigator._candidate_matches_user_search(candidate, "онлайн казино", "casino"))

    def test_casino_mode_rejects_official_bookmaker_domain(self) -> None:
        candidate = Candidate(
            url="https://fonbet.kz",
            domain="fonbet.kz",
            category="casino",
            why="Search result with casino words",
            search_query="онлайн казино",
        )

        self.assertFalse(Investigator._candidate_matches_user_search(candidate, "онлайн казино", "casino"))

    def test_casino_mode_rejects_bookmaker_brand_mirror_without_casino_product(self) -> None:
        candidate = Candidate(
            url="https://1xbet-kz.net",
            domain="1xbet-kz.net",
            category="casino",
            why="Algorithmic-кандидат: домен похож на зеркало известного risky-бренда",
            search_query="онлайн казино",
        )

        self.assertFalse(Investigator._candidate_matches_user_search(candidate, "онлайн казино", "casino"))

    def test_casino_mode_rejects_1win_bonus_mirror(self) -> None:
        candidate = Candidate(
            url="https://1win-bonus.vip",
            domain="1win-bonus.vip",
            category="casino",
            why="Algorithmic mirror candidate",
            search_query="онлайн казино",
        )

        self.assertFalse(Investigator._candidate_matches_user_search(candidate, "онлайн казино", "casino"))

    def test_bookmaker_bootstrap_item_is_not_casino_category(self) -> None:
        one_xbet = {"domain": "1xbet.com", "brand": "1xBet", "aliases": ["1xbet", "1x bet"], "category": "casino"}
        one_win = {"domain": "1win.com", "brand": "1win", "aliases": ["1win", "1 win"], "category": "casino"}
        vavada = {"domain": "vavada.com", "brand": "Vavada", "aliases": ["vavada"], "category": "casino"}

        self.assertEqual(Investigator._bootstrap_item_category(one_xbet), "betting")
        self.assertEqual(Investigator._bootstrap_item_category(one_win), "betting")
        self.assertEqual(Investigator._bootstrap_item_category(vavada), "casino")

    def test_casino_bootstrap_skips_betting_first_brands(self) -> None:
        candidates = self.investigator._discover_from_bootstrap("онлайн казино", 12, "casino")
        domains = [candidate.domain for candidate in candidates]

        self.assertTrue(candidates)
        self.assertNotIn("1xbet.com", domains)
        self.assertNotIn("1win.com", domains)
        self.assertNotIn("mostbet.com", domains)
        self.assertTrue(all(candidate.category == "casino" for candidate in candidates))

    def test_casino_algorithmic_refill_skips_betting_first_brands(self) -> None:
        candidates = self.investigator._discover_from_algorithmic_mirrors("онлайн казино", 40, set(), "casino")
        domains = [candidate.domain for candidate in candidates]

        self.assertTrue(candidates)
        self.assertFalse(any(domain.startswith(("1xbet", "1win", "mostbet")) for domain in domains))
        self.assertTrue(any("pinup" in domain or "vavada" in domain or "vulkan" in domain for domain in domains))

    def test_casino_mode_keeps_casino_path_candidate(self) -> None:
        candidate = Candidate(
            url="https://casino-play.kz/casino",
            domain="casino-play.kz",
            category="casino",
            why="Casino page from search result",
            search_query="онлайн казино",
        )

        self.assertTrue(Investigator._candidate_matches_user_search(candidate, "онлайн казино", "casino"))

    def test_casino_mode_keeps_global_casino_candidate(self) -> None:
        candidate = Candidate(
            url="https://8888.bg/casino",
            domain="8888.bg",
            category="casino",
            why="Casino page from search result",
            search_query="онлайн казино",
        )

        self.assertTrue(Investigator._candidate_matches_user_search(candidate, "онлайн казино", "casino"))

    def test_casino_mode_content_skip_rejects_betting_only_page(self) -> None:
        class FakeEvidence:
            final_url = "https://bookmaker.example/sports"

        candidate = Candidate(
            url="https://bookmaker.example/sports",
            domain="bookmaker.example",
            category="betting",
            why="Спортивные ставки",
        )
        content_ai = {
            "site_quality": {"quality": "usable"},
            "category_hint": "sports_betting_review",
            "casino_keywords": [],
            "betting_keywords": ["ставки на спорт"],
        }

        reason = Investigator._content_skip_reason(content_ai, FakeEvidence(), candidate, "casino")

        self.assertIn("режим casino", reason or "")

    def test_casino_mode_content_skip_rejects_official_bookmaker_domain(self) -> None:
        class FakeEvidence:
            final_url = "https://fonbet.kz"
            title = "Fonbet"
            description = ""
            text_excerpt = ""
            blocked_by_policy = False

        candidate = Candidate(
            url="https://fonbet.kz",
            domain="fonbet.kz",
            category="casino",
            why="Search result",
        )
        content_ai = {
            "site_quality": {"quality": "usable"},
            "category_hint": "online_casino",
            "casino_keywords": ["casino"],
            "betting_keywords": ["fonbet"],
            "pyramid_keywords": [],
            "signals": [],
        }

        reason = Investigator._content_skip_reason(content_ai, FakeEvidence(), candidate, "casino")

        self.assertIn("official bookmaker", reason or "")

    def test_content_skip_rejects_blocked_page_even_with_casino_signals(self) -> None:
        class FakeEvidence:
            final_url = "https://blocked-casino.example"
            title = "Access to this site is blocked"
            description = ""
            text_excerpt = "The requested resource is blocked by policy."
            blocked_by_policy = False

        candidate = Candidate(
            url="https://blocked-casino.example",
            domain="blocked-casino.example",
            category="casino",
            why="Search result",
        )
        content_ai = {
            "site_quality": {"quality": "usable", "markers": ["access to this site is blocked"]},
            "category_hint": "online_casino",
            "casino_keywords": ["casino", "slots"],
            "betting_keywords": [],
            "pyramid_keywords": [],
            "signals": ["casino keywords present"],
        }

        reason = Investigator._content_skip_reason(content_ai, FakeEvidence(), candidate, "casino")

        self.assertIn("blocked/restricted", reason or "")

    def test_casino_mode_content_skip_rejects_bookmaker_brand_without_casino_product(self) -> None:
        class FakeEvidence:
            final_url = "https://1xbet-kz.net"

        candidate = Candidate(
            url="https://1xbet-kz.net",
            domain="1xbet-kz.net",
            category="betting",
            why="Algorithmic mirror candidate",
        )
        content_ai = {
            "site_quality": {"quality": "usable"},
            "category_hint": "phishing",
            "casino_keywords": [],
            "betting_keywords": [],
            "pyramid_keywords": [],
        }

        reason = Investigator._content_skip_reason(content_ai, FakeEvidence(), candidate, "casino")

        self.assertIn("betting-first", reason or "")

    def test_casino_mode_content_rejects_bookmaker_brand_even_with_casino_product(self) -> None:
        class FakeEvidence:
            final_url = "https://1xbet-kz.net/casino"

        candidate = Candidate(
            url="https://1xbet-kz.net/casino",
            domain="1xbet-kz.net",
            category="betting",
            why="Search result",
        )
        content_ai = {
            "site_quality": {"quality": "usable"},
            "category_hint": "online_casino",
            "casino_keywords": ["slots", "roulette"],
            "betting_keywords": ["1xbet"],
            "pyramid_keywords": [],
        }

        reason = Investigator._content_skip_reason(content_ai, FakeEvidence(), candidate, "casino")

        self.assertIn("betting-first", reason or "")

    def test_casino_mode_content_allows_global_casino_page(self) -> None:
        class FakeEvidence:
            final_url = "https://mrbit.bg/bg"

        candidate = Candidate(
            url="https://mrbit.bg/bg",
            domain="mrbit.bg",
            category="casino",
            why="Casino page from search result",
        )
        content_ai = {
            "site_quality": {"quality": "usable"},
            "category_hint": "online_casino",
            "casino_keywords": ["casino"],
            "betting_keywords": [],
        }

        reason = Investigator._content_skip_reason(content_ai, FakeEvidence(), candidate, "casino")

        self.assertIsNone(reason)

    def test_user_search_uses_search_pages_without_gemini_by_default(self) -> None:
        class FakeDb:
            def __init__(self) -> None:
                self.logs = []

            def add_log(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
                self.logs.append((args, kwargs))

        def fake_search_pages(run_id, query, limit, search_mode="auto", disabled_engines=None):  # noqa: ANN001
            return [
                Candidate(
                    url="https://play-slots.example",
                    domain="play-slots.example",
                    category="casino",
                    why="Search page result",
                    search_query=query,
                )
            ]

        def fail_gemini(*args, **kwargs):  # noqa: ANN002, ANN003
            raise AssertionError("Gemini must not be used while GEMINI_USER_SEARCH_FALLBACK=false")

        self.investigator.settings = Settings(search_pages_enabled=True, gemini_user_search_fallback=False)
        self.investigator.db = FakeDb()
        self.investigator._discover_from_search_pages = fake_search_pages
        self.investigator._discover_with_gemini = fail_gemini

        candidates = self.investigator._discover_with_user_search(1, "онлайн казино", 10, 5)

        self.assertEqual([candidate.domain for candidate in candidates], ["play-slots.example"])

    def test_search_error_summary_sanitizes_google_429_url(self) -> None:
        request = httpx.Request("GET", "https://www.google.com/sorry/index?continue=very-long-url")
        response = httpx.Response(429, request=request)
        exc = httpx.HTTPStatusError(
            "Client error '429 Too Many Requests' for url 'https://www.google.com/sorry/index?continue=very-long-url'",
            request=request,
            response=response,
        )

        error, status_code = Investigator._search_error_summary(exc)

        self.assertEqual(error, "HTTP 429 Too Many Requests")
        self.assertEqual(status_code, 429)
        self.assertNotIn("sorry/index", error)

    def test_search_pages_aggregate_google_429_without_disabling_google(self) -> None:
        class FakeDb:
            def __init__(self) -> None:
                self.logs = []

            def add_log(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
                self.logs.append((args, kwargs))

        class FakeClient:
            requests: list[str] = []
            headers = {}

            def __init__(self, **kwargs) -> None:  # noqa: ANN003
                self.headers = dict(kwargs.get("headers") or {})
                FakeClient.headers = self.headers

            def __enter__(self) -> "FakeClient":
                return self

            def __exit__(self, *args) -> None:  # noqa: ANN002
                return None

            def get(self, url: str) -> httpx.Response:
                self.requests.append(url)
                request = httpx.Request("GET", url)
                if "google.com" in url:
                    return httpx.Response(429, request=request)
                return httpx.Response(200, text="<html><body></body></html>", request=request)

        original_client = investigator_module.httpx.Client
        investigator_module.httpx.Client = FakeClient
        try:
            self.investigator.settings = Settings()
            self.investigator.db = FakeDb()

            candidates = self.investigator._discover_with_user_search(1, "онлайн казино", 10, 5, "casino")
        finally:
            investigator_module.httpx.Client = original_client

        google_requests = [url for url in FakeClient.requests if "google.com" in url]
        self.assertGreaterEqual(len(google_requests), 2)
        self.assertEqual(candidates, [])
        self.assertFalse(any(log[0][2] == "Search engine temporarily disabled" for log in self.investigator.db.logs))
        degraded_logs = [log for log in self.investigator.db.logs if log[0][2] == "Search pages unavailable"]
        self.assertEqual(len(degraded_logs), 1)
        self.assertIn("Mozilla/5.0", FakeClient.headers.get("User-Agent", ""))

    def test_yandex_search_url_uses_text_query_param(self) -> None:
        engine = next(engine for engine in investigator_module.USER_SEARCH_ENGINES if engine["name"] == "yandex_kz")

        url = Investigator._search_engine_url(engine, "онлайн казино")

        self.assertIn("text=", url)
        self.assertNotIn("&q=", url)

    def test_search_html_extracts_yandex_redirect_target(self) -> None:
        html = """
        <html><body>
          <div class="serp-item">
            <a href="/clck/jsredir?url=https%3A%2F%2Fpinco4.aktif.kz%2F">
              Онлайн казино играть Казахстан
            </a>
          </div>
        </body></html>
        """

        candidates = self.investigator._candidates_from_search_html(
            query="онлайн казино",
            html=html,
            source_url="https://yandex.kz/search/?text=онлайн+казино",
            engine="yandex_kz",
            limit=10,
            search_mode="casino",
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].domain, "pinco4.aktif.kz")

    def test_bootstrap_adds_verification_candidates_when_discovery_is_empty(self) -> None:
        self.investigator.settings = Settings(seed_queries=["казино зеркало рабочий вход"])

        candidates = self.investigator._discover_from_bootstrap(None, 3)

        self.assertEqual(len(candidates), 3)
        self.assertTrue(all(candidate.why.startswith("Bootstrap-кандидат") for candidate in candidates))

    def test_build_finding_skips_active_http_site_without_html_content(self) -> None:
        class FakeDb:
            def __init__(self) -> None:
                self.logs = []

            def add_log(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
                self.logs.append((args, kwargs))

        class FakeEvidence:
            async def collect(self, url: str, run_id: int) -> EvidenceResult:
                return EvidenceResult(
                    requested_url=url,
                    final_url="http://no-ssl.example",
                    domain="no-ssl.example",
                    status_code=200,
                    active=True,
                    response_time_ms=95,
                    page_size_bytes=512,
                    dns={"records": ["203.0.113.10"], "mx_records": []},
                    tls={"valid": False, "error": "no certificate"},
                )

        class FakeScreenshots:
            async def capture(self, url: str, run_id: int, **kwargs) -> ScreenshotResult:  # noqa: ANN003
                return ScreenshotResult(path=None, error="browser blocked")

        class FakeContentAI:
            def analyze(self, url: str, evidence: EvidenceResult) -> dict:
                return {"signals": [], "risk_delta": 0}

        class FakeClassifier:
            def classify(self, url: str, evidence: EvidenceResult, content_ai: dict | None = None) -> dict:
                return {"available": False}

        self.investigator.settings = Settings()
        self.investigator.db = FakeDb()
        self.investigator.evidence = FakeEvidence()
        self.investigator.screenshots = FakeScreenshots()
        self.investigator.content_ai = FakeContentAI()
        self.investigator.cyberscan = FakeClassifier()
        self.investigator.ml = FakeClassifier()

        finding = asyncio.run(
            self.investigator._build_finding(
                1,
                Candidate(
                    url="https://no-ssl.example",
                    domain="no-ssl.example",
                    category="suspicious",
                    why="unit test",
                ),
                None,
                True,
            )
        )

        self.assertTrue(finding["_skip"])
        self.assertEqual(finding["status_code"], 200)
        self.assertIn("пустышку", finding["_skip_reason"])


if __name__ == "__main__":
    unittest.main()
