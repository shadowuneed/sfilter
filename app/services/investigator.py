from __future__ import annotations

import asyncio
import csv
import re
from dataclasses import dataclass, field
from io import StringIO
from threading import Event
from typing import Any

import httpx

from app.config import Settings
from app.database import Database, utc_now
from app.services.domains import (
    extract_domain,
    find_domains,
    is_candidate_domain,
    is_candidate_url,
    is_technical_url,
    likely_related_domains,
    normalize_url,
    registered_domain,
)
from app.services.content_intelligence import ContentIntelligence
from app.services.cyberscan_classifier import CyberScanClassifier
from app.services.evidence import EvidenceCollector, score_finding
from app.services.gemini import GeminiAPIError, GeminiClient, GeminiQuotaError
from app.services.ml_classifier import DomainMLClassifier
from app.services.screenshots import ScreenshotService


CYBERSCAN_OSINT_SOURCES = [
    {
        "name": "openphish",
        "url": "https://openphish.com/feed.txt",
        "category": "phishing",
        "parser": "plain_list",
    },
    {
        "name": "urlhaus",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "category": "malware",
        "parser": "csv",
    },
    {
        "name": "phishing_database",
        "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        "category": "phishing",
        "parser": "plain_list",
    },
    {
        "name": "stevenblack_gambling",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts",
        "category": "casino",
        "parser": "hosts_file",
    },
    {
        "name": "stopgambling",
        "url": "https://raw.githubusercontent.com/StopGambling/domain-list/main/domains.txt",
        "category": "casino",
        "parser": "plain_list",
    },
]

BOOTSTRAP_CANDIDATES = [
    {"domain": "1xbet.com", "category": "casino", "brand": "1xBet", "aliases": ["1xbet", "1x bet"]},
    {"domain": "1win.com", "category": "casino", "brand": "1win", "aliases": ["1win", "1 win"]},
    {"domain": "mostbet.com", "category": "casino", "brand": "Mostbet", "aliases": ["mostbet", "most bet"]},
    {"domain": "mostbet-kz.org", "category": "casino", "brand": "Mostbet", "aliases": ["mostbet", "most bet"]},
    {"domain": "pin-up.kz", "category": "casino", "brand": "Pin-Up", "aliases": ["pinup", "pin-up", "pin up"]},
    {"domain": "pin-up.com", "category": "casino", "brand": "Pin-Up", "aliases": ["pinup", "pin-up", "pin up"]},
    {"domain": "olimpbet.kz", "category": "casino", "brand": "Olimpbet", "aliases": ["olimp", "olimpbet"]},
    {"domain": "melbet.com", "category": "casino", "brand": "Melbet", "aliases": ["melbet", "mel bet"]},
    {"domain": "fonbet.kz", "category": "casino", "brand": "Fonbet", "aliases": ["fonbet", "fon bet"]},
    {"domain": "parimatch.kz", "category": "casino", "brand": "Parimatch", "aliases": ["parimatch", "pari match"]},
    {"domain": "bet365.com", "category": "casino", "brand": "Bet365", "aliases": ["bet365", "bet 365"]},
    {"domain": "vavada.com", "category": "casino", "brand": "Vavada", "aliases": ["vavada"]},
    {"domain": "vulkanvegas.com", "category": "casino", "brand": "Vulkan Vegas", "aliases": ["vulkan", "vulkan vegas"]},
    {"domain": "joycasino.com", "category": "casino", "brand": "JoyCasino", "aliases": ["joycasino", "joy casino"]},
    {"domain": "playfortuna.com", "category": "casino", "brand": "Play Fortuna", "aliases": ["playfortuna", "play fortuna"]},
    {"domain": "ggbet.com", "category": "casino", "brand": "GG.Bet", "aliases": ["ggbet", "gg bet"]},
    {"domain": "stake.com", "category": "casino", "brand": "Stake", "aliases": ["stake"]},
    {"domain": "bc.game", "category": "casino", "brand": "BC.Game", "aliases": ["bcgame", "bc game"]},
    {"domain": "roobet.com", "category": "casino", "brand": "Roobet", "aliases": ["roobet"]},
    {"domain": "rollbit.com", "category": "casino", "brand": "Rollbit", "aliases": ["rollbit"]},
    {"domain": "sportsbet.io", "category": "casino", "brand": "Sportsbet.io", "aliases": ["sportsbet"]},
    {"domain": "cloudbet.com", "category": "casino", "brand": "Cloudbet", "aliases": ["cloudbet"]},
    {"domain": "duelbits.com", "category": "casino", "brand": "Duelbits", "aliases": ["duelbits"]},
    {"domain": "bitsler.com", "category": "casino", "brand": "Bitsler", "aliases": ["bitsler"]},
    {"domain": "22bet.com", "category": "casino", "brand": "22Bet", "aliases": ["22bet", "22 bet"]},
    {"domain": "betwinner.com", "category": "casino", "brand": "Betwinner", "aliases": ["betwinner"]},
    {"domain": "linebet.com", "category": "casino", "brand": "Linebet", "aliases": ["linebet"]},
    {"domain": "megapari.com", "category": "casino", "brand": "Megapari", "aliases": ["megapari"]},
    {"domain": "rabona.com", "category": "casino", "brand": "Rabona", "aliases": ["rabona"]},
    {"domain": "spinbetter.com", "category": "casino", "brand": "SpinBetter", "aliases": ["spinbetter", "spin better"]},
    {"domain": "betway.com", "category": "casino", "brand": "Betway", "aliases": ["betway"]},
    {"domain": "betfair.com", "category": "casino", "brand": "Betfair", "aliases": ["betfair"]},
    {"domain": "unibet.com", "category": "casino", "brand": "Unibet", "aliases": ["unibet"]},
    {"domain": "bwin.com", "category": "casino", "brand": "Bwin", "aliases": ["bwin"]},
    {"domain": "betano.com", "category": "casino", "brand": "Betano", "aliases": ["betano"]},
    {"domain": "pokerstars.com", "category": "casino", "brand": "PokerStars", "aliases": ["pokerstars", "poker stars"]},
    {"domain": "888casino.com", "category": "casino", "brand": "888casino", "aliases": ["888casino", "888 casino"]},
    {"domain": "leovegas.com", "category": "casino", "brand": "LeoVegas", "aliases": ["leovegas", "leo vegas"]},
    {"domain": "williamhill.com", "category": "casino", "brand": "William Hill", "aliases": ["williamhill", "william hill"]},
    {"domain": "ladbrokes.com", "category": "casino", "brand": "Ladbrokes", "aliases": ["ladbrokes"]},
    {"domain": "coral.co.uk", "category": "casino", "brand": "Coral", "aliases": ["coral"]},
    {"domain": "marathonbet.com", "category": "casino", "brand": "Marathonbet", "aliases": ["marathonbet", "marathon bet"]},
    {"domain": "winline.ru", "category": "casino", "brand": "Winline", "aliases": ["winline"]},
    {"domain": "leon.ru", "category": "casino", "brand": "Leon", "aliases": ["leon"]},
    {"domain": "tennisi.kz", "category": "casino", "brand": "Tennisi", "aliases": ["tennisi"]},
    {"domain": "fairspin.io", "category": "casino", "brand": "Fairspin", "aliases": ["fairspin"]},
    {"domain": "zotabet.com", "category": "casino", "brand": "Zotabet", "aliases": ["zotabet"]},
    {"domain": "xparibet.com", "category": "casino", "brand": "XpariBet", "aliases": ["xparibet", "xpari"]},
    {"domain": "wazamba.com", "category": "casino", "brand": "Wazamba", "aliases": ["wazamba"]},
    {"domain": "nationalcasino.com", "category": "casino", "brand": "National Casino", "aliases": ["national casino"]},
]


@dataclass
class Candidate:
    url: str
    domain: str
    category: str = "suspicious"
    why: str = ""
    search_query: str = ""
    source_urls: list[str] = field(default_factory=list)
    mirror_hints: list[str] = field(default_factory=list)
    brand: str | None = None

    def key(self) -> str:
        return registered_domain(self.domain or extract_domain(self.url))


class Investigator:
    def __init__(self, settings: Settings, db: Database, gemini: GeminiClient):
        self.settings = settings
        self.db = db
        self.gemini = gemini
        self.evidence = EvidenceCollector(settings)
        self.screenshots = ScreenshotService(settings)
        self.ml = DomainMLClassifier(settings)
        self.content_ai = ContentIntelligence(settings)
        self.cyberscan = CyberScanClassifier(settings)

    def run(self, run_id: int, seed_query: str | None, max_candidates: int, take_screenshots: bool, cancel_event: Event | None = None) -> None:
        asyncio.run(self._run(run_id, seed_query, max_candidates, take_screenshots, cancel_event))

    def run_manual(
        self,
        run_id: int,
        target: str,
        category: str,
        take_screenshots: bool,
        cancel_event: Event | None = None,
    ) -> None:
        asyncio.run(self._run_manual(run_id, target, category, take_screenshots, cancel_event))

    async def _run_manual(
        self,
        run_id: int,
        target: str,
        category: str,
        take_screenshots: bool,
        cancel_event: Event | None = None,
    ) -> None:
        self.db.update_run(run_id, status="running", candidate_count=1)
        if self.settings.require_kz_proxy and not self.settings.kz_proxy_url:
            message = "KZ proxy is required: set KZ_PROXY_URL, KZ_HTTP_PROXY, KZ_HTTPS_PROXY, or KZ_PROXY to a Kazakhstan HTTP/SOCKS proxy."
            self.db.update_run(run_id, status="failed", finished_at=utc_now(), error=message)
            self.db.add_log(run_id, "error", message, {"required": True, "configured": False})
            return
        self.db.add_log(run_id, "info", "Ручная проверка запущена", {"target": target, "started_at": utc_now()})
        methodology = [
            "Оператор вручную указал домен или URL для проверки.",
            "Gemini не используется, поэтому квота AI не тратится.",
            "Сайт открывается через ту же сеть проверки доступности, что и автоматический мониторинг.",
            "Для сайта собираются HTTP, HTML, SHA-256, DNS, TLS, RDAP, скорость ответа, редиректы и скриншот.",
        ]
        self.db.update_run(run_id, methodology_json=methodology)

        try:
            domain = extract_domain(target)
            if not is_candidate_domain(domain) or is_technical_url(target):
                message = "Укажите публичный домен или URL, а не IP, localhost или тестовый адрес."
                self.db.update_run(run_id, status="failed", finished_at=utc_now(), error=message)
                self.db.add_log(run_id, "error", "Ручная проверка остановлена", {"reason": message})
                return

            if cancel_event and cancel_event.is_set():
                self.db.update_run(run_id, status="canceled", finished_at=utc_now())
                self.db.add_log(run_id, "warning", "Ручная проверка остановлена до анализа сайта")
                return

            candidate = Candidate(
                url=normalize_url(target),
                domain=domain,
                category=(category or "manual").lower(),
                why="Домен указан оператором для ручной проверки.",
                search_query=target,
            )
            self.db.add_log(
                run_id,
                "info",
                "Открываю сайт для ручного анализа",
                {"domain": candidate.domain, "url": candidate.url},
            )
            finding = await self._build_finding(run_id, candidate, None, take_screenshots)
            if finding.get("_skip"):
                self.db.update_run(run_id, status="completed", finished_at=utc_now(), finding_count=0)
                self.db.add_log(
                    run_id,
                    "warning",
                    "Сайт не добавлен в отчет",
                    {
                        "domain": candidate.domain,
                        "reason": finding.get("_skip_reason", "не удалось открыть"),
                        "status_code": finding.get("status_code"),
                    },
                )
                return

            self.db.insert_finding(run_id, finding)
            self.db.update_run(run_id, status="completed", finished_at=utc_now(), finding_count=1)
            self.db.add_log(
                run_id,
                "info",
                "Ручная проверка завершена, сайт добавлен в отчет",
                {"domain": finding.get("domain"), "risk_score": finding.get("risk_score")},
            )
        except Exception as exc:  # noqa: BLE001
            self.db.update_run(run_id, status="failed", finished_at=utc_now(), error=f"{type(exc).__name__}: {exc}")
            self.db.add_log(run_id, "error", "Ручная проверка завершилась ошибкой", {"error": str(exc)})

    async def _run(
        self,
        run_id: int,
        seed_query: str | None,
        max_candidates: int,
        take_screenshots: bool,
        cancel_event: Event | None = None,
    ) -> None:
        self.db.update_run(run_id, status="running")
        self.db.add_log(run_id, "info", "Поиск запущен", {"started_at": utc_now()})
        if self.settings.require_kz_proxy and not self.settings.kz_proxy_url:
            message = "KZ proxy is required: set KZ_PROXY_URL, KZ_HTTP_PROXY, KZ_HTTPS_PROXY, or KZ_PROXY to a Kazakhstan HTTP/SOCKS proxy."
            self.db.update_run(run_id, status="failed", finished_at=utc_now(), error=message)
            self.db.add_log(run_id, "error", message, {"required": True, "configured": False})
            return
        if self.settings.kz_proxy_url:
            self.db.add_log(
                run_id,
                "info",
                "Проверка доступности выполняется через казахстанскую точку",
                {"access_origin": self.settings.kz_access_label},
            )
        else:
            self.db.add_log(
                run_id,
                "info",
                "KZ_PROXY_URL не настроен: проверка доступности идет из сети хостинга",
                {"access_origin": self.settings.kz_access_label},
            )

        methodology = [
            "Ищем подозрительные casino/scam сайты через Gemini Search, а не через сырые malware/IP фиды.",
            "В поисковых запросах просим только живые домены, рабочие зеркала и страницы, доступные для пользователей Казахстана.",
            "Открытие кандидатов проверяем через KZ_PROXY_URL; если прокси не задан, фиксируем прямую сеть сервера как ограничение доказательства.",
            "Отбрасываем IP-адреса, localhost, тестовые домены и технические источники.",
            "Оставляем в таблице только сайты, которые удалось открыть и зафиксировать, а страницы блокировки не показываем как рабочие сайты.",
            "Для каждого открытого сайта сохраняем HTML, SHA-256, DNS/TLS, RDAP, скорость ответа, размер страницы, редиректы и скриншот.",
            "Зеркала ищем отдельно по найденным доменам и похожести имен.",
            "Все ошибки и пропущенные сайты пишем в журнал проверки и терминал.",
        ]
        self.db.update_run(run_id, methodology_json=methodology)

        try:
            candidates = await self._discover_candidates(run_id, seed_query, max_candidates)
            self.db.update_run(run_id, candidate_count=len(candidates))
            self.db.add_log(run_id, "info", "Список сайтов-кандидатов готов", {"count": len(candidates)})

            if not candidates:
                self.db.add_log(
                    run_id,
                    "warning",
                    "Не нашлось подходящих доменов. Уточните запрос: например 'казино зеркало рабочий вход' или название бренда.",
                )

            if cancel_event and cancel_event.is_set():
                self.db.update_run(run_id, status="canceled", finished_at=utc_now())
                self.db.add_log(run_id, "warning", "Проверка остановлена до анализа сайтов")
                return

            mirror_groups = await self._discover_mirrors(run_id, candidates)
            findings_count = 0

            for index, candidate in enumerate(candidates, start=1):
                if cancel_event and cancel_event.is_set():
                    self.db.update_run(run_id, status="canceled", finished_at=utc_now(), finding_count=findings_count)
                    self.db.add_log(run_id, "warning", "Проверка остановлена пользователем", {"findings": findings_count})
                    return
                if findings_count >= max_candidates:
                    break
                self.db.add_log(
                    run_id,
                    "info",
                    "Открываю сайт-кандидат",
                    {"index": index, "domain": candidate.domain, "url": candidate.url},
                )
                mirror_group = self._mirror_group_for(candidate, candidates, mirror_groups)
                finding = await self._build_finding(run_id, candidate, mirror_group, take_screenshots)
                if finding.get("_skip"):
                    self.db.add_log(
                        run_id,
                        "warning",
                        "Сайт пропущен и не показан пользователю",
                        {
                            "domain": candidate.domain,
                            "reason": finding.get("_skip_reason", "не удалось открыть"),
                            "status_code": finding.get("status_code"),
                        },
                    )
                    continue

                self.db.insert_finding(run_id, finding)
                findings_count += 1
                self.db.update_run(run_id, finding_count=findings_count)
                self.db.add_log(
                    run_id,
                    "info",
                    "Сайт добавлен в отчет",
                    {"domain": finding.get("domain"), "risk_score": finding.get("risk_score")},
                )

            self.db.update_run(run_id, status="completed", finished_at=utc_now(), finding_count=findings_count)
            self.db.add_log(run_id, "info", "Поиск завершен", {"findings": findings_count})
        except Exception as exc:  # noqa: BLE001
            self.db.update_run(run_id, status="failed", finished_at=utc_now(), error=f"{type(exc).__name__}: {exc}")
            self.db.add_log(run_id, "error", "Поиск завершился ошибкой", {"error": str(exc)})

    async def _discover_candidates(
        self,
        run_id: int,
        seed_query: str | None,
        max_candidates: int,
    ) -> list[Candidate]:
        discovery_limit = min(
            max(max_candidates * 7, 150),
            max(max_candidates, self.settings.osint_candidate_pool_size),
        )
        discovered: list[Candidate] = []
        if self.settings.osint_feeds_enabled:
            feed_candidates = await self._discover_from_feeds(run_id, discovery_limit)
            discovered.extend(feed_candidates)

        if self.gemini.available:
            try:
                gemini_limit = min(discovery_limit, max(max_candidates * 2, 50))
                discovered.extend(self._discover_with_gemini(run_id, seed_query, gemini_limit))
            except GeminiAPIError as exc:
                level = "warning" if exc.status_code in {401, 403} else "error"
                self.db.add_log(
                    run_id,
                    level,
                    "Gemini Search недоступен, продолжаю через OSINT/ML",
                    {"error": str(exc), "status_code": exc.status_code},
                )
                if not discovered and not self.settings.osint_feeds_enabled:
                    discovered.extend(await self._discover_from_feeds(run_id, discovery_limit))
            except Exception as exc:  # noqa: BLE001
                self.db.add_log(run_id, "warning", "Gemini Search недоступен, продолжаю через OSINT/ML", {"error": str(exc)})
                if not discovered and not self.settings.osint_feeds_enabled:
                    discovered.extend(await self._discover_from_feeds(run_id, discovery_limit))
        else:
            self.db.add_log(run_id, "warning", "Gemini ключ не настроен. Автопоиск продолжается через OSINT-фиды.")

        if seed_query:
            for domain in find_domains(seed_query):
                if not is_candidate_domain(domain):
                    continue
                discovered.append(
                    Candidate(
                        url=normalize_url(domain),
                        domain=domain,
                        category="manual",
                        why="Домен указан оператором вручную.",
                        search_query=seed_query,
                    )
                )

        if len(discovered) < max_candidates:
            bootstrap = self._discover_from_bootstrap(seed_query, max_candidates - len(discovered))
            if bootstrap:
                discovered.extend(bootstrap)
                self.db.add_log(
                    run_id,
                    "warning",
                    "Discovery bootstrap добавил кандидатов для проверки",
                    {"added": len(bootstrap), "reason": "Gemini/OSINT дали мало доменов"},
                )

        candidates = self._dedupe_candidates(discovered, discovery_limit)
        known_domains = self.db.known_domains()
        known_rechecked = sum(1 for candidate in candidates if candidate.key() in known_domains)
        self.db.add_log(
            run_id,
            "info",
            "Discovery candidates deduplicated",
            {"raw": len(discovered), "deduped": len(candidates), "known_rechecked": known_rechecked},
        )
        return candidates[:discovery_limit]

    def _discover_from_bootstrap(self, seed_query: str | None, limit: int) -> list[Candidate]:
        if limit <= 0:
            return []
        focus = (seed_query or " ".join(self.settings.seed_queries)).lower()
        normalized_focus = re.sub(r"[^a-zа-я0-9]+", " ", focus)
        wants_gambling = bool(re.search(r"(casino|казино|bet|бет|букмекер|ставк|зеркал|mirror)", normalized_focus))
        use_all = not seed_query or wants_gambling

        candidates: list[Candidate] = []
        for item in BOOTSTRAP_CANDIDATES:
            aliases = [str(alias).lower() for alias in item.get("aliases", [])]
            matched = use_all or any(alias in normalized_focus for alias in aliases)
            if not matched:
                continue
            domain = extract_domain(str(item["domain"]))
            if not is_candidate_domain(domain):
                continue
            candidates.append(
                Candidate(
                    url=normalize_url(domain),
                    domain=domain,
                    category=str(item.get("category") or "suspicious"),
                    why=(
                        "Bootstrap-кандидат: внешний поиск не дал достаточно доменов, "
                        "поэтому известный бренд/домен отправлен на техническую проверку."
                    ),
                    search_query=seed_query or "bootstrap brand candidates",
                    brand=str(item.get("brand") or "") or None,
                )
            )
            if len(candidates) >= limit:
                break
        return candidates

    def _discover_with_gemini(
        self,
        run_id: int,
        seed_query: str | None,
        max_candidates: int,
    ) -> list[Candidate]:
        focus = seed_query.strip() if seed_query else " ; ".join(self.settings.seed_queries)
        prompt = f"""
Ты OSINT-следователь. Найди публичные подозрительные сайты. Учитывай, что сайт может выглядеть как обычный домен, но внутри содержать casino, betting, фишинг или финансовый скам. Найди сайты, которые похожи на:
Используй Google Search grounding как браузерный поиск. Обязательно проверяй жалобы пользователей, форумы, отзывы, публичные обсуждения, blacklist reports и страницы с complaints.
Важно: форум, новость, Telegram, YouTube, соцсеть или каталог не является кандидатом. Из таких страниц извлекай прямой домен подозрительного сайта и сохраняй страницу жалобы в source_urls.
1) онлайн-казино/беттинг без очевидной лицензии,
2) рабочие зеркала казино/беттинга,
3) инвестиционные лохотроны или фишинговые страницы.

Очень важно:
- Фокус: Казахстан. Нужны домены, которые сейчас открываются у пользователей Казахстана, включая рабочие зеркала.
- Не возвращай домены, которые публично описаны как заблокированные и не имеют рабочего зеркала.
- НЕ возвращай IP-адреса.
- НЕ возвращай служебные URL Gemini/Google Search вроде vertexaisearch.cloud.google.com/grounding-api-redirect, google.com/url или google.com/search.
- НЕ возвращай статьи, новости, форумы, Telegram, YouTube, соцсети, GitHub, каталоги и справочники.
- Возвращай только прямой домен или URL подозрительного сайта, который можно открыть в браузере и зафиксировать скриншотом.
- Если уверен только частично, все равно объясни сигнал, но не обвиняй окончательно.
- Нужны живые домены, а не threat-feed строки.
- Верни не меньше {max_candidates} разных доменов, если они есть. Лучше дать запас кандидатов, потому что часть сайтов может не открыться.

Фокус поиска:
{focus}

Верни только JSON без Markdown:
{{
  "methodology": ["какие запросы использовал"],
  "candidates": [
    {{
      "url": "https://domain.example",
      "domain": "domain.example",
      "category": "casino|gambling|phishing|scam|pyramid|suspicious",
      "why": "коротко: почему домен выглядит подозрительно",
      "search_query": "поисковый запрос, которым найдено",
      "source_urls": ["https://public-source.example/page"],
      "mirror_hints": ["other-domain.example"],
      "brand": "название бренда если понятно"
    }}
  ]
}}
"""
        self.db.add_log(run_id, "info", "Ищу сайты через Gemini Search", {"limit": max_candidates})
        data, meta = self.gemini.generate_json(prompt, use_search=True, temperature=0.2)
        grounding_sources = meta.get("grounding_sources", [])
        raw_items = data.get("candidates", []) or []
        self.db.add_log(
            run_id,
            "info",
            "Gemini вернул список для проверки",
            {"items": len(raw_items), "sources": len(grounding_sources)},
        )

        candidates: list[Candidate] = []
        skipped_technical = 0
        for item in raw_items:
            candidate = self._candidate_from_item(item, default_sources=grounding_sources)
            if candidate:
                candidates.append(candidate)
            else:
                skipped_technical += 1
        if skipped_technical:
            self.db.add_log(
                run_id,
                "warning",
                "Технические или неподходящие URL от Gemini пропущены",
                {"count": skipped_technical},
            )
        return candidates

    async def _discover_from_plain_feeds_legacy(self, run_id: int, max_candidates: int) -> list[Candidate]:
        candidates: list[Candidate] = []
        timeout = min(self.settings.request_timeout_seconds, 15)
        headers = {"User-Agent": self.settings.user_agent}
        async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
            for feed_url in self.settings.osint_feeds:
                if len(candidates) >= max_candidates:
                    break
                try:
                    response = await client.get(feed_url)
                    response.raise_for_status()
                except Exception as exc:  # noqa: BLE001
                    self.db.add_log(run_id, "warning", "OSINT feed недоступен", {"url": feed_url, "error": str(exc)})
                    continue

                added = 0
                skipped = 0
                for line in response.text.splitlines():
                    if len(candidates) >= max_candidates:
                        break
                    text = line.strip()
                    if not text or text.startswith("#"):
                        continue
                    domain = extract_domain(text)
                    if not is_candidate_domain(domain):
                        skipped += 1
                        continue
                    candidates.append(
                        Candidate(
                            url=normalize_url(text),
                            domain=domain,
                            category="phishing" if "phish" in feed_url.lower() else "suspicious",
                            why=f"Домен найден в публичном OSINT feed: {feed_url}",
                            search_query="public OSINT feed",
                            source_urls=[feed_url],
                        )
                    )
                    added += 1
                self.db.add_log(run_id, "info", "OSINT feed обработан", {"url": feed_url, "added": added, "skipped": skipped})
        return candidates

    async def _discover_from_feeds(self, run_id: int, max_candidates: int) -> list[Candidate]:
        candidates: list[Candidate] = []
        seen: set[str] = set()
        timeout = min(self.settings.request_timeout_seconds, 15)
        headers = {"User-Agent": self.settings.user_agent}
        sources = self._osint_sources()

        self.db.add_log(run_id, "info", "OSINT discovery started", {"sources": len(sources), "limit": max_candidates})
        async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
            for source in sources:
                if len(candidates) >= max_candidates:
                    break
                try:
                    response = await client.get(source["url"])
                    response.raise_for_status()
                except Exception as exc:  # noqa: BLE001
                    self.db.add_log(
                        run_id,
                        "warning",
                        "OSINT source unavailable",
                        {"name": source["name"], "url": source["url"], "error": str(exc)},
                    )
                    continue

                added = 0
                skipped = 0
                for token in self._feed_tokens(response.text, source["parser"]):
                    if len(candidates) >= max_candidates:
                        break
                    domain = extract_domain(token)
                    if not is_candidate_domain(domain):
                        skipped += 1
                        continue
                    key = registered_domain(domain)
                    if not key or key in seen:
                        skipped += 1
                        continue
                    seen.add(key)
                    candidates.append(
                        Candidate(
                            url=normalize_url(token or domain),
                            domain=domain,
                            category=source["category"],
                            why=f"Domain found in CyberScan-style OSINT source: {source['name']}.",
                            search_query=f"OSINT feed: {source['name']}",
                            source_urls=[source["url"]],
                        )
                    )
                    added += 1
                self.db.add_log(
                    run_id,
                    "info",
                    "OSINT source processed",
                    {"name": source["name"], "category": source["category"], "added": added, "skipped": skipped},
                )
        return candidates

    def _osint_sources(self) -> list[dict[str, str]]:
        sources = [dict(item) for item in CYBERSCAN_OSINT_SOURCES]
        known_urls = {item["url"] for item in sources}
        for feed_url in self.settings.osint_feeds:
            if feed_url in known_urls:
                continue
            known_urls.add(feed_url)
            sources.append(
                {
                    "name": extract_domain(feed_url) or "custom_feed",
                    "url": feed_url,
                    "category": "phishing" if "phish" in feed_url.lower() else "suspicious",
                    "parser": "plain_list",
                }
            )
        return sources

    def _feed_tokens(self, text: str, parser: str) -> list[str]:
        if parser == "csv":
            tokens: list[str] = []
            rows = csv.reader(StringIO("\n".join(line for line in text.splitlines() if not line.startswith("#"))))
            for row in rows:
                for cell in row:
                    tokens.extend(self._domains_or_urls_from_text(cell))
            return tokens

        tokens = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", "!", "//")):
                continue
            line = line.split("#", 1)[0].strip()
            if parser == "hosts_file":
                parts = [part.strip() for part in line.split() if part.strip()]
                line_tokens = [part for part in parts[1:] if "." in part] if len(parts) > 1 else parts
            else:
                line_tokens = [line]
            for token in line_tokens:
                tokens.extend(self._domains_or_urls_from_text(token))
        return tokens

    @staticmethod
    def _domains_or_urls_from_text(text: str) -> list[str]:
        cleaned = text.strip().strip('"').strip("'").strip(",")
        if not cleaned:
            return []
        urls = [url for url in re.findall(r"(?i)https?://[^\s,\"'<>]+", cleaned) if is_candidate_url(url)]
        if urls:
            return urls
        domains = [
            domain
            for domain in re.findall(r"(?i)(?:[a-z0-9-]+\.)+[a-z]{2,24}", cleaned)
            if is_candidate_domain(domain)
        ]
        if cleaned.startswith("||"):
            domains.append(cleaned[2:].strip("^/"))
        if not urls and not domains and is_candidate_domain(extract_domain(cleaned)):
            domains.append(cleaned)
        return [*urls, *domains]

    async def _discover_mirrors(
        self,
        run_id: int,
        candidates: list[Candidate],
    ) -> list[dict[str, Any]]:
        casino_candidates = [
            candidate
            for candidate in candidates
            if candidate.category.lower() in {"casino", "gambling", "betting", "suspicious"}
        ][: self.settings.max_mirror_checks_per_run]

        groups: list[dict[str, Any]] = []
        if not casino_candidates:
            return groups
        if not self.gemini.available:
            self.db.add_log(run_id, "warning", "Поиск зеркал пропущен: Gemini ключ не настроен")
            return groups

        domains = [candidate.domain for candidate in casino_candidates if is_candidate_domain(candidate.domain)]
        if not domains:
            return groups

        prompt = f"""
Найди возможные зеркальные домены для этих casino/betting/scam сайтов.
Используй только публичный поиск. Не возвращай IP, статьи, соцсети и каталоги.

Домены:
{", ".join(domains)}

Верни только JSON без Markdown:
{{
  "mirror_groups": [
    {{
      "brand": "brand-or-domain",
      "domains": ["domain1.com", "domain2.com"],
      "why": "что связывает домены",
      "source_urls": ["https://public-source.example"]
    }}
  ]
}}
"""
        try:
            data, meta = self.gemini.generate_json(prompt, use_search=True, temperature=0.1)
        except GeminiQuotaError as exc:
            self.db.add_log(run_id, "warning", "Лимит Gemini для поиска зеркал исчерпан", {"error": str(exc)})
            return groups
        except Exception as exc:  # noqa: BLE001
            self.db.add_log(run_id, "warning", "Поиск зеркал не дал результата", {"error": str(exc)})
            return groups

        grounding_sources = meta.get("grounding_sources", [])
        for group in data.get("mirror_groups", []) or []:
            domains = sorted({extract_domain(domain) for domain in group.get("domains", []) if is_candidate_domain(extract_domain(domain))})
            if not domains:
                continue
            groups.append(
                {
                    "brand": group.get("brand") or domains[0],
                    "domains": domains,
                    "why": group.get("why") or "",
                    "source_urls": group.get("source_urls") or grounding_sources,
                }
            )
        self.db.add_log(run_id, "info", "Зеркальные группы проверены", {"count": len(groups)})
        return groups

    async def _build_finding(
        self,
        run_id: int,
        candidate: Candidate,
        mirror_group: str | None,
        take_screenshots: bool,
    ) -> dict[str, Any]:
        evidence = await self.evidence.collect(candidate.url, run_id)
        domain = evidence.domain or candidate.domain
        if not is_candidate_domain(domain):
            return {
                "_skip": True,
                "_skip_reason": "это IP, непубличный или технический домен",
                "url": candidate.url,
                "domain": domain,
                "status_code": evidence.status_code,
            }
        status_code = int(evidence.status_code or 0)
        if not evidence.active or not evidence.final_url or status_code < 200 or status_code >= 400:
            skip_reason = "сайт не открылся с нормальным HTTP 2xx/3xx"
            if evidence.blocked_by_policy:
                skip_reason = "страница похожа на блокировку доступа и не считается рабочей из Казахстана"
            return {
                "_skip": True,
                "_skip_reason": skip_reason,
                "url": candidate.url,
                "domain": domain,
                "status_code": evidence.status_code,
            }
        if not evidence.html_path:
            self.db.add_log(
                run_id,
                "warning",
                "HTML не сохранен, но сайт добавлен по HTTP/DNS/TLS данным",
                {"domain": domain, "status_code": evidence.status_code, "page_size_bytes": evidence.page_size_bytes},
            )

        screenshot_path = None
        screenshot_error = None
        if take_screenshots and evidence.final_url:
            self.db.add_log(run_id, "info", "Делаю скриншот сайта", {"domain": domain, "url": evidence.final_url})
            screenshot = await self.screenshots.capture(evidence.final_url, run_id)
            screenshot_path = screenshot.path
            screenshot_error = screenshot.error
            if screenshot_path:
                self.db.add_log(run_id, "info", "Скриншот сохранен", {"domain": domain, "path": screenshot_path})
            elif screenshot_error:
                self.db.add_log(run_id, "warning", "Скриншот не сохранен", {"domain": domain, "error": screenshot_error})
        elif not take_screenshots:
            self.db.add_log(run_id, "info", "Скриншот пропущен: выключен в запуске", {"domain": domain})

        source_urls = self._clean_sources(candidate.source_urls)
        content_ai = self.content_ai.analyze(candidate.url, evidence)
        cyberscan_result = self.cyberscan.classify(candidate.url, evidence, content_ai)
        if cyberscan_result.get("available"):
            self.db.add_log(
                run_id,
                "info",
                "CyberScan ML classification completed",
                {
                    "domain": domain,
                    "label": cyberscan_result.get("label"),
                    "suspicious_probability": cyberscan_result.get("suspicious_probability"),
                },
            )
        elif cyberscan_result.get("error"):
            self.db.add_log(
                run_id,
                "warning",
                "CyberScan ML unavailable",
                {"domain": domain, "error": cyberscan_result.get("error")},
            )

        ml_result = self.ml.classify(candidate.url, evidence)
        if ml_result.get("available"):
            self.db.add_log(
                run_id,
                "info",
                "ML классификация сайта завершена",
                {
                    "domain": domain,
                    "label": ml_result.get("label"),
                    "confidence": ml_result.get("confidence"),
                    "model": ml_result.get("model"),
                },
            )
        elif ml_result.get("error"):
            self.db.add_log(
                run_id,
                "warning",
                "ML классификация недоступна",
                {"domain": domain, "error": ml_result.get("error")},
            )

        category = self._category_with_ai(candidate.category or "suspicious", ml_result, cyberscan_result, content_ai)
        risk, verdict, reasons = score_finding(
            category=category,
            active=evidence.active,
            status_code=evidence.status_code,
            keyword_hits=evidence.keyword_hits,
            has_sources=bool(source_urls),
            domain=domain,
            mirror_group=mirror_group,
        )
        risk = min(
            100,
            risk
            + int(content_ai.get("risk_delta") or 0)
            + self._cyberscan_risk_delta(cyberscan_result),
        )
        verdict = self._verdict_for_risk(risk)
        if candidate.why:
            reasons.insert(0, candidate.why)
        for signal in reversed(content_ai.get("signals") or []):
            reasons.insert(1 if candidate.why else 0, str(signal))
        cyberscan_reason = self._cyberscan_reason(cyberscan_result)
        if cyberscan_reason:
            reasons.insert(1 if candidate.why else 0, cyberscan_reason)
        ml_reason = self._ml_reason(ml_result)
        if ml_reason:
            reasons.insert(1 if candidate.why else 0, ml_reason)
        if screenshot_error:
            if screenshot_path:
                reasons.append(f"Screenshot saved with warning: {screenshot_error}")
            else:
                reasons.append(f"Screenshot not saved: {screenshot_error}")
        if not evidence.html_path:
            reasons.append("HTML не сохранен, но сайт ответил нормальным HTTP-кодом; DNS/TLS/скорость/редиректы зафиксированы.")
        if evidence.tls and not evidence.tls.get("valid"):
            reasons.append("SSL/TLS сертификат отсутствует или недействителен; сайт все равно зафиксирован как рабочий по HTTP-доступности.")

        return {
            "url": candidate.url,
            "final_url": evidence.final_url,
            "domain": domain,
            "normalized_domain": registered_domain(domain),
            "title": evidence.title,
            "category": category,
            "verdict": verdict,
            "risk_score": risk,
            "active": evidence.active,
            "status_code": evidence.status_code,
            "mirror_group": mirror_group,
            "screenshot_path": screenshot_path,
            "html_path": evidence.html_path,
            "html_sha256": evidence.html_sha256,
            "dns_json": evidence.dns,
            "tls_json": evidence.tls,
            "evidence_json": {
                **evidence.as_evidence(),
                "search_query": candidate.search_query,
                "brand": candidate.brand,
                "mirror_hints": candidate.mirror_hints,
                "ml": ml_result,
                "cyberscan_ml": cyberscan_result,
                "content_ai": content_ai,
                "screenshot_error": screenshot_error,
            },
            "sources_json": [{"url": url} for url in source_urls],
            "reasons_json": reasons,
        }

    def _category_with_ai(
        self,
        category: str,
        ml_result: dict[str, Any],
        cyberscan_result: dict[str, Any],
        content_ai: dict[str, Any],
    ) -> str:
        content_label = str(content_ai.get("category_hint") or "").lower()
        content_confidence = str(content_ai.get("category_confidence") or "low").lower()
        if content_label in {"casino", "pyramid", "phishing", "suspicious"} and content_confidence in {"medium", "high"}:
            return content_label

        ml_category = self._category_with_ml(category, ml_result)
        if ml_category != category:
            return ml_category

        cyber_label = str(cyberscan_result.get("label") or "").lower()
        cyber_probability = float(cyberscan_result.get("suspicious_probability") or 0)
        weak_category = category.lower() in {"", "manual", "unknown", "suspicious"}
        if cyber_label == "suspicious" and cyber_probability >= 0.68 and weak_category:
            return "suspicious"
        return category

    def _category_with_ml(self, category: str, ml_result: dict[str, Any]) -> str:
        label = str(ml_result.get("label") or "").lower()
        confidence = float(ml_result.get("confidence") or 0)
        if label not in {"phishing", "casino", "pyramid", "suspicious"}:
            return category
        weak_category = category.lower() in {"", "manual", "unknown", "suspicious"}
        if confidence >= self.settings.ml_min_confidence and (weak_category or confidence >= 0.65):
            return label
        return category

    @staticmethod
    def _cyberscan_risk_delta(cyberscan_result: dict[str, Any]) -> int:
        if not cyberscan_result.get("available"):
            return 0
        probability = float(cyberscan_result.get("suspicious_probability") or 0)
        if probability >= 0.85:
            return 18
        if probability >= 0.68:
            return 12
        if probability >= 0.55:
            return 6
        return 0

    @staticmethod
    def _cyberscan_reason(cyberscan_result: dict[str, Any]) -> str | None:
        if not cyberscan_result.get("available"):
            return None
        probability = float(cyberscan_result.get("suspicious_probability") or 0)
        top = [
            str(item.get("feature"))
            for item in cyberscan_result.get("top_features", [])
            if item.get("feature")
        ][:5]
        details = f"; признаки: {', '.join(top)}" if top else ""
        return f"CyberScan ML оценил вероятность подозрительности как {probability:.0%}{details}."

    @staticmethod
    def _verdict_for_risk(risk: int) -> str:
        if risk >= 80:
            return "suspected_fraud_or_illegal"
        if risk >= 60:
            return "suspicious"
        if risk >= 40:
            return "needs_review"
        return "low_signal"

    @staticmethod
    def _ml_reason(ml_result: dict[str, Any]) -> str | None:
        if not ml_result.get("available"):
            return None
        label = str(ml_result.get("label") or "unknown")
        confidence = float(ml_result.get("confidence") or 0)
        top = [
            str(item.get("feature"))
            for item in ml_result.get("top_features", [])
            if item.get("feature")
        ][:4]
        details = f"; признаки: {', '.join(top)}" if top else ""
        return f"ML CatBoost классифицировал сайт как {label} с уверенностью {confidence:.0%}{details}."

    def _candidate_from_item(
        self,
        item: dict[str, Any],
        default_sources: list[dict[str, str]],
    ) -> Candidate | None:
        url = str(item.get("url") or item.get("domain") or "").strip()
        if not url:
            text_blob = " ".join(str(value) for value in item.values())
            domains = re.findall(r"(?i)(?:[a-z0-9-]+\.)+[a-z]{2,24}", text_blob)
            url = domains[0] if domains else ""
        domain = extract_domain(item.get("domain") or url)
        if not is_candidate_domain(domain):
            return None
        normalized_url = normalize_url(url or domain)
        if not is_candidate_url(normalized_url):
            if is_candidate_domain(domain):
                normalized_url = normalize_url(domain)
            else:
                return None
        sources = item.get("source_urls") or []
        if isinstance(sources, str):
            sources = [sources]
        if not sources:
            sources = [source["url"] for source in default_sources if source.get("url")]
        mirrors = item.get("mirror_hints") or []
        if isinstance(mirrors, str):
            mirrors = [mirrors]
        mirror_hints = [extract_domain(str(mirror)) for mirror in mirrors]
        mirror_hints = [domain for domain in mirror_hints if is_candidate_domain(domain)]
        return Candidate(
            url=normalized_url,
            domain=domain,
            category=str(item.get("category") or "suspicious").lower(),
            why=str(item.get("why") or ""),
            search_query=str(item.get("search_query") or ""),
            source_urls=self._clean_sources(sources),
            mirror_hints=mirror_hints,
            brand=str(item.get("brand") or "") or None,
        )

    def _dedupe_candidates(self, candidates: list[Candidate], limit: int) -> list[Candidate]:
        by_key: dict[str, Candidate] = {}
        for candidate in candidates:
            if not is_candidate_domain(candidate.domain) or not is_candidate_url(candidate.url):
                continue
            key = candidate.key()
            if not key:
                continue
            if key not in by_key:
                by_key[key] = candidate
                continue
            existing = by_key[key]
            existing.source_urls = self._clean_sources([*existing.source_urls, *candidate.source_urls])
            existing.mirror_hints = sorted(set([*existing.mirror_hints, *candidate.mirror_hints]))
            if not existing.why and candidate.why:
                existing.why = candidate.why
            if existing.category == "suspicious" and candidate.category != "suspicious":
                existing.category = candidate.category
        return list(by_key.values())[:limit]

    def _mirror_group_for(
        self,
        candidate: Candidate,
        all_candidates: list[Candidate],
        mirror_groups: list[dict[str, Any]],
    ) -> str | None:
        for group in mirror_groups:
            domains = [domain for domain in group.get("domains", []) if is_candidate_domain(domain)]
            registered = {registered_domain(domain) for domain in domains}
            if candidate.domain in domains or registered_domain(candidate.domain) in registered:
                return str(group.get("brand") or candidate.domain)

        related = [
            other.domain
            for other in all_candidates
            if other.domain != candidate.domain and likely_related_domains(candidate.domain, other.domain)
        ]
        if related:
            return f"похожий домен: {registered_domain(candidate.domain)}"
        return None

    @staticmethod
    def _clean_sources(sources: list[Any]) -> list[str]:
        cleaned: list[str] = []
        for source in sources:
            url = str(source).strip()
            if not url or url in cleaned:
                continue
            if is_technical_url(url):
                continue
            if url.startswith("http://") or url.startswith("https://"):
                cleaned.append(url)
        return cleaned[:20]





