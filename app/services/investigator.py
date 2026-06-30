from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from threading import Event
from typing import Any

import httpx

from app.config import Settings
from app.database import Database, utc_now
from app.services.domains import (
    extract_domain,
    find_domains,
    is_public_domain,
    likely_related_domains,
    normalize_url,
    registered_domain,
)
from app.services.evidence import EvidenceCollector, score_finding
from app.services.gemini import GeminiClient, GeminiQuotaError
from app.services.screenshots import ScreenshotService


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

    def run(self, run_id: int, seed_query: str | None, max_candidates: int, take_screenshots: bool, cancel_event: Event | None = None) -> None:
        asyncio.run(self._run(run_id, seed_query, max_candidates, take_screenshots, cancel_event))

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
                "warning",
                "KZ_PROXY_URL не настроен: Render проверяет доступность из своей сети, а не из Казахстана",
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
        discovery_limit = min(max(max_candidates * 3, 8), 20)
        discovered: list[Candidate] = []
        if self.gemini.available:
            try:
                discovered.extend(self._discover_with_gemini(run_id, seed_query, discovery_limit))
            except Exception as exc:  # noqa: BLE001
                self.db.add_log(run_id, "error", "Gemini не смог собрать кандидатов", {"error": str(exc)})
        else:
            self.db.add_log(run_id, "warning", "Gemini ключ не настроен. Автопоиск в интернете выключен.")

        if self.settings.osint_feeds_enabled:
            feed_candidates = await self._discover_from_feeds(run_id, discovery_limit)
            discovered.extend(feed_candidates)

        if seed_query:
            for domain in find_domains(seed_query):
                discovered.append(
                    Candidate(
                        url=normalize_url(domain),
                        domain=domain,
                        category="manual",
                        why="Домен указан оператором вручную.",
                        search_query=seed_query,
                    )
                )

        candidates = self._dedupe_candidates(discovered, discovery_limit)
        known_domains = self.db.known_domains()
        fresh: list[Candidate] = []
        skipped_known = 0
        for candidate in candidates:
            if candidate.key() in known_domains:
                skipped_known += 1
                continue
            fresh.append(candidate)
        if skipped_known:
            self.db.add_log(run_id, "info", "Уже известные домены пропущены", {"count": skipped_known})
        return fresh

    def _discover_with_gemini(
        self,
        run_id: int,
        seed_query: str | None,
        max_candidates: int,
    ) -> list[Candidate]:
        focus = seed_query.strip() if seed_query else " ; ".join(self.settings.seed_queries)
        prompt = f"""
Ты OSINT-следователь. Найди публичные подозрительные сайты. Учитывай, что сайт может выглядеть как обычный домен, но внутри содержать casino, betting, фишинг или финансовый скам. Найди сайты, которые похожи на:
1) онлайн-казино/беттинг без очевидной лицензии,
2) рабочие зеркала казино/беттинга,
3) инвестиционные лохотроны или фишинговые страницы.

Очень важно:
- Фокус: Казахстан. Нужны домены, которые сейчас открываются у пользователей Казахстана, включая рабочие зеркала.
- Не возвращай домены, которые публично описаны как заблокированные и не имеют рабочего зеркала.
- НЕ возвращай IP-адреса.
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
        for item in raw_items:
            candidate = self._candidate_from_item(item, default_sources=grounding_sources)
            if candidate:
                candidates.append(candidate)
        return candidates

    async def _discover_from_feeds(self, run_id: int, max_candidates: int) -> list[Candidate]:
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
                    if not is_public_domain(domain):
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

        domains = [candidate.domain for candidate in casino_candidates if is_public_domain(candidate.domain)]
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
            domains = sorted({extract_domain(domain) for domain in group.get("domains", []) if is_public_domain(extract_domain(domain))})
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
        if not is_public_domain(domain):
            return {
                "_skip": True,
                "_skip_reason": "это IP или непубличный домен",
                "url": candidate.url,
                "domain": domain,
                "status_code": evidence.status_code,
            }
        status_code = int(evidence.status_code or 0)
        if not evidence.active or not evidence.final_url or not evidence.html_path or status_code < 200 or status_code >= 400:
            skip_reason = "сайт не открылся с нормальным HTTP 2xx/3xx или не дал HTML для фиксации"
            if evidence.blocked_by_policy:
                skip_reason = "страница похожа на блокировку доступа и не считается рабочей из Казахстана"
            return {
                "_skip": True,
                "_skip_reason": skip_reason,
                "url": candidate.url,
                "domain": domain,
                "status_code": evidence.status_code,
            }

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
        category = candidate.category or "suspicious"
        risk, verdict, reasons = score_finding(
            category=category,
            active=evidence.active,
            status_code=evidence.status_code,
            keyword_hits=evidence.keyword_hits,
            has_sources=bool(source_urls),
            domain=domain,
            mirror_group=mirror_group,
        )
        if candidate.why:
            reasons.insert(0, candidate.why)
        if screenshot_error:
            if screenshot_path:
                reasons.append(f"Screenshot saved with warning: {screenshot_error}")
            else:
                reasons.append(f"Screenshot not saved: {screenshot_error}")

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
                "screenshot_error": screenshot_error,
            },
            "sources_json": [{"url": url} for url in source_urls],
            "reasons_json": reasons,
        }

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
        if not is_public_domain(domain):
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
        mirror_hints = [domain for domain in mirror_hints if is_public_domain(domain)]
        return Candidate(
            url=normalize_url(url or domain),
            domain=domain,
            category=str(item.get("category") or "suspicious").lower(),
            why=str(item.get("why") or ""),
            search_query=str(item.get("search_query") or ""),
            source_urls=[str(source) for source in sources if source],
            mirror_hints=mirror_hints,
            brand=str(item.get("brand") or "") or None,
        )

    def _dedupe_candidates(self, candidates: list[Candidate], limit: int) -> list[Candidate]:
        by_key: dict[str, Candidate] = {}
        for candidate in candidates:
            if not is_public_domain(candidate.domain):
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
            domains = [domain for domain in group.get("domains", []) if is_public_domain(domain)]
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
            if url.startswith("http://") or url.startswith("https://"):
                cleaned.append(url)
        return cleaned[:20]





