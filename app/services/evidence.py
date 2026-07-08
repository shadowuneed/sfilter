from __future__ import annotations

import hashlib
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from app.config import Settings
from app.services.domains import extract_domain, normalize_url, registered_domain, suspicious_tld


CASINO_KEYWORDS = {
    "casino",
    "казино",
    "slot",
    "slots",
    "слоты",
    "roulette",
    "рулетка",
    "blackjack",
    "poker",
    "jackpot",
    "джекпот",
    "free spins",
    "фриспины",
    "игровые автоматы",
    "live casino",
}

SCAM_KEYWORDS = {
    "phishing",
    "wallet",
    "airdrop",
    "giveaway",
    "лохотрон",
    "обман",
    "скам",
    "инвестиции",
    "удвоение",
    "доход",
    "гарантированный",
}

BETTING_KEYWORDS = {
    "bookmaker",
    "букмекер",
    "ставки",
    "sportsbook",
    "sports betting",
    "betting",
}

BLOCK_PAGE_MARKERS = {
    "access to this site is blocked",
    "site is blocked",
    "blocked by",
    "resource is blocked",
    "доступ к данному ресурсу ограничен",
    "доступ ограничен",
    "сайт заблокирован",
    "ресурс заблокирован",
    "заблокировано",
    "заблокирован",
    "бұғатталған",
    "қолжетімділік шектелген",
}


@dataclass
class EvidenceResult:
    requested_url: str
    final_url: str | None = None
    domain: str | None = None
    status_code: int | None = None
    active: bool = False
    title: str | None = None
    description: str | None = None
    text_excerpt: str | None = None
    html_path: str | None = None
    html_sha256: str | None = None
    response_time_ms: int | None = None
    page_size_bytes: int | None = None
    redirect_count: int = 0
    redirect_chain: list[dict[str, Any]] = field(default_factory=list)
    tls_verified_fetch: bool | None = None
    access_origin: str | None = None
    blocked_by_policy: bool = False
    domain_info: dict[str, Any] = field(default_factory=dict)
    dns: dict[str, Any] = field(default_factory=dict)
    tls: dict[str, Any] = field(default_factory=dict)
    keyword_hits: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_evidence(self) -> dict[str, Any]:
        return {
            "requested_url": self.requested_url,
            "description": self.description,
            "text_excerpt": self.text_excerpt,
            "keyword_hits": self.keyword_hits,
            "errors": self.errors,
            "response_time_ms": self.response_time_ms,
            "page_size_bytes": self.page_size_bytes,
            "redirect_count": self.redirect_count,
            "redirect_chain": self.redirect_chain,
            "tls_verified_fetch": self.tls_verified_fetch,
            "access_origin": self.access_origin,
            "blocked_by_policy": self.blocked_by_policy,
            "domain": self.domain_info,
        }


class EvidenceCollector:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def collect(self, url: str, run_id: int) -> EvidenceResult:
        normalized = normalize_url(url)
        result = EvidenceResult(requested_url=normalized)
        result.domain = extract_domain(normalized)
        result.access_origin = self.settings.kz_access_label
        result.dns = {"records": [], "mx_records": []} if self.settings.fast_evidence_mode else self._resolve_dns(result.domain)
        if not self.settings.fast_evidence_mode:
            result.tls = self._tls_certificate(result.domain)

        candidates = self._url_candidates(normalized)
        headers = {"User-Agent": self.settings.user_agent}

        client_options = {
            "follow_redirects": True,
            "timeout": self.settings.request_timeout_seconds,
            "headers": headers,
            "proxy": self.settings.kz_proxy_url,
        }

        async with httpx.AsyncClient(
            **client_options,
            verify=True,
        ) as client, httpx.AsyncClient(
            **client_options,
            verify=False,
        ) as insecure_client:
            if not self.settings.fast_evidence_mode:
                result.dns.update(await self._resolve_mx(client, result.domain))
                result.domain_info = await self._domain_rdap(client, result.domain)
            for candidate in candidates:
                response = None
                verified_fetch = candidate.startswith("https://")
                try:
                    started = time.perf_counter()
                    response = await client.get(candidate)
                except Exception as exc:  # noqa: BLE001 - keep evidence of network failures.
                    result.errors.append(f"{candidate}: {type(exc).__name__}: {exc}")
                    try:
                        started = time.perf_counter()
                        response = await insecure_client.get(candidate)
                        verified_fetch = False
                        result.errors.append(
                            f"{candidate}: strict TLS/redirect check failed; fetched with certificate verification disabled"
                        )
                    except Exception as fallback_exc:  # noqa: BLE001
                        result.errors.append(
                            f"{candidate}: fallback without TLS verification failed: "
                            f"{type(fallback_exc).__name__}: {fallback_exc}"
                        )
                        continue

                result.response_time_ms = int((time.perf_counter() - started) * 1000)
                result.status_code = response.status_code
                result.final_url = str(response.url)
                result.page_size_bytes = len(response.content)
                result.redirect_count = len(response.history)
                result.redirect_chain = [
                    {"status_code": item.status_code, "url": str(item.url)}
                    for item in response.history[:10]
                ]
                result.tls_verified_fetch = verified_fetch if str(response.url).startswith("https://") else None
                result.active = 200 <= response.status_code < 400
                content_type = response.headers.get("content-type", "")
                if "text/html" in content_type or response.text:
                    self._parse_html(result, response.text[:1_500_000], run_id)
                if response.status_code == 451 or self._looks_blocked(result):
                    result.blocked_by_policy = True
                    result.active = False
                break

        return result

    def _url_candidates(self, url: str) -> list[str]:
        parsed = urlparse(url)
        if parsed.scheme == "https":
            return [url, url.replace("https://", "http://", 1)]
        if parsed.scheme == "http":
            return [url, url.replace("http://", "https://", 1)]
        return [normalize_url(url, prefer_https=True), normalize_url(url, prefer_https=False)]

    def _parse_html(self, result: EvidenceResult, html: str, run_id: int) -> None:
        sha256 = hashlib.sha256(html.encode("utf-8", errors="ignore")).hexdigest()
        safe_domain = re.sub(r"[^a-zA-Z0-9_.-]+", "_", result.domain or "unknown")[:80]
        html_path = self.settings.evidence_dir / f"run_{run_id}_{safe_domain}_{sha256[:12]}.html"
        html_path.write_text(html, encoding="utf-8", errors="ignore")

        soup = BeautifulSoup(html, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else None
        description_tag = soup.find("meta", attrs={"name": "description"})
        description = None
        if description_tag and description_tag.get("content"):
            description = str(description_tag["content"]).strip()

        for script in soup(["script", "style", "noscript"]):
            script.decompose()
        visible_text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))
        excerpt = visible_text[:1200]

        result.title = title
        result.description = description
        result.text_excerpt = excerpt
        result.html_sha256 = sha256
        result.html_path = f"evidence/{html_path.name}"
        result.keyword_hits = self._keyword_hits(" ".join([title or "", description or "", excerpt]))

    def _keyword_hits(self, text: str) -> list[str]:
        lowered = text.lower()
        hits: set[str] = set()
        for word in CASINO_KEYWORDS | SCAM_KEYWORDS | BETTING_KEYWORDS:
            pattern = r"(?<![\w])" + r"\s+".join(re.escape(part) for part in word.lower().split()) + r"(?![\w])"
            if re.search(pattern, lowered, re.IGNORECASE):
                hits.add(word)
        return sorted(hits)[:30]

    def _resolve_dns(self, domain: str | None) -> dict[str, Any]:
        if not domain:
            return {"records": [], "mx_records": [], "error": "empty domain"}
        try:
            addresses = socket.getaddrinfo(domain, None)
            ips = sorted({item[4][0] for item in addresses if item and item[4]})
            return {"records": ips[:20], "mx_records": []}
        except Exception as exc:  # noqa: BLE001
            return {"records": [], "mx_records": [], "error": f"{type(exc).__name__}: {exc}"}

    async def _resolve_mx(self, client: httpx.AsyncClient, domain: str | None) -> dict[str, Any]:
        if not domain:
            return {"mx_records": []}
        try:
            response = await client.get(
                "https://cloudflare-dns.com/dns-query",
                params={"name": domain, "type": "MX"},
                headers={"accept": "application/dns-json"},
            )
            response.raise_for_status()
            payload = response.json()
            records: list[str] = []
            for answer in payload.get("Answer", []) or []:
                data = str(answer.get("data") or "").strip().rstrip(".")
                if data:
                    records.append(data)
            return {"mx_records": sorted(set(records))[:20]}
        except Exception as exc:  # noqa: BLE001
            return {"mx_records": [], "mx_error": f"{type(exc).__name__}: {exc}"}

    def _tls_certificate(self, domain: str | None) -> dict[str, Any]:
        if not domain:
            return {"error": "empty domain"}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=8) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                    cert = tls_sock.getpeercert()
            issuer = cert.get("issuer", [])
            subject = cert.get("subject", [])
            return {
                "subject": self._cert_name(subject),
                "issuer": self._cert_name(issuer),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "valid": True,
                "expires_in_days": self._cert_days_left(cert.get("notAfter")),
            }
        except Exception as exc:  # noqa: BLE001
            return {"valid": False, "error": f"{type(exc).__name__}: {exc}"}

    async def _domain_rdap(self, client: httpx.AsyncClient, domain: str | None) -> dict[str, Any]:
        if not domain:
            return {}
        reg_domain = registered_domain(domain)
        if not reg_domain:
            return {}
        try:
            response = await client.get(f"https://rdap.org/domain/{reg_domain}")
            if response.status_code == 404:
                return {"registered_domain": reg_domain, "error": "RDAP record not found"}
            response.raise_for_status()
            payload = response.json()
            created_at = self._rdap_event(payload, "registration")
            expires_at = self._rdap_event(payload, "expiration")
            updated_at = self._rdap_event(payload, "last changed") or self._rdap_event(payload, "last update")
            return {
                "registered_domain": reg_domain,
                "created_at": created_at,
                "expires_at": expires_at,
                "updated_at": updated_at,
                "age_days": self._age_days(created_at),
                "registrar": self._rdap_registrar(payload),
            }
        except Exception as exc:  # noqa: BLE001
            return {"registered_domain": reg_domain, "error": f"{type(exc).__name__}: {exc}"}

    @staticmethod
    def _rdap_event(payload: dict[str, Any], action: str) -> str | None:
        action = action.lower()
        for event in payload.get("events", []) or []:
            if str(event.get("eventAction") or "").lower() == action:
                return str(event.get("eventDate") or "") or None
        return None

    @staticmethod
    def _rdap_registrar(payload: dict[str, Any]) -> str | None:
        for entity in payload.get("entities", []) or []:
            roles = {str(role).lower() for role in entity.get("roles", []) or []}
            if "registrar" not in roles:
                continue
            vcard = entity.get("vcardArray") or []
            if len(vcard) < 2:
                continue
            for item in vcard[1]:
                if not item or item[0] not in {"fn", "org"}:
                    continue
                value = item[3] if len(item) > 3 else None
                if isinstance(value, str) and value.strip():
                    return value.strip()
                if isinstance(value, list) and value:
                    return str(value[0]).strip()
        return None

    @staticmethod
    def _age_days(value: str | None) -> int | None:
        if not value:
            return None
        try:
            created = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return max(0, (datetime.now(timezone.utc) - created).days)
        except ValueError:
            return None

    @staticmethod
    def _cert_days_left(value: str | None) -> int | None:
        if not value:
            return None
        try:
            expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)
            return (expires - datetime.now(timezone.utc)).days
        except Exception:
            return None

    @staticmethod
    def _looks_blocked(result: EvidenceResult) -> bool:
        text = " ".join(
            [
                result.title or "",
                result.description or "",
                result.text_excerpt or "",
            ]
        ).lower()
        return any(marker in text for marker in BLOCK_PAGE_MARKERS)

    @staticmethod
    def _cert_name(value: Any) -> str:
        parts: list[str] = []
        for group in value or []:
            for key, item in group:
                if key in {"commonName", "organizationName"}:
                    parts.append(str(item))
        return ", ".join(parts[:4])


def score_finding(
    *,
    category: str,
    active: bool,
    status_code: int | None,
    keyword_hits: list[str],
    has_sources: bool,
    domain: str,
    mirror_group: str | None,
) -> tuple[int, str, list[str]]:
    reasons: list[str] = []
    risk = 20

    category_lower = (category or "").lower()
    category_tokens = set(re.split(r"[^a-z_]+", category_lower))
    if category_tokens & {"online_casino", "casino", "gambling"}:
        risk += 38
        reasons.append("Категория похожа на онлайн-казино/азартные игры.")
    elif category_tokens & {"sports_betting", "sports_betting_review", "betting", "bookmaker"}:
        risk += 18
        reasons.append("Категория похожа на букмекерский/ставочный сайт и требует проверки лицензии.")
    elif category_tokens & {"phishing", "scam", "pyramid", "investment_pyramid", "malware"}:
        risk += 45
        reasons.append("Категория похожа на фишинг/скам/пирамиду.")
    elif category_tokens & {"legit"}:
        risk -= 12
    elif category_tokens & {"empty_or_parked", "blocked_or_unreachable"}:
        risk -= 10
    elif category_lower == "suspicious":
        risk += 25
        reasons.append("Источник пометил домен как подозрительный.")

    if active:
        risk += 12
        reasons.append(f"Сайт отвечает HTTP {status_code}.")
    elif status_code:
        risk += 5
        reasons.append(f"Сайт доступен, но отвечает HTTP {status_code}.")

    if keyword_hits:
        casino_hits = sorted(set(keyword_hits) & CASINO_KEYWORDS)
        scam_hits = sorted(set(keyword_hits) & SCAM_KEYWORDS)
        betting_hits = sorted(set(keyword_hits) & BETTING_KEYWORDS)
        if casino_hits:
            risk += min(18, 4 * len(casino_hits))
            reasons.append("На странице найдены casino/game маркеры: " + ", ".join(casino_hits[:8]))
        if betting_hits:
            risk += min(8, 2 * len(betting_hits))
            reasons.append("На странице найдены betting/bookmaker маркеры: " + ", ".join(betting_hits[:8]))
        if scam_hits:
            risk += min(18, 4 * len(scam_hits))
            reasons.append("На странице найдены скам/фишинг-маркеры: " + ", ".join(scam_hits[:8]))

    if has_sources:
        risk += 10
        reasons.append("Есть внешние источники или Gemini Search Grounding, указывающие на находку.")

    if suspicious_tld(domain):
        risk += 8
        reasons.append("Домен использует часто встречающийся у одноразовых сайтов TLD.")

    if mirror_group:
        risk += 12
        reasons.append(f"Домен связан с зеркальной группой: {mirror_group}.")

    risk = max(0, min(100, risk))
    if risk >= 80:
        verdict = "suspected_fraud_or_illegal"
    elif risk >= 60:
        verdict = "suspicious"
    elif risk >= 40:
        verdict = "needs_review"
    else:
        verdict = "low_signal"
    return risk, verdict, reasons
