from __future__ import annotations

import hashlib
import re
import socket
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from app.config import Settings
from app.services.domains import extract_domain, normalize_url, suspicious_tld


CASINO_KEYWORDS = {
    "casino",
    "казино",
    "bet",
    "bets",
    "bookmaker",
    "букмекер",
    "slot",
    "slots",
    "слоты",
    "bonus",
    "бонус",
    "deposit",
    "депозит",
    "withdraw",
    "вывод",
    "mirror",
    "зеркало",
    "1xbet",
}

SCAM_KEYWORDS = {
    "phishing",
    "login",
    "verify",
    "wallet",
    "crypto",
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
        }


class EvidenceCollector:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def collect(self, url: str, run_id: int) -> EvidenceResult:
        normalized = normalize_url(url)
        result = EvidenceResult(requested_url=normalized)
        result.domain = extract_domain(normalized)
        result.dns = self._resolve_dns(result.domain)
        result.tls = self._tls_certificate(result.domain)

        candidates = self._url_candidates(normalized)
        headers = {"User-Agent": self.settings.user_agent}

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=self.settings.request_timeout_seconds,
            headers=headers,
            verify=True,
        ) as client:
            for candidate in candidates:
                try:
                    response = await client.get(candidate)
                    result.status_code = response.status_code
                    result.final_url = str(response.url)
                    result.active = 200 <= response.status_code < 400
                    content_type = response.headers.get("content-type", "")
                    if "text/html" in content_type or response.text:
                        self._parse_html(result, response.text[:1_500_000], run_id)
                    break
                except Exception as exc:  # noqa: BLE001 - keep evidence of network failures.
                    result.errors.append(f"{candidate}: {type(exc).__name__}: {exc}")

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
        hits = sorted({word for word in CASINO_KEYWORDS | SCAM_KEYWORDS if word in lowered})
        return hits[:30]

    def _resolve_dns(self, domain: str | None) -> dict[str, Any]:
        if not domain:
            return {"records": [], "error": "empty domain"}
        try:
            addresses = socket.getaddrinfo(domain, None)
            ips = sorted({item[4][0] for item in addresses if item and item[4]})
            return {"records": ips[:20]}
        except Exception as exc:  # noqa: BLE001
            return {"records": [], "error": f"{type(exc).__name__}: {exc}"}

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
            }
        except Exception as exc:  # noqa: BLE001
            return {"error": f"{type(exc).__name__}: {exc}"}

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
    if category_lower in {"casino", "gambling", "betting"}:
        risk += 35
        reasons.append("Категория похожа на казино/беттинг.")
    elif category_lower in {"phishing", "scam", "pyramid", "malware"}:
        risk += 45
        reasons.append("Категория похожа на фишинг/скам/пирамиду.")
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
        if casino_hits:
            risk += min(18, 4 * len(casino_hits))
            reasons.append("На странице найдены казино/беттинг-маркеры: " + ", ".join(casino_hits[:8]))
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
