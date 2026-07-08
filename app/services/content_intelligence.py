from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from app.config import Settings
from app.services.domain_policy import domain_policy
from app.services.domains import extract_domain, is_ip_address, registered_domain, suspicious_tld
from app.services.risky_domains import gambling_domain_signals


CASINO_PRODUCT_KEYWORDS = [
    "казино",
    "casino",
    "вулкан",
    "vulkan",
    "1xslots",
    "joycasino",
    "joy casino",
    "слоты",
    "slots",
    "slot games",
    "игровые автоматы",
    "автоматы",
    "live casino",
    "roulette",
    "рулетка",
    "blackjack",
    "блэкджек",
    "poker",
    "покер",
    "free spins",
    "фриспины",
    "jackpot",
    "джекпот",
    "бонус за регистрацию",
    "бездепозитный бонус",
]

BETTING_KEYWORDS = [
    "ставки на спорт",
    "спортивные ставки",
    "ставки",
    "букмекер",
    "букмекерская контора",
    "bookmaker",
    "sportsbook",
    "sports betting",
    "betting",
    "коэффициенты",
    "линия ставок",
    "экспресс",
    "тотализатор",
    "pari match",
    "parimatch",
    "fonbet",
    "olimpbet",
    "1win",
    "1xbet",
    "mostbet",
    "melbet",
    "linebet",
    "bet365",
]

PYRAMID_KEYWORDS = [
    "инвестиционная платформа",
    "гарантированный доход",
    "гарантированная прибыль",
    "пассивный доход",
    "быстрый заработок",
    "ежедневная прибыль",
    "доходность",
    "hyip",
    "roi",
    "double your money",
    "guaranteed profit",
    "passive income",
    "investment opportunity",
    "usdt",
    "bitcoin",
    "crypto",
    "token",
    "mining",
]

PHISHING_KEYWORDS = [
    "login",
    "password",
    "verify",
    "account",
    "secure",
    "sign in",
    "wallet",
    "card number",
    "cvv",
    "kaspi",
    "halyk",
    "homebank",
    "paypal",
    "apple id",
    "microsoft",
    "подтвердите",
    "пароль",
    "аккаунт",
    "карта",
]

PARKED_OR_EMPTY_MARKERS = [
    "domain is for sale",
    "buy this domain",
    "this domain may be for sale",
    "parkingcrew",
    "sedo domain parking",
    "coming soon",
    "website coming soon",
    "under construction",
    "default web site page",
    "index of /",
    "домен продается",
    "сайт продается",
    "скоро открытие",
    "технические работы",
]

BLOCKED_OR_RESTRICTED_MARKERS = [
    "access to this site is blocked",
    "site is blocked",
    "resource is blocked",
    "access denied",
    "unavailable for legal reasons",
    "blocked by",
    "доступ ограничен",
    "доступ запрещен",
    "сайт заблокирован",
    "ресурс заблокирован",
    "заблокировано",
    "по решению суда",
    "қолжетімділік шектелген",
    "бұғатталған",
]

SUSPICIOUS_SCRIPT_PATTERNS = [
    r"\beval\s*\(",
    r"\batob\s*\(",
    r"document\.write",
    r"navigator\.clipboard",
    r"geolocation",
    r"getUserMedia",
    r"setTimeout\s*\(.{0,80}location",
    r"window\.location",
]

BRAND_DOMAINS = {
    "kaspi": "kaspi.kz",
    "halyk": "halykbank.kz",
    "homebank": "homebank.kz",
    "paypal": "paypal.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
}


class ContentIntelligence:
    def __init__(self, settings: Settings):
        self.settings = settings

    def analyze(self, url: str, evidence: Any) -> dict[str, Any]:
        html = self._read_html(getattr(evidence, "html_path", None))
        final_url = getattr(evidence, "final_url", None) or url
        domain = extract_domain(getattr(evidence, "domain", None) or final_url)
        dns = getattr(evidence, "dns", {}) or {}
        tls = getattr(evidence, "tls", {}) or {}
        domain_info = getattr(evidence, "domain_info", {}) or {}

        soup = BeautifulSoup(html or "", "html.parser")
        text = self._visible_text(soup)
        html_lower = (html or "").lower()
        text_lower = text.lower()
        url_lower = final_url.lower()
        domain_registered = registered_domain(domain)
        policy = domain_policy(domain)
        site_quality = self._site_quality(html, text, getattr(evidence, "page_size_bytes", None))

        form_stats = self._form_stats(soup, final_url)
        link_stats = self._link_stats(soup, final_url)
        script_stats = self._script_stats(soup, final_url)
        hidden_elements = self._hidden_elements(soup)
        num_iframes = len(soup.find_all("iframe"))
        has_meta_refresh = bool(
            soup.find("meta", attrs={"http-equiv": re.compile(r"refresh", re.IGNORECASE)})
        )

        casino_hits = self._keyword_hits(text_lower + " " + html_lower + " " + url_lower, CASINO_PRODUCT_KEYWORDS)
        betting_hits = self._keyword_hits(text_lower + " " + url_lower, BETTING_KEYWORDS)
        pyramid_hits = self._keyword_hits(text_lower + " " + url_lower, PYRAMID_KEYWORDS)
        phishing_hits = self._keyword_hits(text_lower + " " + url_lower, PHISHING_KEYWORDS)
        brand_hits = self._brand_impersonation(text_lower, domain_registered)

        suspicious_patterns = []
        for pattern in SUSPICIOUS_SCRIPT_PATTERNS:
            if re.search(pattern, html or "", re.IGNORECASE | re.DOTALL):
                suspicious_patterns.append(pattern)

        domain_gambling_signals = gambling_domain_signals(domain, f"{final_url} {text_lower[:4000]} {html_lower[:4000]}")
        has_casino_in_url = any(
            token in url_lower
            for token in ["casino", "kazino", "vulkan", "slot", "slots", "1xslots", "pinco", "pinup"]
        ) or bool(domain_gambling_signals)
        has_betting_in_url = any(token in url_lower for token in ["bookmaker", "sportsbook", "1win", "1xbet", "mostbet", "fonbet", "olimpbet", "melbet", "linebet", "bet365"])
        casino_confidence_score = self._casino_confidence(casino_hits, form_stats, has_casino_in_url)
        betting_confidence_score = self._betting_confidence(betting_hits, has_betting_in_url)
        credential_risk = self._credential_risk(form_stats, brand_hits)
        category, category_confidence = self._category_hint(
            policy=policy,
            site_quality=site_quality,
            casino_hits=casino_hits,
            betting_hits=betting_hits,
            pyramid_hits=pyramid_hits,
            phishing_hits=phishing_hits,
            brand_hits=brand_hits,
            domain_gambling_signals=domain_gambling_signals,
            form_stats=form_stats,
            casino_confidence_score=casino_confidence_score,
            betting_confidence_score=betting_confidence_score,
            credential_risk=credential_risk,
        )

        signals = self._signals(
            category=category,
            site_quality=site_quality,
            policy=policy,
            casino_hits=casino_hits,
            betting_hits=betting_hits,
            pyramid_hits=pyramid_hits,
            phishing_hits=phishing_hits,
            brand_hits=brand_hits,
            form_stats=form_stats,
            link_stats=link_stats,
            num_iframes=num_iframes,
            has_meta_refresh=has_meta_refresh,
            suspicious_patterns=suspicious_patterns,
            hidden_elements=hidden_elements,
            domain_gambling_signals=domain_gambling_signals,
        )

        features = {
            "url_length": len(final_url),
            "num_dots": domain.count("."),
            "num_hyphens": domain.count("-"),
            "num_digits": sum(ch.isdigit() for ch in domain),
            "has_ip": int(is_ip_address(domain)),
            "subdomain_count": max(0, len(domain.split(".")) - len(domain_registered.split("."))),
            "suspicious_tld": int(suspicious_tld(domain)),
            "path_length": len(urlparse(final_url).path or ""),
            "num_query_params": self._query_param_count(final_url),
            "special_chars_count": len(re.findall(r"[%@&?=]", final_url)),
            "has_dns": int(bool(dns.get("records"))),
            "has_mx": int(bool(dns.get("mx_records"))),
            "num_ip_addresses": len(dns.get("records") or []),
            "num_ns_servers": len(dns.get("ns_records") or []),
            "domain_age_days": self._number(domain_info.get("age_days"), -1),
            "is_private_whois": int(bool(domain_info.get("privacy") or domain_info.get("is_private"))),
            "days_to_expiry": self._number(self._days_to_expiry(domain_info.get("expires_at")), -1),
            "ssl_valid": int(bool(tls.get("valid"))),
            "ssl_days_until_expiry": self._number(tls.get("expires_in_days"), -1),
            "num_forms": form_stats["num_forms"],
            "num_password_forms": form_stats["num_password_forms"],
            "num_external_scripts": script_stats["num_external_scripts"],
            "num_external_resources": link_stats["num_external_resources"] + script_stats["num_external_scripts"],
            "scam_word_count": len(phishing_hits) + len(pyramid_hits),
            "has_brand_impersonation": int(bool(brand_hits)),
            "trusted_domain": int(bool(policy.get("trusted"))),
            "site_quality_score": site_quality["score"],
            "num_suspicious_patterns": len(suspicious_patterns),
            "num_iframes": num_iframes,
            "has_meta_refresh": int(has_meta_refresh),
            "has_redirect": int(getattr(evidence, "redirect_count", 0) > 0),
            "num_hidden_elements": hidden_elements,
            "num_external_links": link_stats["num_external_links"],
            "casino_keywords_count": len(casino_hits),
            "betting_keywords_count": len(betting_hits),
            "has_casino_in_url": int(has_casino_in_url),
            "has_betting_in_url": int(has_betting_in_url),
            "casino_confidence_score": casino_confidence_score,
            "betting_confidence_score": betting_confidence_score,
            "gambling_domain_signal_count": len(domain_gambling_signals),
        }

        return {
            "available": bool(html),
            "category_hint": category,
            "category_confidence": category_confidence,
            "risk_delta": self._risk_delta(
                category,
                category_confidence,
                form_stats,
                suspicious_patterns,
                hidden_elements,
                policy,
                site_quality,
            ),
            "signals": signals,
            "casino_keywords": casino_hits[:12],
            "betting_keywords": betting_hits[:12],
            "pyramid_keywords": pyramid_hits[:12],
            "phishing_keywords": phishing_hits[:12],
            "brand_impersonation": brand_hits,
            "domain_gambling_signals": domain_gambling_signals,
            "domain_policy": policy,
            "site_quality": site_quality,
            "credential_risk": credential_risk,
            "forms": form_stats,
            "links": link_stats,
            "scripts": script_stats,
            "num_iframes": num_iframes,
            "has_meta_refresh": has_meta_refresh,
            "num_hidden_elements": hidden_elements,
            "suspicious_patterns": suspicious_patterns[:10],
            "features": features,
        }

    def _read_html(self, html_path: str | None) -> str:
        if not html_path:
            return ""
        path = Path(str(html_path).replace("\\", "/"))
        if not path.is_absolute():
            path = self.settings.evidence_dir / path.name
        try:
            return path.read_text(encoding="utf-8", errors="ignore")[:1_500_000]
        except OSError:
            return ""

    @staticmethod
    def _visible_text(soup: BeautifulSoup) -> str:
        soup = BeautifulSoup(str(soup), "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        return re.sub(r"\s+", " ", soup.get_text(" ", strip=True))[:200_000]

    def _form_stats(self, soup: BeautifulSoup, base_url: str) -> dict[str, Any]:
        base_domain = registered_domain(extract_domain(base_url))
        forms = []
        for form in soup.find_all("form"):
            action = str(form.get("action") or "").strip()
            action_url = urljoin(base_url, action) if action else ""
            action_domain = registered_domain(extract_domain(action_url)) if action_url else ""
            input_types = [str(item.get("type") or "text").lower() for item in form.find_all("input")]
            names = " ".join(str(item.get("name") or item.get("id") or "").lower() for item in form.find_all("input"))
            has_card = any(token in names for token in ["card", "cc", "cvv", "pan", "карта"])
            external_action = bool(action_domain and action_domain != base_domain)
            forms.append(
                {
                    "action": action_url,
                    "method": str(form.get("method") or "GET").upper(),
                    "input_count": len(input_types),
                    "input_types": input_types[:20],
                    "has_password": "password" in input_types,
                    "has_hidden": "hidden" in input_types,
                    "has_credit_card": has_card,
                    "external_action": external_action,
                }
            )
        return {
            "num_forms": len(forms),
            "num_password_forms": sum(1 for item in forms if item["has_password"]),
            "num_hidden_inputs": sum(item["input_types"].count("hidden") for item in forms),
            "num_external_form_actions": sum(1 for item in forms if item["external_action"]),
            "num_credit_card_forms": sum(1 for item in forms if item["has_credit_card"]),
            "items": forms[:8],
        }

    def _link_stats(self, soup: BeautifulSoup, base_url: str) -> dict[str, int]:
        base_domain = registered_domain(extract_domain(base_url))
        external_links = 0
        internal_links = 0
        external_resources = 0

        for tag in soup.find_all("a", href=True):
            target_domain = registered_domain(extract_domain(urljoin(base_url, str(tag.get("href")))))
            if not target_domain:
                continue
            if target_domain == base_domain:
                internal_links += 1
            else:
                external_links += 1

        for tag_name, attr in [("img", "src"), ("link", "href"), ("source", "src"), ("iframe", "src")]:
            for tag in soup.find_all(tag_name):
                value = str(tag.get(attr) or "")
                target_domain = registered_domain(extract_domain(urljoin(base_url, value)))
                if target_domain and target_domain != base_domain:
                    external_resources += 1

        return {
            "num_external_links": external_links,
            "num_internal_links": internal_links,
            "num_external_resources": external_resources,
        }

    def _script_stats(self, soup: BeautifulSoup, base_url: str) -> dict[str, int]:
        base_domain = registered_domain(extract_domain(base_url))
        external = 0
        inline_suspicious = 0
        for script in soup.find_all("script"):
            src = str(script.get("src") or "")
            if src:
                target_domain = registered_domain(extract_domain(urljoin(base_url, src)))
                if target_domain and target_domain != base_domain:
                    external += 1
            body = script.string or ""
            if body and any(re.search(pattern, body, re.IGNORECASE | re.DOTALL) for pattern in SUSPICIOUS_SCRIPT_PATTERNS):
                inline_suspicious += 1
        return {"num_external_scripts": external, "num_suspicious_inline_scripts": inline_suspicious}

    @staticmethod
    def _hidden_elements(soup: BeautifulSoup) -> int:
        count = 0
        for tag in soup.find_all(True):
            style = str(tag.get("style") or "").replace(" ", "").lower()
            if tag.has_attr("hidden") or "display:none" in style or "visibility:hidden" in style or "opacity:0" in style:
                count += 1
        return count

    @staticmethod
    def _keyword_hits(text: str, keywords: list[str]) -> list[str]:
        hits: set[str] = set()
        for keyword in keywords:
            clean = keyword.lower().strip()
            if not clean:
                continue
            pattern = r"(?<![\w])" + r"\s+".join(re.escape(part) for part in clean.split()) + r"(?![\w])"
            if re.search(pattern, text, re.IGNORECASE):
                hits.add(keyword)
        return sorted(hits)

    @staticmethod
    def _brand_impersonation(text: str, domain: str) -> list[str]:
        hits = []
        for brand, official_domain in BRAND_DOMAINS.items():
            pattern = r"(?<![\w])" + re.escape(brand) + r"(?![\w])"
            if re.search(pattern, text, re.IGNORECASE) and registered_domain(official_domain) != domain:
                hits.append(brand)
        return hits[:8]

    @staticmethod
    def _site_quality(html: str, text: str, page_size_bytes: Any) -> dict[str, Any]:
        html_size = len(html or "")
        text_size = len(text or "")
        try:
            page_size = int(page_size_bytes or 0)
        except (TypeError, ValueError):
            page_size = 0
        lowered = " ".join([html[:80_000], text[:20_000]]).lower()
        marker_hits = [marker for marker in PARKED_OR_EMPTY_MARKERS if marker in lowered]
        blocked_hits = [marker for marker in BLOCKED_OR_RESTRICTED_MARKERS if marker in lowered]
        thin = text_size < 120 and html_size < 20_000 and page_size < 20_000
        empty = not html or (text_size < 40 and html_size < 5000 and page_size < 5000)
        parked = bool(marker_hits)
        blocked = bool(blocked_hits)
        score = 100
        if text_size < 120:
            score -= 35
        if html_size < 5000:
            score -= 20
        if page_size and page_size < 3000:
            score -= 15
        if parked:
            score -= 60
        if blocked:
            score -= 80
        quality = "usable"
        if blocked:
            quality = "blocked_or_unreachable"
        elif empty or parked:
            quality = "empty_or_parked"
        elif thin:
            quality = "thin_content"
        return {
            "quality": quality,
            "score": max(0, min(100, score)),
            "is_empty_or_parked": quality == "empty_or_parked",
            "is_blocked_or_restricted": quality == "blocked_or_unreachable",
            "is_thin": quality in {"empty_or_parked", "thin_content", "blocked_or_unreachable"},
            "html_size": html_size,
            "visible_text_size": text_size,
            "page_size_bytes": page_size,
            "markers": (blocked_hits + marker_hits)[:8],
        }

    @staticmethod
    def _casino_confidence(casino_hits: list[str], form_stats: dict[str, Any], has_casino_in_url: bool) -> float:
        score = min(0.82, len(casino_hits) * 0.16)
        if has_casino_in_url:
            score += 0.18
        if form_stats["num_forms"]:
            score += 0.03
        return round(min(1.0, score), 4)

    @staticmethod
    def _betting_confidence(betting_hits: list[str], has_betting_in_url: bool) -> float:
        score = min(0.72, len(betting_hits) * 0.14)
        if has_betting_in_url:
            score += 0.18
        return round(min(1.0, score), 4)

    @staticmethod
    def _credential_risk(form_stats: dict[str, Any], brand_hits: list[str]) -> bool:
        return bool(
            brand_hits
            or form_stats["num_external_form_actions"]
            or form_stats["num_credit_card_forms"]
            or form_stats["num_password_forms"] >= 2
        )

    @staticmethod
    def _category_hint(
        *,
        policy: dict[str, Any],
        site_quality: dict[str, Any],
        casino_hits: list[str],
        betting_hits: list[str],
        pyramid_hits: list[str],
        phishing_hits: list[str],
        brand_hits: list[str],
        domain_gambling_signals: list[str],
        form_stats: dict[str, Any],
        casino_confidence_score: float,
        betting_confidence_score: float,
        credential_risk: bool,
    ) -> tuple[str | None, str]:
        has_domain_signals = bool(casino_hits or betting_hits or pyramid_hits or brand_hits or domain_gambling_signals)
        if site_quality.get("is_blocked_or_restricted"):
            return "blocked_or_unreachable", "high"
        if site_quality.get("is_empty_or_parked") and (site_quality.get("markers") or not has_domain_signals):
            return "empty_or_parked", "high"
        if policy.get("trusted") and not credential_risk:
            return "legit", "high"
        if brand_hits:
            confidence = "high" if brand_hits or form_stats["num_external_form_actions"] or form_stats["num_credit_card_forms"] else "medium"
            return "phishing", confidence
        if casino_confidence_score >= 0.50 and len(casino_hits) >= 2:
            return "online_casino", "high" if casino_confidence_score >= 0.76 else "medium"
        if domain_gambling_signals and casino_confidence_score >= 0.18:
            return "online_casino", "medium"
        if credential_risk:
            confidence = "high" if form_stats["num_external_form_actions"] or form_stats["num_credit_card_forms"] else "medium"
            return "phishing", confidence
        if betting_confidence_score >= 0.42 and betting_hits:
            return "sports_betting_review", "medium"
        if len(pyramid_hits) >= 3:
            return "investment_pyramid", "high" if len(pyramid_hits) >= 5 else "medium"
        if len(phishing_hits) >= 4:
            return "suspicious", "medium"
        return None, "low"

    @staticmethod
    def _signals(
        *,
        category: str | None,
        site_quality: dict[str, Any],
        policy: dict[str, Any],
        casino_hits: list[str],
        betting_hits: list[str],
        pyramid_hits: list[str],
        phishing_hits: list[str],
        brand_hits: list[str],
        domain_gambling_signals: list[str],
        form_stats: dict[str, Any],
        link_stats: dict[str, int],
        num_iframes: int,
        has_meta_refresh: bool,
        suspicious_patterns: list[str],
        hidden_elements: int,
    ) -> list[str]:
        signals = []
        if policy.get("trusted"):
            signals.append(f"Домен находится в доверенном списке: {policy.get('reason')}.")
        if site_quality.get("quality") != "usable":
            signals.append(
                f"Качество страницы: {site_quality.get('quality')} "
                f"(text={site_quality.get('visible_text_size')}, html={site_quality.get('html_size')})."
            )
        if category:
            signals.append(f"Контентный анализ дал категорию: {category}.")
        if casino_hits:
            signals.append("Найдены casino/game маркеры: " + ", ".join(casino_hits[:8]))
        if betting_hits:
            signals.append("Найдены betting/bookmaker маркеры: " + ", ".join(betting_hits[:8]))
        if pyramid_hits:
            signals.append("Найдены признаки пирамиды/инвест-скама: " + ", ".join(pyramid_hits[:8]))
        if phishing_hits:
            signals.append("Найдены phishing/login маркеры: " + ", ".join(phishing_hits[:8]))
        if brand_hits:
            signals.append("Упоминание известных брендов вне официального домена: " + ", ".join(brand_hits))
        if domain_gambling_signals:
            signals.append("Домен похож на casino/mirror landing: " + ", ".join(domain_gambling_signals[:4]))
        if form_stats["num_password_forms"]:
            signals.append(f"Формы с password-полем: {form_stats['num_password_forms']}.")
        if form_stats["num_external_form_actions"]:
            signals.append(f"Формы отправляют данные на внешний домен: {form_stats['num_external_form_actions']}.")
        if form_stats["num_credit_card_forms"]:
            signals.append(f"Формы запрашивают карточные данные: {form_stats['num_credit_card_forms']}.")
        if num_iframes:
            signals.append(f"iframe на странице: {num_iframes}.")
        if has_meta_refresh:
            signals.append("Обнаружен meta refresh redirect.")
        if suspicious_patterns:
            signals.append(f"Подозрительные JS-паттерны: {len(suspicious_patterns)}.")
        if hidden_elements:
            signals.append(f"Скрытые элементы в HTML: {hidden_elements}.")
        if link_stats["num_external_links"] > 25:
            signals.append(f"Много внешних ссылок: {link_stats['num_external_links']}.")
        return signals[:18]

    @staticmethod
    def _risk_delta(
        category: str | None,
        confidence: str,
        form_stats: dict[str, Any],
        suspicious_patterns: list[str],
        hidden_elements: int,
        policy: dict[str, Any],
        site_quality: dict[str, Any],
    ) -> int:
        delta = 0
        if category in {"online_casino", "investment_pyramid", "phishing"}:
            delta += 24 if confidence == "high" else 16
        elif category == "sports_betting_review":
            delta += 8
        elif category == "suspicious":
            delta += 10
        elif category in {"empty_or_parked", "blocked_or_unreachable"}:
            delta -= 20
        delta += min(16, form_stats["num_password_forms"] * 8)
        delta += min(18, form_stats["num_external_form_actions"] * 12)
        delta += min(12, len(suspicious_patterns) * 3)
        delta += min(8, hidden_elements // 4)
        if policy.get("trusted") and category != "phishing":
            delta -= 30
        if site_quality.get("is_empty_or_parked"):
            delta -= 20
        if site_quality.get("is_blocked_or_restricted"):
            delta -= 25
        return max(-45, min(45, delta))

    @staticmethod
    def _query_param_count(url: str) -> int:
        query = urlparse(url).query
        if not query:
            return 0
        return len([item for item in query.split("&") if item])

    @staticmethod
    def _number(value: Any, default: float = 0) -> float:
        try:
            if value is None:
                return float(default)
            number = float(value)
            return float(default) if math.isnan(number) else number
        except (TypeError, ValueError):
            return float(default)

    @staticmethod
    def _days_to_expiry(value: Any) -> int | None:
        if not value:
            return None
        from datetime import datetime, timezone

        try:
            expires = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            return (expires - datetime.now(timezone.utc)).days
        except (TypeError, ValueError):
            return None
