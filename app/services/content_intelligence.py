from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from app.config import Settings
from app.services.domains import extract_domain, is_ip_address, registered_domain, suspicious_tld


CASINO_KEYWORDS = [
    "казино",
    "casino",
    "вулкан",
    "vulkan",
    "pin up",
    "pinup",
    "пин ап",
    "joycasino",
    "joy casino",
    "mostbet",
    "1xbet",
    "1xslots",
    "ставки",
    "betting",
    "букмекер",
    "bookmaker",
    "слоты",
    "slots",
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
    "игровые автоматы",
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

        form_stats = self._form_stats(soup, final_url)
        link_stats = self._link_stats(soup, final_url)
        script_stats = self._script_stats(soup, final_url)
        hidden_elements = self._hidden_elements(soup)
        num_iframes = len(soup.find_all("iframe"))
        has_meta_refresh = bool(
            soup.find("meta", attrs={"http-equiv": re.compile(r"refresh", re.IGNORECASE)})
        )

        casino_hits = self._keyword_hits(text_lower + " " + html_lower + " " + url_lower, CASINO_KEYWORDS)
        pyramid_hits = self._keyword_hits(text_lower + " " + url_lower, PYRAMID_KEYWORDS)
        phishing_hits = self._keyword_hits(text_lower + " " + url_lower, PHISHING_KEYWORDS)
        brand_hits = self._brand_impersonation(text_lower, domain_registered)

        suspicious_patterns = []
        for pattern in SUSPICIOUS_SCRIPT_PATTERNS:
            if re.search(pattern, html or "", re.IGNORECASE | re.DOTALL):
                suspicious_patterns.append(pattern)

        has_casino_in_url = any(token in url_lower for token in ["casino", "kazino", "vulkan", "1x", "bet", "slot"])
        casino_confidence_score = self._casino_confidence(casino_hits, form_stats, has_casino_in_url)
        category, category_confidence = self._category_hint(
            casino_hits=casino_hits,
            pyramid_hits=pyramid_hits,
            phishing_hits=phishing_hits,
            brand_hits=brand_hits,
            form_stats=form_stats,
            casino_confidence_score=casino_confidence_score,
        )

        signals = self._signals(
            category=category,
            casino_hits=casino_hits,
            pyramid_hits=pyramid_hits,
            phishing_hits=phishing_hits,
            brand_hits=brand_hits,
            form_stats=form_stats,
            link_stats=link_stats,
            num_iframes=num_iframes,
            has_meta_refresh=has_meta_refresh,
            suspicious_patterns=suspicious_patterns,
            hidden_elements=hidden_elements,
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
            "num_suspicious_patterns": len(suspicious_patterns),
            "num_iframes": num_iframes,
            "has_meta_refresh": int(has_meta_refresh),
            "has_redirect": int(getattr(evidence, "redirect_count", 0) > 0),
            "num_hidden_elements": hidden_elements,
            "num_external_links": link_stats["num_external_links"],
            "casino_keywords_count": len(casino_hits),
            "has_casino_in_url": int(has_casino_in_url),
            "casino_confidence_score": casino_confidence_score,
        }

        return {
            "available": bool(html),
            "category_hint": category,
            "category_confidence": category_confidence,
            "risk_delta": self._risk_delta(category, category_confidence, form_stats, suspicious_patterns, hidden_elements),
            "signals": signals,
            "casino_keywords": casino_hits[:12],
            "pyramid_keywords": pyramid_hits[:12],
            "phishing_keywords": phishing_hits[:12],
            "brand_impersonation": brand_hits,
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
        return sorted({keyword for keyword in keywords if keyword.lower() in text})

    @staticmethod
    def _brand_impersonation(text: str, domain: str) -> list[str]:
        hits = []
        for brand, official_domain in BRAND_DOMAINS.items():
            if brand in text and registered_domain(official_domain) != domain:
                hits.append(brand)
        return hits[:8]

    @staticmethod
    def _casino_confidence(casino_hits: list[str], form_stats: dict[str, Any], has_casino_in_url: bool) -> float:
        score = min(0.85, len(casino_hits) * 0.12)
        if has_casino_in_url:
            score += 0.25
        if form_stats["num_forms"]:
            score += 0.05
        return round(min(1.0, score), 4)

    @staticmethod
    def _category_hint(
        *,
        casino_hits: list[str],
        pyramid_hits: list[str],
        phishing_hits: list[str],
        brand_hits: list[str],
        form_stats: dict[str, Any],
        casino_confidence_score: float,
    ) -> tuple[str | None, str]:
        if casino_confidence_score >= 0.55 or len(casino_hits) >= 3:
            return "casino", "high" if casino_confidence_score >= 0.75 else "medium"
        if len(pyramid_hits) >= 3:
            return "pyramid", "high" if len(pyramid_hits) >= 5 else "medium"
        if brand_hits or form_stats["num_password_forms"] or form_stats["num_credit_card_forms"]:
            confidence = "high" if brand_hits or form_stats["num_external_form_actions"] else "medium"
            return "phishing", confidence
        if len(phishing_hits) >= 4:
            return "suspicious", "medium"
        return None, "low"

    @staticmethod
    def _signals(
        *,
        category: str | None,
        casino_hits: list[str],
        pyramid_hits: list[str],
        phishing_hits: list[str],
        brand_hits: list[str],
        form_stats: dict[str, Any],
        link_stats: dict[str, int],
        num_iframes: int,
        has_meta_refresh: bool,
        suspicious_patterns: list[str],
        hidden_elements: int,
    ) -> list[str]:
        signals = []
        if category:
            signals.append(f"Контентный анализ дал категорию: {category}.")
        if casino_hits:
            signals.append("Найдены casino/betting маркеры: " + ", ".join(casino_hits[:8]))
        if pyramid_hits:
            signals.append("Найдены признаки пирамиды/инвест-скама: " + ", ".join(pyramid_hits[:8]))
        if phishing_hits:
            signals.append("Найдены phishing/login маркеры: " + ", ".join(phishing_hits[:8]))
        if brand_hits:
            signals.append("Упоминание известных брендов вне официального домена: " + ", ".join(brand_hits))
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
    ) -> int:
        delta = 0
        if category in {"casino", "pyramid", "phishing"}:
            delta += 24 if confidence == "high" else 16
        elif category == "suspicious":
            delta += 10
        delta += min(16, form_stats["num_password_forms"] * 8)
        delta += min(18, form_stats["num_external_form_actions"] * 12)
        delta += min(12, len(suspicious_patterns) * 3)
        delta += min(8, hidden_elements // 4)
        return min(45, delta)

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
