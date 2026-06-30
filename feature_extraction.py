from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import math
import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
import tldextract
from bs4 import BeautifulSoup

try:
    import dns.resolver
except Exception:  # pragma: no cover - optional at runtime
    dns = None  # type: ignore[assignment]

try:
    import whois
except Exception:  # pragma: no cover - optional at runtime
    whois = None  # type: ignore[assignment]


LABELS = ("legit", "phishing", "casino", "pyramid", "suspicious")
TLD_EXTRACT = tldextract.TLDExtract(cache_dir="data/ml/tldextract", suffix_list_urls=())

FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "path_length",
    "dot_count",
    "hyphen_count",
    "slash_count",
    "digit_count",
    "has_ip_host",
    "has_at_symbol",
    "subdomain_count",
    "suspicious_tld",
    "domain_age_days",
    "domain_expiry_days",
    "whois_privacy",
    "registrar_country_kz",
    "whois_available",
    "dns_a_count",
    "dns_mx_count",
    "dns_txt_count",
    "has_spf",
    "has_dmarc",
    "ssl_valid",
    "ssl_days_to_expiry",
    "ssl_self_signed",
    "ssl_issuer_known",
    "response_time_ms",
    "page_size_bytes",
    "password_form_count",
    "iframe_count",
    "external_link_ratio",
    "popup_or_redirect",
    "casino_keyword_count",
    "pyramid_keyword_count",
    "phishing_keyword_count",
]

if len(FEATURE_COLUMNS) != 34:
    raise RuntimeError("FEATURE_COLUMNS contract changed; update the report and tests.")


SUSPICIOUS_TLDS = {
    "top",
    "xyz",
    "lol",
    "shop",
    "click",
    "live",
    "icu",
    "quest",
    "cfd",
    "sbs",
    "buzz",
}

KNOWN_SSL_ISSUERS = (
    "let's encrypt",
    "google trust",
    "digicert",
    "sectigo",
    "cloudflare",
    "amazon",
    "globalsign",
    "zerossl",
)

CASINO_KEYWORDS = (
    "casino",
    "slot",
    "slots",
    "bet",
    "betting",
    "bookmaker",
    "bonus",
    "jackpot",
    "deposit",
    "withdraw",
    "1xbet",
    "pinup",
    "mostbet",
    "melbet",
    "parimatch",
    "olimpbet",
    "vavada",
    "ggbet",
)

PYRAMID_KEYWORDS = (
    "hyip",
    "mlm",
    "ponzi",
    "income",
    "profit",
    "investment",
    "invest",
    "crypto",
    "bitcoin",
    "usdt",
    "guaranteed",
    "earn",
    "roi",
    "passive",
)

PHISHING_KEYWORDS = (
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "password",
    "wallet",
    "signin",
    "auth",
    "support",
    "kaspi",
    "halyk",
    "bcc",
    "forte",
)


@dataclass(frozen=True)
class FetchResult:
    final_url: str = ""
    status_code: int = 0
    response_time_ms: int = -1
    page_size_bytes: int = -1
    html: str = ""
    redirect_count: int = 0
    error: str = ""


def normalize_url(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    if not re.match(r"^[a-z][a-z0-9+.-]*://", value, flags=re.I):
        value = "https://" + value
    return value


def registered_domain(hostname: str) -> str:
    extracted = TLD_EXTRACT(hostname or "")
    if not extracted.domain or not extracted.suffix:
        return hostname.lower().strip(".")
    return f"{extracted.domain}.{extracted.suffix}".lower()


def hostname_from_url(url: str) -> str:
    try:
        parsed = urlparse(normalize_url(url))
        return (parsed.hostname or "").lower().strip(".")
    except ValueError:
        return ""


def is_ip_hostname(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def count_keywords(text: str, keywords: tuple[str, ...]) -> int:
    lowered = (text or "").lower()
    return sum(1 for word in keywords if word in lowered)


def safe_days_between(start: Any, end: datetime) -> int:
    if isinstance(start, list):
        start = next((item for item in start if item), None)
    if not isinstance(start, datetime):
        return -1
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    return max(-1, (end - start).days)


def fetch_url(url: str, *, timeout: int = 10, proxy: str | None = None) -> FetchResult:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"
        )
    }
    try:
        started = time.perf_counter()
        response = requests.get(
            normalize_url(url),
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            proxies=proxies,
            verify=True,
        )
        elapsed = int((time.perf_counter() - started) * 1000)
        content_type = response.headers.get("content-type", "")
        html = response.text[:1_000_000] if "html" in content_type or response.text else ""
        return FetchResult(
            final_url=str(response.url),
            status_code=int(response.status_code),
            response_time_ms=elapsed,
            page_size_bytes=len(response.content or b""),
            html=html,
            redirect_count=len(response.history),
        )
    except Exception as exc:  # noqa: BLE001
        return FetchResult(error=f"{type(exc).__name__}: {exc}")


def extract_content_features(html: str, final_url: str, redirect_count: int) -> tuple[dict[str, float], str]:
    if not html:
        return {
            "password_form_count": 0,
            "iframe_count": 0,
            "external_link_ratio": -1,
            "popup_or_redirect": 1 if redirect_count > 2 else 0,
        }, ""

    soup = BeautifulSoup(html, "html.parser")
    host = hostname_from_url(final_url)
    forms = soup.find_all("form")
    password_forms = 0
    for form in forms:
        if form.find("input", attrs={"type": re.compile("password", re.I)}):
            password_forms += 1

    links = [a.get("href") for a in soup.find_all("a") if a.get("href")]
    internal = 0
    external = 0
    for href in links[:1000]:
        link_host = hostname_from_url(str(href)) if str(href).startswith(("http://", "https://")) else host
        if link_host and host and registered_domain(link_host) != registered_domain(host):
            external += 1
        else:
            internal += 1
    total_links = internal + external

    text_parts = []
    if soup.title and soup.title.string:
        text_parts.append(soup.title.string)
    description = soup.find("meta", attrs={"name": re.compile("^description$", re.I)})
    if description and description.get("content"):
        text_parts.append(str(description.get("content")))
    for script in soup(["script", "style", "noscript"]):
        script.decompose()
    text_parts.append(soup.get_text(" ", strip=True)[:4000])
    text_blob = re.sub(r"\s+", " ", " ".join(text_parts)).strip()

    popup_markers = ("window.open", "settimeout", "location.href", "document.location")
    lowered_html = html[:200_000].lower()
    return {
        "password_form_count": float(password_forms),
        "iframe_count": float(len(soup.find_all("iframe"))),
        "external_link_ratio": float(external / total_links) if total_links else -1,
        "popup_or_redirect": 1 if redirect_count > 2 or any(marker in lowered_html for marker in popup_markers) else 0,
    }, text_blob


def extract_whois_features(domain: str) -> dict[str, float]:
    empty = {
        "domain_age_days": -1,
        "domain_expiry_days": -1,
        "whois_privacy": 0,
        "registrar_country_kz": 0,
        "whois_available": 0,
    }
    if whois is None or not domain or is_ip_hostname(domain):
        return empty
    try:
        info = whois.whois(domain)
    except Exception:
        return empty

    now = datetime.now(timezone.utc)
    created = getattr(info, "creation_date", None)
    expires = getattr(info, "expiration_date", None)
    country = str(getattr(info, "country", "") or "").upper()
    registrar = str(getattr(info, "registrar", "") or "").lower()
    org = str(getattr(info, "org", "") or getattr(info, "organization", "") or "").lower()
    privacy = int(any(token in f"{registrar} {org}" for token in ("privacy", "redacted", "whoisguard", "private")))
    expiry_days = safe_days_between(now, expires) if isinstance(expires, datetime) else -1
    if isinstance(expires, list):
        expiry_days = safe_days_between(now, next((item for item in expires if item), None))
    return {
        "domain_age_days": safe_days_between(created, now),
        "domain_expiry_days": expiry_days,
        "whois_privacy": privacy,
        "registrar_country_kz": 1 if country == "KZ" else 0,
        "whois_available": 1,
    }


def extract_dns_features(domain: str) -> dict[str, float]:
    result = {
        "dns_a_count": 0,
        "dns_mx_count": 0,
        "dns_txt_count": 0,
        "has_spf": 0,
        "has_dmarc": 0,
    }
    if dns is None or not domain or is_ip_hostname(domain):
        return result
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4
    resolver.timeout = 3
    try:
        result["dns_a_count"] = len(resolver.resolve(domain, "A"))
    except Exception:
        pass
    try:
        result["dns_mx_count"] = len(resolver.resolve(domain, "MX"))
    except Exception:
        pass
    try:
        txt_records = [b" ".join(item.strings).decode("utf-8", errors="ignore") for item in resolver.resolve(domain, "TXT")]
        result["dns_txt_count"] = len(txt_records)
        result["has_spf"] = int(any("v=spf1" in item.lower() for item in txt_records))
    except Exception:
        pass
    try:
        dmarc = [b" ".join(item.strings).decode("utf-8", errors="ignore") for item in resolver.resolve(f"_dmarc.{domain}", "TXT")]
        result["has_dmarc"] = int(any("v=dmarc1" in item.lower() for item in dmarc))
    except Exception:
        pass
    return result


def extract_ssl_features(domain: str) -> dict[str, float]:
    result = {
        "ssl_valid": 0,
        "ssl_days_to_expiry": -1,
        "ssl_self_signed": 0,
        "ssl_issuer_known": 0,
    }
    if not domain or is_ip_hostname(domain):
        return result
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
    except Exception:
        return result

    issuer = " ".join(str(item) for group in cert.get("issuer", []) for _, item in group).lower()
    subject = " ".join(str(item) for group in cert.get("subject", []) for _, item in group).lower()
    not_after = cert.get("notAfter")
    result["ssl_valid"] = 1
    if not_after:
        try:
            expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
            result["ssl_days_to_expiry"] = (expires - datetime.now(timezone.utc)).days
        except Exception:
            pass
    result["ssl_self_signed"] = int(bool(issuer and subject and issuer == subject))
    result["ssl_issuer_known"] = int(any(token in issuer for token in KNOWN_SSL_ISSUERS))
    return result


def extract_features(url: str, *, network: bool = False, timeout: int = 10, proxy: str | None = None) -> dict[str, Any]:
    normalized = normalize_url(url)
    try:
        parsed = urlparse(normalized)
    except ValueError:
        parsed = urlparse("https://invalid.local/")
    host = hostname_from_url(normalized)
    reg_domain = registered_domain(host)
    ext = TLD_EXTRACT(host)
    fetch = FetchResult(final_url=normalized)
    text_blob = " ".join([normalized, host, reg_domain, parsed.path.replace("/", " "), parsed.query.replace("&", " ")])
    if network:
        fetch = fetch_url(normalized, timeout=timeout, proxy=proxy)
        content, page_text = extract_content_features(fetch.html, fetch.final_url or normalized, fetch.redirect_count)
        if page_text:
            text_blob = f"{text_blob} {page_text}"
    else:
        content = {
            "password_form_count": 0,
            "iframe_count": 0,
            "external_link_ratio": -1,
            "popup_or_redirect": 0,
        }

    features: dict[str, Any] = {
        "url": normalized,
        "domain": reg_domain,
        "url_hash": hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16],
        "text_blob": text_blob[:8000],
        "url_length": len(normalized),
        "hostname_length": len(host),
        "path_length": len(parsed.path or ""),
        "query_length": len(parsed.query or ""),
        "dot_count": normalized.count("."),
        "hyphen_count": normalized.count("-"),
        "slash_count": normalized.count("/"),
        "digit_count": sum(char.isdigit() for char in normalized),
        "special_char_count": sum(1 for char in normalized if not char.isalnum()),
        "has_ip_host": int(is_ip_hostname(host)),
        "has_at_symbol": int("@" in normalized),
        "subdomain_count": max(0, len([part for part in ext.subdomain.split(".") if part])),
        "suspicious_tld": int((ext.suffix or "").split(".")[-1] in SUSPICIOUS_TLDS),
        "response_time_ms": fetch.response_time_ms,
        "page_size_bytes": fetch.page_size_bytes,
        "casino_keyword_count": count_keywords(text_blob, CASINO_KEYWORDS),
        "pyramid_keyword_count": count_keywords(text_blob, PYRAMID_KEYWORDS),
        "phishing_keyword_count": count_keywords(text_blob, PHISHING_KEYWORDS),
    }

    if network:
        features.update(extract_whois_features(reg_domain))
        features.update(extract_dns_features(reg_domain))
        features.update(extract_ssl_features(reg_domain))
    else:
        features.update(
            {
                "domain_age_days": -1,
                "domain_expiry_days": -1,
                "whois_privacy": 0,
                "registrar_country_kz": 0,
                "whois_available": 0,
                "dns_a_count": 0,
                "dns_mx_count": 0,
                "dns_txt_count": 0,
                "has_spf": 0,
                "has_dmarc": 0,
                "ssl_valid": 0,
                "ssl_days_to_expiry": -1,
                "ssl_self_signed": 0,
                "ssl_issuer_known": 0,
            }
        )
    features.update(content)

    for name in FEATURE_COLUMNS:
        value = features.get(name, 0)
        if value is None or (isinstance(value, float) and math.isnan(value)):
            value = -1
        features[name] = value
    return features


def extract_csv(input_csv: Path, output_csv: Path, *, url_column: str, label_column: str | None, network: bool, limit: int | None) -> None:
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with input_csv.open("r", encoding="utf-8-sig", errors="replace", newline="") as src, output_csv.open(
        "w", encoding="utf-8", newline=""
    ) as dst:
        reader = csv.DictReader(src)
        fields = ["url", "domain", "url_hash", "label", "text_blob", *FEATURE_COLUMNS]
        writer = csv.DictWriter(dst, fieldnames=fields)
        writer.writeheader()
        for index, row in enumerate(reader):
            if limit is not None and index >= limit:
                break
            url = row.get(url_column) or row.get("\ufeff" + url_column) or ""
            if not url:
                continue
            features = extract_features(url, network=network)
            features["label"] = row.get(label_column, "") if label_column else ""
            writer.writerow({key: features.get(key, "") for key in fields})


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract unified URL/domain features for Argus ML.")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--url-column", default="url")
    parser.add_argument("--label-column", default=None)
    parser.add_argument("--network", action="store_true", help="Enable requests/DNS/WHOIS/SSL/content features.")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    extract_csv(
        args.input,
        args.output,
        url_column=args.url_column,
        label_column=args.label_column,
        network=args.network,
        limit=args.limit,
    )


if __name__ == "__main__":
    main()
