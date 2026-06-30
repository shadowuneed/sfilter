from __future__ import annotations

import ipaddress
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse


DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b")
URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>'\")]+")

SECOND_LEVEL_SUFFIXES = {
    "co.uk",
    "com.au",
    "com.br",
    "com.kz",
    "com.tr",
    "co.nz",
    "co.jp",
    "org.uk",
    "net.au",
}

SUSPICIOUS_TLDS = {
    "click",
    "top",
    "xyz",
    "quest",
    "lol",
    "monster",
    "cam",
    "icu",
    "rest",
    "shop",
    "site",
    "live",
    "buzz",
    "cfd",
}

BLOCKED_HOSTS = {"localhost", "local", "example.com", "example.org", "example.net"}

TECHNICAL_HOSTS = {
    "accounts.google.com",
    "cloud.google.com",
    "developers.google.com",
    "gemini.google.com",
    "generativelanguage.googleapis.com",
    "google.com",
    "search.google.com",
    "vertexaisearch.cloud.google.com",
    "www.google.com",
}

TECHNICAL_DOMAIN_SUFFIXES = (
    ".googleapis.com",
    ".gstatic.com",
)

TECHNICAL_URL_MARKERS = (
    "/grounding-api-redirect/",
    "/search?",
    "/url?",
)


def normalize_adblock_token(value: str) -> str:
    text = (value or "").strip()
    if text.startswith("||"):
        text = text[2:]
    text = text.strip("^")
    text = text.strip("/")
    return text


def extract_domain(value: str) -> str:
    value = normalize_adblock_token(value)
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"http://{value}")
    host = parsed.netloc or parsed.path.split("/", 1)[0]
    host = host.split("@")[-1].split(":")[0].strip(".").lower()
    if host.startswith("www."):
        host = host[4:]
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return host


def normalize_url(value: str, prefer_https: bool = True) -> str:
    value = normalize_adblock_token(value)
    if not value:
        return ""
    if "://" not in value:
        value = ("https://" if prefer_https else "http://") + value
    parsed = urlparse(value)
    host = extract_domain(value)
    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""
    scheme = parsed.scheme or ("https" if prefer_https else "http")
    return f"{scheme}://{host}{path}{query}"


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip("[]"))
        return True
    except ValueError:
        return False


def is_public_domain(domain: str) -> bool:
    domain = extract_domain(domain)
    if not domain or domain in BLOCKED_HOSTS:
        return False
    if is_ip_address(domain):
        return False
    labels = [label for label in domain.split(".") if label]
    if len(labels) < 2:
        return False
    if not (2 <= len(labels[-1]) <= 24) or not labels[-1].isalpha():
        return False
    for label in labels:
        if len(label) > 63:
            return False
        if not re.fullmatch(r"[a-z0-9-]+", label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True


def is_technical_domain(domain: str) -> bool:
    domain = extract_domain(domain)
    if not domain:
        return True
    if domain in TECHNICAL_HOSTS:
        return True
    return any(domain.endswith(suffix) for suffix in TECHNICAL_DOMAIN_SUFFIXES)


def is_candidate_domain(domain: str) -> bool:
    return is_public_domain(domain) and not is_technical_domain(domain)


def is_technical_url(value: str) -> bool:
    if not value:
        return True
    normalized = normalize_url(value)
    domain = extract_domain(normalized)
    if is_technical_domain(domain):
        return True
    parsed = urlparse(normalized)
    path_and_query = f"{parsed.path}?{parsed.query}".lower()
    return any(marker in path_and_query for marker in TECHNICAL_URL_MARKERS)


def is_candidate_url(value: str) -> bool:
    domain = extract_domain(value)
    return is_candidate_domain(domain) and not is_technical_url(value)


def registered_domain(domain: str) -> str:
    labels = [label for label in extract_domain(domain).split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    suffix2 = ".".join(labels[-2:])
    if suffix2 in SECOND_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def domain_stem(domain: str) -> str:
    reg = registered_domain(domain)
    labels = reg.split(".")
    if len(labels) <= 1:
        return reg
    stem = labels[0].lower()
    stem = re.sub(r"[^a-z0-9]+", "", stem)
    stem = re.sub(r"(casino|bet|bets|slot|slots|club|online|official|mirror|zerkalo)$", "", stem)
    return stem or labels[0].lower()


def domain_tokens(domain: str) -> list[str]:
    stem = domain_stem(domain)
    raw = re.sub(r"([a-z])([0-9])", r"\1 \2", stem)
    raw = re.sub(r"([0-9])([a-z])", r"\1 \2", raw)
    raw = re.sub(r"[^a-z0-9]+", " ", raw.lower())
    return [token for token in raw.split() if len(token) >= 3]


def similarity(left: str, right: str) -> float:
    return SequenceMatcher(None, left.lower(), right.lower()).ratio()


def likely_related_domains(left: str, right: str) -> bool:
    left_stem = domain_stem(left)
    right_stem = domain_stem(right)
    if not left_stem or not right_stem:
        return False
    if left_stem == right_stem:
        return True
    if left_stem in right_stem or right_stem in left_stem:
        return min(len(left_stem), len(right_stem)) >= 5
    return similarity(left_stem, right_stem) >= 0.82


def find_domains(text: str) -> list[str]:
    domains = {extract_domain(match.group(0)) for match in DOMAIN_RE.finditer(text or "")}
    return sorted(domain for domain in domains if is_public_domain(domain))


def find_urls(text: str) -> list[str]:
    urls = {normalize_url(match.group(0)) for match in URL_RE.finditer(text or "")}
    return sorted(url for url in urls if is_public_domain(extract_domain(url)))


def suspicious_tld(domain: str) -> bool:
    labels = extract_domain(domain).split(".")
    return bool(labels and labels[-1].lower() in SUSPICIOUS_TLDS)
