from __future__ import annotations

import re

from app.services.domains import extract_domain, registered_domain


GAMBLING_CONTEXT_RE = re.compile(
    r"(casino|kazino|казино|слот|slots?|ставк|букмекер|betting|bookmaker|"
    r"зеркал|mirror|pin[-\s]?up|pinco|1xbet|mostbet|1win|vulkan|joycasino)",
    re.IGNORECASE,
)

USER_RISK_SEARCH_RE = re.compile(
    r"(casino|kazino|казино|слот|slots?|ставк|букмекер|betting|bookmaker|"
    r"зеркал|mirror|легк(?:ие|их|ими)?\s+деньг|л[её]гк(?:ие|их|ими)?\s+деньг|"
    r"быстр(?:ый|ого|ые|ых)\s+(?:заработ|доход)|заработ(?:ать|ок)|"
    r"инвестиц|пассивн(?:ый|ого)\s+доход|доход\s+без\s+влож|"
    r"usdt|crypto|крипт|pin[-\s]?up|pinco|1xbet|mostbet|1win|vulkan|joycasino)",
    re.IGNORECASE,
)

CASINO_CONTEXT_RE = re.compile(
    r"(casino|kazino|казино|слот|slots?|roulette|рулет|blackjack|jackpot|"
    r"live\s+casino|pin[-\s]?up|pinco|vulkan|joycasino)",
    re.IGNORECASE,
)

CASINO_BRAND_LABEL_PREFIXES = (
    "pinco",
    "pinup",
    "1xbet",
    "1win",
    "mostbet",
    "melbet",
    "fonbet",
    "olimpbet",
    "parimatch",
    "vavada",
    "vulkan",
    "joycasino",
    "playfortuna",
    "ggbet",
    "bet365",
    "linebet",
    "megapari",
    "betwinner",
    "888casino",
)

CASINO_DOMAIN_TERMS = (
    "casino",
    "kazino",
    "slots",
    "slot",
    "vulkan",
    "jackpot",
    "roulette",
    "blackjack",
)

KZ_SEARCH_LANDING_LABELS = {
    "top",
    "go",
    "play",
    "app",
    "start",
    "lk",
    "m",
    "win",
    "vip",
    "club",
    "bonus",
    "online",
}


def has_gambling_context(text: str | None) -> bool:
    return bool(GAMBLING_CONTEXT_RE.search(text or ""))


def has_user_risk_search_context(text: str | None) -> bool:
    return bool(USER_RISK_SEARCH_RE.search(text or ""))


def has_casino_context(text: str | None) -> bool:
    return bool(CASINO_CONTEXT_RE.search(text or ""))


def gambling_domain_signals(domain_or_url: str | None, context: str | None = None) -> list[str]:
    domain = extract_domain(domain_or_url or "")
    if not domain:
        return []

    labels = [label for label in domain.split(".") if label]
    compact_labels = [re.sub(r"[^a-z0-9]+", "", label.lower()) for label in labels]
    compact_domain = "".join(compact_labels)
    context_text = context or ""
    registered = registered_domain(domain)

    signals: list[str] = []
    for prefix in CASINO_BRAND_LABEL_PREFIXES:
        if any(label.startswith(prefix) for label in compact_labels):
            signals.append(f"casino brand-like host label: {prefix}")
            break

    for term in CASINO_DOMAIN_TERMS:
        if term in compact_domain:
            signals.append(f"casino term in domain: {term}")
            break

    if has_gambling_context(context_text) and registered.endswith(".kz"):
        sub_labels = compact_labels[: max(0, len(compact_labels) - len(registered.split(".")))]
        landing_label = any(label in KZ_SEARCH_LANDING_LABELS for label in sub_labels)
        numbered_label = any(re.fullmatch(r"[a-z]{2,12}\d{1,4}", label) for label in sub_labels)
        if landing_label or numbered_label:
            signals.append("KZ search-result landing subdomain with gambling context")

    return list(dict.fromkeys(signals))
