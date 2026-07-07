from __future__ import annotations

from app.services.domains import extract_domain, registered_domain


TRUSTED_REGISTERED_DOMAINS = {
    "kaspi.kz",
    "halykbank.kz",
    "homebank.kz",
    "bcc.kz",
    "forte.kz",
    "jusan.kz",
    "homecredit.kz",
    "bankrbk.kz",
    "altynbank.kz",
    "nationalbank.kz",
    "hcsbk.kz",
    "berekebank.kz",
    "nurbank.kz",
    "bankffin.kz",
    "egov.kz",
    "enpf.kz",
    "kgd.gov.kz",
}

TRUSTED_SUFFIXES = (
    ".gov.kz",
)

TRUSTED_DOMAIN_REASONS = {
    "kaspi.kz": "официальный домен Kaspi",
    "halykbank.kz": "официальный домен Halyk Bank",
    "homebank.kz": "официальный домен Homebank/Halyk",
    "bcc.kz": "официальный домен Bank CenterCredit",
    "forte.kz": "официальный домен ForteBank",
    "jusan.kz": "официальный домен Jusan",
    "homecredit.kz": "официальный домен Home Credit Kazakhstan",
    "bankrbk.kz": "официальный домен Bank RBK",
    "altynbank.kz": "официальный домен Altyn Bank",
    "nationalbank.kz": "официальный домен Национального Банка РК",
    "hcsbk.kz": "официальный домен Отбасы банка",
    "berekebank.kz": "официальный домен Bereke Bank",
    "nurbank.kz": "официальный домен Nurbank",
    "bankffin.kz": "официальный домен Freedom Bank",
    "egov.kz": "официальный домен электронного правительства РК",
    "enpf.kz": "официальный домен ЕНПФ",
}


def domain_policy(domain_or_url: str | None) -> dict[str, object]:
    domain = extract_domain(domain_or_url or "")
    registered = registered_domain(domain)
    trusted = registered in TRUSTED_REGISTERED_DOMAINS or any(domain.endswith(suffix) for suffix in TRUSTED_SUFFIXES)
    reason = ""
    if trusted:
        reason = TRUSTED_DOMAIN_REASONS.get(registered) or "официальный/доверенный домен Казахстана"
    return {
        "domain": domain,
        "registered_domain": registered,
        "trusted": trusted,
        "reason": reason,
    }


def is_trusted_domain(domain_or_url: str | None) -> bool:
    return bool(domain_policy(domain_or_url).get("trusted"))
