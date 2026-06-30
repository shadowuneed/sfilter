from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from app.config import Settings


@dataclass(frozen=True)
class KzAccessCheck:
    ok: bool
    message: str
    country: str | None = None


def country_from_payload(payload: dict[str, Any]) -> str | None:
    for key in ("country", "countryCode", "country_code"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().upper()
    return None


def check_kz_proxy(settings: Settings) -> KzAccessCheck:
    if not settings.kz_proxy_url:
        return KzAccessCheck(
            ok=not settings.require_kz_proxy,
            message="KZ proxy is not configured",
        )

    try:
        with httpx.Client(
            timeout=min(settings.request_timeout_seconds, 12),
            proxy=settings.kz_proxy_url,
            headers={"User-Agent": settings.user_agent},
        ) as client:
            response = client.get(settings.kz_proxy_check_url)
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:  # noqa: BLE001
        return KzAccessCheck(
            ok=False,
            message=f"KZ proxy check failed: {type(exc).__name__}",
        )

    country = country_from_payload(payload)
    if country == "KZ":
        return KzAccessCheck(ok=True, message="KZ proxy verified", country=country)
    if not country:
        return KzAccessCheck(ok=False, message="KZ proxy check did not return a country code")
    return KzAccessCheck(ok=False, message=f"KZ proxy country is {country}, expected KZ", country=country)
