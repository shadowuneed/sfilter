from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


def _load_dotenv(path: str = ".env") -> None:
    env_path = Path(path)
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().lstrip("\ufeff")
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _split_env(name: str) -> list[str]:
    value = os.getenv(name, "")
    if not value:
        return []
    stripped = value.strip()
    if stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, list):
            return [str(item).strip().strip('"').strip("'") for item in parsed if str(item).strip()]
    parts: list[str] = []
    for chunk in value.replace("\n", ",").replace(";", ",").split(","):
        item = chunk.strip()
        if item:
            parts.append(item)
    return parts


def _clean_api_key(value: str) -> str | None:
    item = value.strip().strip('"').strip("'")
    if item.lower().startswith("authorization:"):
        item = item.split(":", 1)[1].strip()
    if item.lower().startswith("bearer "):
        item = item[7:].strip()
    if item.lower().startswith("key="):
        item = item[4:].strip()
    item = item.strip().strip('"').strip("'")
    return item or None


def _api_keys_from_env(names: tuple[str, ...]) -> list[str]:
    keys: list[str] = []
    seen: set[str] = set()
    for name in names:
        for raw in _split_env(name):
            key = _clean_api_key(raw)
            if not key or key in seen:
                continue
            seen.add(key)
            keys.append(key)
    return keys


def _optional_env(name: str) -> str | None:
    value = os.getenv(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _first_env(names: tuple[str, ...]) -> tuple[str | None, str | None]:
    for name in names:
        value = _optional_env(name)
        if value:
            return name, value
    return None, None


DEFAULT_SEED_QUERIES = [
    'казино зеркало рабочий вход новый домен',
    'онлайн казино зеркало бонус новый домен',
    '1xbet зеркало рабочее зеркало вход',
    'casino mirror new domain bonus',
    'betting mirror casino login',
    'инвестиционный лохотрон отзывы сайт',
    'казино не выводит деньги жалобы новый домен',
    'scam complaint withdraw problem casino domain',
    'фишинг Kaspi жалобы поддельный сайт',
]

# Эти фиды выключены по умолчанию. Они часто дают malware/IP и засоряют задачу casino/scam.
DEFAULT_OSINT_FEEDS = [
    "https://openphish.com/feed.txt",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
]

DEFAULT_USER_AGENT = (
    "Argus/1.0 (+https://example.local; public OSINT evidence collection; "
    "contact=security@example.local)"
)


@dataclass(frozen=True)
class Settings:
    gemini_api_keys: list[str] = field(default_factory=list)
    gemini_model: str = "gemini-2.5-flash"
    gemini_fallback_models: list[str] = field(default_factory=list)
    gemini_rpm_limit: int = 10
    gemini_rpd_limit: int = 250
    gemini_timeout_seconds: int = 90
    admin_token: str | None = None
    auth_required: bool = True

    database_url: str | None = None
    database_path: Path = Path("data/argus.db")
    require_postgres: bool = False
    evidence_dir: Path = Path("evidence")
    export_dir: Path = Path("exports")

    max_candidates_per_run: int = 500
    max_mirror_checks_per_run: int = 6
    request_timeout_seconds: int = 18
    scan_concurrency: int = 3
    candidate_timeout_seconds: int = 45
    screenshot_timeout_seconds: int = 10
    screenshot_settle_ms: int = 700
    screenshots_enabled: bool = True
    browser_screenshots_enabled: bool = True
    screenshot_fallback_enabled: bool = True
    screenshot_concurrency: int = 1
    osint_feeds_enabled: bool = True
    osint_candidate_pool_size: int = 1500
    ml_enabled: bool = True
    ml_model_path: Path = Path("models/domain_classifier.cbm")
    cyberscan_model_path: Path = Path("models/cyberscan_model.pkl")
    ml_min_confidence: float = 0.45
    user_agent: str = DEFAULT_USER_AGENT
    kz_proxy_url: str | None = None
    kz_proxy_source: str | None = None
    kz_access_label: str = "server direct network"
    require_kz_proxy: bool = False
    kz_proxy_check_url: str = "https://api.country.is/"
    seed_queries: list[str] = field(default_factory=lambda: DEFAULT_SEED_QUERIES.copy())
    osint_feeds: list[str] = field(default_factory=lambda: DEFAULT_OSINT_FEEDS.copy())

    @property
    def screenshots_dir(self) -> Path:
        return self.evidence_dir / "screenshots"

    @property
    def gemini_models(self) -> list[str]:
        models: list[str] = []
        for model in [self.gemini_model, *self.gemini_fallback_models]:
            clean = str(model or "").strip()
            if clean and clean not in models:
                models.append(clean)
        return models or ["gemini-2.5-flash"]

    def masked_keys(self) -> list[str]:
        masked: list[str] = []
        for key in self.gemini_api_keys:
            if len(key) <= 8:
                masked.append("****")
            else:
                masked.append(f"{key[:4]}...{key[-4:]}")
        return masked


def get_settings() -> Settings:
    _load_dotenv()

    seed_queries = _split_env("SEED_QUERIES") or DEFAULT_SEED_QUERIES.copy()
    osint_feeds = _split_env("OSINT_FEEDS") or DEFAULT_OSINT_FEEDS.copy()
    kz_proxy_source, kz_proxy_url = _first_env(("KZ_PROXY_URL", "KZ_HTTP_PROXY", "KZ_HTTPS_PROXY", "KZ_PROXY"))

    settings = Settings(
        gemini_api_keys=_api_keys_from_env(("GEMINI_API_KEYS", "GEMINI_API_KEY", "GOOGLE_API_KEY")),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip() or "gemini-2.5-flash",
        gemini_fallback_models=_split_env("GEMINI_FALLBACK_MODELS"),
        gemini_rpm_limit=_int_env("GEMINI_RPM_LIMIT", _int_env("GEMINI_RPM_PER_KEY", 10)),
        gemini_rpd_limit=_int_env("GEMINI_RPD_LIMIT", _int_env("GEMINI_RPD_PER_KEY", 250)),
        gemini_timeout_seconds=_int_env("GEMINI_TIMEOUT_SECONDS", 90),
        admin_token=_optional_env("ADMIN_TOKEN") or _optional_env("ARGUS_ADMIN_TOKEN"),
        auth_required=_bool_env("AUTH_REQUIRED", True),
        database_url=_optional_env("DATABASE_URL"),
        database_path=Path(os.getenv("DATABASE_PATH", "data/argus.db")),
        require_postgres=_bool_env("REQUIRE_POSTGRES", False),
        evidence_dir=Path(os.getenv("EVIDENCE_DIR", "evidence")),
        export_dir=Path(os.getenv("EXPORT_DIR", "exports")),
        max_candidates_per_run=max(1, min(_int_env("MAX_CANDIDATES_PER_RUN", 500), 500)),
        max_mirror_checks_per_run=_int_env("MAX_MIRROR_CHECKS_PER_RUN", 6),
        request_timeout_seconds=_int_env("REQUEST_TIMEOUT_SECONDS", 18),
        scan_concurrency=max(1, min(_int_env("SCAN_CONCURRENCY", 3), 8)),
        candidate_timeout_seconds=max(10, _int_env("CANDIDATE_TIMEOUT_SECONDS", 45)),
        screenshot_timeout_seconds=max(4, _int_env("SCREENSHOT_TIMEOUT_SECONDS", 10)),
        screenshot_settle_ms=max(0, _int_env("SCREENSHOT_SETTLE_MS", 700)),
        screenshots_enabled=_bool_env("SCREENSHOTS_ENABLED", True),
        browser_screenshots_enabled=_bool_env(
            "BROWSER_SCREENSHOTS_ENABLED",
            _bool_env("SCREENSHOT_BROWSER_ENABLED", True),
        ),
        screenshot_fallback_enabled=_bool_env("SCREENSHOT_FALLBACK_ENABLED", True),
        screenshot_concurrency=max(1, min(_int_env("SCREENSHOT_CONCURRENCY", 1), 2)),
        osint_feeds_enabled=_bool_env("OSINT_FEEDS_ENABLED", True),
        osint_candidate_pool_size=max(150, min(_int_env("OSINT_CANDIDATE_POOL_SIZE", 1500), 5000)),
        ml_enabled=_bool_env("ML_ENABLED", True),
        ml_model_path=Path(os.getenv("ML_MODEL_PATH", "models/domain_classifier.cbm")),
        cyberscan_model_path=Path(os.getenv("CYBERSCAN_MODEL_PATH", "models/cyberscan_model.pkl")),
        ml_min_confidence=_float_env("ML_MIN_CONFIDENCE", 0.45),
        user_agent=os.getenv("USER_AGENT", DEFAULT_USER_AGENT).strip() or DEFAULT_USER_AGENT,
        kz_proxy_url=kz_proxy_url,
        kz_proxy_source=kz_proxy_source,
        kz_access_label=(
            os.getenv("KZ_ACCESS_LABEL")
            or ("Kazakhstan proxy" if kz_proxy_url else "server direct network")
        ).strip() or "server direct network",
        require_kz_proxy=_bool_env("REQUIRE_KZ_PROXY", False),
        kz_proxy_check_url=os.getenv("KZ_PROXY_CHECK_URL", "https://api.country.is/").strip() or "https://api.country.is/",
        seed_queries=seed_queries,
        osint_feeds=osint_feeds,
    )

    if settings.require_postgres and not settings.database_url:
        raise RuntimeError("REQUIRE_POSTGRES=true, but DATABASE_URL is not configured.")
    if not settings.database_url:
        settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    settings.evidence_dir.mkdir(parents=True, exist_ok=True)
    settings.screenshots_dir.mkdir(parents=True, exist_ok=True)
    settings.export_dir.mkdir(parents=True, exist_ok=True)
    return settings

