from __future__ import annotations

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


def _split_env(name: str) -> list[str]:
    value = os.getenv(name, "")
    if not value:
        return []
    parts: list[str] = []
    for chunk in value.replace("\n", ",").replace(";", ",").split(","):
        item = chunk.strip()
        if item:
            parts.append(item)
    return parts


DEFAULT_SEED_QUERIES = [
    'казино зеркало рабочий вход новый домен',
    'онлайн казино зеркало бонус новый домен',
    '1xbet зеркало рабочее зеркало вход',
    'casino mirror new domain bonus',
    'betting mirror casino login',
    'инвестиционный лохотрон отзывы сайт',
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
    gemini_rpm_limit: int = 10
    gemini_rpd_limit: int = 250
    gemini_timeout_seconds: int = 90

    database_path: Path = Path("data/argus.db")
    evidence_dir: Path = Path("evidence")
    export_dir: Path = Path("exports")

    max_candidates_per_run: int = 15
    max_mirror_checks_per_run: int = 6
    request_timeout_seconds: int = 18
    screenshots_enabled: bool = True
    osint_feeds_enabled: bool = False
    user_agent: str = DEFAULT_USER_AGENT
    seed_queries: list[str] = field(default_factory=lambda: DEFAULT_SEED_QUERIES.copy())
    osint_feeds: list[str] = field(default_factory=lambda: DEFAULT_OSINT_FEEDS.copy())

    @property
    def screenshots_dir(self) -> Path:
        return self.evidence_dir / "screenshots"

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

    settings = Settings(
        gemini_api_keys=_split_env("GEMINI_API_KEYS"),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip() or "gemini-2.5-flash",
        gemini_rpm_limit=_int_env("GEMINI_RPM_LIMIT", _int_env("GEMINI_RPM_PER_KEY", 10)),
        gemini_rpd_limit=_int_env("GEMINI_RPD_LIMIT", _int_env("GEMINI_RPD_PER_KEY", 250)),
        gemini_timeout_seconds=_int_env("GEMINI_TIMEOUT_SECONDS", 90),
        database_path=Path(os.getenv("DATABASE_PATH", "data/argus.db")),
        evidence_dir=Path(os.getenv("EVIDENCE_DIR", "evidence")),
        export_dir=Path(os.getenv("EXPORT_DIR", "exports")),
        max_candidates_per_run=_int_env("MAX_CANDIDATES_PER_RUN", 15),
        max_mirror_checks_per_run=_int_env("MAX_MIRROR_CHECKS_PER_RUN", 6),
        request_timeout_seconds=_int_env("REQUEST_TIMEOUT_SECONDS", 18),
        screenshots_enabled=_bool_env("SCREENSHOTS_ENABLED", True),
        osint_feeds_enabled=_bool_env("OSINT_FEEDS_ENABLED", False),
        user_agent=os.getenv("USER_AGENT", DEFAULT_USER_AGENT).strip() or DEFAULT_USER_AGENT,
        seed_queries=seed_queries,
        osint_feeds=osint_feeds,
    )

    settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    settings.evidence_dir.mkdir(parents=True, exist_ok=True)
    settings.screenshots_dir.mkdir(parents=True, exist_ok=True)
    settings.export_dir.mkdir(parents=True, exist_ok=True)
    return settings

