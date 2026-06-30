from __future__ import annotations

import json
import re
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover - exercised only when DATABASE_URL is configured without dependency
    psycopg = None
    dict_row = None


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


SECRET_QUERY_RE = re.compile(r"(?i)([?&](?:key|api_key|token|access_token|auth|authorization)=)[^&\s''\"<>]+")
API_KEY_RE = re.compile(r"\b(?:AIza|AQ\.)[A-Za-z0-9_-]{12,}\b")
BEARER_RE = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{16,}")


def redact_string(value: str) -> str:
    value = SECRET_QUERY_RE.sub(r"\1[redacted]", value)
    value = API_KEY_RE.sub("[redacted-api-key]", value)
    value = BEARER_RE.sub(r"\1[redacted]", value)
    return value


def redact_secrets(value: Any) -> Any:
    if isinstance(value, str):
        return redact_string(value)
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_secrets(item) for item in value)
    if isinstance(value, dict):
        return {key: redact_secrets(item) for key, item in value.items()}
    return value


def dumps(value: Any) -> str:
    return json.dumps(redact_secrets(value), ensure_ascii=False, sort_keys=True)

def loads(value: Any, default: Any = None) -> Any:
    if not value:
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default



MOJIBAKE_MARKERS = ("\u00c3", "\u00c2", "\u00d0", "\u00d1", "\u00e2")


def _mojibake_score(text: str) -> int:
    cyrillic = sum(1 for char in text if 0x0400 <= ord(char) <= 0x052F)
    controls = sum(1 for char in text if 0x80 <= ord(char) <= 0x9F)
    markers = sum(text.count(marker) for marker in MOJIBAKE_MARKERS)
    replacement = text.count("\ufffd")
    return cyrillic * 3 - (controls + markers + replacement) * 4


def _repair_string(value: str) -> str:
    has_markers = any(marker in value for marker in MOJIBAKE_MARKERS)
    has_controls = any(0x80 <= ord(char) <= 0x9F for char in value)
    if not value or not (has_markers or has_controls):
        return value
    try:
        candidate = value.encode("latin1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return value
    return candidate if _mojibake_score(candidate) > _mojibake_score(value) else value


def repair_mojibake(value: Any) -> Any:
    if isinstance(value, str):
        return _repair_string(value)
    if isinstance(value, list):
        return [repair_mojibake(item) for item in value]
    if isinstance(value, dict):
        return {repair_mojibake(key): repair_mojibake(item) for key, item in value.items()}
    return value


POSTGRES_SCHEMES = ("postgres://", "postgresql://")


def _is_postgres_source(source: str) -> bool:
    return source.lower().startswith(POSTGRES_SCHEMES)


def _normalize_postgres_url(source: str) -> str:
    if source.startswith("postgres://"):
        source = "postgresql://" + source.removeprefix("postgres://")
    return _with_required_supabase_ssl(source)


def _with_required_supabase_ssl(source: str) -> str:
    parsed = urlsplit(source)
    hostname = parsed.hostname or ""
    if not hostname.endswith(".supabase.com"):
        return source
    query = parse_qsl(parsed.query, keep_blank_values=True)
    if any(key.lower() == "sslmode" for key, _ in query):
        return source
    query.append(("sslmode", "require"))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment))


def _redact_database_url(source: str) -> str:
    if not _is_postgres_source(source):
        return source
    parsed = urlsplit(_normalize_postgres_url(source))
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    database = parsed.path or ""
    return urlunsplit((parsed.scheme, f"[redacted]@{host}{port}", database, "", ""))


class DatabaseConnection:
    def __init__(self, raw: Any, backend: str):
        self.raw = raw
        self.backend = backend

    def execute(self, sql: str, params: Any | None = None) -> Any:
        query = self._query(sql)
        values = () if params is None else params
        return self.raw.execute(query, values)

    def executescript(self, script: str) -> None:
        if self.backend == "sqlite":
            self.raw.executescript(script)
            return
        for statement in self._split_script(script):
            self.raw.execute(self._query(statement))

    def _query(self, sql: str) -> str:
        if self.backend == "postgres":
            return sql.replace("?", "%s")
        return sql

    @staticmethod
    def _split_script(script: str) -> list[str]:
        return [part.strip() for part in script.split(";") if part.strip()]


class Database:
    def __init__(self, source: str | Path):
        self.source = str(source)
        self.backend = "postgres" if _is_postgres_source(self.source) else "sqlite"
        self.dsn = _normalize_postgres_url(self.source) if self.backend == "postgres" else None
        self.path = Path(self.source) if self.backend == "sqlite" else None
        self.label = _redact_database_url(self.source) if self.backend == "postgres" else str(self.path)

    @contextmanager
    def connect(self) -> Iterator[DatabaseConnection]:
        if self.backend == "postgres":
            if psycopg is None:
                raise RuntimeError("DATABASE_URL is configured, but psycopg is not installed.")
            conn = psycopg.connect(self.dsn, row_factory=dict_row)
        else:
            assert self.path is not None
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.path)
            conn.row_factory = sqlite3.Row
        try:
            yield DatabaseConnection(conn, self.backend)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init(self) -> None:
        with self.connect() as conn:
            conn.executescript(self._schema_sql())
            self._backfill_cases(conn)

    def _schema_sql(self) -> str:
        if self.backend == "postgres":
            return """
                CREATE TABLE IF NOT EXISTS runs (
                    id BIGSERIAL PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    status TEXT NOT NULL,
                    seed_query TEXT,
                    max_candidates INTEGER NOT NULL,
                    take_screenshots INTEGER NOT NULL,
                    methodology_json TEXT,
                    error TEXT,
                    candidate_count INTEGER DEFAULT 0,
                    finding_count INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id BIGSERIAL PRIMARY KEY,
                    run_id BIGINT NOT NULL REFERENCES runs(id),
                    url TEXT NOT NULL,
                    final_url TEXT,
                    domain TEXT,
                    normalized_domain TEXT,
                    title TEXT,
                    category TEXT,
                    verdict TEXT,
                    risk_score INTEGER NOT NULL,
                    active INTEGER NOT NULL,
                    status_code INTEGER,
                    mirror_group TEXT,
                    screenshot_path TEXT,
                    html_path TEXT,
                    html_sha256 TEXT,
                    dns_json TEXT,
                    tls_json TEXT,
                    evidence_json TEXT,
                    sources_json TEXT,
                    reasons_json TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS cases (
                    id BIGSERIAL PRIMARY KEY,
                    normalized_domain TEXT NOT NULL UNIQUE,
                    domain TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'uninvestigated',
                    archived INTEGER NOT NULL DEFAULT 0,
                    saved INTEGER NOT NULL DEFAULT 0,
                    latest_finding_id BIGINT REFERENCES findings(id),
                    best_risk_score INTEGER NOT NULL DEFAULT 0,
                    category TEXT,
                    verdict TEXT,
                    notes TEXT,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS logs (
                    id BIGSERIAL PRIMARY KEY,
                    run_id BIGINT NOT NULL REFERENCES runs(id),
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    meta_json TEXT
                );

                CREATE TABLE IF NOT EXISTS gemini_usage (
                    key_hash TEXT PRIMARY KEY,
                    day TEXT NOT NULL,
                    day_count INTEGER NOT NULL,
                    minute_window INTEGER NOT NULL,
                    minute_count INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
                CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings(normalized_domain);
                CREATE INDEX IF NOT EXISTS idx_cases_domain ON cases(normalized_domain);
                CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status, archived, saved);
                CREATE INDEX IF NOT EXISTS idx_logs_run ON logs(run_id);
            """

        return """
            PRAGMA journal_mode=WAL;

            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                seed_query TEXT,
                max_candidates INTEGER NOT NULL,
                take_screenshots INTEGER NOT NULL,
                methodology_json TEXT,
                error TEXT,
                candidate_count INTEGER DEFAULT 0,
                finding_count INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                final_url TEXT,
                domain TEXT,
                normalized_domain TEXT,
                title TEXT,
                category TEXT,
                verdict TEXT,
                risk_score INTEGER NOT NULL,
                active INTEGER NOT NULL,
                status_code INTEGER,
                mirror_group TEXT,
                screenshot_path TEXT,
                html_path TEXT,
                html_sha256 TEXT,
                dns_json TEXT,
                tls_json TEXT,
                evidence_json TEXT,
                sources_json TEXT,
                reasons_json TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES runs(id)
            );

            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                normalized_domain TEXT NOT NULL UNIQUE,
                domain TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'uninvestigated',
                archived INTEGER NOT NULL DEFAULT 0,
                saved INTEGER NOT NULL DEFAULT 0,
                latest_finding_id INTEGER,
                best_risk_score INTEGER NOT NULL DEFAULT 0,
                category TEXT,
                verdict TEXT,
                notes TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(latest_finding_id) REFERENCES findings(id)
            );

            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                meta_json TEXT,
                FOREIGN KEY(run_id) REFERENCES runs(id)
            );

            CREATE TABLE IF NOT EXISTS gemini_usage (
                key_hash TEXT PRIMARY KEY,
                day TEXT NOT NULL,
                day_count INTEGER NOT NULL,
                minute_window INTEGER NOT NULL,
                minute_count INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
            CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings(normalized_domain);
            CREATE INDEX IF NOT EXISTS idx_cases_domain ON cases(normalized_domain);
            CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status, archived, saved);
            CREATE INDEX IF NOT EXISTS idx_logs_run ON logs(run_id);
        """

    def _backfill_cases(self, conn: DatabaseConnection) -> None:
        rows = conn.execute("SELECT id FROM findings ORDER BY id ASC").fetchall()
        for row in rows:
            self._upsert_case_for_finding(conn, int(row["id"]))
        conn.execute(
            """
            UPDATE cases
            SET archived=1, updated_at=?
            WHERE saved=0 AND latest_finding_id IN (
                SELECT id FROM findings
                WHERE html_path IS NULL OR html_path='' OR status_code IS NULL OR status_code < 200 OR status_code >= 400
            )
            """,
            (utc_now(),),
        )

    def create_run(self, seed_query: str | None, max_candidates: int, take_screenshots: bool) -> int:
        with self.connect() as conn:
            returning = " RETURNING id" if self.backend == "postgres" else ""
            cursor = conn.execute(
                f"""
                INSERT INTO runs (
                    started_at, status, seed_query, max_candidates, take_screenshots
                ) VALUES (?, ?, ?, ?, ?)
                {returning}
                """,
                (utc_now(), "queued", seed_query, max_candidates, int(take_screenshots)),
            )
            if self.backend == "postgres":
                row = cursor.fetchone()
                return int(row["id"])
            return int(cursor.lastrowid)

    def update_run(self, run_id: int, **fields: Any) -> None:
        if not fields:
            return
        assignments = ", ".join(f"{key}=?" for key in fields)
        values = [dumps(value) if key.endswith("_json") else redact_secrets(value) for key, value in fields.items()]
        with self.connect() as conn:
            conn.execute(f"UPDATE runs SET {assignments} WHERE id=?", [*values, run_id])

    def mark_stale_runs_failed(self) -> int:
        with self.connect() as conn:
            cursor = conn.execute(
                """
                UPDATE runs
                SET status='failed', finished_at=?, error=?
                WHERE status IN ('queued', 'running', 'canceling')
                """,
                (utc_now(), "Сервер был остановлен до завершения проверки. Запустите новую проверку."),
            )
            return int(cursor.rowcount or 0)

    def add_log(self, run_id: int, level: str, message: str, meta: Any | None = None) -> None:
        timestamp = utc_now()
        message = redact_string(message)
        meta = redact_secrets(meta)
        meta_text = f" | {dumps(meta)}" if meta is not None else ""
        try:
            print(f"[{timestamp}] run={run_id} {level.upper()} {message}{meta_text}", flush=True)
        except UnicodeEncodeError:
            safe_message = message.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
            print(f"[{timestamp}] run={run_id} {level.upper()} {safe_message}", file=sys.stderr, flush=True)

        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO logs (run_id, timestamp, level, message, meta_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (run_id, timestamp, level, message, dumps(meta) if meta is not None else None),
            )

    def insert_finding(self, run_id: int, finding: dict[str, Any]) -> int:
        columns = [
            "run_id", "url", "final_url", "domain", "normalized_domain", "title",
            "category", "verdict", "risk_score", "active", "status_code", "mirror_group",
            "screenshot_path", "html_path", "html_sha256", "dns_json", "tls_json",
            "evidence_json", "sources_json", "reasons_json", "created_at",
        ]
        values = {
            "run_id": run_id,
            "created_at": utc_now(),
            "active": int(bool(finding.get("active"))),
            **finding,
        }
        json_fields = {"dns_json", "tls_json", "evidence_json", "sources_json", "reasons_json"}
        row_values = [dumps(values.get(col)) if col in json_fields else values.get(col) for col in columns]
        placeholders = ", ".join("?" for _ in columns)
        returning = " RETURNING id" if self.backend == "postgres" else ""
        with self.connect() as conn:
            cursor = conn.execute(
                f"INSERT INTO findings ({', '.join(columns)}) VALUES ({placeholders}){returning}",
                row_values,
            )
            if self.backend == "postgres":
                row = cursor.fetchone()
                finding_id = int(row["id"])
            else:
                finding_id = int(cursor.lastrowid)
            self._upsert_case_for_finding(conn, finding_id)
            return finding_id

    def _upsert_case_for_finding(self, conn: DatabaseConnection, finding_id: int) -> None:
        row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row or not row["normalized_domain"]:
            return
        existing = conn.execute(
            "SELECT * FROM cases WHERE normalized_domain=?",
            (row["normalized_domain"],),
        ).fetchone()
        now = utc_now()
        risk = int(row["risk_score"] or 0)
        status_code = int(row["status_code"] or 0)
        auto_archived = 1 if risk < 50 or status_code < 200 or status_code >= 400 else 0
        if existing:
            archived = int(existing["archived"])
            best_risk = max(int(existing["best_risk_score"] or 0), risk)
            conn.execute(
                """
                UPDATE cases SET
                    domain=?, last_seen=?, latest_finding_id=?, best_risk_score=?,
                    category=?, verdict=?, updated_at=?
                WHERE normalized_domain=?
                """,
                (
                    row["domain"], row["created_at"], finding_id, best_risk,
                    row["category"], row["verdict"], now, row["normalized_domain"],
                ),
            )
            if best_risk >= 50 and archived and not int(existing["saved"]):
                # Keep manual archive, but new high-risk evidence remains available in run report.
                pass
        else:
            conn.execute(
                """
                INSERT INTO cases (
                    normalized_domain, domain, first_seen, last_seen, status, archived,
                    saved, latest_finding_id, best_risk_score, category, verdict, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["normalized_domain"], row["domain"], row["created_at"], row["created_at"],
                    "uninvestigated", auto_archived, 0, finding_id, risk,
                    row["category"], row["verdict"], now,
                ),
            )

    def get_run(self, run_id: int) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
            return self._run_to_dict(row) if row else None

    def list_runs(self, limit: int = 25) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [self._run_to_dict(row) for row in rows]

    def list_findings(self, run_id: int | None = None, limit: int = 500) -> list[dict[str, Any]]:
        with self.connect() as conn:
            if run_id is None:
                rows = conn.execute("SELECT * FROM findings ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM findings WHERE run_id=? ORDER BY risk_score DESC, id ASC LIMIT ?",
                    (run_id, limit),
                ).fetchall()
            return [self._finding_to_dict(row) for row in rows]

    def list_findings_by_ids(self, finding_ids: list[int]) -> list[dict[str, Any]]:
        ids = [int(item) for item in finding_ids if int(item) > 0]
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM findings WHERE id IN ({placeholders}) ORDER BY risk_score DESC, id ASC",
                ids,
            ).fetchall()
            return [self._finding_to_dict(row) for row in rows]

    def list_findings_for_cases(self, case_ids: list[int]) -> list[dict[str, Any]]:
        ids = [int(item) for item in case_ids if int(item) > 0]
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT f.*, c.id AS case_id, c.status AS case_status, c.saved, c.archived
                FROM cases c
                JOIN findings f ON f.normalized_domain=c.normalized_domain
                WHERE c.id IN ({placeholders})
                ORDER BY c.saved DESC, c.best_risk_score DESC, f.run_id DESC, f.id DESC
                """,
                ids,
            ).fetchall()
            return [self._finding_to_dict(row) for row in rows]

    def list_case_findings(self, case_id: int) -> list[dict[str, Any]]:
        with self.connect() as conn:
            case = conn.execute("SELECT normalized_domain FROM cases WHERE id=?", (case_id,)).fetchone()
            if not case:
                return []
            rows = conn.execute(
                """
                SELECT * FROM findings
                WHERE normalized_domain=?
                ORDER BY run_id DESC, id DESC
                """,
                (case["normalized_domain"],),
            ).fetchall()
            return [self._finding_to_dict(row) for row in rows]

    def list_logs(self, run_id: int, limit: int = 300) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM logs WHERE run_id=? ORDER BY id ASC LIMIT ?",
                (run_id, limit),
            ).fetchall()
            return [
                redact_secrets(repair_mojibake({
                    "id": row["id"],
                    "timestamp": row["timestamp"],
                    "level": row["level"],
                    "message": row["message"],
                    "meta": loads(row["meta_json"], {}),
                }))
                for row in rows
            ]

    def list_cases(
        self,
        *,
        q: str | None = None,
        status: str | None = None,
        archived: bool | None = False,
        saved: bool | None = None,
        min_risk: int | None = None,
        limit: int = 300,
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        if q:
            like_op = "ILIKE" if self.backend == "postgres" else "LIKE"
            where.append(
                f"(c.domain {like_op} ? OR c.normalized_domain {like_op} ? "
                f"OR f.title {like_op} ? OR f.final_url {like_op} ?)"
            )
            needle = f"%{q}%"
            params.extend([needle, needle, needle, needle])
        if status:
            where.append("c.status=?")
            params.append(status)
        if archived is not None:
            where.append("c.archived=?")
            params.append(int(archived))
        if saved is not None:
            where.append("c.saved=?")
            params.append(int(saved))
        if min_risk is not None:
            where.append("c.best_risk_score>=?")
            params.append(int(min_risk))
        sql_where = "WHERE " + " AND ".join(where) if where else ""
        params.append(max(1, min(limit, 1000)))
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT c.*, f.url, f.final_url, f.title, f.screenshot_path, f.html_path,
                       f.html_sha256, f.status_code, f.mirror_group, f.sources_json,
                       f.reasons_json, f.evidence_json, f.dns_json, f.tls_json,
                       f.created_at AS finding_created_at,
                       COALESCE(stats.finding_total, 0) AS finding_total,
                       COALESCE(stats.run_total, 0) AS run_total,
                       stats.first_run_id,
                       stats.latest_run_id
                FROM cases c
                LEFT JOIN findings f ON f.id=c.latest_finding_id
                LEFT JOIN (
                    SELECT normalized_domain,
                           COUNT(*) AS finding_total,
                           COUNT(DISTINCT run_id) AS run_total,
                           MIN(run_id) AS first_run_id,
                           MAX(run_id) AS latest_run_id
                    FROM findings
                    GROUP BY normalized_domain
                ) stats ON stats.normalized_domain=c.normalized_domain
                {sql_where}
                ORDER BY c.saved DESC, c.best_risk_score DESC, c.last_seen DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
            return [self._case_to_dict(row) for row in rows]

    def get_case(self, case_id: int) -> dict[str, Any] | None:
        cases = self.list_cases(archived=None, limit=1000)
        for case in cases:
            if case["id"] == case_id:
                return case
        return None

    def update_case(self, case_id: int, **fields: Any) -> dict[str, Any] | None:
        allowed = {"status", "archived", "saved", "notes"}
        updates = {key: value for key, value in fields.items() if key in allowed}
        if not updates:
            return self.get_case(case_id)
        if "status" in updates and updates["status"] not in {"uninvestigated", "investigating", "investigated"}:
            raise ValueError("Invalid case status")
        if "archived" in updates:
            updates["archived"] = int(bool(updates["archived"]))
        if "saved" in updates:
            updates["saved"] = int(bool(updates["saved"]))
        updates["updated_at"] = utc_now()
        assignments = ", ".join(f"{key}=?" for key in updates)
        with self.connect() as conn:
            conn.execute(f"UPDATE cases SET {assignments} WHERE id=?", [*updates.values(), case_id])
        return self.get_case(case_id)

    def known_domains(self) -> set[str]:
        with self.connect() as conn:
            rows = conn.execute("SELECT normalized_domain FROM cases").fetchall()
            return {row["normalized_domain"] for row in rows if row["normalized_domain"]}

    def usage_row(self, key_hash: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM gemini_usage WHERE key_hash=?", (key_hash,)).fetchone()
            return dict(row) if row else None

    def upsert_usage(self, key_hash: str, day: str, day_count: int, minute_window: int, minute_count: int) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO gemini_usage (key_hash, day, day_count, minute_window, minute_count)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(key_hash) DO UPDATE SET
                    day=excluded.day,
                    day_count=excluded.day_count,
                    minute_window=excluded.minute_window,
                    minute_count=excluded.minute_count
                """,
                (key_hash, day, day_count, minute_window, minute_count),
            )

    def _run_to_dict(self, row: Any) -> dict[str, Any]:
        data = dict(row)
        data["take_screenshots"] = bool(data["take_screenshots"])
        data["methodology"] = loads(data.pop("methodology_json"), [])
        return redact_secrets(repair_mojibake(data))
    def _finding_to_dict(self, row: Any) -> dict[str, Any]:
        data = dict(row)
        data["active"] = bool(data["active"])
        data["dns"] = loads(data.pop("dns_json"), {})
        data["tls"] = loads(data.pop("tls_json"), {})
        data["evidence"] = loads(data.pop("evidence_json"), {})
        data["sources"] = loads(data.pop("sources_json"), [])
        data["reasons"] = loads(data.pop("reasons_json"), [])
        return redact_secrets(repair_mojibake(data))
    def _case_to_dict(self, row: Any) -> dict[str, Any]:
        data = dict(row)
        data["archived"] = bool(data["archived"])
        data["saved"] = bool(data["saved"])
        data["sources"] = loads(data.pop("sources_json"), [])
        data["reasons"] = loads(data.pop("reasons_json"), [])
        data["evidence"] = loads(data.pop("evidence_json"), {})
        data["dns"] = loads(data.pop("dns_json", None), {})
        data["tls"] = loads(data.pop("tls_json", None), {})
        return redact_secrets(repair_mojibake(data))
