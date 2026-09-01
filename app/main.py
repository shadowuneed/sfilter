from __future__ import annotations

import secrets
import threading
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.config import get_settings
from app.database import Database, utc_now
from app.services.exporter import Exporter
from app.services.gemini import GeminiClient
from app.services.investigator import Investigator
from app.services.kz_access import check_kz_proxy


settings = get_settings()
db = Database(settings.database_url or settings.database_path)
db.init()
gemini = GeminiClient(settings, db)
investigator = Investigator(settings, db, gemini)
exporter = Exporter(settings, db)
cancel_events: dict[int, threading.Event] = {}
run_launch_lock = threading.Lock()
screenshot_repair_lock = threading.Lock()

app = FastAPI(title="DOFilter", version="1.0.0")
app.add_middleware(GZipMiddleware, minimum_size=1000)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
RUN_TARGET_MIN = 100
RUN_TARGET_MAX = 500
DEFAULT_SEED_QUERY = "онлайн казино играть Казахстан"

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.mount("/evidence", StaticFiles(directory=settings.evidence_dir), name="evidence")


PUBLIC_API_PATHS = {"/api/health"}


def _ensure_kz_proxy_ready() -> None:
    if settings.require_kz_proxy and not settings.kz_proxy_url:
        raise HTTPException(
            status_code=503,
            detail=(
                "Kazakhstan proxy is required. Set KZ_PROXY_URL, KZ_HTTP_PROXY, "
                "KZ_HTTPS_PROXY, or KZ_PROXY to an HTTP/SOCKS proxy located in Kazakhstan."
            ),
        )
    if settings.kz_proxy_url:
        check = check_kz_proxy(settings)
        if not check.ok:
            if settings.require_kz_proxy:
                raise HTTPException(status_code=503, detail=check.message)
            # Soft mode: a broken optional proxy should not poison all HTTP/Playwright checks.
            object.__setattr__(settings, "kz_proxy_url", None)
            object.__setattr__(settings, "kz_proxy_source", None)
            object.__setattr__(settings, "kz_access_label", "server direct network (KZ proxy unavailable)")


def _bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def _thread_entry(run_id: int, target: Any, args: tuple[Any, ...]) -> None:
    starts_backlog_repair = (
        getattr(target, "__self__", None) is investigator
        and getattr(target, "__func__", None) in {Investigator.run, Investigator.run_manual}
    )
    try:
        target(*args)
    finally:
        try:
            run = db.get_run(run_id)
            if run and run["status"] not in {"queued", "running", "canceling"}:
                removed = db.finish_run_logs(run_id)
                if removed:
                    print(f"run={run_id} cleared_legacy_logs={removed}", flush=True)
        except Exception as exc:  # noqa: BLE001
            print(f"run={run_id} log_cleanup_error={type(exc).__name__}", flush=True)
        cancel_events.pop(run_id, None)
        if starts_backlog_repair:
            _start_screenshot_repair()


def _start_run_thread(run_id: int, name: str, target: Any, *args: Any) -> None:
    thread = threading.Thread(
        target=_thread_entry,
        args=(run_id, target, args),
        daemon=True,
        name=name,
    )
    thread.start()


def _normalize_run_target(max_candidates: int) -> int:
    requested = max(RUN_TARGET_MIN, min(int(max_candidates), RUN_TARGET_MAX))
    return min(requested, settings.max_candidates_per_run)


def _is_automatic_run(run: dict[str, Any]) -> bool:
    return int(run.get("max_candidates") or 0) > 1


def _screenshot_repair_entry() -> None:
    try:
        investigator.repair_completed_screenshot_backlog()
    except Exception as exc:  # noqa: BLE001
        print(f"screenshot_backlog_error={type(exc).__name__}: {exc}", flush=True)
    finally:
        screenshot_repair_lock.release()


def _start_screenshot_repair() -> bool:
    # Search always owns the limited browser/memory budget.  The repair worker
    # starts only while no automatic run is active, and the investigator
    # checks again before every screenshot if a new run appears.
    if any(_is_automatic_run(run) for run in db.list_active_runs()):
        return False
    if not screenshot_repair_lock.acquire(blocking=False):
        return False
    try:
        thread = threading.Thread(
            target=_screenshot_repair_entry,
            daemon=True,
            name="dofilter-screenshot-backlog",
        )
        thread.start()
    except Exception:
        screenshot_repair_lock.release()
        raise
    return True


@app.on_event("startup")
def resume_active_runs_after_restart() -> None:
    if not settings.resume_active_runs:
        db.mark_stale_runs_interrupted()
        return
    active_runs = db.list_active_runs()
    automatic_run_ids = [int(run["id"]) for run in active_runs if _is_automatic_run(run)]
    latest_automatic_run_id = max(automatic_run_ids, default=None)
    for run in active_runs:
        run_id = int(run["id"])
        if run_id in cancel_events:
            continue
        if run.get("status") == "canceling":
            db.update_run(run_id, status="canceled", finished_at=utc_now(), error=None)
            db.add_log(run_id, "warning", "Проверка остановлена пользователем до перезапуска сервера")
            continue

        if not _is_automatic_run(run):
            db.update_run(
                run_id,
                status="interrupted",
                finished_at=utc_now(),
                error="Ручная проверка была прервана перезапуском сервера.",
            )
            continue

        if run_id != latest_automatic_run_id:
            db.update_run(
                run_id,
                status="interrupted",
                finished_at=utc_now(),
                error="Остановлен дублирующий автоматический запуск; продолжен самый новый запуск.",
            )
            db.add_log(
                run_id,
                "warning",
                "Дублирующий запуск не возобновлен после перезапуска сервера",
                {"continued_run_id": latest_automatic_run_id},
            )
            continue

        max_candidates = _normalize_run_target(int(run.get("max_candidates") or RUN_TARGET_MIN))
        cancel_event = threading.Event()
        cancel_events[run_id] = cancel_event
        db.update_run(run_id, max_candidates=max_candidates, status="queued", finished_at=None, error=None)
        db.add_log(
            run_id,
            "warning",
            "Сервер перезапустился: продолжаю проверку до выбранной цели",
            {"target_findings": max_candidates, "already_saved": db.count_findings(run_id)},
        )
        _start_run_thread(
            run_id,
            f"dofilter-resume-{run_id}",
            investigator.run,
            run_id,
            run.get("seed_query"),
            max_candidates,
            bool(run.get("take_screenshots")),
            cancel_event,
            "auto",
        )

    if latest_automatic_run_id is not None:
        return
    _start_screenshot_repair()


@app.middleware("http")
async def api_auth_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and path not in PUBLIC_API_PATHS and settings.auth_required:
        if not settings.admin_token:
            return JSONResponse(
                {"detail": "ADMIN_TOKEN is not configured on the server."},
                status_code=503,
            )

        token = _bearer_token(request.headers.get("authorization"))
        token = token or request.headers.get("x-api-key")
        if not token or not secrets.compare_digest(token, settings.admin_token):
            return JSONResponse(
                {"detail": "Invalid or missing API token."},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

    return await call_next(request)


class RunRequest(BaseModel):
    seed_query: str | None = Field(default=None, max_length=2000)
    search_mode: str = Field(default="auto", max_length=30)
    max_candidates: int = Field(default=100, ge=1, le=5000)
    take_screenshots: bool = True


class ManualCheckRequest(BaseModel):
    target: str = Field(..., min_length=3, max_length=2000)
    category: str = Field(default="manual", max_length=60)
    take_screenshots: bool = True


class CaseUpdate(BaseModel):
    status: str | None = None
    archived: bool | None = None
    saved: bool | None = None
    notes: str | None = Field(default=None, max_length=2000)


def _ids_from_query(ids: str | None) -> list[int]:
    if not ids:
        return []
    parsed: list[int] = []
    for chunk in ids.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            parsed.append(int(chunk))
        except ValueError:
            continue
    return parsed


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/monitor")
def monitor() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/dynamics")
def dynamics() -> RedirectResponse:
    return RedirectResponse(url="/monitor#trendPanel", status_code=307)


@app.get("/registry")
def registry() -> FileResponse:
    return FileResponse(STATIC_DIR / "registry.html")


@app.get("/runs")
def runs_archive() -> FileResponse:
    return FileResponse(STATIC_DIR / "runs.html")


@app.get("/journal")
def journal() -> RedirectResponse:
    return RedirectResponse(url="/monitor#auditPanel", status_code=307)


@app.get("/api/health")
def health() -> dict[str, Any]:
    ml_status = investigator.ml.status()
    cyberscan_status = investigator.cyberscan.status()
    return {
        "ok": True,
        "app_name": "DOFilter",
        "gemini_configured": gemini.available,
        "gemini_key_format_ok": gemini.key_format_ok,
        "gemini_key_warnings": gemini.key_format_warnings,
        "gemini_model": settings.gemini_model,
        "gemini_models": settings.gemini_models,
        "gemini_key_count": len(settings.gemini_api_keys),
        "gemini_key_hashes": gemini.key_hashes,
        "rpm_limit": settings.gemini_rpm_limit,
        "rpd_limit": settings.gemini_rpd_limit,
        "auth_required": settings.auth_required,
        "auth_configured": bool(settings.admin_token),
        "auth_enforced": bool(settings.auth_required and settings.admin_token),
        "require_postgres": settings.require_postgres,
        "screenshots_enabled": settings.screenshots_enabled,
        "scan_concurrency": settings.scan_concurrency,
        "max_candidates_per_run": settings.max_candidates_per_run,
        "run_target_min": RUN_TARGET_MIN,
        "run_target_max": RUN_TARGET_MAX,
        "osint_candidate_pool_size": settings.osint_candidate_pool_size,
        "search_pages_enabled": settings.search_pages_enabled,
        "search_page_delay_seconds": settings.search_page_delay_seconds,
        "search_result_pages": settings.search_result_pages,
        "resume_active_runs": settings.resume_active_runs,
        "gemini_user_search_fallback": settings.gemini_user_search_fallback,
        "groq_configured": investigator.groq.available,
        "groq_model": settings.groq_model,
        "groq_model_version": settings.groq_model_version,
        "groq_requests_per_discovery": settings.groq_requests_per_discovery if investigator.groq.available else 0,
        "candidate_timeout_seconds": settings.candidate_timeout_seconds,
        "fast_evidence_mode": settings.fast_evidence_mode,
        "screenshot_timeout_seconds": settings.screenshot_timeout_seconds,
        "screenshot_runtime": investigator.screenshots.runtime_status(),
        "ml_enabled": investigator.ml.enabled,
        "ml_available": investigator.ml.available,
        "ml_model_path": ml_status.model_path,
        "ml_classes": ml_status.classes,
        "ml_error": ml_status.error,
        "ml_min_confidence": settings.ml_min_confidence,
        "cyberscan_ml_enabled": investigator.cyberscan.enabled,
        "cyberscan_ml_available": investigator.cyberscan.available,
        "cyberscan_model_path": cyberscan_status.model_path,
        "cyberscan_feature_count": len(cyberscan_status.structural_features),
        "cyberscan_ml_error": cyberscan_status.error,
        "database": db.label,
        "database_backend": db.backend,
        "evidence_dir": str(settings.evidence_dir),
        "export_dir": str(settings.export_dir),
        "kz_proxy_required": settings.require_kz_proxy,
        "kz_proxy_configured": bool(settings.kz_proxy_url),
        "kz_proxy_ready": bool(settings.kz_proxy_url) or not settings.require_kz_proxy,
        "kz_proxy_source": settings.kz_proxy_source,
        "kz_proxy_check_url": settings.kz_proxy_check_url,
        "kz_access_label": settings.kz_access_label,
    }


@app.post("/api/runs")
def create_run(request: RunRequest) -> dict[str, Any]:
    _ensure_kz_proxy_ready()
    max_candidates = _normalize_run_target(request.max_candidates)
    search_mode = investigator.normalize_search_mode(request.search_mode)
    seed_query = (request.seed_query or "").strip() or DEFAULT_SEED_QUERY
    with run_launch_lock:
        active_run = next((run for run in reversed(db.list_active_runs()) if _is_automatic_run(run)), None)
        if active_run:
            raise HTTPException(
                status_code=409,
                detail=f"Автоматический запуск #{active_run['id']} уже выполняется.",
            )
        run_id = db.create_run(
            seed_query=seed_query,
            max_candidates=max_candidates,
            take_screenshots=request.take_screenshots,
        )
    cancel_event = threading.Event()
    cancel_events[run_id] = cancel_event
    _start_run_thread(
        run_id,
        f"argus-run-{run_id}",
        investigator.run,
        run_id,
        seed_query,
        max_candidates,
        request.take_screenshots,
        cancel_event,
        search_mode,
    )
    return {"run_id": run_id, "status": "queued"}


@app.post("/api/manual-check")
def manual_check(request: ManualCheckRequest) -> dict[str, Any]:
    _ensure_kz_proxy_ready()
    run_id = db.create_run(
        seed_query=request.target,
        max_candidates=1,
        take_screenshots=request.take_screenshots,
    )
    cancel_event = threading.Event()
    cancel_events[run_id] = cancel_event
    _start_run_thread(
        run_id,
        f"argus-manual-{run_id}",
        investigator.run_manual,
        run_id,
        request.target,
        request.category,
        request.take_screenshots,
        cancel_event,
    )
    return {"run_id": run_id, "status": "queued"}


@app.post("/api/runs/{run_id}/cancel")
def cancel_run(run_id: int) -> dict[str, Any]:
    run = db.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run["status"] not in {"queued", "running", "canceling"}:
        return {"run_id": run_id, "status": run["status"], "changed": False}
    event = cancel_events.get(run_id)
    if event:
        event.set()
    db.update_run(run_id, status="canceling")
    db.add_log(run_id, "warning", "Проверка остановлена пользователем")
    return {"run_id": run_id, "status": "canceling", "changed": True}


@app.get("/api/runs")
def list_runs(limit: int = 25) -> dict[str, Any]:
    return {"runs": db.list_runs(limit=max(1, min(limit, 100)))}


@app.get("/api/runs/{run_id}")
def get_run(
    run_id: int,
    include_findings: bool = False,
    compact_findings: bool = False,
    finding_limit: int = Query(default=500, ge=1, le=500),
    after_log_id: int | None = None,
    log_limit: int = 300,
) -> dict[str, Any]:
    run = db.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    logs = db.list_logs(
        run_id,
        limit=max(1, min(log_limit, 1000)),
        after_id=after_log_id,
    )
    payload: dict[str, Any] = {
        "run": run,
        "logs": logs,
        "log_cursor": logs[-1]["id"] if logs else after_log_id,
    }
    if include_findings:
        if compact_findings:
            payload["findings"] = db.list_run_findings_summary(run_id, finding_limit)
        else:
            payload["findings"] = db.list_findings(run_id=run_id, limit=finding_limit)
    return payload


@app.get("/api/findings")
def list_findings(limit: int = 300) -> dict[str, Any]:
    return {"findings": db.list_findings(limit=max(1, min(limit, 1000)))}


@app.get("/api/cases")
def list_cases(
    q: str | None = None,
    status: str | None = None,
    archived: bool | None = False,
    saved: bool | None = None,
    min_risk: int | None = None,
    limit: int = 300,
) -> dict[str, Any]:
    return {
        "cases": db.list_cases(
            q=q,
            status=status,
            archived=archived,
            saved=saved,
            min_risk=min_risk,
            limit=limit,
        )
    }


@app.patch("/api/cases/{case_id}")
def update_case(case_id: int, update: CaseUpdate) -> dict[str, Any]:
    try:
        case = db.update_case(
            case_id,
            **{key: value for key, value in update.model_dump().items() if value is not None},
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"case": case}


@app.get("/api/cases/{case_id:int}")
def get_case(case_id: int) -> dict[str, Any]:
    case = db.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"case": case, "findings": db.list_case_findings(case_id, limit=25)}


@app.get("/api/runs/{run_id}/export.csv")
def export_csv(run_id: int) -> FileResponse:
    if not db.get_run(run_id):
        raise HTTPException(status_code=404, detail="Run not found")
    path = exporter.csv_for_run(run_id)
    return FileResponse(path, filename=path.name, media_type="text/csv")


@app.get("/api/runs/{run_id}/export.xlsx")
def export_xlsx(run_id: int) -> FileResponse:
    if not db.get_run(run_id):
        raise HTTPException(status_code=404, detail="Run not found")
    path = exporter.xlsx_for_run(run_id)
    media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    if path.suffix.lower() == ".csv":
        media_type = "text/csv"
    return FileResponse(path, filename=path.name, media_type=media_type)


@app.get("/api/cases/export.csv")
def export_cases_csv(ids: str | None = Query(default=None)) -> FileResponse:
    case_ids = _ids_from_query(ids)
    if not case_ids:
        case_ids = [case["id"] for case in db.list_cases(archived=False, limit=1000) if case.get("saved")]
    path = exporter.csv_for_cases(case_ids)
    return FileResponse(path, filename=path.name, media_type="text/csv")


@app.get("/api/cases/export.xlsx")
def export_cases_xlsx(ids: str | None = Query(default=None)) -> FileResponse:
    case_ids = _ids_from_query(ids)
    if not case_ids:
        case_ids = [case["id"] for case in db.list_cases(archived=False, limit=1000) if case.get("saved")]
    path = exporter.xlsx_for_cases(case_ids)
    media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    if path.suffix.lower() == ".csv":
        media_type = "text/csv"
    return FileResponse(path, filename=path.name, media_type=media_type)
