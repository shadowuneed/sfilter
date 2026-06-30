from __future__ import annotations

import secrets
import threading
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.config import get_settings
from app.database import Database
from app.services.exporter import Exporter
from app.services.gemini import GeminiClient
from app.services.investigator import Investigator


settings = get_settings()
db = Database(settings.database_url or settings.database_path)
db.init()
db.mark_stale_runs_failed()
gemini = GeminiClient(settings, db)
investigator = Investigator(settings, db, gemini)
exporter = Exporter(settings, db)
cancel_events: dict[int, threading.Event] = {}

app = FastAPI(title="Argus", version="1.0.0")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.mount("/evidence", StaticFiles(directory=settings.evidence_dir), name="evidence")


PUBLIC_API_PATHS = {"/api/health"}


def _bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


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
    max_candidates: int = Field(default=50, ge=1, le=100)
    take_screenshots: bool = True


class ManualCheckRequest(BaseModel):
    target: str = Field(..., min_length=3, max_length=2000)
    category: str = Field(default="suspicious", max_length=60)
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


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "app_name": "Argus",
        "gemini_configured": gemini.available,
        "gemini_key_format_ok": gemini.key_format_ok,
        "gemini_key_warnings": gemini.key_format_warnings,
        "gemini_model": settings.gemini_model,
        "gemini_key_count": len(settings.gemini_api_keys),
        "rpm_limit": settings.gemini_rpm_limit,
        "rpd_limit": settings.gemini_rpd_limit,
        "auth_required": settings.auth_required,
        "auth_configured": bool(settings.admin_token),
        "auth_enforced": bool(settings.auth_required and settings.admin_token),
        "screenshots_enabled": settings.screenshots_enabled,
        "screenshot_runtime": investigator.screenshots.runtime_status(),
        "database": db.label,
        "database_backend": db.backend,
        "evidence_dir": str(settings.evidence_dir),
        "export_dir": str(settings.export_dir),
        "kz_proxy_configured": bool(settings.kz_proxy_url),
        "kz_access_label": settings.kz_access_label,
    }


@app.post("/api/runs")
def create_run(request: RunRequest) -> dict[str, Any]:
    max_candidates = min(request.max_candidates, settings.max_candidates_per_run)
    run_id = db.create_run(
        seed_query=request.seed_query,
        max_candidates=max_candidates,
        take_screenshots=request.take_screenshots,
    )
    cancel_event = threading.Event()
    cancel_events[run_id] = cancel_event
    thread = threading.Thread(
        target=investigator.run,
        args=(run_id, request.seed_query, max_candidates, request.take_screenshots, cancel_event),
        daemon=True,
        name=f"argus-run-{run_id}",
    )
    thread.start()
    return {"run_id": run_id, "status": "queued"}


@app.post("/api/manual-check")
def manual_check(request: ManualCheckRequest) -> dict[str, Any]:
    run_id = db.create_run(
        seed_query=request.target,
        max_candidates=1,
        take_screenshots=request.take_screenshots,
    )
    cancel_event = threading.Event()
    cancel_events[run_id] = cancel_event
    thread = threading.Thread(
        target=investigator.run_manual,
        args=(run_id, request.target, request.category, request.take_screenshots, cancel_event),
        daemon=True,
        name=f"argus-manual-{run_id}",
    )
    thread.start()
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
def get_run(run_id: int) -> dict[str, Any]:
    run = db.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return {"run": run, "logs": db.list_logs(run_id), "findings": db.list_findings(run_id=run_id)}


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
    return {"case": case, "findings": db.list_case_findings(case_id)}


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
