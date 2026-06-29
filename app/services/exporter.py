from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from app.config import Settings
from app.database import Database


EXPORT_COLUMNS = [
    "case_id",
    "run_id",
    "finding_id",
    "domain",
    "final_url",
    "risk_score",
    "verdict",
    "category",
    "case_status",
    "saved",
    "archived",
    "status_code",
    "mirror_group",
    "title",
    "reasons",
    "sources",
    "screenshot_file",
    "html_file",
    "html_sha256",
    "created_at",
]

EXPORT_HEADERS = {
    "case_id": "ID дела",
    "run_id": "ID запуска",
    "finding_id": "ID находки",
    "domain": "Домен",
    "final_url": "Финальный URL",
    "risk_score": "Риск",
    "verdict": "Вердикт",
    "category": "Категория",
    "case_status": "Статус расследования",
    "saved": "Сохранено",
    "archived": "Архив",
    "status_code": "HTTP",
    "mirror_group": "Зеркальная группа",
    "title": "Заголовок",
    "reasons": "Причины",
    "sources": "Источники",
    "screenshot_file": "Файл скриншота",
    "html_file": "Файл HTML",
    "html_sha256": "SHA-256 HTML",
    "created_at": "Дата фиксации",
}


class Exporter:
    def __init__(self, settings: Settings, db: Database):
        self.settings = settings
        self.db = db

    def csv_for_run(self, run_id: int) -> Path:
        path = self.settings.export_dir / f"run_{run_id}_argus_report.csv"
        findings = self.db.list_findings(run_id=run_id, limit=10_000)
        return self._write_csv(path, findings)

    def xlsx_for_run(self, run_id: int) -> Path:
        path = self.settings.export_dir / f"run_{run_id}_argus_report.xlsx"
        findings = self.db.list_findings(run_id=run_id, limit=10_000)
        return self._write_xlsx(path, findings)

    def csv_for_cases(self, case_ids: list[int]) -> Path:
        suffix = "selected" if case_ids else "saved"
        path = self.settings.export_dir / f"cases_{suffix}_argus_report.csv"
        findings = self.db.list_findings_for_cases(case_ids)
        return self._write_csv(path, findings)

    def xlsx_for_cases(self, case_ids: list[int]) -> Path:
        suffix = "selected" if case_ids else "saved"
        path = self.settings.export_dir / f"cases_{suffix}_argus_report.xlsx"
        findings = self.db.list_findings_for_cases(case_ids)
        return self._write_xlsx(path, findings)

    def _write_csv(self, path: Path, findings: list[dict[str, Any]]) -> Path:
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=[EXPORT_HEADERS[col] for col in EXPORT_COLUMNS])
            writer.writeheader()
            for finding in findings:
                row = self._row(finding)
                writer.writerow({EXPORT_HEADERS[col]: row[col] for col in EXPORT_COLUMNS})
        return path

    def _write_xlsx(self, path: Path, findings: list[dict[str, Any]]) -> Path:
        try:
            from openpyxl import Workbook
            from openpyxl.drawing.image import Image
            from openpyxl.styles import Alignment, Font, PatternFill
        except Exception:
            return self._write_csv(path.with_suffix(".csv"), findings)

        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "Argus Report"
        headers = [EXPORT_HEADERS[col] for col in EXPORT_COLUMNS]
        headers.insert(16, "Скриншот")
        sheet.append(headers)

        header_fill = PatternFill("solid", fgColor="182432")
        header_font = Font(color="FFFFFF", bold=True)
        for cell in sheet[1]:
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(wrap_text=True, vertical="top")

        for index, finding in enumerate(findings, start=2):
            row = self._row(finding)
            values = [row[col] for col in EXPORT_COLUMNS]
            values.insert(16, "")
            sheet.append(values)
            sheet.row_dimensions[index].height = 92
            screenshot = self._local_path(row["screenshot_file"])
            if screenshot and screenshot.exists() and screenshot.suffix.lower() in {".png", ".jpg", ".jpeg"}:
                try:
                    image = Image(str(screenshot))
                    image.width = 150
                    image.height = 85
                    sheet.add_image(image, f"Q{index}")
                except Exception:
                    sheet.cell(index, 17).value = row["screenshot_file"]

        widths = {
            "A": 10, "B": 10, "C": 12, "D": 24, "E": 38, "F": 10,
            "G": 18, "H": 16, "I": 18, "J": 12, "K": 10, "L": 10,
            "M": 22, "N": 34, "O": 60, "P": 44, "Q": 24, "R": 34,
            "S": 34, "T": 42, "U": 20,
        }
        for column, width in widths.items():
            sheet.column_dimensions[column].width = width
        for row in sheet.iter_rows():
            for cell in row:
                cell.alignment = Alignment(wrap_text=True, vertical="top")

        workbook.save(path)
        return path

    def _row(self, finding: dict[str, Any]) -> dict[str, Any]:
        sources = finding.get("sources") or []
        reasons = finding.get("reasons") or []
        return {
            "case_id": finding.get("case_id") or "",
            "run_id": finding.get("run_id"),
            "finding_id": finding.get("id"),
            "domain": finding.get("domain"),
            "final_url": finding.get("final_url") or finding.get("url"),
            "risk_score": finding.get("risk_score"),
            "verdict": finding.get("verdict"),
            "category": finding.get("category"),
            "case_status": finding.get("case_status") or "",
            "saved": self._yes_no(finding.get("saved")),
            "archived": self._yes_no(finding.get("archived")),
            "status_code": finding.get("status_code"),
            "mirror_group": finding.get("mirror_group") or "",
            "title": finding.get("title") or "",
            "reasons": "\n".join(str(item) for item in reasons),
            "sources": "\n".join(str(item.get("url") or item) for item in sources),
            "screenshot_file": finding.get("screenshot_path") or "",
            "html_file": finding.get("html_path") or "",
            "html_sha256": finding.get("html_sha256") or "",
            "created_at": finding.get("created_at"),
        }

    def _local_path(self, value: str | None) -> Path | None:
        if not value:
            return None
        path = Path(value)
        if path.is_absolute():
            return path
        return Path.cwd() / path

    @staticmethod
    def _yes_no(value: Any) -> str:
        return "да" if bool(value) else "нет"
