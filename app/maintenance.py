from __future__ import annotations

import argparse

from app.config import get_settings
from app.database import Database


def log_retention_stats(db: Database) -> dict[str, int]:
    with db.connect() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS total,
                   COUNT(DISTINCT logs.run_id) AS runs,
                   SUM(
                       CASE WHEN runs.status NOT IN ('queued', 'running', 'canceling')
                                  AND logs.level<>'error'
                            THEN 1 ELSE 0 END
                   ) AS removable,
                   SUM(CASE WHEN logs.level='error' THEN 1 ELSE 0 END) AS errors
            FROM logs
            JOIN runs ON runs.id=logs.run_id
            """
        ).fetchone()
    return {
        "total": int(row["total"] or 0),
        "runs": int(row["runs"] or 0),
        "removable": int(row["removable"] or 0),
        "errors": int(row["errors"] or 0),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect or delete non-error logs from finished Qalqan runs.")
    parser.add_argument("--apply", action="store_true", help="Delete removable rows. Default is dry-run.")
    args = parser.parse_args()

    settings = get_settings()
    db = Database(settings.database_url or settings.database_path)
    stats = log_retention_stats(db)
    print(
        f"database={db.label} runs={stats['runs']} total={stats['total']} "
        f"finished_run_logs={stats['removable']} retained_errors={stats['errors']}"
    )
    if not args.apply:
        print("dry_run=true; create a database backup, then rerun with --apply")
        return

    removed = db.delete_finished_run_logs()
    print(f"dry_run=false removed={removed}")


if __name__ == "__main__":
    main()
