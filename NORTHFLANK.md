# Northflank deployment

This branch is isolated from the stable `main` branch. Deploy only
`northflank-production` while the migration is being verified.

## Recommended topology

- One Northflank combined service built from the repository `Dockerfile`.
- One Northflank PostgreSQL addon in the same project and region.
- One service instance. The current scan worker runs inside the web process, so
  multiple replicas could resume the same active run.
- A persistent volume mounted at `/var/data` for HTML, screenshots, and exports.
  Start with at least 10 GB for repeated 500-site runs and monitor usage.
- A private database connection injected through a Northflank secret group.

Northflank Developer Sandbox is always on, but Northflank documents it as a
development tier rather than a production SLA. Browser screenshots previously
exceeded 512 MB on Render, so use at least 1 GB RAM; 2 GB is safer for long runs.

## Service configuration

1. Create a project in the desired region.
2. Create a PostgreSQL addon with TLS enabled. Keep public access disabled after
   the migration.
3. Link the addon to a secret group and alias its `POSTGRES_URI` as
   `DATABASE_URL` for the service.
4. Create a combined service from the GitHub repository:
   - branch: `northflank-production`
   - build type: `Dockerfile`
   - Dockerfile path: `/Dockerfile`
   - build context: `/`
   - public HTTP port: `8000`
   - instances: `1`
5. Mount the persistent volume at `/var/data`.
6. Add an HTTP liveness/readiness check on `/api/health`, port `8000`.

Use the runtime variables from `render.yaml`. At minimum set:

```env
PORT=8000
DATABASE_URL=<injected POSTGRES_URI>
REQUIRE_POSTGRES=true
RESUME_ACTIVE_RUNS=true
ADMIN_TOKEN=<long random secret>
AUTH_REQUIRED=true
GEMINI_API_KEYS=<secret values>
DATABASE_PATH=/var/data/data/argus.db
EVIDENCE_DIR=/var/data/evidence
EXPORT_DIR=/var/data/exports
PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
SCREENSHOTS_ENABLED=true
BROWSER_SCREENSHOTS_ENABLED=true
SCREENSHOT_FALLBACK_ENABLED=true
SCREENSHOT_CONCURRENCY=1
SCAN_CONCURRENCY=1
MAX_CANDIDATES_PER_RUN=15000
CANDIDATE_TIMEOUT_SECONDS=15
```

Do not commit `.env` or paste secrets into the Northflank build configuration.

## Database migration

The application uses standard PostgreSQL through `psycopg`; it does not depend
on the Supabase client SDK. The same schema therefore works with a Northflank
PostgreSQL addon without changing discovery logic.

1. Stop starting new scans, then wait for the active run to finish.
2. Inspect log cleanup without changing data:

   ```powershell
   .\.venv\Scripts\python.exe -m app.maintenance
   ```

3. Create and verify a Supabase database backup.
4. After the backup, compact old technical logs:

   ```powershell
   .\.venv\Scripts\python.exe -m app.maintenance --apply
   ```

5. Import PostgreSQL from the verified dump or the temporary live connection
   using Northflank's addon import flow.
6. Point only the Northflank service at the new database and verify health,
   registry counts, one manual check, one screenshot, and one short scan.
7. Keep Supabase unchanged until those checks pass and a Northflank backup has
   been created.

Rollback is only an environment change: stop the Northflank service, restore
the previous `DATABASE_URL`, and redeploy. Do not write to both databases during
the verification window.

## Operational notes

- Avoid deploying while a scan is active.
- Keep one service replica until scan execution is moved to a dedicated worker
  with database leases.
- The registry API now returns summary columns, and live logs are fetched as a
  delta. Full evidence remains available only when a case or run folder is
  opened.
- Informational and warning logs live only in the service memory while a run is
  active; they are never written to PostgreSQL. Error entries are persisted and
  remain visible after completion. The final status, findings, cases,
  screenshots, and exports remain unchanged.
- Persistent screenshots need a retention or object-storage policy before the
  volume approaches its limit.

Official references:

- https://northflank.com/docs/v1/application/getting-started/build-and-deploy-your-code
- https://northflank.com/docs/v1/application/databases-and-persistence/deploy-databases-on-northflank/deploy-postgresql-on-northflank
- https://northflank.com/docs/v1/application/databases-and-persistence/backup-restore-and-import-data
- https://northflank.com/docs/v1/application/observe/configure-health-checks
