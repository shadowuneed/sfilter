# Argus

Argus is a working OSINT investigation platform for suspicious casino, betting, phishing, scam, mirror-domain, and investment-fraud websites. The name comes from Argus Panoptes, the hundred-eyed giant from Greek mythology: the product is built to watch many signals and keep evidence, not just show a loose list of links.

## What It Does

- Starts an investigation from the browser with one button. A normal run checks up to `50` candidates; the optional context box only adds extra hints.
- Uses Gemini 2.5 Flash with Google Search grounding and URL context where available.
- Rotates multiple Gemini API keys and tracks local limits per key: `10 RPM` and `250 RPD` by default.
- Skips IP-only results, localhost/test domains, social/video/catalog noise, and domains already known in the database.
- Opens candidate sites, follows redirects, records HTTP status, DNS, TLS, title/meta/text, HTML, SHA-256, and sources.
- Saves Playwright screenshots as evidence when the page can be opened.
- Detects mirror groups through Gemini hints and simple domain similarity.
- Keeps a global case list with filters, statuses, saved flags, archive, notes, and latest evidence.
- Lets you stop a running investigation from the UI.
- Exports run reports and selected cases to CSV/XLSX.

## Evidence Exports

CSV cannot embed images as real worksheet objects; it can only contain screenshot file paths. XLSX export embeds screenshot thumbnails directly into the spreadsheet and also keeps the original screenshot path, HTML path, and HTML SHA-256.

## Case Workflow

- `uninvestigated`: new item that needs review.
- `investigating`: actively being checked.
- `investigated`: review is complete.
- `saved`: important case kept for quick export.
- `archived`: hidden from the active suspicion list while still preventing duplicate future searches for that domain.

## Local Start

Use the one-command launcher:

```powershell
cd C:\Users\profm\Desktop\work
.\RUN_ARGUS.bat
```

Manual start:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m playwright install chromium
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open:

```text
http://127.0.0.1:8000
```

## Environment

Create `.env` from `.env.example` and set keys locally or in Render environment variables:

```env
GEMINI_API_KEYS=your_primary_key,your_backup_key
GEMINI_MODEL=gemini-2.5-flash
ADMIN_TOKEN=use-a-long-random-secret
AUTH_REQUIRED=true
DATABASE_URL=postgresql://postgres:password@host:5432/postgres?sslmode=require
```

Do not commit real API keys. Keys pasted into chat should be treated as sensitive; prefer rotating them later and storing only in `.env` or deployment secrets.

`ADMIN_TOKEN` protects all `/api/*` endpoints except `/api/health`. The browser UI asks for this token and sends it as `Authorization: Bearer <token>`, preventing anonymous users from starting runs and spending Gemini quota.
Set `ADMIN_TOKEN` in the deployment environment. If it is missing, the UI no longer blocks the whole page with a login modal, but protected API actions cannot run correctly until the variable exists.

`DATABASE_URL` enables persistent Postgres storage and takes priority over `DATABASE_PATH`. Use the Supabase connection string with SSL enabled. For `*.supabase.com` hosts Argus also adds `sslmode=require` automatically if it is missing. If `DATABASE_URL` is empty, Argus falls back to local SQLite at `DATABASE_PATH`, which is useful only for local development.

## Docker

```powershell
docker build -t argus-investigator .
docker run --rm -p 8000:8000 --env-file .env argus-investigator
```

The Docker image runs as a non-root `argus` user.

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Render

`render.yaml` is ready for a Docker web service. Add `GEMINI_API_KEYS` as a secret environment variable in Render.
Persistent disks are available only on paid Render services, so the blueprint uses the `starter` plan instead of `free`.
For an existing Render service, add `ADMIN_TOKEN` manually in the service's Environment page because `sync: false` variables are prompted only during initial Blueprint creation.

For durable history on any platform, set `DATABASE_URL` to Postgres/Supabase. When `DATABASE_URL` is present, the app creates and uses Postgres tables for runs, findings, cases, logs, and Gemini usage counters.

The blueprint still mounts a persistent disk at `/var/data` for file evidence:

- HTML and screenshots at `/var/data/evidence`
- exports at `/var/data/exports`

For screenshots, deploy Argus as a Docker service so the Dockerfile runs `python -m playwright install --with-deps chromium`. If you create a non-Docker Python service manually, add this to the Render build command instead:

```bash
pip install -r requirements.txt && python -m playwright install chromium
```

Open `/api/health` after deploy and check `screenshot_runtime.chromium_exists`. It should be `true`.

Local SQLite files and evidence files are not durable across rebuilds/restarts unless persistent storage or an external database/storage service is attached. Postgres fixes the run/history database; screenshots and saved HTML still need durable file storage if the host filesystem is ephemeral.

For a real Kazakhstan-only accessibility check, set `KZ_PROXY_URL` in Render/Vercel to an HTTP/SOCKS proxy located in Kazakhstan. `KZ_HTTP_PROXY`, `KZ_HTTPS_PROXY`, and `KZ_PROXY` are accepted aliases. By default `REQUIRE_KZ_PROXY=false`, so Argus can still run without a proxy and marks evidence as checked from the server network. Set `REQUIRE_KZ_PROXY=true` only for strict mode: Argus will then block automatic and manual launches until the proxy exists and `KZ_PROXY_CHECK_URL` confirms country `KZ`.

If the journal shows `Gemini API 401 Unauthorized`, Google rejected the specific key used for that attempt. Check that the deployed `GEMINI_API_KEYS` value contains every key, has no literal quotes or `Bearer ` prefix, and that old standard keys are restricted or migrated to Gemini auth keys. Google notes that from June 19, 2026 the Gemini API rejects unrestricted standard keys: https://ai.google.dev/gemini-api/docs/api-key

## API Docs Used

- Gemini API models: https://ai.google.dev/gemini-api/docs/models/gemini
- Gemini API rate limits: https://ai.google.dev/gemini-api/docs/rate-limits
- Google Search grounding: https://ai.google.dev/gemini-api/docs/google-search
- URL context: https://ai.google.dev/gemini-api/docs/url-context
- Structured output: https://ai.google.dev/gemini-api/docs/structured-output
