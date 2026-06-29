# Argus

Argus is a working OSINT investigation platform for suspicious casino, betting, phishing, scam, mirror-domain, and investment-fraud websites. The name comes from Argus Panoptes, the hundred-eyed giant from Greek mythology: the product is built to watch many signals and keep evidence, not just show a loose list of links.

## What It Does

- Starts an investigation from the browser with one button. The search focus is automatic; the optional context box only adds extra hints.
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
DATABASE_PATH=data/argus.db
```

Do not commit real API keys. Keys pasted into chat should be treated as sensitive; prefer rotating them later and storing only in `.env` or deployment secrets.

## Docker

```powershell
docker build -t argus-investigator .
docker run --rm -p 8000:8000 --env-file .env argus-investigator
```

## Render

`render.yaml` is ready for a Docker web service. Add `GEMINI_API_KEYS` as a secret environment variable in Render. On free Render instances, local SQLite files and evidence files are not durable across rebuilds/restarts unless persistent storage or an external database/storage service is attached.

## API Docs Used

- Gemini API models: https://ai.google.dev/gemini-api/docs/models/gemini
- Gemini API rate limits: https://ai.google.dev/gemini-api/docs/rate-limits
- Google Search grounding: https://ai.google.dev/gemini-api/docs/google-search
- URL context: https://ai.google.dev/gemini-api/docs/url-context
- Structured output: https://ai.google.dev/gemini-api/docs/structured-output