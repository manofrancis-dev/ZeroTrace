# Zero Trace — Live URL Security Scanner

Zero Trace is a server-side URL analysis application. A URL copied from Chrome, Edge, Firefox, Brave, Google results, a QR code, or another browser can be submitted to the live scanner.

## What this build fixes

- **Real backend response is rendered by the website.** The previous frontend/backend field mismatch caused live results to be rejected and replaced by local heuristics.
- **VirusTotal URL reputation**: existing URL reports, optional URL submission/polling, named engine detections, and honest `NO_EXISTING_REPORT` handling.
- **RDAP**: domain/IP registration and nameserver metadata.
- **Dynamic Sandbox**: isolated Chromium execution, final URL, HTTP status, redirect chain, page title, response count, downloads, SHA-256 for downloaded files, and suspicious page signals.
- **SSRF protection**: loopback, private, local, link-local, multicast and reserved destinations are rejected before sandbox execution.
- **Honest scoring**: the score is an evidence-based 0–99 safety score, not a probability. `100/100` is intentionally never returned as a guarantee. Missing provider data, provider errors, or a missing VirusTotal report are never treated as proof of safety.

## Important provider limits

VirusTotal's public API has request limits and its documentation says submitted/queried IoCs are added to the VirusTotal dataset. Do not submit confidential or personal URLs. The public API is also not intended to be used as a commercial antivirus substitute.

## Existing `.env` is included unchanged

This delivery includes the existing `backend/.env` supplied for this project. The API-key values are not regenerated, replaced, or printed by the project. Keep this ZIP private and do not publish the `.env` file to GitHub.

You do **not** need to run `USE_OLD_ENV.ps1`. It is retained only as an optional legacy helper.

## Start the backend

```powershell
cd backend
docker compose up -d --build
docker compose ps
Invoke-RestMethod http://localhost:8000/health
```

The sandbox should show `healthy` and the API should show `ok`.

## Start the website

Open a second PowerShell window:

```powershell
cd docs
python -m http.server 8080
```

Open:

`http://localhost:8080`

## Repeated-scan behavior

Every Deep Scan creates a fresh browser session and a unique client scan ID. API responses are marked `no-store`, and the website does not replace a failed live scan with a local guess. This means you can scan one URL, refresh the page, paste a different URL, and repeat the cycle without reusing the previous scan result.

## Recommended test order

1. `https://www.youtube.com/`
2. A known security-test URL such as an AMTSO test endpoint.
3. A URL that downloads an APK, only if you are authorized to test it.
4. A URL with a known VirusTotal report.
5. A normal URL with no existing VirusTotal report.
6. A URL that redirects, to verify the sandbox final URL and redirect telemetry.

For each result, check **all provider cards**, not only the score. A `NO_EXISTING_REPORT`, `NOT_CONFIGURED`, or `PROVIDER_ERROR` state is evidence of coverage/availability, not a safe verdict.

## Configuration

Keep your existing values. Optional settings added by this build:

```text
VT_SUBMIT_FILES=false
```

This build performs VirusTotal file-hash lookup for downloaded APKs. It does not automatically upload downloaded files to VirusTotal unless you explicitly extend the deployment for that workflow. This avoids silently publishing potentially sensitive files.

## Score semantics

Zero Trace does not claim that a numeric score is the probability that a URL is safe. The score summarizes observed evidence from the configured providers and local/dynamic checks. A high score means the scanner observed fewer threat signals in the available evidence; it does not mean the URL is guaranteed safe.

## Deploy to GitHub

1. **Never commit secrets.** `backend/.env` is gitignored. Use `backend/.env.example` as the template and create `backend/.env` locally (or via your host's secret manager).
2. Create a repo and push:
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   gh repo create ZeroTrace --public --source=. --remote=origin --push
   ```
3. The included GitHub Actions deploy the static website to GitHub Pages on push to `main`. Enable Pages in the repo settings (Source: GitHub Actions).
4. For the frontend to reach a non-local backend, set the API URL:
   - Append `?api=https://your-backend.example.com` to the site URL, or
   - Run `localStorage.setItem("ZERO_TRACE_API","https://your-backend.example.com")` in the browser console.
5. Backend hosting: build/publish the Docker images via the `docker.yml` workflow (GHCR) or run `docker compose up -d --build` on any Docker host. Expose port 8000 and set:
   - `CORS_ORIGINS` to your Pages URL (e.g. `https://manofrancis-dev.github.io`)
   - `COOKIE_SECURE=true` when serving over HTTPS
   - `BROWSER_SESSION_SAMESITE=none` when frontend and backend are on different sites (requires HTTPS)
   - Keep `VT_API_KEY` / `ZERO_TRACE_API_KEY` / `SANDBOX_API_KEY` in the host secret store, never in git.
