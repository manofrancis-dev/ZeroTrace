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

## Secrets and local configuration

`backend/.env` is local-only and is listed in `.gitignore`. It is not tracked by git and is not part of this repository. Never commit `.env`, API keys, or other secrets. Use `backend/.env.example` as the template and create `backend/.env` locally or through your host's secret manager. The API-key values are not regenerated, replaced, or printed by the project.

You do **not** need to run `USE_OLD_ENV.ps1`. It is retained only as an optional legacy helper.

## Start the backend

```powershell
cd backend
docker compose up -d --build
docker compose ps
Invoke-RestMethod http://localhost:8000/health
```

The sandbox should return `ok` and the API should show `ok` with `"sandbox": "ok"`. If the sandbox is unreachable, `/health` returns HTTP 503 with `"status": "degraded"`. If the API and sandbox keys do not match, `/health` returns HTTP 503 with `"sandbox": "unauthorized"` (the API checks an authenticated `/ready` probe, so a key mismatch can no longer masquerade as healthy).

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

Copy `backend/.env.example` to `backend/.env` and set real values. `ZERO_TRACE_API_KEY` signs browser session cookies and must be a strong random secret (placeholders are replaced by an ephemeral key at startup, which invalidates sessions on restart). `SANDBOX_API_KEY` is required: the sandbox rejects unauthenticated scan requests, so the API and worker must share the same value. In the single-container image (`start.sh`, used by `render.yaml` and `Dockerfile.render`) a missing `SANDBOX_API_URL`/`SANDBOX_API_KEY` is auto-configured inside the container, so a manually created Render service without env vars still works. `SANDBOX_TIMEOUT_SECONDS` (default 60) must exceed the worker's navigation and analysis budget. `RATE_LIMIT_PER_MINUTE` (default 20) throttles expensive scans per client address; enforce the same limit at the edge for multi-worker deployments.

Downloaded files are hashed locally with SHA-256 and the hashes are shown in the sandbox provider card. Zero Trace does **not** upload downloaded files to VirusTotal and does **not** perform a VirusTotal file-hash lookup, which avoids silently publishing potentially sensitive files.

SSRF checks are applied both before the scan and to every browser request (including redirects and WebSockets). Because the browser performs its own DNS resolution, a DNS-rebinding domain can still change its answer between checks; deploy the sandbox on an isolated network as the final boundary.

## Score semantics

Zero Trace does not claim that a numeric score is the probability that a URL is safe. The score summarizes observed evidence from the configured providers and local/dynamic checks. A high score means the scanner observed fewer threat signals in the available evidence; it does not mean the URL is guaranteed safe.

## Website, SEO, and search readiness

The static website lives in `docs/` and deploys to GitHub Pages from `main`.

- Canonical site URL: `https://manofrancis-dev.github.io/ZeroTrace/`
- Homepage and content pages: `docs/index.html`, `docs/features/`, `docs/how-it-works/`, `docs/url-security-guide/`, `docs/phishing-detection/`, `docs/faq/`, `docs/about/`, `docs/privacy/`
- Technical SEO files: `docs/robots.txt`, `docs/sitemap.xml`, `docs/404.html`
- Social preview: `docs/assets/img/og-zero-trace-url-scanner.png` (1200 x 630)
- Shared assets: `docs/assets/css/site.css`, `docs/assets/js/scanner.js`

SEO notes:

- The site uses absolute canonical URLs, self-referencing sitemaps, semantic HTML5, descriptive headings, internal links, breadcrumbs on subpages, Open Graph and Twitter card metadata, favicon metadata, and JSON-LD structured data.
- Structured data includes `WebSite`, `SoftwareApplication`, `WebPage`, `BreadcrumbList`, `FAQPage`, `Article`, `AboutPage`, and `Person`. It contains no fake ratings, reviews, or prices.
- No analytics script is installed. If analytics are added later, use a consent-based approach and never send submitted URLs, scan results, API keys, or other sensitive data.
- The scanner API contract is unchanged. The frontend still uses `?api=URL` or `localStorage.ZERO_TRACE_API` for backend overrides.
- GitHub Pages is a project page, so `robots.txt` is served at `/ZeroTrace/robots.txt`. Search engines fetch `robots.txt` from the host root. Submit the sitemap through Google Search Console and Bing Webmaster Tools rather than relying on robots discovery.
- Do not include API endpoints, scan results, or temporary URLs in the sitemap.

### Google Search Console setup

1. Open Google Search Console and add a URL-prefix property for `https://manofrancis-dev.github.io/ZeroTrace/`.
2. Verify ownership. For a GitHub Pages site, the HTML tag method is usually easiest: add the verification meta tag provided by Search Console to `docs/index.html`, redeploy, then click Verify.
3. Submit `https://manofrancis-dev.github.io/ZeroTrace/sitemap.xml` under Sitemaps.
4. Use URL Inspection on the homepage and the most important pages, then request indexing if needed.
5. Monitor Coverage, Core Web Vitals, and Search performance reports after deployment.
6. Do not claim verification or indexing until Search Console confirms it.

### Bing Webmaster Tools

1. Add `https://manofrancis-dev.github.io/ZeroTrace/`.
2. Verify with the HTML meta tag or XML file method.
3. Submit the same sitemap URL.
4. Review crawl stats and keyword reports after the site is crawled.

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
