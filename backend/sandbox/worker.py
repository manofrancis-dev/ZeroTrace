import asyncio
import hashlib
import os
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from playwright.async_api import async_playwright

app = FastAPI(title="Zero Trace Dynamic Sandbox", version="1.1.1")
KEY = os.getenv("SANDBOX_API_KEY", "")


class Scan(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "zero-trace-sandbox", "version": "1.1.1"}


@app.post("/scan")
async def scan(q: Scan, x_sandbox_key: str = Header(default="")):
    if KEY and x_sandbox_key != KEY:
        raise HTTPException(403, "Invalid sandbox key")

    redirects = []
    downloads = []
    malicious_signals = []
    suspicious_signals = []
    requests_seen = []
    final_url = q.url
    status_code = None
    title = ""

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, chromium_sandbox=False, args=["--disable-dev-shm-usage", "--no-first-run"])
        context = await browser.new_context(java_script_enabled=True, accept_downloads=True, ignore_https_errors=False)
        page = await context.new_page()

        async def on_response(response):
            try:
                if response.status in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location", "")
                    if location:
                        redirects.append({"status": response.status, "url": response.url, "location": location})
                if len(requests_seen) < 300:
                    requests_seen.append({"url": response.url, "status": response.status, "resource_type": response.request.resource_type})
            except Exception:
                pass

        page.on("response", on_response)

        async def on_download(download):
            try:
                path = await download.path()
                sha256 = None
                size = None
                if path:
                    data = open(path, "rb").read()
                    sha256 = hashlib.sha256(data).hexdigest()
                    size = len(data)
                downloads.append({"filename": download.suggested_filename, "sha256": sha256, "size": size})
            except Exception as exc:
                downloads.append({"filename": download.suggested_filename, "error": str(exc)[:120]})

        page.on("download", on_download)

        try:
            response = await page.goto(q.url, wait_until="domcontentloaded", timeout=18000)
            status_code = response.status if response else None
            await page.wait_for_timeout(1000)
            final_url = page.url
            title = await page.title()
            text = (await page.locator("body").inner_text(timeout=5000))[:30000].lower()

            for term in [
                "your computer is infected",
                "verify your account",
                "enter your password",
                "security alert",
                "install extension",
                "claim your reward",
            ]:
                if term in text:
                    suspicious_signals.append("Page contains lure phrase: " + term)
            for term in ["download malware", "eicar", "test malware", "amtso malware test"]:
                if term in text or term in q.url.lower():
                    suspicious_signals.append("Recognized security-test or malware-test indicator: " + term)
            if downloads:
                suspicious_signals.append("The page initiated a browser download.")
            if any(str(item.get("filename", "")).lower().endswith((".exe", ".scr", ".bat", ".cmd", ".msi", ".apk", ".dmg", ".iso")) for item in downloads):
                malicious_signals.append("The page initiated a download with an executable/package extension.")
        except Exception as exc:
            suspicious_signals.append("Browser could not fully load the target: " + str(exc)[:160])

        await context.close()
        await browser.close()

    parsed = urlparse(final_url)
    return {
        "status": "ANALYZED",
        "configured": True,
        "final_url": final_url,
        "final_host": parsed.hostname,
        "status_code": status_code,
        "title": title,
        "redirect_count": len(redirects),
        "redirects": redirects[:50],
        "download_count": len(downloads),
        "downloads": downloads[:20],
        "request_count": len(requests_seen),
        "malicious_signals": malicious_signals[:30],
        "suspicious_signals": suspicious_signals[:30],
        "verdict": "MALICIOUS" if malicious_signals else ("SUSPICIOUS" if suspicious_signals else "NO_KNOWN_THREAT"),
    }
