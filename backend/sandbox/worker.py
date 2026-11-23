import asyncio
import hashlib
import ipaddress
import os
import socket
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from playwright.async_api import async_playwright

app = FastAPI(title="Zero Trace Dynamic Sandbox", version="1.1.1")
KEY = os.getenv("SANDBOX_API_KEY", "")


class Scan(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


def _is_private_ip(ip) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _ip_is_private(value: str) -> bool:
    h = value.strip("[]").lower().rstrip(".")
    if not h:
        return True
    try:
        return _is_private_ip(ipaddress.ip_address(h))
    except ValueError:
        pass
    try:
        # Browsers accept shorthand, decimal, hex and octal IPv4 forms that
        # ipaddress rejects and Windows getaddrinfo does not resolve.
        return _is_private_ip(ipaddress.ip_address(socket.inet_aton(h)))
    except (OSError, ValueError):
        return False


async def host_is_private(host: str) -> bool:
    """Applied to every request the browser makes, including redirects."""
    h = host.strip("[]").lower().rstrip(".")
    if not h:
        return True
    if (
        h in {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
        or h.endswith(".local")
        or h.endswith(".internal")
        or h.endswith(".test")
    ):
        return True
    if _ip_is_private(h):
        return True
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, h, None)
        return any(_ip_is_private(item[4][0]) for item in infos)
    except Exception:
        return False


@app.get("/health")
async def health():
    return {"status": "ok", "service": "zero-trace-sandbox", "version": "1.1.1"}


@app.post("/scan")
async def scan(q: Scan, x_sandbox_key: str = Header(default="")):
    if not KEY or x_sandbox_key != KEY:
        raise HTTPException(403, "Sandbox key is required and must be valid")

    redirects = []
    downloads = []
    malicious_signals = []
    suspicious_signals = []
    requests_seen = []
    blocked_destinations = []
    download_tasks = []
    final_url = q.url
    status_code = None
    title = ""
    text = ""

    async def process_download(download):
        filename = download.suggested_filename
        try:
            path = await download.path()
            if not path:
                downloads.append({"filename": filename, "error": "Download path unavailable"})
                return
            with open(path, "rb") as handle:
                data = handle.read()
            downloads.append({"filename": filename, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
        except Exception as exc:
            downloads.append({"filename": filename, "error": str(exc)[:120]})

    async def on_download(download):
        download_tasks.append(asyncio.create_task(process_download(download)))

    async def block_private_requests(route):
        try:
            host = urlparse(route.request.url).hostname or ""
            if await host_is_private(host):
                blocked_destinations.append(route.request.url)
                await route.abort()
                return
        except Exception:
            # Fail closed: never allow a request whose destination cannot be checked.
            blocked_destinations.append(getattr(route.request, "url", "<unknown>"))
            await route.abort()
            return
        await route.continue_()

    async def block_private_websockets(ws_route):
        try:
            host = urlparse(ws_route.url).hostname or ""
            if await host_is_private(host):
                blocked_destinations.append(ws_route.url)
                await ws_route.close()
                return
        except Exception:
            blocked_destinations.append(getattr(ws_route, "url", "<unknown>"))
            await ws_route.close()
            return
        await ws_route.connect_to_server()

    async def on_response(response):
        try:
            if await host_is_private(urlparse(response.url).hostname or ""):
                blocked_destinations.append(response.url)
            if response.status in {301, 302, 303, 307, 308}:
                location = response.headers.get("location", "")
                if location:
                    redirects.append({"status": response.status, "url": response.url, "location": location})
            if len(requests_seen) < 300:
                requests_seen.append({"url": response.url, "status": response.status, "resource_type": response.request.resource_type})
        except Exception:
            pass

    context = None
    browser = None
    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch(headless=True, chromium_sandbox=False, args=["--disable-dev-shm-usage", "--no-first-run"])
            context = await browser.new_context(java_script_enabled=True, accept_downloads=True, ignore_https_errors=False)
            await context.route("**/*", block_private_requests)
            await context.route_web_socket("**/*", block_private_websockets)
            page = await context.new_page()

            page.on("response", on_response)
            page.on("download", on_download)

            try:
                response = await page.goto(q.url, wait_until="domcontentloaded", timeout=18000)
                status_code = response.status if response else None
                await page.wait_for_timeout(1000)
                final_url = page.url
                title = await asyncio.wait_for(page.title(), timeout=5)
                text = (await page.locator("body").inner_text(timeout=5000))[:30000].lower()
            except Exception as exc:
                suspicious_signals.append("Browser could not fully load the target: " + str(exc)[:160])

            if download_tasks:
                await asyncio.gather(*download_tasks, return_exceptions=True)

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
            if blocked_destinations:
                malicious_signals.append("An attempt to reach a private/internal destination was blocked.")
            if await host_is_private(urlparse(final_url).hostname or ""):
                malicious_signals.append("The final URL resolved to a private/internal destination.")
        finally:
            for closeable in (context, browser):
                if closeable is not None:
                    try:
                        await closeable.close()
                    except Exception:
                        pass

    return {
        "status": "ANALYZED",
        "configured": True,
        "final_url": final_url,
        "final_host": urlparse(final_url).hostname,
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
