import asyncio
import base64
import hashlib
import ipaddress
import os
import re
import secrets
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer
from pydantic import BaseModel, Field

API_KEY = os.getenv("ZERO_TRACE_API_KEY", "change-me")
CORS_ORIGINS = [x.strip() for x in os.getenv("CORS_ORIGINS", "http://localhost:8080,http://127.0.0.1:8080").split(",") if x.strip()]
VT_KEY = os.getenv("VT_API_KEY", "").strip()
VT_SUBMIT = os.getenv("VT_SUBMIT_NEW", "true").lower() == "true"
VT_REANALYZE = os.getenv("VT_REANALYZE", "true").lower() == "true"
VT_POLL_SECONDS = float(os.getenv("VT_POLL_SECONDS", "10"))
VT_MAX_POLLS = min(2, max(1, int(os.getenv("VT_MAX_POLLS", "2"))))
VT_SUBMIT_FILES = os.getenv("VT_SUBMIT_FILES", "false").lower() == "true"
WR_KEY = os.getenv("WEBRISK_API_KEY", "").strip()
RDAP_ENABLED = os.getenv("RDAP_ENABLED", "true").lower() == "true"
SANDBOX_ENABLED = os.getenv("SANDBOX_ENABLED", "true").lower() == "true"
SANDBOX_URL = os.getenv("SANDBOX_API_URL", "http://sandbox:8001").rstrip("/")
SANDBOX_KEY = os.getenv("SANDBOX_API_KEY", "")
MAX_URL = int(os.getenv("MAX_URL_LENGTH", "2048"))
SESSION_AGE = int(os.getenv("BROWSER_SESSION_MAX_AGE", "900"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
COOKIE_SAMESITE = os.getenv("BROWSER_SESSION_SAMESITE", os.getenv("BROWSER_SESSION_SAMESITE", "lax"))
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT_SECONDS", "12"))

serializer = URLSafeTimedSerializer(API_KEY, salt="zero-trace-session")
app = FastAPI(title="Zero Trace API", version="1.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def no_store_scan_responses(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/v1/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=MAX_URL)
    client_scan_id: str | None = Field(default=None, min_length=8, max_length=128)


def normalize(raw: str) -> str:
    value = raw.strip()
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if parsed.username or parsed.password:
        # Keep the URL for analysis, but never request it from the sandbox.
        return value
    return value


def url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def finding(out, severity, title, detail, source):
    out.append({"severity": severity, "title": title, "detail": detail, "source": source})


def is_private_host(host: str) -> bool:
    h = host.strip("[]").lower().rstrip(".")
    if h in {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"} or h.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(h, None)
        return any(
            (lambda ip: ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)(ipaddress.ip_address(item[4][0]))
            for item in infos
        )
    except Exception:
        return False


def local_checks(url: str):
    p = urlparse(url)
    host = (p.hostname or "").lower().rstrip(".")
    findings = []
    risk = 0

    if p.scheme != "https":
        risk += 8
        finding(findings, "LOW", "HTTPS is not enabled", "The URL uses HTTP instead of HTTPS.", "URL structure")
    if "@" in p.netloc:
        risk += 18
        finding(findings, "HIGH", "Credential-style URL syntax", "An @ character can obscure the destination host.", "URL structure")
    if len(url) > 180:
        risk += 6
        finding(findings, "LOW", "Unusually long URL", f"The URL contains {len(url)} characters.", "URL structure")
    if "xn--" in host:
        risk += 12
        finding(findings, "MEDIUM", "Punycode hostname", "The hostname contains an internationalized/punycode label.", "Punycode")
    terms = ["login", "signin", "verify", "password", "wallet", "reset", "account", "payment", "confirm", "security"]
    hits = [x for x in terms if x in (p.path + "?" + p.query).lower()]
    if len(hits) >= 2:
        risk += min(18, 5 * len(hits))
        finding(findings, "MEDIUM", "Credential or account lure terms", ", ".join(sorted(set(hits))) + " found in the URL.", "Phishing heuristic")
    if re.search(r"(?:redirect|url|target|dest|next|continue|return|goto)=", p.query.lower()):
        risk += 6
        finding(findings, "LOW", "Redirect-style parameter", "A parameter commonly used for navigation or redirecting is present.", "Redirect analysis")
    try:
        ipaddress.ip_address(host)
        risk += 10
        finding(findings, "MEDIUM", "IP address used as host", "The URL points directly to an IP address.", "IP host check")
    except ValueError:
        pass
    if re.search(r"\.(?:exe|scr|bat|cmd|msi|apk|dmg|iso)(?:$|[?#])", p.path, re.I):
        risk += 12
        finding(findings, "MEDIUM", "Downloadable executable path", "The URL path looks like a downloadable executable or package.", "Payload analysis")
    if re.search(r"(?:javascript|data|file|blob):", url, re.I):
        risk += 40
        finding(findings, "CRITICAL", "Potentially unsafe URL scheme", "The URL uses a scheme outside normal web navigation.", "Scheme analysis")
    if re.search(r"(?:micros0ft|paypa[l1]|facebo0k|g00gle|app1e|amaz0n|netf1ix)", host, re.I):
        risk += 25
        finding(findings, "HIGH", "Lookalike brand token", "The hostname contains a common brand-impersonation pattern.", "Identity analysis")
    return max(0, min(100, 100 - risk)), findings


def _vt_stats(report):
    attrs = report.get("data", {}).get("attributes", {}) if isinstance(report, dict) else {}
    stats = attrs.get("last_analysis_stats", {}) or {}
    results = attrs.get("last_analysis_results", {}) or {}
    detections = []
    threat_names = []
    for engine, result in results.items():
        category = str(result.get("category", "")).lower()
        result_name = result.get("result") or "Detection"
        if category in {"malicious", "suspicious"}:
            detections.append({"engine": engine, "category": category, "result": result_name})
            if result_name and result_name not in threat_names:
                threat_names.append(result_name)
    return attrs, stats, detections, len(results), threat_names


async def vt_url(client, url):
    """Run a fresh VirusTotal URL analysis when enabled, then return per-engine evidence.

    The public VirusTotal API is rate-limited, so Zero Trace deliberately keeps the
    fresh-analysis path bounded: one scan submission/reanalysis plus at most three
    analysis-status requests. If a fresh report cannot be completed, the response
    says so instead of turning missing data into a clean verdict.
    """
    if not VT_KEY:
        return {"status": "NOT_CONFIGURED", "configured": False}

    headers = {"x-apikey": VT_KEY, "accept": "application/json"}
    try:
        # Fresh scan path: reanalyse an existing URL identifier. If VT says the
        # URL is unknown, submit the raw URL to create a new analysis.
        if VT_SUBMIT and VT_REANALYZE:
            submit = await client.post(
                f"https://www.virustotal.com/api/v3/urls/{url_id(url)}/analyse",
                headers=headers,
            )
            if submit.status_code == 404:
                submit = await client.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers={**headers, "content-type": "application/x-www-form-urlencoded"},
                    data={"url": url},
                )
            if submit.status_code in (200, 201):
                analysis_id = submit.json().get("data", {}).get("id")
                if analysis_id:
                    last_attrs = None
                    for poll_index in range(VT_MAX_POLLS):
                        # Spread the bounded status checks so slower VT analyses have
                        # time to complete without exceeding the public API request budget.
                        poll_delay = VT_POLL_SECONDS * (poll_index + 1)
                        await asyncio.sleep(max(0.5, poll_delay))
                        analysis = await client.get(
                            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                            headers=headers,
                        )
                        if analysis.status_code != 200:
                            continue
                        attrs = analysis.json().get("data", {}).get("attributes", {}) or {}
                        last_attrs = attrs
                        if attrs.get("status") != "completed":
                            continue
                        results = attrs.get("results", {}) or {}
                        stats = attrs.get("stats", {}) or {}
                        detections = []
                        threat_names = []
                        for engine, result in results.items():
                            category = str(result.get("category", "")).lower()
                            result_name = result.get("result") or "Detection"
                            if category in {"malicious", "suspicious"}:
                                detections.append({"engine": engine, "category": category, "result": result_name})
                                if result_name and result_name not in threat_names:
                                    threat_names.append(result_name)
                        return {
                            "status": "ANALYZED",
                            "configured": True,
                            "stats": stats,
                            "detections": detections[:100],
                            "threat_names": threat_names[:50],
                            "total_engines": len(results),
                            "analysis_id": analysis_id,
                            "analysis_status": "completed",
                            "meaning": "Fresh VirusTotal URL analysis completed; engine results are provider evidence, not a guarantee of future safety.",
                        }
                    # Never return a hanging/pending provider state to the UI.
                    # After the bounded fresh-analysis window, use the current VT
                    # URL report when available and label it explicitly as fallback evidence.
                    report = await client.get(
                        f"https://www.virustotal.com/api/v3/urls/{url_id(url)}",
                        headers=headers,
                    )
                    if report.status_code == 200:
                        attrs, stats, detections, total, threat_names = _vt_stats(report.json())
                        return {
                            "status": "FOUND",
                            "configured": True,
                            "stats": stats,
                            "detections": detections[:100],
                            "threat_names": threat_names[:50],
                            "total_engines": total,
                            "last_analysis_date": attrs.get("last_analysis_date"),
                            "reputation": attrs.get("reputation"),
                            "refresh_status": "FRESH_SCAN_TIMEOUT_FALLBACK",
                            "analysis_id": analysis_id,
                            "meaning": "Fresh VirusTotal analysis did not finish within the scan deadline; the current VirusTotal URL report is returned instead of a pending state.",
                        }
                    if report.status_code == 404:
                        return {
                            "status": "NO_EXISTING_REPORT",
                            "configured": True,
                            "refresh_status": "FRESH_SCAN_TIMEOUT_NO_REPORT",
                            "analysis_id": analysis_id,
                            "meaning": "Fresh VirusTotal analysis did not finish within the scan deadline and no existing URL report is available.",
                        }
                    return {
                        "status": "PROVIDER_ERROR",
                        "configured": True,
                        "http_status": report.status_code,
                        "refresh_status": "FRESH_SCAN_TIMEOUT_REPORT_ERROR",
                        "analysis_id": analysis_id,
                    }

            # Fresh scan could not be started. Fetch the existing report as a
            # fallback, but label it as existing/stale evidence rather than fresh.
            report = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id(url)}",
                headers=headers,
            )
            if report.status_code == 200:
                attrs, stats, detections, total, threat_names = _vt_stats(report.json())
                return {
                    "status": "FOUND",
                    "configured": True,
                    "stats": stats,
                    "detections": detections[:100],
                    "threat_names": threat_names[:50],
                    "total_engines": total,
                    "last_analysis_date": attrs.get("last_analysis_date"),
                    "reputation": attrs.get("reputation"),
                    "refresh_status": "REFRESH_FAILED",
                    "refresh_http_status": submit.status_code,
                    "meaning": "Existing VirusTotal URL report found, but a fresh analysis could not be started; this is not proof of safety.",
                }
            if report.status_code == 404:
                return {"status": "NO_EXISTING_REPORT", "configured": True, "refresh_status": "REFRESH_FAILED", "refresh_http_status": submit.status_code, "meaning": "VirusTotal has no usable URL report and the fresh scan could not be started."}
            return {"status": "PROVIDER_ERROR", "configured": True, "http_status": submit.status_code}

        # Compatibility path when fresh submissions are disabled: retrieve the
        # current URL report only. Missing reports remain explicit.
        report = await client.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id(url)}",
            headers=headers,
        )
        if report.status_code == 404:
            return {"status": "NO_EXISTING_REPORT", "configured": True, "meaning": "VirusTotal has no existing URL report; this is not proof of safety."}
        if report.status_code != 200:
            return {"status": "PROVIDER_ERROR", "configured": True, "http_status": report.status_code}
        attrs, stats, detections, total, threat_names = _vt_stats(report.json())
        return {
            "status": "FOUND",
            "configured": True,
            "stats": stats,
            "detections": detections[:100],
            "threat_names": threat_names[:50],
            "total_engines": total,
            "last_analysis_date": attrs.get("last_analysis_date"),
            "reputation": attrs.get("reputation"),
            "meaning": "Existing VirusTotal URL report found; this is reputation evidence, not a safety guarantee.",
        }
    except Exception as exc:
        return {"status": "PROVIDER_ERROR", "configured": True, "error": str(exc)[:180]}


async def rdap(client, host):
    if not RDAP_ENABLED:
        return {"status": "NOT_CONFIGURED", "configured": False}
    try:
        ip = ipaddress.ip_address(host)
        endpoint = f"https://rdap.org/ip/{ip}"
    except ValueError:
        endpoint = f"https://rdap.org/domain/{host}"
    try:
        r = await client.get(endpoint, follow_redirects=True)
        if r.status_code != 200:
            return {"status": "NO_RECORD", "configured": True, "http_status": r.status_code}
        d = r.json()
        events = {x.get("eventAction"): x.get("eventDate") for x in d.get("events", []) if x.get("eventAction")}
        nameservers = [x.get("ldhName") for x in d.get("nameservers", []) if x.get("ldhName")]
        return {
            "status": "FOUND",
            "configured": True,
            "registration": events.get("registration"),
            "expiration": events.get("expiration"),
            "nameservers": nameservers,
            "secure_dns": bool(d.get("secureDNS", {}).get("delegationSigned")),
            "object_class": d.get("objectClassName"),
        }
    except Exception as exc:
        return {"status": "PROVIDER_ERROR", "configured": True, "error": str(exc)[:180]}


async def sandbox(client, url):
    if not SANDBOX_ENABLED:
        return {"status": "NOT_CONFIGURED", "configured": False}
    try:
        r = await client.post(
            f"{SANDBOX_URL}/scan",
            json={"url": url},
            headers={"x-sandbox-key": SANDBOX_KEY},
            timeout=float(os.getenv("SANDBOX_TIMEOUT_SECONDS", "23")),
        )
        if r.status_code != 200:
            return {"status": "PROVIDER_ERROR", "configured": True, "http_status": r.status_code}
        return r.json()
    except Exception as exc:
        return {"status": "PROVIDER_ERROR", "configured": True, "error": str(exc)[:180]}


def combine_score(base_score, findings, vt, sb):
    risk = 100 - base_score
    hard_threat = False
    strong_sources = 0

    for source in (vt,):
        stats = source.get("stats", {}) if source.get("status") in {"FOUND", "ANALYZED"} else {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        if malicious:
            # A confirmed provider detection is decisive evidence. Keep the score
            # low enough that a MALICIOUS verdict cannot visually resemble a clean
            # result, while still leaving room for additional independent evidence.
            risk += min(95, 45 + malicious * 12 + suspicious * 4)
            hard_threat = True
            strong_sources += 1
        elif suspicious:
            risk += min(45, 12 + suspicious * 6)
            strong_sources += 1
        if source.get("status") in {"FOUND", "ANALYZED"}:
            strong_sources += 1

    malicious_signals = sb.get("malicious_signals", []) or []
    suspicious_signals = sb.get("suspicious_signals", []) or []
    if malicious_signals:
        risk += min(65, 20 + 12 * len(malicious_signals))
        hard_threat = True
        strong_sources += 1
    elif suspicious_signals:
        risk += min(35, 8 + 7 * len(suspicious_signals))
        strong_sources += 1
    if sb.get("download_count", 0):
        risk += min(18, 6 + 4 * sb["download_count"])

    # Provider errors and missing reports do not count as safe evidence.
    score = max(0, min(99, round(100 - risk)))
    reputation_live = vt.get("status") in {"FOUND", "ANALYZED"}
    sandbox_live = sb.get("status") == "ANALYZED"
    # Coverage caps prevent sparse evidence from looking like a near-certainty.
    # RDAP is contextual intelligence, not a threat verdict, so it does not lift
    # the safety score by itself.
    if not reputation_live and not sandbox_live:
        score = min(score, 85)
    elif not reputation_live or not sandbox_live:
        score = min(score, 94)
    decisive = hard_threat or any(x.get("severity") == "CRITICAL" for x in findings)
    if decisive:
        verdict = "MALICIOUS"
    elif score < 45 or any(x.get("severity") == "HIGH" for x in findings):
        verdict = "SUSPICIOUS"
    else:
        verdict = "NO KNOWN THREAT"

    if strong_sources >= 3:
        confidence = "High"
    elif strong_sources >= 1:
        confidence = "Moderate"
    else:
        confidence = "Limited"

    return score, verdict, confidence


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "zero-trace",
        "version": "1.2.0",
        "providers": {
            "virustotal": bool(VT_KEY),
            "rdap": RDAP_ENABLED,
            "sandbox": SANDBOX_ENABLED,
        },
    }


@app.post("/api/v1/browser-session")
async def session(request: Request):
    origin = request.headers.get("origin", "")
    if origin and origin not in CORS_ORIGINS:
        raise HTTPException(403, "Origin not allowed")
    token = serializer.dumps({"scope": "scan", "issued_at": int(time.time()), "nonce": secrets.token_urlsafe(18)})
    response = JSONResponse({"ok": True, "expires_in": SESSION_AGE})
    response.set_cookie("zero_trace_session", token, max_age=SESSION_AGE, httponly=True, secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE, path="/")
    return response


def require_session(request: Request):
    token = request.cookies.get("zero_trace_session")
    if not token:
        raise HTTPException(401, "Secure scan session missing.")
    try:
        claims = serializer.loads(token, max_age=SESSION_AGE)
    except BadSignature:
        raise HTTPException(401, "Secure scan session expired.")
    if claims.get("scope") != "scan" or not claims.get("nonce"):
        raise HTTPException(401, "Invalid secure scan session.")
    return claims


@app.post("/api/v1/browser-scan")
async def scan(req: ScanRequest, request: Request):
    session_claims = require_session(request)
    try:
        url = normalize(req.url)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if is_private_host(host):
        raise HTTPException(400, "Private, loopback, local, multicast, or reserved destinations are not scannable.")

    base_score, findings = local_checks(url)
    timeout = httpx.Timeout(HTTP_TIMEOUT, connect=min(6, HTTP_TIMEOUT))
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, headers={"User-Agent": "ZeroTrace/1.1 Security Scanner"}) as client:
        vt_result, rdap_result, sandbox_result = await asyncio.gather(
            vt_url(client, url),
            rdap(client, host),
            sandbox(client, url),
        )

    if vt_result.get("status") in {"FOUND", "ANALYZED"}:
        stats = vt_result.get("stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        if malicious:
            finding(findings, "CRITICAL", "VirusTotal malicious detections", f"{malicious} security engines marked the URL malicious.", "VirusTotal")
        elif suspicious:
            finding(findings, "HIGH", "VirusTotal suspicious detections", f"{suspicious} security engines marked the URL suspicious.", "VirusTotal")

    for signal in sandbox_result.get("malicious_signals", []) or []:
        finding(findings, "HIGH", "Dynamic sandbox threat signal", signal, "Dynamic Sandbox")
    for signal in sandbox_result.get("suspicious_signals", []) or []:
        finding(findings, "MEDIUM", "Dynamic sandbox suspicious signal", signal, "Dynamic Sandbox")

    score, verdict, confidence = combine_score(base_score, findings, vt_result, sandbox_result)

    providers = {
        "VirusTotal": vt_result,
        "RDAP": rdap_result,
        "Dynamic Sandbox": sandbox_result,
    }
    reporting = sum(1 for x in providers.values() if x.get("status") not in {"NOT_CONFIGURED", "PROVIDER_ERROR", "NOT_APPLICABLE"})

    if verdict == "MALICIOUS":
        recommendation = "Do not open or download from this URL. Treat the observed threat evidence as unsafe unless independently verified in a controlled environment."
    elif verdict == "SUSPICIOUS":
        recommendation = "Avoid the URL until the flagged signals are independently verified. A suspicious result is not proof of malware, but it warrants caution."
    else:
        recommendation = "No known threat was found in the evidence available to Zero Trace. This score is evidence-based, not a probability or guarantee of future safety."

    return {
        "scan_id": req.client_scan_id or ("ZT-" + hashlib.sha256((url + str(time.time_ns()) + str(session_claims.get("nonce"))).encode()).hexdigest()[:12].upper()),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "target": {"url": url, "host": host},
        "summary": {
            "score": score,
            "verdict": verdict,
            "confidence": confidence,
            "evidence_count": len(findings),
            "recommendation": recommendation,
            "score_definition": "0-99 evidence-based safety score. It is not a probability and 100 is intentionally never used as a guarantee.",
            "coverage_note": "Missing provider reports/configuration reduce coverage and are never treated as proof of safety.",
        },
        "findings": findings,
        "providers": providers,
        "detections": (vt_result.get("detections", []) or []),
        "threat_names": list(dict.fromkeys((vt_result.get("threat_names", []) or []))),
        "correlation": {
            "reporting_providers": reporting,
            "available_provider_count": len(providers),
            "threat_agreement": sum(1 for x in (vt_result, sandbox_result) if x.get("status") in {"THREAT_FOUND"} or int((x.get("stats") or {}).get("malicious", 0) or 0) > 0 or bool(x.get("malicious_signals"))),
        },
    }
