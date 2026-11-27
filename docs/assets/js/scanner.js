/* Zero Trace live scanner UI.
   The scan API contract is unchanged: create a session, submit the URL,
   render the backend response. No provider keys or secrets live here. */
(function () {
  "use strict";

  const API = (() => {
    try {
      const q = new URLSearchParams(location.search).get("api");
      if (q) return q.replace(/\/+$/, "");
      const stored = localStorage.getItem("ZERO_TRACE_API");
      if (stored) return stored.replace(/\/+$/, "");
    } catch (e) {}
    const isLocal = location.hostname === "localhost" || location.hostname === "127.0.0.1";
    const defaultApi = isLocal ? "http://localhost:8000" : "https://zerotrace-xv91.onrender.com";
    return (window.ZERO_TRACE_API || defaultApi).replace(/\/+$/, "");
  })();

  const $ = (id) => document.getElementById(id);
  let activeScanToken = 0;
  let scanTimer = null;
  let scanPct = 0;
  let activeController = null;

  function setProgress(value) {
    scanPct = Math.max(0, Math.min(100, value));
    const bar = document.getElementById("scanBar");
    if (bar) bar.style.width = scanPct + "%";
    const text = document.getElementById("scanPct");
    if (text) text.textContent = Math.round(scanPct) + "%";
  }

  setTimeout(() => {
    const el = document.getElementById("apiHint");
    if (el) el.textContent = API;
  }, 0);

  const esc = (value) =>
    String(value ?? "").replace(/[&<>"']/g, (m) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;"
    }[m]));

  function cls(status) {
    return /MALICIOUS|THREAT|FAILED|ERROR/.test(status)
      ? "bad"
      : /SUSPICIOUS|PENDING|REVIEW|NO_EXISTING|NO_MATCH|REFRESH/.test(status)
        ? "warn"
        : /FOUND|ANALYZED|NO_KNOWN/.test(status)
          ? "good"
          : "neutral";
  }

  function providerRow(name, provider) {
    if (!provider) {
      return `<div class="provider"><b>${esc(name)}</b><span class="state neutral">NO DATA</span></div>`;
    }

    const status = String(provider.status || "UNKNOWN");
    let detail = status.replaceAll("_", " ");
    const refresh = String(provider.refresh_status || "");

    if (name === "VirusTotal" && (status === "FOUND" || status === "ANALYZED")) {
      const stats = provider.stats || {};
      detail = `${stats.malicious || 0} malicious · ${stats.suspicious || 0} suspicious · ${stats.harmless || 0} harmless · ${stats.undetected || 0} undetected${status === "ANALYZED" ? " · fresh analysis" : ""}`;
    }

    if (name === "RDAP" && status === "FOUND") {
      detail = `Registration ${provider.registration ? new Date(provider.registration).toLocaleDateString() : "unknown"} · ${provider.nameservers?.length || 0} nameservers · DNSSEC ${provider.secure_dns ? "signed" : "not signed"}`;
    }

    if (name === "Dynamic Sandbox" && status === "ANALYZED") {
      detail = `${provider.verdict || "ANALYZED"} · ${provider.redirect_count || 0} redirects · ${provider.download_count || 0} downloads · ${provider.request_count || 0} responses`;
      if (provider.final_url) detail += ` · final: ${provider.final_url}`;
      if (provider.status_code) detail += ` · HTTP ${provider.status_code}`;
      if (Array.isArray(provider.downloads) && provider.downloads.length) {
        detail += " · files: " + provider.downloads.map((file) =>
          `${file.filename || "file"} (${file.sha256 || "no hash"} · ${file.size ?? "?"} bytes)`
        ).join(", ");
      }
    }

    if (status === "ANALYSIS_PENDING") {
      detail = "VirusTotal accepted a fresh scan, but the analysis is still pending. Zero Trace does not treat pending data as clean.";
    }
    if (status === "NO_EXISTING_REPORT") {
      detail = "No existing provider report; this is not proof of safety.";
    }
    if (status === "NOT_CONFIGURED") {
      detail = "Provider key/configuration is not present.";
    }
    if (status === "PROVIDER_ERROR") {
      detail = provider.detail || provider.error || ("Provider request failed" + (provider.http_status ? " (HTTP " + provider.http_status + ")" : "") + ".");
    }

    if (refresh === "REFRESH_FAILED") detail += " · fresh scan could not start; existing evidence only";
    else if (refresh === "FRESH_SCAN_TIMEOUT_FALLBACK") detail += " · fresh scan timed out; fallback report only";
    else if (refresh === "FRESH_SCAN_TIMEOUT_NO_REPORT") detail += " · fresh scan timed out; no existing report";
    else if (refresh === "FRESH_SCAN_TIMEOUT_REPORT_ERROR") detail += " · fresh scan timed out; report lookup failed";

    const badge = (refresh ? "STALE · " : "") + status.replaceAll("_", " ");
    return `<div class="provider"><div><b>${esc(name)}</b><div class="src">${esc(detail)}</div></div><span class="state ${refresh ? "warn" : cls(status)}">${esc(badge)}</span></div>`;
  }

  async function session(controller) {
    const response = await fetch(API + "/api/v1/browser-session", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      signal: controller.signal,
      headers: { Accept: "application/json", "Cache-Control": "no-cache" }
    });
    if (!response.ok) throw Error("Secure scan session failed (" + response.status + ").");
  }

  async function scan(url, token) {
    if (activeController) activeController.abort();
    const controller = new AbortController();
    activeController = controller;
    const clientScanId = "ZT-UI-" + Date.now().toString(36) + "-" + token;

    await session(controller);

    const response = await fetch(API + "/api/v1/browser-scan", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "Cache-Control": "no-cache"
      },
      body: JSON.stringify({ url, client_scan_id: clientScanId })
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw Error(data.detail || "Scan failed (" + response.status + ").");
    if (token !== activeScanToken) throw Error("Scan superseded by a newer request.");
    return data;
  }

  $("form").onsubmit = async (event) => {
    event.preventDefault();
    const url = $("url").value.trim();
    if (!url) return;

    const token = ++activeScanToken;
    const status = $("status");
    const statusText = $("statusText");
    const go = $("go");

    // Keep the button clickable so a user can replace an in-flight scan.
    // The scan token and AbortController make the older request a no-op.
    go.textContent = "SCAN NEW…";
    $("result").classList.remove("show");
    clearInterval(scanTimer);
    setProgress(0);
    status.className = "status show scan-active";
    status.setAttribute("aria-busy", "true");
    statusText.textContent = "SCANNING · ANALYZING LIVE EVIDENCE";

    // Keep this timer local: an aborted older scan must not clear a newer scan's timer.
    const thisTimer = setInterval(() => {
      if (scanPct < 90) setProgress(scanPct + Math.max(1, (90 - scanPct) * 0.08));
    }, 250);
    scanTimer = thisTimer;

    try {
      const payload = await scan(url, token);
      if (token !== activeScanToken) return;

      clearInterval(thisTimer);
      setProgress(100);
      await new Promise((resolve) => setTimeout(resolve, 400));
      if (token !== activeScanToken) return;

      render(payload);
      status.className = "status show done";
      statusText.textContent = "SCAN COMPLETE · LIVE RESULTS READY";
      go.textContent = "COMPLETED";
    } catch (error) {
      if (error?.name === "AbortError" || token !== activeScanToken) return;

      clearInterval(thisTimer);
      setProgress(0);
      status.className = "status show err";

      const message = error?.message || "Unable to complete scan";
      const lower = message.toLowerCase();
      let friendly = message;

      if (lower.includes("failed to fetch")) {
        friendly = "Backend not reachable. Set the API URL with ?api=YOUR_HTTPS_BACKEND (current: " + API + ") and ensure CORS allows this site.";
      } else if (/scan failed \((502|503|504)\)/.test(lower)) {
        friendly = "Backend is starting (Render free tier cold start). Wait ~30s and retry. Current API: " + API;
      }

      statusText.textContent = "SCAN FAILED · " + friendly;
      go.textContent = "DEEP SCAN";
    } finally {
      clearInterval(thisTimer);
      if (token === activeScanToken) {
        go.disabled = false;
        activeController = null;
        scanTimer = null;
        status.setAttribute("aria-busy", "false");
      }
    }
  };

  $("url").addEventListener("input", () => {
    if ($("go").textContent !== "SCAN NEW…") $("go").textContent = "DEEP SCAN";
    $("status").classList.remove("done");
    setProgress(0);
  });

  function render(data) {
    $("result").classList.add("show");

    const summary = data.summary || {};
    const score = summary.score;

    $("verdict").textContent = summary.verdict || "INSUFFICIENT EVIDENCE";
    $("host").textContent = data.target?.url || "";
    $("score").textContent = score == null ? "—" : String(score) + "/99";
    $("rec").innerHTML = "<b>Recommendation:</b> " + esc(summary.recommendation || "");

    const findings = data.findings || [];
    $("findings").innerHTML = findings.length
      ? findings.map((finding) => `<div class="finding"><div><span class="tag ${esc(finding.severity)}">${esc(finding.severity)}</span><b>${esc(finding.title)}</b></div><p>${esc(finding.detail)}</p><div class="src">${esc(finding.source)}</div></div>`).join("")
      : "<div class='finding'><b>No threat finding returned</b><p>No provider or local finding crossed the scanner's configured thresholds.</p></div>";

    const providers = data.providers || {};
    $("providers").innerHTML = [
      providerRow("VirusTotal", providers.VirusTotal),
      providerRow("RDAP", providers.RDAP),
      providerRow("Dynamic Sandbox", providers["Dynamic Sandbox"])
    ].join("");

    const detections = data.detections || [];
    const names = data.threat_names || [];
    $("dets").style.display = (detections.length || names.length) ? "block" : "none";
    $("detlist").innerHTML = (names.length
      ? `<div class="det"><b>Provider threat names</b> <span>· ${esc(names.join(" · "))}</span></div>`
      : "") + detections.map((detection) =>
        `<div class="det"><b>${esc(detection.result)}</b> <span>· ${esc(detection.engine)} · ${esc(detection.category)}</span></div>`
      ).join("");

    $("meta").innerHTML = `Confidence: <b>${esc(summary.confidence || "—")}</b> · Evidence: <b>${esc(summary.evidence_count ?? "—")}</b> · Providers reporting: <b>${esc(data.correlation?.reporting_providers ?? 0)}/${esc(data.correlation?.available_provider_count ?? 0)}</b><br>${esc(summary.score_definition || "")}<br>${esc(summary.coverage_note || "")}<br>Scan ID: <b>${esc(data.scan_id || "—")}</b> · ${esc(data.scanned_at || "")}`;
  }
})();
