// ============================================================
// popup/popup.js
//
// Controls the extension popup UI:
//  - Fetches current tab's scan result from background.js
//  - Renders animated score gauge
//  - Displays layer-by-layer breakdown
//  - Handles settings load/save
//  - Shows scan history
// ============================================================

"use strict";

// ── Tab Switching ────────────────────────────────────────────
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab, .panel").forEach(el => el.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
    if (tab.dataset.tab === "history") loadHistory();
    if (tab.dataset.tab === "settings") loadSettings();
  });
});

// Shortcut buttons in header
document.getElementById("btnHistory").addEventListener("click", () =>
  document.querySelector('[data-tab="history"]').click()
);
document.getElementById("btnSettings").addEventListener("click", () =>
  document.querySelector('[data-tab="settings"]').click()
);

// ── Main: Load current tab result ───────────────────────────
let currentResult  = null;
let currentTabId   = null;
let currentUrl     = null;

async function init() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  currentTabId = tab.id;
  currentUrl   = tab.url;

  // Show truncated URL
  const urlEl = document.getElementById("urlText");
  const iconEl = document.getElementById("urlIcon");
  try {
    const u = new URL(tab.url);
    urlEl.textContent = u.hostname + u.pathname.substring(0, 30);
    iconEl.textContent = tab.url.startsWith("https") ? "🔒" : "🔓";
  } catch {
    urlEl.textContent = tab.url || "—";
  }

  // Ask background for result
  const result = await browser.runtime.sendMessage({
    type: "GET_RESULT",
    tabId: currentTabId
  });

  currentResult = result;
  renderResult(result);
}

// ── Render result ────────────────────────────────────────────
function renderResult(result) {
  if (!result || result.verdict === "SCANNING") {
    setScanning();
    // Keep polling every 1 second until scan completes
    // Max 12 attempts = 12 seconds (scan always completes within 8s)
    let pollAttempts = (result && result._pollAttempts) || 0;
    if (pollAttempts < 12) {
      setTimeout(async () => {
        let fresh = null;
        try {
          fresh = await browser.runtime.sendMessage({
            type: "GET_RESULT", tabId: currentTabId
          });
        } catch(e) {}
        if (fresh && fresh.verdict !== "SCANNING") {
          currentResult = fresh;
          renderResult(fresh);
        } else {
          // Keep polling — attach attempt count to avoid infinite loop
          if (fresh) fresh._pollAttempts = pollAttempts + 1;
          else fresh = { verdict:"SCANNING", _pollAttempts: pollAttempts + 1 };
          renderResult(fresh);
        }
      }, 1000);
    } else {
      // 12 seconds passed — something went wrong, show timeout message
      document.getElementById("verdictMessage").textContent =
        "Scan taking longer than expected. Try clicking Rescan.";
    }
    return;
  }

  const { score, verdict, message, layers } = result;

  // ── Score Gauge ──────────────────────────────────────────
  const color = verdict === "PHISHING" ? "#ef4444" :
                verdict === "SUSPICIOUS" ? "#f59e0b" : "#22c55e";

  const numEl = document.getElementById("scoreNum");
  numEl.textContent = score >= 0 ? score : "--";
  numEl.style.color = color;

  // Arc: total arc length ≈ 201. Fill based on score.
  const arc    = document.getElementById("gaugeArc");
  const filled = score >= 0 ? (score / 100) * 201 : 0;
  arc.style.strokeDashoffset = 201 - filled;
  arc.style.stroke           = color;

  // Verdict badge
  const badge     = document.getElementById("verdictBadge");
  const badgeIcon = document.getElementById("verdictIcon");
  const badgeText = document.getElementById("verdictText");
  badge.className = "verdict-badge " +
    (verdict === "PHISHING" ? "danger" : verdict === "SUSPICIOUS" ? "warn" : verdict === "SAFE" ? "safe" : "scanning");
  badgeIcon.textContent = verdict === "PHISHING" ? "🚨" : verdict === "SUSPICIOUS" ? "⚠️" : verdict === "SAFE" ? "✅" : "⟳";
  badgeText.textContent = verdict || "Unknown";
  badge.classList.remove("scanning");

  document.getElementById("verdictMessage").textContent = message || "";

  // Cache label
  document.getElementById("cacheLabel").textContent =
    result.fromCache ? "⚡ From cache" :
    result.whitelisted ? "✓ Whitelisted" : "";

  // ── Layer Scores ─────────────────────────────────────────
  const layerData = [
    { id: "url",    score: layers?.url?.score,    label: layers?.url?.score >= 0 ? layers.url.score + "/100" : "N/A" },
    { id: "domain", score: layers?.domain?.score, label: layers?.domain?.score >= 0 ? layers.domain.score + "/100" : "N/A" },
    { id: "dom",    score: layers?.dom?.score,    label: layers?.dom?.score >= 0 ? layers.dom.score + "/100" : "N/A" },
    { id: "api",    score: layers?.api?.score,    label: layers?.api?.score >= 0 ? layers.api.score + "/100" : "No Keys" }
  ];

  for (const { id, score: ls, label } of layerData) {
    const bar   = document.getElementById("bar-" + id);
    const scoreEl = document.getElementById("score-" + id);
    if (ls >= 0) {
      const barColor = ls >= 66 ? "#ef4444" : ls >= 35 ? "#f59e0b" : "#22c55e";
      bar.style.width      = ls + "%";
      bar.style.background = barColor;
      scoreEl.textContent  = label;
      scoreEl.style.color  = barColor;
    } else {
      bar.style.width = "0%";
      scoreEl.textContent = label;
      scoreEl.style.color = "#64748b";
    }
  }

  // ── Findings (Details tab) ───────────────────────────────
  renderFindings(result);
  renderDomainInfo(result);
}

function setScanning() {
  document.getElementById("scoreNum").textContent = "--";
  document.getElementById("verdictBadge").className = "verdict-badge scanning";
  document.getElementById("verdictText").textContent = "Scanning...";
  document.getElementById("verdictIcon").textContent = "⟳";
  document.getElementById("verdictMessage").textContent = "Analyzing this page for threats...";
  document.getElementById("gaugeArc").style.strokeDashoffset = 201;
  ["url","domain","dom","api"].forEach(id => {
    document.getElementById("score-" + id).textContent = "...";
    document.getElementById("bar-" + id).style.width = "0%";
  });
}

function renderFindings(result) {
  const list = document.getElementById("findingsList");
  const allBreakdowns = [
    ...(result.layers?.url?.breakdown    || []),
    ...(result.layers?.domain?.breakdown || []),
    ...(result.layers?.dom?.breakdown    || []),
    ...(result.reason ? [result.reason]  : [])
  ];

  if (allBreakdowns.length === 0) {
    list.innerHTML = '<div class="empty-state"><div class="es-icon">✅</div><p>No threats detected.</p></div>';
    return;
  }

  list.innerHTML = allBreakdowns.map(finding => {
    // Parse the score added from the finding string e.g. "(+20)"
    const scoreMatch = finding.match(/\(\+(\d+)\)/);
    const addedScore = scoreMatch ? parseInt(scoreMatch[1]) : 0;
    const cls  = addedScore >= 20 ? "high" : addedScore >= 10 ? "med" : "";
    const dot  = addedScore >= 20 ? "🔴" : addedScore >= 10 ? "🟡" : "⚪";
    const text = finding.replace(/\(\+\d+\)/, "").trim();
    return `<div class="finding-item ${cls}">
      <span class="fi-dot">${dot}</span>
      <span>${text}${addedScore > 0 ? ` <b>+${addedScore}</b>` : ""}</span>
    </div>`;
  }).join("");
}

function renderDomainInfo(result) {
  const el = document.getElementById("domainInfo");
  const d  = result.layers?.domain?.features || {};
  const u  = result.layers?.url?.features    || {};

  const rows = [
    ["Hostname",     result.layers?.url?.hostname || "—"],
    ["TLD",          result.layers?.url?.tld       || "—"],
    ["Domain Age",   d.domainAgeDays != null ? `${d.domainAgeDays} days` : "Unknown"],
    ["SSL Valid",    d.sslValid != null ? (d.sslValid ? "✓ Yes" : "✗ No") : "—"],
    ["SSL Issuer",   d.sslIssuer || "—"],
    ["DNS Valid",    d.dnsValid != null ? (d.dnsValid ? "✓ Yes" : "✗ No") : "—"],
    ["Typosquat?",   u.typosquatTarget ? `⚠ Near "${u.typosquatTarget}"` : "✓ No"],
    ["Protocol",     u.isHttp ? "⚠ HTTP" : "✓ HTTPS"]
  ];

  el.innerHTML = rows.map(([k, v]) =>
    `<div><span style="color:#64748b;display:inline-block;width:90px">${k}:</span> ${v}</div>`
  ).join("");
}

// ── Rescan ───────────────────────────────────────────────────
document.getElementById("rescanBtn").addEventListener("click", async () => {
  setScanning();
  const result = await browser.runtime.sendMessage({
    type: "RESCAN", tabId: currentTabId, url: currentUrl
  });
  currentResult = result;
  renderResult(result);
});

// ── Whitelist ─────────────────────────────────────────────────
document.getElementById("whitelistBtn").addEventListener("click", async () => {
  const hostname = new URL(currentUrl).hostname;
  await browser.runtime.sendMessage({
    type: "WHITELIST_DOMAIN", domain: hostname, tabId: currentTabId
  });
  alert(`"${hostname}" added to your whitelist.`);
  init();
});

// ── Report ────────────────────────────────────────────────────
document.getElementById("reportBtn").addEventListener("click", () => {
  const url = `https://phishtank.org/add_web_phish.php?url=${encodeURIComponent(currentUrl)}`;
  browser.tabs.create({ url });
});

// ── History ───────────────────────────────────────────────────
async function loadHistory() {
  const history = await browser.runtime.sendMessage({ type: "GET_HISTORY" });
  const list = document.getElementById("historyList");

  if (!history || history.length === 0) {
    list.innerHTML = '<div class="empty-state"><div class="es-icon">📋</div><p>No scan history yet.</p></div>';
    return;
  }

  list.innerHTML = history.slice(0, 30).map(item => {
    const color   = item.verdict === "PHISHING" ? "#ef4444" : item.verdict === "SUSPICIOUS" ? "#f59e0b" : "#22c55e";
    const timeAgo = formatTimeAgo(item.timestamp);
    let host = item.url;
    try { host = new URL(item.url).hostname; } catch {}
    return `<div class="history-item">
      <div class="h-dot" style="background:${color}"></div>
      <span class="h-url" title="${item.url}">${host}</span>
      <span class="h-score" style="color:${color}">${item.score}</span>
      <span class="h-time">${timeAgo}</span>
    </div>`;
  }).join("");
}

document.getElementById("clearHistoryBtn").addEventListener("click", async () => {
  await browser.storage.local.remove("history");
  loadHistory();
});

function formatTimeAgo(ts) {
  const diff = Date.now() - ts;
  if (diff < 60000)   return "just now";
  if (diff < 3600000) return Math.floor(diff/60000) + "m ago";
  if (diff < 86400000)return Math.floor(diff/3600000) + "h ago";
  return Math.floor(diff/86400000) + "d ago";
}

// ── Settings ──────────────────────────────────────────────────
async function loadSettings() {
  const keys = await browser.storage.local.get("apiKeys");
  const k    = keys.apiKeys || {};
  document.getElementById("key-gsb").value  = k.googleSafeBrowsing || "";
  document.getElementById("key-pt").value   = k.phishTank          || "";
  document.getElementById("key-us").value   = k.urlScanIo          || "";
  document.getElementById("key-ipqs").value = k.ipQualityScore     || "";

  const prefs = await browser.storage.local.get("prefs");
  const p = prefs.prefs || {};
  document.getElementById("pref-badge").checked  = p.showBadge         !== false;
  document.getElementById("pref-notify").checked = p.notifyPhishing     !== false;
  document.getElementById("pref-dom").checked    = p.enableDomAnalysis  !== false;
  document.getElementById("pref-block").checked  = p.blockPhishing      === true;
  document.getElementById("pref-api").checked    = p.enableApiChecks    !== false;
}

document.getElementById("saveSettingsBtn").addEventListener("click", async () => {
  const apiKeys = {
    googleSafeBrowsing: document.getElementById("key-gsb").value.trim(),
    phishTank:          document.getElementById("key-pt").value.trim(),
    urlScanIo:          document.getElementById("key-us").value.trim(),
    ipQualityScore:     document.getElementById("key-ipqs").value.trim()
  };

  const prefs = {
    showBadge:         document.getElementById("pref-badge").checked,
    notifyPhishing:    document.getElementById("pref-notify").checked,
    enableDomAnalysis: document.getElementById("pref-dom").checked,
    blockPhishing:     document.getElementById("pref-block").checked,
    enableApiChecks:   document.getElementById("pref-api").checked
  };

  await browser.storage.local.set({ apiKeys, prefs });

  const btn = document.getElementById("saveSettingsBtn");
  btn.textContent = "✓ Saved!";
  setTimeout(() => { btn.textContent = "💾 Save Settings"; }, 2000);
});

// ── Init ──────────────────────────────────────────────────────
init();
