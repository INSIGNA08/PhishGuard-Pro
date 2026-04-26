// ============================================================
// background/background.js  (v2 — Fixed)
//
// KEY FIXES:
//  1. Overall 8-second scan timeout — scan ALWAYS completes
//  2. Each layer wrapped in Promise.race with timeout
//  3. RedirectChecker limited to 3 hops, 2s timeout each
//  4. ThreatFeeds non-blocking startup
//  5. Graceful fallback — partial results shown if layer fails
// ============================================================

const tabResults = {};
const domResults = {};

// ── Helper: wrap any promise with a timeout ──────────────────
// If the promise takes longer than ms, returns fallback value
// instead of hanging forever.
function withTimeout(promise, ms, fallback) {
  const timer = new Promise(resolve => setTimeout(() => resolve(fallback), ms));
  return Promise.race([promise, timer]);
}

// ── Startup ──────────────────────────────────────────────────
// IMPORTANT: Don't await ThreatFeeds.init() — let it load in
// background so it doesn't delay the first scan.
ThreatFeeds.init().catch(e => console.warn("[PhishGuard] Feed init failed:", e));
NetworkMonitor.init();
console.log("[PhishGuard v2] Initialized — feeds loading in background");

// ── Navigation detection ─────────────────────────────────────
browser.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;
  if (url.startsWith("about:") || url.startsWith("moz-extension:") ||
      url.startsWith("chrome:")  || url.startsWith("file:")) return;
  NetworkMonitor.resetTab(details.tabId);
  await scanUrl(url, details.tabId);
});

browser.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  const url = tab.url;
  if (!url || url.startsWith("about:") || url.startsWith("moz-extension:")) return;
  const ex = tabResults[tabId];
  if (ex && ex.url === url && Date.now() - ex.timestamp < 5000) return;
  NetworkMonitor.resetTab(tabId);
  await scanUrl(url, tabId);
});

// ── MAIN SCAN — always completes within 8 seconds ────────────
async function scanUrl(url, tabId) {
  tabResults[tabId] = { url, verdict: "SCANNING", score: -1, timestamp: Date.now() };
  updateBadge(tabId, "SCANNING");

  // ── Safety net: force complete after 8 seconds no matter what
  // This means even if every single layer hangs, user gets a result.
  const scanTimeout = setTimeout(() => {
    if (tabResults[tabId]?.verdict === "SCANNING") {
      console.warn("[PhishGuard] Scan timeout — using URL-only result");
      const urlOnly = URLAnalyzer.analyze(url);
      const result  = Scorer.combineV2(
        urlOnly,
        { score:-1, features:{}, breakdown:[] },
        { score:-1, features:{}, breakdown:[] },
        { score:-1, results:{}, hasKeys:false },
        { score:-1, isKnownThreat:false },
        { score:-1, chain:[], hopCount:0, breakdown:[] },
        { score:-1, features:{}, breakdown:[] },
        { mlScore:-1, correlationsTriggered:[], confidence:"very_low" },
        getDomainTrust(new URL(url).hostname)
      );
      result.url       = url;
      result.timestamp = Date.now();
      result.timedOut  = true;
      result.layers    = { url: urlOnly };
      tabResults[tabId] = result;
      updateBadge(tabId, result.verdict);
      Storage.setCache(url, result);
      Storage.addToHistory({ url, score: result.score, verdict: result.verdict });
    }
  }, 8000);

  try {
    const hostname = new URL(url).hostname;

    // Whitelist check
    if (await withTimeout(Storage.isWhitelisted(hostname), 500, false)) {
      clearTimeout(scanTimeout);
      const r = { url, verdict:"SAFE", score:0, message:"Domain is whitelisted.", timestamp:Date.now(), whitelisted:true };
      tabResults[tabId] = r;
      updateBadge(tabId, "SAFE");
      return;
    }

    // Cache check
    const cached = await withTimeout(Storage.getCached(url), 500, null);
    if (cached) {
      clearTimeout(scanTimeout);
      tabResults[tabId] = { ...cached, fromCache: true };
      updateBadge(tabId, cached.verdict);
      return;
    }

    const prefs = await withTimeout(Storage.getPrefs(), 500, {
      enableApiChecks: true, enableDomAnalysis: true,
      notifyPhishing: true, blockPhishing: false
    });

    const trust = getDomainTrust(hostname);

    // ── Run all layers with individual timeouts ──────────────
    // Each layer has its own timeout so one slow layer can't
    // block the others from contributing to the final score.
    const FALLBACK_URL    = { score:-1, features:{}, breakdown:[] };
    const FALLBACK_DOMAIN = { score:-1, features:{}, breakdown:[] };
    const FALLBACK_API    = { score:-1, results:{}, hasKeys:false };
    const FALLBACK_REDIR  = { score:-1, chain:[], hopCount:0, breakdown:[] };
    const FALLBACK_NET    = { score:-1, features:{}, breakdown:[] };
    const FALLBACK_FEED   = { score:-1, isKnownThreat:false, sources:[] };
    const FALLBACK_ML     = { mlScore:-1, correlationsTriggered:[], confidence:"very_low" };

    const [urlResult, domainResult, apiResult, redirectResult] = await Promise.all([
      // Layer 1: URL — instant, no timeout needed
      Promise.resolve(URLAnalyzer.analyze(url)),

      // Layer 2: Domain Intel — 5s max (RDAP + DNS + SSL)
      withTimeout(DomainIntel.analyze(url), 5000, FALLBACK_DOMAIN),

      // Layer 4: APIs — 4s max
      prefs.enableApiChecks
        ? withTimeout(ApiChecker.check(url), 4000, FALLBACK_API)
        : Promise.resolve(FALLBACK_API),

      // Layer 6: Redirect chain — 7s max (3 hops × 2s + buffer)
      // Phishing URLs often don't respond — this is the most common hang
      withTimeout(RedirectChecker.analyze(url), 7000, FALLBACK_REDIR),
    ]);

    // Layer 5: Threat Feeds — instant Set lookup (already in memory)
    const feedResult = withTimeout(
      Promise.resolve(ThreatFeeds.check(url)), 100, FALLBACK_FEED
    );

    // Layer 7: Network monitor — instant (already collected)
    const networkResult = NetworkMonitor.analyze(tabId, hostname);

    // DOM results from content script (may have arrived already)
    const domResult = prefs.enableDomAnalysis
      ? (domResults[tabId] || { score:-1, features:{}, breakdown:[] })
      : { score:-1, features:{}, breakdown:[] };

    // Hard overrides — check before ML scoring
    const feedRes = await feedResult;

    if (apiResult?.results?.googleSafeBrowsing?.isPhishing) {
      clearTimeout(scanTimeout);
      const r = Scorer.buildHardOverride(100, "Google Safe Browsing confirmed phishing", {});
      r.url = url; r.timestamp = Date.now();
      r.layers = { url:urlResult, domain:domainResult, api:apiResult, feeds:feedRes };
      tabResults[tabId] = r;
      updateBadge(tabId, "PHISHING");
      await afterScan(url, r, tabId, prefs);
      return;
    }

    if (feedRes?.isKnownThreat) {
      clearTimeout(scanTimeout);
      const r = Scorer.buildHardOverride(100, `Known threat: ${feedRes.sources?.join(", ")}`, {});
      r.url = url; r.timestamp = Date.now();
      r.layers = { url:urlResult, feeds:feedRes };
      tabResults[tabId] = r;
      updateBadge(tabId, "PHISHING");
      await afterScan(url, r, tabId, prefs);
      return;
    }

    // Build ML features
    const featureMap = MLScorer.buildFeatureMap(urlResult, domResult, domainResult, redirectResult);
    const mlResult   = MLScorer.calculateMLScore(featureMap);

    // Combine all layers
    const finalResult = Scorer.combineV2(
      urlResult, domResult, domainResult, apiResult,
      feedRes, redirectResult, networkResult, mlResult, trust
    );
    finalResult.url       = url;
    finalResult.timestamp = Date.now();
    finalResult.layers    = {
      url:urlResult, dom:domResult, domain:domainResult,
      api:apiResult, feeds:feedRes, redirect:redirectResult,
      network:networkResult, ml:mlResult
    };

    clearTimeout(scanTimeout);
    tabResults[tabId] = finalResult;
    await afterScan(url, finalResult, tabId, prefs);

  } catch(e) {
    clearTimeout(scanTimeout);
    console.error("[PhishGuard] Scan error:", e);
    // Even on error — show URL-only result, never stay on SCANNING
    const urlOnly = URLAnalyzer.analyze(url);
    const fallback = Scorer.combineV2(
      urlOnly, null, null, null, null, null, null, null,
      getDomainTrust(new URL(url).hostname)
    );
    fallback.url = url; fallback.timestamp = Date.now(); fallback.error = e.message;
    tabResults[tabId] = fallback;
    updateBadge(tabId, fallback.verdict);
    Storage.setCache(url, fallback);
  }
}

async function afterScan(url, result, tabId, prefs) {
  updateBadge(tabId, result.verdict);
  Storage.setCache(url, result).catch(()=>{});
  Storage.addToHistory({ url, score: result.score, verdict: result.verdict }).catch(()=>{});

  try {
    const hostname = new URL(url).hostname;
    if (result.verdict === "PHISHING" && prefs.notifyPhishing) {
      browser.notifications.create({
        type:"basic", iconUrl: browser.runtime.getURL("icons/icon96.png"),
        title:"⚠️ PhishGuard: Phishing Detected!",
        message:`"${hostname}" — Risk Score: ${result.score}/100`
      });
    }
    if (result.verdict === "PHISHING" && prefs.blockPhishing) {
      browser.tabs.update(tabId, {
        url: browser.runtime.getURL(`popup/warning.html?url=${encodeURIComponent(url)}&score=${result.score}`)
      });
    }
  } catch(e) {}
}

function updateBadge(tabId, verdict) {
  const s = Scorer.getBadgeStyle(verdict);
  try {
    browser.browserAction.setBadgeText({ text:s.text, tabId });
    browser.browserAction.setBadgeBackgroundColor({ color:s.color, tabId });
  } catch(e) {}
}

// ── Message Listener ─────────────────────────────────────────
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === "GET_RESULT") {
    sendResponse(tabResults[message.tabId] || null);
    return true;
  }

  if (message.type === "RESCAN") {
    delete tabResults[message.tabId];
    delete domResults[message.tabId];
    NetworkMonitor.resetTab(message.tabId);
    scanUrl(message.url, message.tabId).then(() => {
      sendResponse(tabResults[message.tabId]);
    }).catch(() => sendResponse(null));
    return true;
  }

  if (message.type === "DOM_RESULT") {
    const tabId = sender.tab?.id;
    if (tabId) {
      domResults[tabId] = message.data;
      // Re-score with new DOM data
      const ex = tabResults[tabId];
      if (ex && ex.verdict !== "SCANNING" && ex.url) {
        try {
          const trust = getDomainTrust(new URL(ex.url).hostname);
          const fm    = MLScorer.buildFeatureMap(ex.layers?.url, message.data, ex.layers?.domain, ex.layers?.redirect);
          const ml    = MLScorer.calculateMLScore(fm);
          const upd   = Scorer.combineV2(
            ex.layers?.url, message.data, ex.layers?.domain, ex.layers?.api,
            ex.layers?.feeds, ex.layers?.redirect, ex.layers?.network, ml, trust
          );
          upd.url = ex.url; upd.timestamp = Date.now();
          upd.layers = { ...ex.layers, dom:message.data, ml };
          tabResults[tabId] = upd;
          updateBadge(tabId, upd.verdict);
          Storage.setCache(ex.url, upd).catch(()=>{});
        } catch(e) {}
      }
    }
    sendResponse({ ok:true });
    return true;
  }

  if (message.type === "WHITELIST_DOMAIN") {
    Storage.addToWhitelist(message.domain).then(() => {
      if (tabResults[message.tabId]) {
        tabResults[message.tabId].verdict = "SAFE";
        tabResults[message.tabId].score   = 0;
        updateBadge(message.tabId, "SAFE");
      }
      sendResponse({ ok:true });
    }).catch(() => sendResponse({ ok:false }));
    return true;
  }

  if (message.type === "GET_HISTORY") {
    Storage.getHistory().then(h => sendResponse(h)).catch(() => sendResponse([]));
    return true;
  }

  if (message.type === "GET_FEED_STATS") {
    sendResponse(ThreatFeeds.getStats());
    return true;
  }
});

browser.tabs.onRemoved.addListener((tabId) => {
  delete tabResults[tabId];
  delete domResults[tabId];
  NetworkMonitor.resetTab(tabId);
});
