// ============================================================
// background/networkMonitor.js
//
// NEW CONCEPT: Network Request Analysis
//
// Uses browser's webRequest API to monitor EVERY network request
// made by a page — images, scripts, fonts, API calls, etc.
//
// What we detect:
//  1. Crypto miners — CoinHive, Coinhive alternatives, browser mining scripts
//  2. Keyloggers — scripts from known data-theft domains
//  3. Exfiltration — page sending data to suspicious 3rd party domains
//  4. Malicious CDN patterns — scripts loaded from unusual locations
//  5. Known bad domains in any request
//  6. Excessive tracker loading (privacy + phishing signal)
//
// HOW webRequest WORKS:
//  browser.webRequest.onBeforeRequest → fires BEFORE each request is sent
//  browser.webRequest.onCompleted     → fires AFTER each request completes
//  We collect all requests per tab and analyze patterns.
//
// The data is stored per-tabId and analyzed when the scan runs.
// ============================================================

const NetworkMonitor = {

  // Store requests per tab: tabId → [requestInfo, ...]
  _tabRequests: {},

  // Known malicious/suspicious domains in network requests
  CRYPTO_MINER_PATTERNS: [
    "coinhive.com", "coin-hive.com", "cryptonight.js",
    "webmr.js", "wsm.min.js", "minero.cc",
    "crypto-loot.com", "coinblind.com", "monerominer",
    "deepminer", "jsecoin.com", "authedmine.com",
    "coinhive.min.js", "crypta.js", "ppoi.org"
  ],

  KEYLOGGER_PATTERNS: [
    "logkey", "keylog", "keystroke", "keytrack",
    "formgrabber", "formgrab", "webformspy"
  ],

  KNOWN_MALICIOUS_CDNS: [
    "malware-traffic-analysis.net",
    "openstat.ru", "counter.yadro.ru",
    "hotlog.ru", "r.i.ua"
  ],

  // ── Initialize webRequest monitoring ────────────────────
  init() {
    // Listen to ALL requests across ALL tabs
    browser.webRequest.onBeforeRequest.addListener(
      (details) => this._onRequest(details),
      { urls: ["<all_urls>"] },
      []
    );

    // Clean up when tab is closed
    browser.tabs.onRemoved.addListener((tabId) => {
      delete this._tabRequests[tabId];
    });

    // Clean up old data periodically
    setInterval(() => this._cleanup(), 5 * 60 * 1000);
  },

  // ── Record each request ──────────────────────────────────
  _onRequest(details) {
    const tabId = details.tabId;
    if (tabId < 0) return; // Background requests, ignore

    if (!this._tabRequests[tabId]) {
      this._tabRequests[tabId] = {
        requests: [],
        startTime: Date.now()
      };
    }

    this._tabRequests[tabId].requests.push({
      url:  details.url,
      type: details.type,  // "script", "image", "xmlhttprequest", etc.
      time: Date.now()
    });

    // Keep only last 200 requests per tab (memory management)
    if (this._tabRequests[tabId].requests.length > 200) {
      this._tabRequests[tabId].requests.shift();
    }
  },

  // ── Analyze requests for a specific tab ─────────────────
  analyze(tabId, mainDomain) {
    const data = this._tabRequests[tabId];
    if (!data || data.requests.length === 0) {
      return { score: -1, breakdown: [], features: {} };
    }

    let totalRisk = 0;
    const breakdown = [];
    const features  = {};
    const requests  = data.requests;

    // ── Check 1: Crypto Miners ───────────────────────────
    const minerRequests = requests.filter(r =>
      this.CRYPTO_MINER_PATTERNS.some(p =>
        r.url.toLowerCase().includes(p)
      )
    );
    features.cryptoMinerCount = minerRequests.length;
    if (minerRequests.length > 0) {
      totalRisk += 60;
      breakdown.push(`Crypto mining script detected: ${minerRequests[0].url.substring(0, 60)} (+60)`);
    }

    // ── Check 2: Keylogger Patterns ──────────────────────
    const keylogRequests = requests.filter(r =>
      r.type === "script" &&
      this.KEYLOGGER_PATTERNS.some(p =>
        r.url.toLowerCase().includes(p)
      )
    );
    features.keyloggerCount = keylogRequests.length;
    if (keylogRequests.length > 0) {
      totalRisk += 70;
      breakdown.push(`Possible keylogger script: ${keylogRequests[0].url.substring(0, 60)} (+70)`);
    }

    // ── Check 3: Data Exfiltration ───────────────────────
    // XHR/fetch requests to a different domain while on a page
    // Legitimate sites do this, but phishing pages do it suspiciously
    const xhrRequests = requests.filter(r =>
      r.type === "xmlhttprequest" || r.type === "fetch"
    );
    const externalXhr = xhrRequests.filter(r => {
      try {
        return new URL(r.url).hostname !== mainDomain;
      } catch { return false; }
    });
    features.externalXhrCount = externalXhr.length;
    if (externalXhr.length > 5) {
      totalRisk += 20;
      breakdown.push(`${externalXhr.length} external XHR/fetch requests (possible data exfiltration) (+20)`);
    }

    // ── Check 4: Scripts from Known Malicious CDNs ───────
    const maliciousCdnReqs = requests.filter(r =>
      r.type === "script" &&
      this.KNOWN_MALICIOUS_CDNS.some(d => r.url.includes(d))
    );
    if (maliciousCdnReqs.length > 0) {
      totalRisk += 40;
      breakdown.push(`Script from known malicious CDN (+40)`);
    }

    // ── Check 5: Excessive External Scripts ──────────────
    // Legitimate pages load scripts from a few trusted CDNs.
    // Phishing kits often load from many random domains.
    const externalScripts = requests.filter(r => {
      if (r.type !== "script") return false;
      try {
        const host = new URL(r.url).hostname;
        return host !== mainDomain &&
               !["ajax.googleapis.com","cdnjs.cloudflare.com",
                 "code.jquery.com","cdn.jsdelivr.net",
                 "stackpath.bootstrapcdn.com","fonts.googleapis.com"].some(safe =>
                   host.endsWith(safe)
                 );
      } catch { return false; }
    });
    features.suspiciousScriptCount = externalScripts.length;
    if (externalScripts.length > 8) {
      totalRisk += 15;
      breakdown.push(`${externalScripts.length} scripts from external unknown domains (+15)`);
    }

    // ── Check 6: No Resources Loaded (cloned static page) ─
    // A phishing page cloned from a screenshot has almost no resources.
    // A real login page loads CSS, fonts, scripts, images.
    const resourceTypes = new Set(requests.map(r => r.type));
    features.resourceTypeCount = resourceTypes.size;
    if (requests.length < 5 && data.startTime &&
        Date.now() - data.startTime > 3000) {
      totalRisk += 15;
      breakdown.push(`Very few network resources loaded (possible static clone) (+15)`);
    }

    const score = Math.min(100, Math.round((totalRisk / 150) * 100));
    return { score, breakdown, features };
  },

  // ── Reset data for a tab (new navigation) ────────────────
  resetTab(tabId) {
    delete this._tabRequests[tabId];
  },

  // ── Periodic cleanup (tabs not updated in 30 min) ────────
  _cleanup() {
    const cutoff = Date.now() - 30 * 60 * 1000;
    for (const [tabId, data] of Object.entries(this._tabRequests)) {
      if (data.startTime < cutoff) {
        delete this._tabRequests[tabId];
      }
    }
  }
};
