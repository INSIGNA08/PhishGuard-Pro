// ============================================================
// utils/storage.js
// Handles all browser.storage operations for:
//  - API Keys (user-supplied)
//  - Scan history (last 100 URLs)
//  - Cache (avoid re-scanning same URL within 10 min)
//  - User preferences
// ============================================================

const Storage = {

  // ── API Keys ───────────────────────────────────────────────
  // Users enter their own free API keys in the settings popup.
  // Keys are stored locally in browser.storage.local (encrypted at rest by browser).

  async getApiKeys() {
    const result = await browser.storage.local.get("apiKeys");
    const saved  = result.apiKeys || {};
    return {
      googleSafeBrowsing: saved.googleSafeBrowsing || "YOUR_GOOGLE_SAFE_BROWSING_KEY_HERE",
      phishTank:          saved.phishTank          || "",//Leave this
      urlScanIo:          saved.urlScanIo          || "",//Leave this
      ipQualityScore:     saved.ipQualityScore     || ""//Leave this
    };
  },

  async saveApiKeys(keys) {
    await browser.storage.local.set({ apiKeys: keys });
  },

  // ── Cache ──────────────────────────────────────────────────
  // Cache scan results for 10 minutes to avoid hammering APIs
  // and to give instant results for recently visited pages.
  CACHE_TTL: 10 * 60 * 1000, // 10 minutes in milliseconds

  async getCached(url) {
    const normalizedUrl = this._normalizeUrl(url);
    const key = "cache_" + btoa(normalizedUrl).substring(0, 40);
    const result = await browser.storage.local.get(key);
    if (!result[key]) return null;
    const cached = result[key];
    if (Date.now() - cached.timestamp > this.CACHE_TTL) {
      await browser.storage.local.remove(key);
      return null;
    }
    return cached.data;
  },

  async setCache(url, data) {
    const normalizedUrl = this._normalizeUrl(url);
    const key = "cache_" + btoa(normalizedUrl).substring(0, 40);
    await browser.storage.local.set({
      [key]: { data, timestamp: Date.now() }
    });
  },

  // ── History ─────────────────────────────────────────────────
  // Keep last 100 scans with results for the History tab in popup.

  async addToHistory(entry) {
    const result = await browser.storage.local.get("history");
    let history = result.history || [];
    history.unshift({
      url:       entry.url,
      score:     entry.score,
      verdict:   entry.verdict,
      timestamp: Date.now(),
      favicon:   entry.favicon || ""
    });
    if (history.length > 100) history = history.slice(0, 100);
    await browser.storage.local.set({ history });
  },

  async getHistory() {
    const result = await browser.storage.local.get("history");
    return result.history || [];
  },

  async clearHistory() {
    await browser.storage.local.remove("history");
  },

  // ── Whitelist (user-approved sites) ────────────────────────
  async getWhitelist() {
    const result = await browser.storage.local.get("whitelist");
    return result.whitelist || [];
  },

  async addToWhitelist(domain) {
    const list = await this.getWhitelist();
    if (!list.includes(domain)) {
      list.push(domain);
      await browser.storage.local.set({ whitelist: list });
    }
  },

  async isWhitelisted(domain) {
    const list = await this.getWhitelist();
    return list.includes(domain);
  },

  // ── Preferences ─────────────────────────────────────────────
  async getPrefs() {
    const result = await browser.storage.local.get("prefs");
    return result.prefs || {
      showBadge:          true,  // Show colored badge on extension icon
      notifyPhishing:     true,  // Show browser notification for phishing
      blockPhishing:      false, // Auto-block phishing pages (replace with warning)
      enableDomAnalysis:  true,  // Enable content script DOM scanning
      enableApiChecks:    true   // Enable external API calls
    };
  },

  async savePrefs(prefs) {
    await browser.storage.local.set({ prefs });
  },

  // ── Internal ────────────────────────────────────────────────
  _normalizeUrl(url) {
    try {
      const u = new URL(url);
      return u.hostname + u.pathname; // ignore params for caching
    } catch {
      return url;
    }
  }
};
