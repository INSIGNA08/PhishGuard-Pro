// ============================================================
// background/threatFeeds.js
//
// NEW CONCEPT: Real-time Threat Intelligence Feeds
//
// Instead of only checking APIs per-URL (slow, uses quota),
// we download ENTIRE databases of known phishing URLs and
// cache them locally. Then checking a URL is instant (no API call).
//
// Feeds used (ALL FREE, NO KEY NEEDED):
//
//  1. URLhaus (abuse.ch) — https://urlhaus.abuse.ch/downloads/text/
//     Updated every 5 minutes. Contains malware + phishing URLs.
//     Format: plain text, one URL per line.
//
//  2. OpenPhish — https://openphish.com/feed.txt
//     Updated every 12 hours. Community phishing feed.
//     Format: plain text, one URL per line.
//
// How it works:
//  - On extension startup → download both feeds → cache in memory
//  - Every 30 minutes → refresh feeds in background
//  - When checking a URL → instant Set lookup (O(1) speed)
//
// WHY THIS IS SMART:
//  - 0ms lookup time (vs 300ms API call)
//  - Works offline (cached)
//  - No API quota used
//  - Covers thousands of threats not in Google Safe Browsing
// ============================================================

const ThreatFeeds = {

  // In-memory cache — Set allows O(1) lookup
  // (Array.includes() is O(n), Set.has() is O(1))
  _urlhausUrls:   new Set(),
  _openphishUrls: new Set(),
  _lastUpdated:   null,
  _isLoading:     false,

  REFRESH_INTERVAL: 30 * 60 * 1000, // Refresh every 30 minutes

  // ── Initialize on startup ────────────────────────────────
  async init() {
    await this._loadFeeds();
    // Schedule periodic refresh
    setInterval(() => this._loadFeeds(), this.REFRESH_INTERVAL);
  },

  // ── Download and parse both feeds ───────────────────────
  async _loadFeeds() {
    if (this._isLoading) return;
    this._isLoading = true;

    try {
      // Run both downloads in parallel
      const [urlhausText, openphishText] = await Promise.allSettled([
        this._fetchFeed("https://urlhaus.abuse.ch/downloads/text/"),
        this._fetchFeed("https://openphish.com/feed.txt")
      ]);

      // Parse URLhaus
      if (urlhausText.status === "fulfilled" && urlhausText.value) {
        this._urlhausUrls = new Set(
          urlhausText.value
            .split("\n")
            .map(l => l.trim().toLowerCase())
            .filter(l => l && !l.startsWith("#") && l.startsWith("http"))
        );
      }

      // Parse OpenPhish
      if (openphishText.status === "fulfilled" && openphishText.value) {
        this._openphishUrls = new Set(
          openphishText.value
            .split("\n")
            .map(l => l.trim().toLowerCase())
            .filter(l => l && l.startsWith("http"))
        );
      }

      this._lastUpdated = Date.now();
      console.log(`[PhishGuard Feeds] Loaded: URLhaus=${this._urlhausUrls.size}, OpenPhish=${this._openphishUrls.size}`);
    } catch (e) {
      console.warn("[PhishGuard Feeds] Load failed:", e.message);
    } finally {
      this._isLoading = false;
    }
  },

  async _fetchFeed(url) {
    // 8 second timeout for feed downloads
    // If URLhaus or OpenPhish is slow, don't block the extension
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const resp = await fetch(url, {
        cache: "no-store",
        signal: controller.signal
      });
      clearTimeout(timer);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      return resp.text();
    } catch(e) {
      clearTimeout(timer);
      throw e;
    }
  },

  // ── Check a URL against all feeds ───────────────────────
  // Returns { score: 0-100, sources: [], isKnownThreat: bool }
  check(url) {
    const normalizedUrl = url.toLowerCase().trim();
    const sources = [];
    let score = 0;

    // Exact match first (fastest)
    if (this._urlhausUrls.has(normalizedUrl)) {
      sources.push("URLhaus (abuse.ch)");
      score = 100;
    }
    if (this._openphishUrls.has(normalizedUrl)) {
      sources.push("OpenPhish");
      score = 100;
    }

    // If no exact match, try prefix matching
    // (catches http://evil.com/phish even if feed has http://evil.com)
    if (score === 0) {
      score = this._prefixCheck(normalizedUrl, sources);
    }

    return {
      score,
      sources,
      isKnownThreat: score >= 80,
      feedSizes: {
        urlhaus:   this._urlhausUrls.size,
        openphish: this._openphishUrls.size
      },
      lastUpdated: this._lastUpdated
    };
  },

  // Prefix matching: check if URL starts with any known threat domain
  _prefixCheck(url, sources) {
    // Extract just the domain for prefix matching
    let domain = "";
    try {
      domain = new URL(url).hostname.toLowerCase();
    } catch { return 0; }

    // Check if any feed entry starts with this domain
    for (const feedUrl of this._urlhausUrls) {
      try {
        if (new URL(feedUrl).hostname === domain) {
          sources.push("URLhaus (domain match)");
          return 85; // High but not 100 (partial match)
        }
      } catch {}
    }

    for (const feedUrl of this._openphishUrls) {
      try {
        if (new URL(feedUrl).hostname === domain) {
          sources.push("OpenPhish (domain match)");
          return 85;
        }
      } catch {}
    }

    return 0;
  },

  // Stats for popup display
  getStats() {
    return {
      urlhausCount:   this._urlhausUrls.size,
      openphishCount: this._openphishUrls.size,
      totalUrls:      this._urlhausUrls.size + this._openphishUrls.size,
      lastUpdated:    this._lastUpdated,
      isLoaded:       this._urlhausUrls.size > 0
    };
  }
};
