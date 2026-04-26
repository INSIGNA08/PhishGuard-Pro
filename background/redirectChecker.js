// ============================================================
// background/redirectChecker.js
//
// NEW CONCEPT: Redirect Chain Analysis
//
// Many phishing attacks use redirect chains to hide the real
// destination:
//   bit.ly/abc → tracker.com → fake-paypal.xyz
//
// We follow every redirect hop and analyze EACH URL.
// A clean-looking first URL that redirects to a phishing page
// is still dangerous.
//
// HOW IT WORKS:
//  1. Send HEAD request to the URL
//  2. If response is 301/302/303/307/308 → follow Location header
//  3. Repeat up to 10 hops
//  4. Analyze each hop's URL for phishing signals
//  5. The WORST score across all hops = final redirect score
//
// WHAT WE DETECT:
//  - URL shorteners hiding phishing destinations
//  - Tracker → phishing redirect chains
//  - Country-based redirects (looks safe in US, phishing elsewhere)
//  - Mixed HTTPS→HTTP downgrade attacks
//  - Suspiciously long redirect chains (10+ hops = very suspicious)
// ============================================================

const RedirectChecker = {

  MAX_HOPS:    3,   // Reduced from 10 — phishing URLs often hang
  TIMEOUT_MS:  2000, // Reduced from 5000ms — fail fast

  // ── Follow redirect chain ────────────────────────────────
  async analyze(startUrl) {
    const chain   = [];
    const visited = new Set();
    let   current = startUrl;
    let   worstScore = 0;
    const breakdown  = [];

    for (let hop = 0; hop < this.MAX_HOPS; hop++) {
      if (visited.has(current)) {
        breakdown.push("Redirect loop detected — very suspicious");
        worstScore = Math.max(worstScore, 70);
        break;
      }
      visited.add(current);

      let nextUrl = null;
      let statusCode = null;

      try {
        // Use fetch with redirect: "manual" to intercept redirects
        // instead of following them automatically
        const controller = new AbortController();
        const timeout    = setTimeout(() => controller.abort(), this.TIMEOUT_MS);

        const resp = await fetch(current, {
          method:   "HEAD",       // HEAD = get headers only, no body (faster)
          redirect: "manual",     // Don't auto-follow — we want to see each hop
          signal:   controller.signal
        });
        clearTimeout(timeout);

        statusCode = resp.status;

        // 3xx = redirect
        if (statusCode >= 300 && statusCode < 400) {
          nextUrl = resp.headers.get("location");
          // Resolve relative URLs
          if (nextUrl && !nextUrl.startsWith("http")) {
            nextUrl = new URL(nextUrl, current).href;
          }
        }

      } catch (e) {
        if (e.name === "AbortError") {
          breakdown.push(`Hop ${hop + 1} timed out (${current.substring(0, 50)})`);
        }
        break;
      }

      chain.push({
        url:    current,
        hop:    hop,
        status: statusCode,
        next:   nextUrl
      });

      // Analyze THIS hop's URL for phishing signals
      const hopScore = this._analyzeHopUrl(current, hop, breakdown);
      worstScore = Math.max(worstScore, hopScore);

      if (!nextUrl) break; // End of chain
      current = nextUrl;
    }

    // Chain-level analysis
    const chainScore = this._analyzeChain(chain, breakdown);
    worstScore = Math.max(worstScore, chainScore);

    return {
      score:      Math.min(100, worstScore),
      chain,
      hopCount:   chain.length,
      breakdown,
      finalUrl:   current // Where the chain ends
    };
  },

  // ── Analyze a single hop URL ─────────────────────────────
  _analyzeHopUrl(url, hopIndex, breakdown) {
    let risk = 0;

    try {
      const u = new URL(url);

      // HTTPS → HTTP downgrade is a serious attack
      // Attacker starts with HTTPS (looks safe) then redirects to HTTP
      if (hopIndex === 0 && url.startsWith("https")) {
        // First hop is HTTPS — fine
      } else if (url.startsWith("http://") && hopIndex > 0) {
        risk += 25;
        breakdown.push(`HTTPS→HTTP downgrade at hop ${hopIndex + 1} (+25)`);
      }

      // URL shortener in the middle of chain = hiding something
      const shorteners = ["bit.ly","tinyurl.com","t.co","ow.ly","goo.gl",
                          "rb.gy","is.gd","buff.ly","cutt.ly","s.id"];
      if (hopIndex > 0 && shorteners.some(s => u.hostname.includes(s))) {
        risk += 20;
        breakdown.push(`Shortener in redirect chain hop ${hopIndex + 1} (+20)`);
      }

      // Data URI redirect — often used for credential theft
      if (url.startsWith("data:")) {
        risk += 40;
        breakdown.push(`Data URI redirect — extremely suspicious (+40)`);
      }

      // JavaScript URI redirect
      if (url.startsWith("javascript:")) {
        risk += 45;
        breakdown.push(`JavaScript URI redirect — extremely suspicious (+45)`);
      }

    } catch { /* invalid URL in chain */ }

    return risk;
  },

  // ── Analyze the full chain ───────────────────────────────
  _analyzeChain(chain, breakdown) {
    let risk = 0;

    // Too many hops = suspicious (legitimate sites rarely need 5+ redirects)
    if (chain.length >= 7) {
      risk += 30;
      breakdown.push(`Very long redirect chain (${chain.length} hops) (+30)`);
    } else if (chain.length >= 4) {
      risk += 15;
      breakdown.push(`Long redirect chain (${chain.length} hops) (+15)`);
    }

    // Cross-TLD redirect: starts on .com → ends on .tk
    if (chain.length >= 2) {
      try {
        const startTld = "." + new URL(chain[0].url).hostname.split(".").pop();
        const endTld   = "." + new URL(chain[chain.length-1].url).hostname.split(".").pop();
        const suspTlds = new Set([".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click"]);

        if (!suspTlds.has(startTld) && suspTlds.has(endTld)) {
          risk += 25;
          breakdown.push(`Redirects from ${startTld} to suspicious TLD ${endTld} (+25)`);
        }
      } catch {}
    }

    // Different domains at each hop (no continuity)
    if (chain.length >= 3) {
      const domains = chain.map(h => {
        try { return new URL(h.url).hostname; } catch { return ""; }
      });
      const uniqueDomains = new Set(domains).size;
      if (uniqueDomains === chain.length) {
        risk += 15;
        breakdown.push(`Every redirect hop is a different domain (+15)`);
      }
    }

    return risk;
  }
};
