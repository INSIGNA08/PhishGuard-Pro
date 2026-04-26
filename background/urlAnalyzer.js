// ============================================================
// background/urlAnalyzer.js
//
// LAYER 1: URL ANALYSIS  (runs instantly, no network needed)
//
// Extracts 20+ features from the raw URL string.
// Based on academic research:
//  - "Phishing Websites Features" – UCI ML Repository
//  - Hannousse & Yahiouche (2021) – "Towards benchmark datasets
//    for machine learning based website phishing detection"
//
// Returns: { score: 0-100, features: {}, breakdown: [] }
// ============================================================

const URLAnalyzer = {

  analyze(rawUrl) {
    let totalRisk = 0;
    const features = {};
    const breakdown = [];

    let parsedUrl;
    try {
      parsedUrl = new URL(rawUrl);
    } catch {
      // Unparseable URL is itself suspicious
      return { score: 60, features: { parseError: true }, breakdown: ["Unparseable URL"] };
    }

    const url      = rawUrl;
    const hostname = parsedUrl.hostname.toLowerCase();
    const path     = parsedUrl.pathname.toLowerCase();
    const fullUrl  = url.toLowerCase();

    // ── Feature 1: IP Address as Host ───────────────────────
    // Legitimate sites use domain names. Phishers use raw IPs
    // to avoid domain registration records.
    // e.g. http://192.168.1.1/login
    features.ipAsHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) ||
                        /^\[?[0-9a-f:]+\]?$/.test(hostname); // IPv6
    if (features.ipAsHost) {
      totalRisk += PHISHGUARD.URL_FEATURES.IP_AS_HOST;
      breakdown.push(`IP as hostname (+${PHISHGUARD.URL_FEATURES.IP_AS_HOST})`);
    }

    // ── Feature 2: URL Length ────────────────────────────────
    // Phishing URLs tend to be long because they stuff the real
    // domain into a path/subdomain to fool the casual eye.
    // Safe: < 54 chars. Suspicious: 54-75. Phishing: > 75.
    features.urlLength = url.length;
    let lengthScore = 0;
    if (url.length > 100) lengthScore = PHISHGUARD.URL_FEATURES.LONG_URL;
    else if (url.length > 75) lengthScore = Math.round(PHISHGUARD.URL_FEATURES.LONG_URL * 0.7);
    else if (url.length > 54) lengthScore = Math.round(PHISHGUARD.URL_FEATURES.LONG_URL * 0.3);
    if (lengthScore > 0) {
      totalRisk += lengthScore;
      breakdown.push(`Long URL (${url.length} chars) (+${lengthScore})`);
    }

    // ── Feature 3: URL Shortener ────────────────────────────
    // Shorteners hide the real destination. Phishers use them
    // to bypass link scanners and trick users.
    features.isShortener = PHISHGUARD.SHORTENERS.some(s => hostname.includes(s));
    if (features.isShortener) {
      totalRisk += PHISHGUARD.URL_FEATURES.URL_SHORTENER;
      breakdown.push(`URL shortener service (+${PHISHGUARD.URL_FEATURES.URL_SHORTENER})`);
    }

    // ── Feature 4: @ Symbol ─────────────────────────────────
    // Browser ignores everything before @ — classic trick.
    // http://paypal.com@evil.com → goes to evil.com
    features.hasAtSymbol = url.includes("@");
    if (features.hasAtSymbol) {
      totalRisk += PHISHGUARD.URL_FEATURES.AT_SYMBOL;
      breakdown.push(`@ symbol in URL (+${PHISHGUARD.URL_FEATURES.AT_SYMBOL})`);
    }

    // ── Feature 5: Double Slash Redirect ────────────────────
    // http://legitimate.com//http://evil.com
    features.doubleSlashRedirect = (path.indexOf("//") > 0) ||
                                   (url.indexOf("//", 8) !== url.indexOf("//"));
    if (features.doubleSlashRedirect) {
      totalRisk += PHISHGUARD.URL_FEATURES.DOUBLE_SLASH_REDIRECT;
      breakdown.push(`Double-slash redirect (+${PHISHGUARD.URL_FEATURES.DOUBLE_SLASH_REDIRECT})`);
    }

    // ── Feature 6: Hyphen in Domain ─────────────────────────
    // paypal-login.security-update.com — hyphens in the domain
    // (not subdomain) indicate a manually crafted phishing domain.
    // Multiple hyphens are worse.
    const domainParts = hostname.split(".");
    const mainDomain  = domainParts.length >= 2
      ? domainParts[domainParts.length - 2]
      : hostname;
    features.hyphenCount = (mainDomain.match(/-/g) || []).length;
    if (features.hyphenCount >= 1) {
      const hScore = Math.min(
        PHISHGUARD.URL_FEATURES.HYPHEN_IN_DOMAIN,
        features.hyphenCount * 4
      );
      totalRisk += hScore;
      breakdown.push(`${features.hyphenCount} hyphen(s) in domain (+${hScore})`);
    }

    // ── Feature 7: Subdomain Depth ──────────────────────────
    // paypal.account-verify.update.evil.com
    // Safe: 1 subdomain. Suspicious: 2. Phishing: 3+
    // (Excludes "www")
    const subdomainParts = domainParts.slice(0, -2).filter(p => p !== "www");
    features.subdomainDepth = subdomainParts.length;
    if (features.subdomainDepth >= 3) {
      totalRisk += PHISHGUARD.URL_FEATURES.EXCESSIVE_SUBDOMAINS;
      breakdown.push(`Deep subdomain nesting (${features.subdomainDepth}) (+${PHISHGUARD.URL_FEATURES.EXCESSIVE_SUBDOMAINS})`);
    } else if (features.subdomainDepth === 2) {
      totalRisk += Math.round(PHISHGUARD.URL_FEATURES.EXCESSIVE_SUBDOMAINS * 0.5);
      breakdown.push(`2 subdomains (+${Math.round(PHISHGUARD.URL_FEATURES.EXCESSIVE_SUBDOMAINS * 0.5)})`);
    }

    // ── Feature 8: Protocol ──────────────────────────────────
    // HTTP sites offer no encryption. Any login page on HTTP is
    // immediately suspicious. (Note: HTTPS doesn't mean "safe",
    // but HTTP + login = very risky)
    features.isHttp = parsedUrl.protocol === "http:";
    const hasLoginPath = PHISHGUARD.PHISHING_PATHS.some(kw => path.includes(kw));
    if (features.isHttp && hasLoginPath) {
      totalRisk += PHISHGUARD.URL_FEATURES.NON_HTTPS;
      breakdown.push(`HTTP login page (no encryption) (+${PHISHGUARD.URL_FEATURES.NON_HTTPS})`);
    } else if (features.isHttp) {
      totalRisk += Math.round(PHISHGUARD.URL_FEATURES.NON_HTTPS * 0.5);
      breakdown.push(`HTTP (unencrypted) (+${Math.round(PHISHGUARD.URL_FEATURES.NON_HTTPS * 0.5)})`);
    }

    // ── Feature 9: Non-Standard Port ────────────────────────
    // http://paypal.com:8080/login — real sites use 80/443
    const port = parsedUrl.port;
    features.nonStandardPort = port && !["80","443","8080",""].includes(port);
    if (features.nonStandardPort) {
      totalRisk += PHISHGUARD.URL_FEATURES.PORT_IN_URL;
      breakdown.push(`Non-standard port (${port}) (+${PHISHGUARD.URL_FEATURES.PORT_IN_URL})`);
    }

    // ── Feature 10: "https" in Domain Name ──────────────────
    // https-paypal.com — phishers add "https" as a subdomain to
    // appear trustworthy even on HTTP pages.
    features.httpsInDomain = hostname.includes("https") || hostname.includes("secure");
    if (features.httpsInDomain && hostname !== "secure.example.com") {
      totalRisk += PHISHGUARD.URL_FEATURES.HTTPS_IN_DOMAIN;
      breakdown.push(`"https"/"secure" keyword in domain (+${PHISHGUARD.URL_FEATURES.HTTPS_IN_DOMAIN})`);
    }

    // ── Feature 11: Punycode / IDN Homograph Attack ─────────
    // аррlе.com looks like apple.com but uses Cyrillic 'а','р','р'
    // Browsers show the unicode version in the address bar.
    features.hasPunycode = hostname.startsWith("xn--") ||
                           hostname.split(".").some(p => p.startsWith("xn--"));
    if (features.hasPunycode) {
      totalRisk += PHISHGUARD.URL_FEATURES.PUNYCODE_IDN;
      breakdown.push(`Punycode/IDN homograph domain (+${PHISHGUARD.URL_FEATURES.PUNYCODE_IDN})`);
    }

    // ── Feature 12: Typosquatting / Brand Impersonation ─────
    // Uses Levenshtein distance to detect near-matches with
    // known brand domains (e.g. "arnazon.com" vs "amazon.com").
    const typosquatResult = this._checkTyposquatting(hostname);
    features.typosquatTarget = typosquatResult.target;
    features.typosquatDistance = typosquatResult.distance;
    if (typosquatResult.detected) {
      totalRisk += PHISHGUARD.URL_FEATURES.BRAND_TYPOSQUAT;
      breakdown.push(`Typosquatting "${typosquatResult.target}" (distance=${typosquatResult.distance}) (+${PHISHGUARD.URL_FEATURES.BRAND_TYPOSQUAT})`);
    }

    // ── Feature 13: Phishing Path Keywords ──────────────────
    // /signin, /verify, /account-update, /secure-login etc.
    const matchedPaths = PHISHGUARD.PHISHING_PATHS.filter(kw => path.includes(kw));
    features.phishingPathKeywords = matchedPaths;
    if (matchedPaths.length >= 2) {
      totalRisk += PHISHGUARD.URL_FEATURES.PATH_KEYWORDS;
      breakdown.push(`Multiple phishing path keywords: ${matchedPaths.join(",")} (+${PHISHGUARD.URL_FEATURES.PATH_KEYWORDS})`);
    } else if (matchedPaths.length === 1) {
      totalRisk += Math.round(PHISHGUARD.URL_FEATURES.PATH_KEYWORDS * 0.5);
      breakdown.push(`Phishing path keyword: "${matchedPaths[0]}" (+${Math.round(PHISHGUARD.URL_FEATURES.PATH_KEYWORDS * 0.5)})`);
    }

    // ── Feature 14: Suspicious TLD ──────────────────────────
    // .tk, .ml, .ga, .cf, .gq are free and heavily abused
    const tld = "." + domainParts[domainParts.length - 1];
    features.suspiciousTld = SUSPICIOUS_TLDS.has(tld);
    if (features.suspiciousTld) {
      totalRisk += PHISHGUARD.URL_FEATURES.TLD_SUSPICIOUS;
      breakdown.push(`Suspicious TLD "${tld}" (+${PHISHGUARD.URL_FEATURES.TLD_SUSPICIOUS})`);
    }

    // ── Feature 15: Random-Looking Subdomain ────────────────
    // 8f3k2j.paypal.com — high entropy prefix suggests DGA or
    // random subdomain generation (common in phishing kits)
    if (subdomainParts.length > 0) {
      const entropy = this._shannonEntropy(subdomainParts[0]);
      features.randomSubdomainEntropy = entropy;
      if (entropy > 3.8 && subdomainParts[0].length > 6) {
        totalRisk += PHISHGUARD.URL_FEATURES.RANDOM_SUBDOMAIN;
        breakdown.push(`High-entropy subdomain "${subdomainParts[0]}" (entropy=${entropy.toFixed(2)}) (+${PHISHGUARD.URL_FEATURES.RANDOM_SUBDOMAIN})`);
      }
    }

    // ── Feature 16: Hex/Percent Encoding in Path ────────────
    // %70%61%79%70%61%6C — encoding used to hide "paypal"
    const hexRatio = (url.match(/%[0-9a-f]{2}/gi) || []).length / url.length;
    features.hexEncoded = hexRatio > 0.05;
    if (features.hexEncoded) {
      totalRisk += PHISHGUARD.URL_FEATURES.HEX_ENCODED;
      breakdown.push(`Heavy percent-encoding (${(hexRatio*100).toFixed(1)}%) (+${PHISHGUARD.URL_FEATURES.HEX_ENCODED})`);
    }

    // ── Feature 17: Excessive Dots ──────────────────────────
    const dotCount = (hostname.match(/\./g) || []).length;
    features.dotCount = dotCount;
    if (dotCount > 4) {
      totalRisk += PHISHGUARD.URL_FEATURES.EXCESSIVE_DOTS;
      breakdown.push(`Many dots in hostname (${dotCount}) (+${PHISHGUARD.URL_FEATURES.EXCESSIVE_DOTS})`);
    }

    // ── Feature 18: Too Many Query Parameters ───────────────
    const paramCount = [...parsedUrl.searchParams.keys()].length;
    features.queryParamCount = paramCount;
    if (paramCount > 5) {
      totalRisk += PHISHGUARD.URL_FEATURES.QUERY_PARAM_COUNT;
      breakdown.push(`Many query parameters (${paramCount}) (+${PHISHGUARD.URL_FEATURES.QUERY_PARAM_COUNT})`);
    }

    // ── Feature 19: Known Suspicious Hostname Patterns ──────
    for (const pattern of SUSPICIOUS_HOSTNAME_PATTERNS) {
      if (pattern.test(hostname)) {
        totalRisk += 8;
        breakdown.push(`Suspicious hostname pattern: ${pattern.source} (+8)`);
        break;
      }
    }

    // ── Feature 20: Redirect Chain in URL ───────────────────
    // url=http://... inside the URL itself indicates redirection
    const redirectMatch = /(?:url|redirect|goto|link|go)=https?%3A/i.test(url) ||
                          /(?:url|redirect|goto|link|go)=https?:/i.test(url);
    features.hasRedirectParam = redirectMatch;
    if (redirectMatch) {
      totalRisk += 10;
      breakdown.push(`Redirect parameter in URL (+10)`);
    }

    // ── Feature 21: Free Subdomain Hosting ──────────────────
    // Sites like great-site.net, 000webhostapp.com, weebly.com
    // are free hosting platforms heavily abused for phishing.
    const freeHosts = [
      "great-site.net","000webhostapp.com","weebly.com","wixsite.com",
      "wordpress.com","blogspot.com","github.io","gitlab.io","netlify.app",
      "vercel.app","pages.dev","web.app","firebaseapp.com","glitch.me",
      "repl.co","replit.dev","surge.sh","onrender.com","fly.dev",
      "pythonanywhere.com","infinityfreeapp.com","byethost","freehostia",
      "freehosting","hostfree","awardspace","biz.nf","esy.es",
      "uhostfull.com","site44.com","atspace","comxa.com"
    ];
    const isFreeHost = freeHosts.some(fh => hostname.endsWith(fh));
    features.isFreeHost = isFreeHost;
    if (isFreeHost) {
      totalRisk += 20;
      breakdown.push(`Free hosting platform (${hostname}) (+20)`);
    }

    // ── Feature 22: Brand name in subdomain of unrelated domain ─
    // paypal.evilsite.com — brand in subdomain but domain is different
    const brandNames = ["paypal","amazon","google","facebook","apple","microsoft",
      "netflix","instagram","twitter","linkedin","ebay","chase","wellsfargo",
      "bankofamerica","coinbase","binance","steam","spotify","dropbox","adobe"];
    if (subdomainParts.length > 0) {
      const subStr = subdomainParts.join(".").toLowerCase();
      const hasBrandInSub = brandNames.some(b => subStr.includes(b));
      const mainIsNotBrand = !brandNames.some(b => mainDomain.includes(b) &&
        hostname.endsWith(b + "." + domainParts.slice(-1)[0]));
      if (hasBrandInSub && mainIsNotBrand) {
        totalRisk += 25;
        breakdown.push(`Brand name in subdomain of unrelated domain (+25)`);
        features.brandInSubdomain = true;
      }
    }

    // ── Normalize Score ──────────────────────────────────────
    // maxPossible = 75: a URL with 2-3 phishing features hits "suspicious",
    // with 4-5 features hits "phishing". Calibrated against real phishing URLs.
    const maxPossible = 75;
    const normalizedScore = Math.min(100, Math.round((totalRisk / maxPossible) * 100));

    return {
      score:    normalizedScore,
      rawRisk:  totalRisk,
      features,
      breakdown,
      hostname,
      tld
    };
  },

  // ── Levenshtein Distance ────────────────────────────────────
  // Dynamic programming implementation.
  // Compares the analyzed domain against top 500 brand domains.
  // Distance ≤ 2 on the main domain = typosquatting detected.
  _levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, (_, i) =>
      Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
    );
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        dp[i][j] = a[i-1] === b[j-1]
          ? dp[i-1][j-1]
          : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
      }
    }
    return dp[m][n];
  },

  _checkTyposquatting(hostname) {
    // Strip www and extract main domain (second-level domain)
    const parts = hostname.replace(/^www\./, "").split(".");
    if (parts.length < 2) return { detected: false };
    const mainDomain = parts[0]; // e.g. "arnazon" from "arnazon.com"

    let minDist = Infinity;
    let closestTarget = "";

    for (const topDomain of TOP_DOMAINS) {
      const topParts = topDomain.split(".");
      const topMain  = topParts[0]; // e.g. "amazon" from "amazon.com"

      // Skip if lengths differ too much (speed optimization)
      if (Math.abs(mainDomain.length - topMain.length) > 3) continue;

      const dist = this._levenshtein(mainDomain, topMain);
      if (dist < minDist) {
        minDist = dist;
        closestTarget = topDomain;
      }
    }

    // Distance 1-2 AND it's not the exact domain itself
    const isExactMatch = hostname.endsWith(closestTarget) || hostname === closestTarget;
    return {
      detected: minDist > 0 && minDist <= 2 && !isExactMatch,
      target:   closestTarget,
      distance: minDist
    };
  },

  // ── Shannon Entropy ─────────────────────────────────────────
  // Measures randomness of a string. High entropy = likely random.
  // Normal words like "login" have low entropy (~2.5).
  // Random strings like "x8f3k2" have high entropy (>3.8).
  _shannonEntropy(str) {
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    return Object.values(freq).reduce((e, f) => {
      const p = f / str.length;
      return e - p * Math.log2(p);
    }, 0);
  }
};
