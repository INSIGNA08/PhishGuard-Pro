// ============================================================
// utils/constants.js
// Central config for weights, thresholds, and API endpoints
// ============================================================

const PHISHGUARD = {

  // ── Risk Score Thresholds ──────────────────────────────────
  // Final score is 0-100. Higher = more dangerous.
  THRESHOLDS: {
    SAFE:       35,   // 0–35  → green (safe)
    SUSPICIOUS: 65,   // 36–65 → yellow (suspicious)
    PHISHING:   66    // 66+   → red (phishing)
  },

  // ── Module Weights ─────────────────────────────────────────
  // How much each analysis layer contributes to the final score.
  // Must sum to 1.0
  WEIGHTS: {
    URL_ANALYSIS:     0.25,  // Pure URL heuristics (fast, always runs)
    DOMAIN_INTEL:     0.20,  // WHOIS age, DNS, SSL checks
    DOM_ANALYSIS:     0.20,  // Page content, forms, scripts (from content script)
    API_SAFEBROWSE:   0.25,  // Google Safe Browsing API (most reliable)
    API_PHISHTANK:    0.10   // PhishTank community database
  },

  // ── API Endpoints ──────────────────────────────────────────
  // APIs used for reputation lookups.
  // - Google Safe Browsing: FREE, 10,000 req/day, very accurate
  // - PhishTank: FREE, community-driven phishing DB
  // - URLScan.io: FREE, 1000 req/day, full-page screenshot + analysis
  APIS: {
    GOOGLE_SAFE_BROWSING: "https://safebrowsing.googleapis.com/v4/threatMatches:find",
    PHISHTANK:            "https://checkurl.phishtank.com/checkurl/",
    URLSCAN_SUBMIT:       "https://urlscan.io/api/v1/scan/",
    URLSCAN_RESULT:       "https://urlscan.io/api/v1/result/",
    IPQUALITYSCORE:       "https://ipqualityscore.com/api/json/url/"
  },

  // ── URL Analysis Feature Weights ───────────────────────────
  // Each URL feature adds to a 0-100 URL risk score.
  // Based on: "Phishing Websites Features" dataset (UCI ML Repo)
  // and research paper: "An Efficient Approach for Detection of Phishing Websites"
  URL_FEATURES: {
    IP_AS_HOST:           20,  // Using IP instead of domain name
    LONG_URL:             10,  // URL > 75 chars is suspicious, > 100 is very suspicious
    URL_SHORTENER:        18,  // bit.ly, tinyurl etc used to hide real URL
    AT_SYMBOL:            12,  // @ in URL redirects browser to what's after @
    DOUBLE_SLASH_REDIRECT: 8,  // http://legit.com//evil.com
    HYPHEN_IN_DOMAIN:      8,  // paypal-login.com vs paypal.com
    EXCESSIVE_SUBDOMAINS:  8,  // a.b.c.evil.com
    NON_HTTPS:            12,  // HTTP (not HTTPS) – no encryption
    PORT_IN_URL:          10,  // http://paypal.com:8080
    HTTPS_IN_DOMAIN:       8,  // https-paypal.com (fake trust signal)
    PUNYCODE_IDN:         15,  // Unicode lookalike (аррlе.com vs apple.com)
    BRAND_TYPOSQUAT:      25,  // paypa1.com, gooogle.com
    PATH_KEYWORDS:        15,  // /login, /secure, /account, /update, /verify
    QUERY_PARAM_COUNT:     5,  // Excessive parameters
    TLD_SUSPICIOUS:       12,  // .tk, .ml, .ga, .cf, .gq are free/abused TLDs
    RANDOM_SUBDOMAIN:     10,  // 38fjd2.legit.com (random prefix)
    EXCESSIVE_DOTS:        8,  // Too many dots in URL
    HEX_ENCODED:          10   // %2F%41 encoding to hide intent
  },

  // ── DOM Analysis Feature Weights ───────────────────────────
  DOM_FEATURES: {
    PASSWORD_FIELD_ON_HTTP:   25,  // Collecting passwords without SSL
    EXTERNAL_FORM_ACTION:     20,  // Form submits data to different domain
    MULTIPLE_PASSWORD_FIELDS: 15,  // More than 1 password field
    IFRAME_HIDDEN:            12,  // Hidden iframes (clickjacking)
    FAVICON_EXTERNAL:         10,  // Favicon loaded from another domain
    META_REFRESH_REDIRECT:    15,  // Auto-redirect after X seconds
    DISABLE_RIGHT_CLICK:      10,  // JS blocking right-click (hiding source)
    POPUP_ON_LOAD:             8,  // Immediate popup window
    VERY_FEW_LINKS:           10,  // Phishing pages often have very few internal links
    BRAND_LOGO_BUT_NO_MATCH:  20,  // Has PayPal logo but URL isn't paypal.com
    OBFUSCATED_JS:            18,  // Base64 or heavily minified suspicious JS
    LOW_EXTERNAL_RESOURCES:   12,  // Pages with <3 external resources = possibly cloned
    OVERLY_URGENT_TEXT:       15,  // "Verify NOW", "Account suspended", "Click immediately"
    CREDIT_CARD_FORM:         20,  // Form asking for credit card on suspicious page
    SSN_KEYWORDS:             20,  // Keywords: social security, SSN, tax ID
  },

  // ── Shortener Domains ──────────────────────────────────────
  // These services hide the real destination URL
  SHORTENERS: [
    "bit.ly","tinyurl.com","goo.gl","ow.ly","t.co","is.gd","buff.ly",
    "adf.ly","bit.do","cutt.ly","shorturl.at","rb.gy","tiny.cc",
    "lnkd.in","snip.ly","clicky.me","budurl.com","bc.vc","s.id"
  ],

  // ── Phishing Path Keywords ──────────────────────────────────
  PHISHING_PATHS: [
    "login","signin","sign-in","logon","verify","verification",
    "secure","security","account","update","confirm","banking",
    "webscr","ebayisapi","paypal","authenticate","password","recover",
    "suspension","unlock","billing","invoice","credential"
  ],

  // ── Urgent Text Patterns ────────────────────────────────────
  URGENT_PATTERNS: [
    /verify.{0,20}(now|immediately|urgent)/i,
    /account.{0,20}(suspend|terminat|clos|block)/i,
    /click.{0,20}(immediately|now|here).{0,20}(or|to avoid)/i,
    /unusual.{0,20}(activit|sign.?in)/i,
    /(limited|expires?|24 hours?|48 hours?).{0,20}(action|time|left)/i,
    /your.{0,10}(password|account).{0,20}(expir|reset|compromis)/i,
    /confirm.{0,20}(identit|account|email|information)/i
  ]
};

// Make available globally in background scripts
if (typeof window !== "undefined") window.PHISHGUARD = PHISHGUARD;
