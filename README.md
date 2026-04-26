# 🛡️ PhishGuard Pro — Firefox Extension

**A multi-layer phishing website detector with high accuracy.**

---

## ⚡ Quick Setup After Downloading

1. Copy `utils/storage.template.js` → rename to `utils/storage.js`
2. Open `utils/storage.js` → replace `YOUR_GOOGLE_SAFE_BROWSING_KEY_HERE` with your free API key
   - Get key at: console.cloud.google.com → Enable Safe Browsing API → Credentials
3. Open Firefox → go to `about:debugging` → This Firefox → Load Temporary Add-on
4. Select `manifest.json` from the PhishGuard folder
5. Done ✅

---

## 🧠 Architecture Overview

PhishGuard uses **4 independent analysis layers** that run in parallel and combine into a single risk score (0–100).

```
URL → [Layer 1: URL Heuristics] ──┐
      [Layer 2: Domain Intel   ] ──┤──→ Scorer ──→ Verdict
      [Layer 3: DOM Analysis   ] ──┤    (weighted   (Safe / Suspicious / Phishing)
      [Layer 4: API Reputation ] ──┘     average)
```

### Layer 1 — URL Analysis (`background/urlAnalyzer.js`)
**What it uses:** Pure JavaScript, no network calls. Runs instantly.

Extracts **20+ features** from the raw URL string:
| Feature | Why it matters |
|---|---|
| IP as hostname | `http://192.168.1.1/login` — avoids domain registration |
| URL length > 75 chars | Phishers pad URLs to hide the real domain |
| URL shorteners | bit.ly hides the real destination |
| `@` symbol | `http://paypal.com@evil.com` → goes to evil.com |
| Hyphen in domain | `paypal-login.com` vs `paypal.com` |
| Punycode/IDN | `аррlе.com` (Cyrillic) looks like `apple.com` |
| Typosquatting | Levenshtein distance ≤ 2 from top 500 brands |
| Suspicious TLD | `.tk`, `.ml`, `.ga`, `.cf`, `.gq` (free/abused) |
| High-entropy subdomain | `8f3k2j.paypal.com` (random prefix) |
| Path keywords | `/login`, `/verify`, `/secure`, `/account-update` |

**Algorithm:** Levenshtein distance (dynamic programming) for typosquatting detection.

---

### Layer 2 — Domain Intelligence (`background/domainIntel.js`)
**What it uses:**
- **RDAP** (rdap.org) — Free RFC-standard WHOIS replacement. No API key needed.
- **Cloudflare DoH** (cloudflare-dns.com) — Free DNS-over-HTTPS.
- **crt.sh** — Free certificate transparency log.

Checks:
| Check | Signal |
|---|---|
| Domain age (RDAP) | Domains < 30 days old are extremely suspicious |
| DNS A records (Cloudflare DoH) | No DNS = domain doesn't resolve |
| SSL certificate (crt.sh) | Cert issued today = burner domain |
| SSL issuer | Let's Encrypt is fine, but combined with new domain = suspicious |
| Free hosting provider | 000webhost, weebly, etc. = common phishing hosts |

---

### Layer 3 — DOM Analysis (`content/contentScript.js`)
**What it uses:** Browser's built-in DOM API. Injected into every page.

Checks the actual page content:
| Check | Why |
|---|---|
| Password field on HTTP | Credentials sent unencrypted |
| External form action | Form submits to a different domain |
| Hidden iframes | Clickjacking |
| Brand logo on wrong domain | PayPal logo on `fake-paypal.xyz` |
| Urgency language | "Verify NOW or your account closes in 24h" |
| Obfuscated JavaScript | `eval(atob(...))` = hidden malicious code |
| Credit card / SSN fields | Sensitive data collection |
| Right-click disabled | Hiding source code from users |
| Very few internal links | Cloned page without proper navigation |

---

### Layer 4 — API Reputation (`background/apiChecker.js`)
**What it uses:** External threat intelligence APIs (user-supplied free API keys).

| API | Cost | Requests/day | Accuracy |
|---|---|---|---|
| **Google Safe Browsing v4** | Free | 10,000 | ⭐⭐⭐⭐⭐ Best |
| **PhishTank** | Free | Unlimited | ⭐⭐⭐⭐ Community-verified |
| **URLScan.io** | Free | 1,000 | ⭐⭐⭐⭐ Full sandbox scan |
| **IPQualityScore** | Free tier | 5,000 | ⭐⭐⭐⭐ Reputation + domain age |

All 4 APIs run **in parallel** to minimize total scan time.

---

### Scorer (`background/scorer.js`)
Combines all layers using **weighted average**:

| Layer | Weight |
|---|---|
| URL Analysis | 25% |
| Domain Intelligence | 20% |
| DOM Analysis | 20% |
| Google Safe Browsing | 25% |
| PhishTank | 10% |

**Hard overrides:**
- Google Safe Browsing says phishing → Score = **100** instantly
- PhishTank verified → Score = **95** instantly

**Score thresholds:**
- 0–35 = ✅ Safe (green)
- 36–65 = ⚠️ Suspicious (yellow)
- 66–100 = 🚨 Phishing (red)

---

## 📁 File Structure

```
PhishGuard/
├── manifest.json            # Firefox MV2 extension manifest
├── background/
│   ├── background.js        # Main orchestrator, tab listener, message hub
│   ├── urlAnalyzer.js       # Layer 1: URL heuristics (20+ features)
│   ├── domainIntel.js       # Layer 2: RDAP, DNS, SSL checks
│   ├── apiChecker.js        # Layer 4: Google Safe Browsing, PhishTank, etc.
│   └── scorer.js            # Combines all layers → final verdict
├── content/
│   └── contentScript.js     # Layer 3: DOM analysis (injected into pages)
├── popup/
│   ├── popup.html           # Extension popup UI
│   ├── popup.js             # Popup logic, UI rendering
│   └── warning.html         # Shown when auto-blocking a phishing page
├── utils/
│   ├── constants.js         # All weights, thresholds, config
│   └── storage.js           # browser.storage wrapper (cache, history, keys)
├── data/
│   ├── topDomains.js        # 500 brand domains for typosquatting detection
│   └── suspiciousTLDs.js    # Abused TLDs, hostname patterns
└── icons/
    ├── icon48.png
    └── icon96.png
```

---

## 🚀 Installation (Firefox)

1. Open Firefox → `about:debugging`
2. Click **"This Firefox"** → **"Load Temporary Add-on"**
3. Select `manifest.json` from this folder

For permanent install → submit to [Firefox Add-on Store](https://addons.mozilla.org/)

---

## 🔑 Getting Free API Keys

### Google Safe Browsing (Most Important)
1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Create a project → Enable "Safe Browsing API"
3. Create an API key under Credentials
4. Paste in PhishGuard Settings → "Google Safe Browsing"

### PhishTank
1. Register at [phishtank.com](https://phishtank.com)
2. Go to [phishtank.com/api_info.php](https://phishtank.com/api_info.php)
3. Request an API key
4. Paste in PhishGuard Settings → "PhishTank"

### URLScan.io
1. Register at [urlscan.io](https://urlscan.io/user/profile)
2. Get API key from your profile
3. Paste in PhishGuard Settings → "URLScan.io"

### IPQualityScore
1. Register at [ipqualityscore.com](https://ipqualityscore.com)
2. Copy your private key from the dashboard
3. Paste in PhishGuard Settings → "IPQualityScore"

---

## 🔬 How It Achieves High Accuracy

1. **Multi-layer redundancy** — No single layer is 100% accurate.
   When multiple independent layers agree, confidence is very high.

2. **Hard overrides** — Google's threat database is authoritative.
   If GSB says phishing, we trust it immediately.

3. **No false positives from new domains** — Domain age alone doesn't trigger
   a "phishing" verdict. It must combine with other signals.

4. **Real DOM analysis** — Unlike URL-only tools, we actually look inside
   the page for brand impersonation and credential harvesting forms.

5. **Levenshtein typosquatting** — Academic research shows this catches
   60%+ of typosquatting attacks missed by simple string matching.

6. **Caching** — Results cached for 10 minutes to avoid re-scanning
   frequently visited sites, reducing API costs and latency.

---

**Technologies Used:**
- **JavaScript (ES6+)** — Extension logic
- **WebExtensions API** — Firefox extension framework
- **RDAP Protocol (RFC 7483)** — Domain registration lookup
- **DNS-over-HTTPS (Cloudflare)** — Privacy-preserving DNS
- **Google Safe Browsing API v4** — Threat intelligence
- **PhishTank API** — Community phishing database
- **URLScan.io API** — Sandboxed URL analysis
- **crt.sh** — Certificate Transparency log
- **Levenshtein Distance Algorithm** — Typosquatting detection
- **Shannon Entropy** — Random subdomain detection
- **browser.storage.local** — Local data persistence

**ML Concepts Applied (Without a Model):**
- Feature engineering (20+ URL features mirroring UCI ML Phishing Dataset)
- Weighted scoring (mimics logistic regression weights)
- Multi-source ensemble (like ensemble/stacking classifiers)
- Threshold-based classification

**Future Enhancements:**
- Train a TensorFlow.js model on UCI Phishing Dataset
- Add screenshot comparison using perceptual hashing
- Implement DMARC/SPF email authentication checks
- Add crowd-sourced reporting to improve accuracy
