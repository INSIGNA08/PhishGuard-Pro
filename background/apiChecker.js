// ============================================================
// background/apiChecker.js
//
// LAYER 3: EXTERNAL API CHECKS  (network calls, most reliable)
//
// Integrates with:
//  1. Google Safe Browsing API v4 — FREE, 10k req/day
//     Maintained by Google's Security team. Catches most known
//     phishing/malware URLs in real time.
//     Setup: console.cloud.google.com → Enable "Safe Browsing API"
//
//  2. PhishTank API — FREE, community-verified phishing database
//     Crowd-sourced database of verified phishing URLs.
//     Setup: phishtank.com/api_info.php (requires registration)
//
//  3. URLScan.io — FREE, 1000 req/day
//     Sandboxed browser scan of pages with screenshot + analysis.
//     Setup: urlscan.io/user/profile
//
//  4. IPQualityScore — FREE tier, URL + IP reputation
//     Scores URLs for phishing, spam, malware, parking.
//     Setup: ipqualityscore.com
//
// Returns: { score: 0-100, results: {}, error: null }
// ============================================================

const ApiChecker = {

  async check(url) {
    const apiKeys = await Storage.getApiKeys();
    const results = {};
    const promises = [];

    // Run all available API checks in PARALLEL for speed
    if (apiKeys.googleSafeBrowsing) {
      promises.push(
        this._checkGoogleSafeBrowsing(url, apiKeys.googleSafeBrowsing)
          .then(r => { results.googleSafeBrowsing = r; })
          .catch(e => { results.googleSafeBrowsing = { error: e.message }; })
      );
    }

    if (apiKeys.phishTank) {
      promises.push(
        this._checkPhishTank(url, apiKeys.phishTank)
          .then(r => { results.phishTank = r; })
          .catch(e => { results.phishTank = { error: e.message }; })
      );
    }

    if (apiKeys.urlScanIo) {
      promises.push(
        this._checkUrlScan(url, apiKeys.urlScanIo)
          .then(r => { results.urlScan = r; })
          .catch(e => { results.urlScan = { error: e.message }; })
      );
    }

    if (apiKeys.ipQualityScore) {
      promises.push(
        this._checkIPQS(url, apiKeys.ipQualityScore)
          .then(r => { results.ipqs = r; })
          .catch(e => { results.ipqs = { error: e.message }; })
      );
    }

    await Promise.all(promises);

    return {
      score:   this._aggregateApiScore(results),
      results,
      hasKeys: Object.keys(results).length > 0
    };
  },

  // ── 1. Google Safe Browsing API v4 ──────────────────────────
  // Checks URL against Google's Threat Intelligence:
  //  - MALWARE, SOCIAL_ENGINEERING (phishing), UNWANTED_SOFTWARE, MALICIOUS_BINARY
  //
  // Request: POST with JSON body listing URL to check
  // Response: { matches: [...] } if threat found, {} if clean
  async _checkGoogleSafeBrowsing(url, apiKey) {
    const endpoint = `${PHISHGUARD.APIS.GOOGLE_SAFE_BROWSING}?key=${apiKey}`;

    const body = {
      client: { clientId: "phishguard-extension", clientVersion: "1.0.0" },
      threatInfo: {
        threatTypes:      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "MALICIOUS_BINARY"],
        platformTypes:    ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries:    [{ url }]
      }
    };

    const resp = await fetch(endpoint, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(body)
    });

    if (!resp.ok) throw new Error(`GSB HTTP ${resp.status}`);
    const data = await resp.json();

    const isPhishing = !!(data.matches && data.matches.length > 0);
    const threats    = isPhishing ? data.matches.map(m => m.threatType) : [];

    return {
      isPhishing,
      threats,
      score: isPhishing ? 100 : 0,   // Binary: Google says yes or no
      source: "Google Safe Browsing"
    };
  },

  // ── 2. PhishTank API ────────────────────────────────────────
  // Community-verified phishing URL database.
  // Returns isPhishing (true/false) with verification count.
  //
  // Request: POST with url + app_key + format=json
  // Response: { results: { in_database, valid, verified } }
  async _checkPhishTank(url, apiKey) {
    const formData = new URLSearchParams({
      url:      encodeURIComponent(url),
      format:   "json",
      app_key:  apiKey
    });

    const resp = await fetch(PHISHGUARD.APIS.PHISHTANK, {
      method:  "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body:    formData.toString()
    });

    if (!resp.ok) throw new Error(`PhishTank HTTP ${resp.status}`);
    const data = await resp.json();

    const inDB       = data.results?.in_database === true;
    const isPhishing = inDB && data.results?.valid === true;
    const verified   = data.results?.verified === true;

    return {
      isPhishing,
      inDatabase: inDB,
      verified,
      score:  isPhishing ? 100 : (inDB && !verified ? 60 : 0),
      source: "PhishTank"
    };
  },

  // ── 3. URLScan.io ───────────────────────────────────────────
  // Submits URL to a sandboxed browser, gets back:
  //  - Verdicts (malicious / suspicious)
  //  - Screenshot
  //  - Lists of IPs, domains, resources contacted
  //
  // Note: Scan is async. We submit then poll after 10 seconds.
  // In production, you'd use webhooks. Here we do a quick poll.
  async _checkUrlScan(url, apiKey) {
    // Step 1: Submit scan
    const submitResp = await fetch(PHISHGUARD.APIS.URLSCAN_SUBMIT, {
      method:  "POST",
      headers: {
        "Content-Type": "application/json",
        "API-Key":       apiKey
      },
      body: JSON.stringify({ url, visibility: "public" })
    });

    if (submitResp.status === 429) return { error: "Rate limited", score: -1 };
    if (!submitResp.ok) throw new Error(`URLScan submit HTTP ${submitResp.status}`);

    const submitData = await submitResp.json();
    const resultUUID = submitData.uuid;

    // Step 2: Poll for result (wait 12 seconds for scan to complete)
    await new Promise(r => setTimeout(r, 12000));

    const resultResp = await fetch(`${PHISHGUARD.APIS.URLSCAN_RESULT}${resultUUID}/`);
    if (!resultResp.ok) return { error: "Result not ready", score: -1 };

    const result = await resultResp.json();

    const overallScore   = result.verdicts?.overall?.score     || 0;   // 0-100
    const isMalicious    = result.verdicts?.overall?.malicious || false;
    const categories     = result.verdicts?.overall?.categories || [];
    const screenshotUrl  = result.screenshot || "";

    return {
      isPhishing: isMalicious || categories.includes("phishing"),
      score:      isMalicious ? 90 : Math.min(80, overallScore),
      categories,
      screenshotUrl,
      source: "URLScan.io"
    };
  },

  // ── 4. IPQualityScore ───────────────────────────────────────
  // Comprehensive URL reputation: phishing, malware, spam, parking.
  // Also checks if domain is newly registered or recently changed.
  async _checkIPQS(url, apiKey) {
    const encodedUrl = encodeURIComponent(url);
    const endpoint   = `${PHISHGUARD.APIS.IPQUALITYSCORE}${apiKey}/${encodedUrl}`;

    const resp = await fetch(`${endpoint}?strictness=1`);
    if (!resp.ok) throw new Error(`IPQS HTTP ${resp.status}`);

    const data = await resp.json();

    return {
      isPhishing:        data.phishing,
      isMalware:         data.malware,
      isSpam:            data.spamming,
      riskScore:         data.risk_score,        // 0-100
      isNewDomain:       data.domain_age?.days < 30,
      domainAgeDays:     data.domain_age?.days,
      isSuspicious:      data.suspicious,
      score:             data.phishing ? 95 :
                         data.malware  ? 90 :
                         data.suspicious ? 60 :
                         Math.min(70, data.risk_score),
      source: "IPQualityScore"
    };
  },

  // ── Aggregate All API Scores ────────────────────────────────
  // If ANY major API says "phishing" → high score.
  // Otherwise weighted average of available scores.
  _aggregateApiScore(results) {
    const scores = [];
    const weights = {
      googleSafeBrowsing: 5,  // Most trusted
      phishTank:          4,
      urlScan:            3,
      ipqs:               3
    };

    let totalWeight = 0;
    let weightedSum = 0;

    for (const [source, result] of Object.entries(results)) {
      if (result.error || result.score === -1) continue;
      const w = weights[source] || 1;
      weightedSum += result.score * w;
      totalWeight += w;
      scores.push(result.score);
    }

    if (scores.length === 0) return -1; // No APIs ran

    // Hard override: if Google or PhishTank says phishing → 100
    if (results.googleSafeBrowsing?.isPhishing) return 100;
    if (results.phishTank?.isPhishing)          return 100;

    return totalWeight > 0
      ? Math.round(weightedSum / totalWeight)
      : Math.max(...scores);
  }
};
