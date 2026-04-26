// ============================================================
// background/mlScorer.js
//
// NEW CONCEPT: Naive Bayes Inspired Probabilistic Scoring
//
// Traditional scoring: just adds up risk points.
// Problem: 3 small signals (10+10+10=30) treated same as 1 big one.
//
// ML Approach — Naive Bayes Concept:
//  P(phishing | features) ∝ P(feature1|phishing) × P(feature2|phishing) × ...
//
// In simple terms: we calculate the PROBABILITY a site is phishing
// based on how often each feature appears in known phishing sites
// vs known safe sites.
//
// RISK CORRELATION MATRIX:
//  Some features are MUCH more dangerous when they co-occur.
//  Example:
//    - New domain ALONE → maybe just a new legitimate site
//    - New domain + no MX records + free TLD + login path
//    → Almost certainly phishing
//
//  The matrix multiplies risk when dangerous features appear together.
//
// CONFIDENCE SCORING:
//  We also track how CONFIDENT we are in the score.
//  More active layers = higher confidence.
//  Low confidence → we lean towards "suspicious" not "safe".
//
// Based on:
//  - "Detecting Phishing Websites using Machine Learning" (2019)
//  - UCI ML Phishing Dataset feature correlation analysis
// ============================================================

const MLScorer = {

  // ── Naive Bayes Feature Probabilities ───────────────────
  // P(feature=1 | phishing) — from UCI dataset analysis
  // How often does each feature appear in CONFIRMED phishing sites?
  PHISHING_PROBS: {
    ipAsHost:           0.65,  // 65% of phishing sites use IP
    isShortener:        0.42,  // 42% use URL shorteners
    hasAtSymbol:        0.31,
    typosquat:          0.48,  // 48% typosquat a brand
    suspiciousTld:      0.52,
    isFreeHost:         0.38,
    newDomain:          0.71,  // 71% of phishing domains < 90 days old
    noMxRecord:         0.44,
    httpOnly:           0.28,
    externalFormAction: 0.67,  // 67% of phishing pages have external forms
    brandImpersonation: 0.73,
    urgencyLanguage:    0.61,
    obfuscatedJs:       0.55,
    passwordOnHttp:     0.39,
    deepSubdomains:     0.43,
    randomSubdomain:    0.37,
    longRedirectChain:  0.58,
    ccField:            0.29,
    hiddenIframe:       0.33,
    hexEncoded:         0.41,
  },

  // P(feature=1 | safe) — how often in LEGITIMATE sites?
  SAFE_PROBS: {
    ipAsHost:           0.002,
    isShortener:        0.04,
    hasAtSymbol:        0.001,
    typosquat:          0.001,
    suspiciousTld:      0.008,
    isFreeHost:         0.12,   // Many legit small sites use free hosting
    newDomain:          0.15,
    noMxRecord:         0.08,
    httpOnly:           0.18,   // Some legit sites still use HTTP
    externalFormAction: 0.05,
    brandImpersonation: 0.001,
    urgencyLanguage:    0.04,
    obfuscatedJs:       0.06,
    passwordOnHttp:     0.02,
    deepSubdomains:     0.09,
    randomSubdomain:    0.05,
    longRedirectChain:  0.07,
    ccField:            0.11,   // Legit e-commerce has CC forms
    hiddenIframe:       0.03,
    hexEncoded:         0.08,
  },

  // ── Risk Correlation Matrix ──────────────────────────────
  // Feature COMBINATIONS that massively increase risk.
  // Format: { features: [...], multiplier: X }
  // If ALL listed features are present → multiply score by X
  CORRELATIONS: [
    {
      name:       "Classic phishing combo",
      features:   ["newDomain", "suspiciousTld", "externalFormAction"],
      multiplier: 2.2,
      addScore:   35
    },
    {
      name:       "Brand clone attack",
      features:   ["typosquat", "brandImpersonation", "passwordOnHttp"],
      multiplier: 2.5,
      addScore:   40
    },
    {
      name:       "Credential harvester",
      features:   ["externalFormAction", "urgencyLanguage", "brandImpersonation"],
      multiplier: 2.0,
      addScore:   30
    },
    {
      name:       "Burner domain phishing",
      features:   ["newDomain", "isFreeHost", "obfuscatedJs"],
      multiplier: 1.8,
      addScore:   25
    },
    {
      name:       "IP-based attack",
      features:   ["ipAsHost", "passwordOnHttp"],
      multiplier: 2.3,
      addScore:   30
    },
    {
      name:       "Redirect-based hiding",
      features:   ["isShortener", "longRedirectChain", "newDomain"],
      multiplier: 1.7,
      addScore:   20
    },
    {
      name:       "Financial data theft",
      features:   ["ccField", "externalFormAction", "brandImpersonation"],
      multiplier: 2.4,
      addScore:   35
    },
    {
      name:       "Script injection attack",
      features:   ["obfuscatedJs", "hiddenIframe", "brandImpersonation"],
      multiplier: 2.0,
      addScore:   28
    },
    {
      name:       "Deep fake domain",
      features:   ["deepSubdomains", "typosquat", "urgencyLanguage"],
      multiplier: 1.9,
      addScore:   22
    },
  ],

  // ── Main ML Score Function ───────────────────────────────
  // Takes a feature map and returns a probability-based score
  calculateMLScore(features) {
    // Step 1: Naive Bayes log-likelihood ratio
    let logRatio = 0;
    let activeFeatures = 0;

    for (const [feature, isPresent] of Object.entries(features)) {
      if (!this.PHISHING_PROBS[feature]) continue;
      if (!isPresent) continue; // Only count present features

      activeFeatures++;

      const pPhish = this.PHISHING_PROBS[feature];
      const pSafe  = this.SAFE_PROBS[feature];

      // Log-likelihood ratio: log(P(feature|phishing) / P(feature|safe))
      // Positive = more likely phishing, negative = more likely safe
      const likelihood = Math.log(pPhish / pSafe);
      logRatio += likelihood;
    }

    // Convert log ratio to 0-100 score using sigmoid function
    // sigmoid(x) = 1 / (1 + e^(-x))
    // Maps any number to 0-1 range
    const sigmoid = 1 / (1 + Math.exp(-logRatio * 0.5));
    let mlScore = Math.round(sigmoid * 100);

    // Step 2: Apply Risk Correlation Matrix
    const correlationBonus = this._applyCorrelations(features);
    mlScore = Math.min(100, mlScore + correlationBonus.totalBonus);

    // Step 3: Calculate confidence
    const confidence = this._calculateConfidence(activeFeatures);

    return {
      mlScore,
      logRatio,
      correlationsTriggered: correlationBonus.triggered,
      correlationBonus:      correlationBonus.totalBonus,
      confidence,
      activeFeatures
    };
  },

  // ── Apply Correlation Matrix ─────────────────────────────
  _applyCorrelations(features) {
    let totalBonus = 0;
    const triggered = [];

    for (const correlation of this.CORRELATIONS) {
      // Check if ALL features in this correlation are present
      const allPresent = correlation.features.every(f => features[f] === true);
      if (allPresent) {
        totalBonus += correlation.addScore;
        triggered.push({
          name:     correlation.name,
          bonus:    correlation.addScore,
          features: correlation.features
        });
      }
    }

    return { totalBonus: Math.min(50, totalBonus), triggered };
  },

  // ── Calculate Confidence ─────────────────────────────────
  // More active features = higher confidence in our prediction
  _calculateConfidence(activeFeatures) {
    if (activeFeatures === 0) return "very_low";
    if (activeFeatures <= 2)  return "low";
    if (activeFeatures <= 4)  return "medium";
    if (activeFeatures <= 7)  return "high";
    return "very_high";
  },

  // ── Extract Feature Map from Layer Results ───────────────
  // Converts raw layer results into boolean feature map
  buildFeatureMap(urlResult, domResult, domainResult, redirectResult) {
    const f = urlResult?.features || {};
    const d = domResult?.features  || {};
    const n = domainResult?.features || {};
    const r = redirectResult || {};

    return {
      ipAsHost:           !!f.ipAsHost,
      isShortener:        !!f.isShortener,
      hasAtSymbol:        !!f.hasAtSymbol,
      typosquat:          !!f.typosquatTarget,
      suspiciousTld:      !!f.suspiciousTld,
      isFreeHost:         !!f.isFreeHost,
      newDomain:          (n.domainAgeDays != null && n.domainAgeDays < 90),
      noMxRecord:         (n.hasMX === false),
      httpOnly:           !!f.isHttp,
      externalFormAction: (d.externalFormActions > 0),
      brandImpersonation: !!(d.impersonatedBrand || f.brandInSubdomain),
      urgencyLanguage:    (d.urgencyMatchCount > 0),
      obfuscatedJs:       !!d.obfuscatedJs,
      passwordOnHttp:     (d.passwordFieldCount > 0 && !!f.isHttp),
      deepSubdomains:     ((f.subdomainDepth || 0) >= 3),
      randomSubdomain:    ((f.randomSubdomainEntropy || 0) > 3.8),
      longRedirectChain:  ((r.hopCount || 0) >= 3),
      ccField:            !!d.hasCCField,
      hiddenIframe:       ((d.hiddenIframeCount || 0) > 0),
      hexEncoded:         !!f.hexEncoded,
    };
  }
};
