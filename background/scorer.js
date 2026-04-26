// ============================================================
// background/scorer.js  (v2 — clean rewrite, no syntax errors)
// ============================================================

const Scorer = {

  combineV2(urlResult, domResult, domainResult, apiResult,
            feedResult, redirectResult, networkResult, mlResult, trust) {

    const scores  = {};
    const factors = [];

    // Hard Override: Google Safe Browsing
    if (apiResult?.results?.googleSafeBrowsing?.isPhishing) {
      return this._buildVerdict(100, "Google Safe Browsing confirmed phishing", {});
    }

    // Hard Override: Threat Feed
    if (feedResult?.isKnownThreat) {
      return this._buildVerdict(100, `Known phishing: ${feedResult.sources?.join(", ")}`, {});
    }

    let totalWeight = 0, weightedSum = 0;

    // Layer 1: URL Analysis (always runs)
    if (urlResult && urlResult.score >= 0) {
      scores.url = urlResult.score;
      weightedSum += urlResult.score * 0.20;
      totalWeight += 0.20;
      factors.push(...(urlResult.breakdown || []).slice(0, 3));
    }

    // Layer 2: Domain Intelligence
    const domainHasData = domainResult && domainResult.score >= 0 &&
      (domainResult.score > 0 || (domainResult.breakdown && domainResult.breakdown.length > 0));
    if (domainHasData) {
      scores.domain = domainResult.score;
      weightedSum += domainResult.score * 0.15;
      totalWeight += 0.15;
      if (domainResult.score > 20) factors.push(...(domainResult.breakdown || []).slice(0, 2));
    }

    // Layer 3: DOM Analysis
    const domHasData = domResult && domResult.score >= 0 &&
      (domResult.score > 0 || (domResult.breakdown && domResult.breakdown.length > 0));
    if (domHasData) {
      scores.dom = domResult.score;
      weightedSum += domResult.score * 0.15;
      totalWeight += 0.15;
      if (domResult.score > 20) factors.push(...(domResult.breakdown || []).slice(0, 3));
    }

    // Layer 4: API Reputation
    if (apiResult && apiResult.score >= 0 && apiResult.hasKeys) {
      scores.api = apiResult.score;
      weightedSum += apiResult.score * 0.20;
      totalWeight += 0.20;
    }

    // Layer 5: Redirect Chain
    if (redirectResult && redirectResult.score >= 0 && redirectResult.score > 0) {
      scores.redirect = redirectResult.score;
      weightedSum += redirectResult.score * 0.10;
      totalWeight += 0.10;
      factors.push(...(redirectResult.breakdown || []).slice(0, 2));
    }

    // Layer 6: Network Monitor
    if (networkResult && networkResult.score >= 0 && networkResult.score > 0) {
      scores.network = networkResult.score;
      weightedSum += networkResult.score * 0.10;
      totalWeight += 0.10;
      factors.push(...(networkResult.breakdown || []).slice(0, 2));
    }

    // Layer 7: ML Score
    if (mlResult && mlResult.mlScore >= 0) {
      scores.ml = mlResult.mlScore;
      weightedSum += mlResult.mlScore * 0.10;
      totalWeight += 0.10;
      for (const c of (mlResult.correlationsTriggered || [])) {
        factors.push("ML: " + c.name + " (+" + c.bonus + ")");
      }
    }

    if (totalWeight === 0) {
      return this._buildVerdict(urlResult ? urlResult.score : 0, "URL analysis only", {});
    }

    let finalScore = Math.round(weightedSum / totalWeight);

    // Corroboration boost
    const suspicious = Object.values(scores).filter(s => s >= 35).length;
    const high       = Object.values(scores).filter(s => s >= 60).length;
    if (high >= 3)            finalScore = Math.min(100, finalScore + 20);
    else if (high >= 2)       finalScore = Math.min(100, finalScore + 12);
    else if (suspicious >= 4) finalScore = Math.min(100, finalScore + 8);

    // URL floor rule
    if (urlResult && urlResult.score >= 70)      finalScore = Math.max(finalScore, 66);
    else if (urlResult && urlResult.score >= 50)  finalScore = Math.max(finalScore, 36);

    // Safe domain trust reduction
    if (trust && trust.trusted && finalScore < 80) {
      finalScore = Math.round(finalScore * (1 - trust.reduction));
    }

    // Low confidence floor
    if (mlResult && mlResult.confidence === "very_low" &&
        finalScore >= 36 && finalScore <= 45) {
      finalScore = 35;
    }

    const reason = factors.length > 0
      ? factors.slice(0, 6).join(" | ")
      : "No specific threats detected";

    return this._buildVerdict(finalScore, reason, { scores });
  },

  buildHardOverride(score, reason, details) {
    return this._buildVerdict(score, reason, details);
  },

  _buildVerdict(score, reason, details) {
    let verdict, color, icon, message;
    if (score >= 66) {
      verdict = "PHISHING"; color = "#ef4444"; icon = "🚨";
      message = "This website is likely a phishing site. Do not enter any personal information.";
    } else if (score >= 36) {
      verdict = "SUSPICIOUS"; color = "#f59e0b"; icon = "⚠️";
      message = "Suspicious characteristics detected. Proceed with caution.";
    } else {
      verdict = "SAFE"; color = "#22c55e"; icon = "✅";
      message = "No significant threats detected. Site appears safe.";
    }
    return {
      score:   score,
      verdict: verdict,
      color:   color,
      icon:    icon,
      message: message,
      reason:  reason,
      details: details,
      timestamp: Date.now()
    };
  },

  getBadgeStyle(verdict) {
    const styles = {
      "PHISHING":   { text: "!", color: "#ef4444" },
      "SUSPICIOUS": { text: "?", color: "#f59e0b" },
      "SAFE":       { text: "\u2713", color: "#22c55e" },
      "SCANNING":   { text: "\u2026", color: "#6b7280" },
      "ERROR":      { text: "E", color: "#6b7280" }
    };
    return styles[verdict] || styles["SCANNING"];
  }

};
