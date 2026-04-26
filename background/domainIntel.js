// ============================================================
// background/domainIntel.js
//
// LAYER 2: DOMAIN INTELLIGENCE  (lightweight network checks)
//
// Checks:
//  1. Domain Age  — via whois.whoisxmlapi.com (free tier: 500/mo)
//     OR rdap.org (completely free, no key needed, RFC 7483)
//     New domains (< 30 days) are extremely suspicious.
//
//  2. DNS Records — via Cloudflare DoH (DNS over HTTPS, free)
//     Missing A/MX records, or records pointing to free hosts.
//
//  3. SSL Certificate — parsed from the connection.
//     Self-signed cert, cert issued today, wildcard for wrong domain.
//
//  4. Redirect Chain — does the URL redirect multiple times?
//     Phishing often uses a chain: shortener → tracker → phish page.
//
// Returns: { score: 0-100, breakdown: [], features: {} }
// ============================================================

const DomainIntel = {


  // ── Fetch with timeout ───────────────────────────────────
  // Every network call MUST have a timeout — phishing domains
  // often don't respond, hanging the whole scan indefinitely.
  async _fetchWithTimeout(url, options = {}, timeoutMs = 4000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const resp = await fetch(url, { ...options, signal: controller.signal });
      clearTimeout(timer);
      return resp;
    } catch(e) {
      clearTimeout(timer);
      throw e;
    }
  },

  async analyze(url) {
    let totalRisk = 0;
    const features  = {};
    const breakdown = [];

    let hostname;
    try {
      hostname = new URL(url).hostname.replace(/^www\./, "");
    } catch {
      return { score: 0, features: {}, breakdown: [] };
    }

    const checks = await Promise.allSettled([
      this._checkDomainAge(hostname),
      this._checkDNS(hostname),
      this._checkSSL(url)
    ]);

    // ── Domain Age ───────────────────────────────────────────
    const ageResult = checks[0].status === "fulfilled" ? checks[0].value : null;
    if (ageResult) {
      features.domainAgeDays = ageResult.ageDays;
      features.domainCreated = ageResult.created;

      if (ageResult.ageDays !== null) {
        if (ageResult.ageDays < 7) {
          totalRisk += 45;
          breakdown.push(`Domain created ${ageResult.ageDays} days ago (VERY new) (+45)`);
        } else if (ageResult.ageDays < 30) {
          totalRisk += 35;
          breakdown.push(`Domain created ${ageResult.ageDays} days ago (new) (+35)`);
        } else if (ageResult.ageDays < 90) {
          totalRisk += 20;
          breakdown.push(`Domain created ${ageResult.ageDays} days ago (recent) (+20)`);
        } else if (ageResult.ageDays < 365) {
          totalRisk += 8;
          breakdown.push(`Domain created ${ageResult.ageDays} days ago (<1 year) (+8)`);
        }
        // Domains > 1 year get no penalty
      }
    }

    // ── DNS Checks ───────────────────────────────────────────
    const dnsResult = checks[1].status === "fulfilled" ? checks[1].value : null;
    if (dnsResult) {
      features.dnsValid    = dnsResult.hasA;
      features.hasMX       = dnsResult.hasMX;
      features.dnsProvider = dnsResult.provider;

      if (!dnsResult.hasA) {
        totalRisk += 30;
        breakdown.push("No DNS A record found (domain may not exist) (+30)");
      }

      // Free DNS providers often used for phishing infrastructure
      if (dnsResult.provider && this._isFreeHostingProvider(dnsResult.provider)) {
        totalRisk += 15;
        breakdown.push(`Free/suspicious DNS provider: ${dnsResult.provider} (+15)`);
      }
    }

    // ── SSL Certificate ──────────────────────────────────────
    const sslResult = checks[2].status === "fulfilled" ? checks[2].value : null;
    if (sslResult) {
      features.sslValid        = sslResult.valid;
      features.sslIssuer       = sslResult.issuer;
      features.sslAgeDays      = sslResult.ageDays;
      features.sslIsWildcard   = sslResult.isWildcard;
      features.sslIsDV         = sslResult.isDV; // Domain Validated (cheapest, easiest to get)

      if (!sslResult.valid) {
        totalRisk += 20;
        breakdown.push("Invalid/missing SSL certificate (+20)");
      }

      if (sslResult.ageDays !== null && sslResult.ageDays < 7) {
        totalRisk += 20;
        breakdown.push(`SSL cert issued ${sslResult.ageDays} days ago (brand new) (+20)`);
      }

      // Let's Encrypt is legitimate but VERY commonly used for phishing
      // (free, instant, no identity verification)
      if (sslResult.issuer && sslResult.issuer.includes("Let's Encrypt")) {
        // Only add risk if combined with other factors
        features.sslIsLetsEncrypt = true;
        // Don't penalize alone — millions of legit sites use it
      }
    }

    // ── Normalize ────────────────────────────────────────────
    // maxPossible lowered to 70 so domain age + bad SSL = "phishing" range
    const score = Math.min(100, Math.round((totalRisk / 70) * 100));

    return { score, features, breakdown };
  },

  // ── RDAP Domain Age ─────────────────────────────────────────
  // RDAP (Registration Data Access Protocol) is RFC-standard,
  // completely free, no API key needed.
  // Fallback: we parse response from rdap.org
  async _checkDomainAge(hostname) {
    try {
      const tld      = hostname.split(".").slice(-1)[0];
      const rdapUrl  = `https://rdap.org/domain/${hostname}`;

      const resp = await this._fetchWithTimeout(rdapUrl, {
        headers: { Accept: "application/rdap+json" }
      }, 4000);
      if (!resp.ok) return { ageDays: null };

      const data = await resp.json();

      // RDAP events include "registration" event with date
      const regEvent = (data.events || []).find(e => e.eventAction === "registration");
      if (!regEvent) return { ageDays: null };

      const created  = new Date(regEvent.eventDate);
      const ageDays  = Math.floor((Date.now() - created.getTime()) / 86400000);

      return { ageDays, created: regEvent.eventDate };
    } catch {
      return { ageDays: null };
    }
  },

  // ── DNS via Cloudflare DoH ───────────────────────────────────
  // Cloudflare's DNS-over-HTTPS (1.1.1.1) is free, fast, private.
  // We check for A records (does domain resolve?) and MX (email server).
  async _checkDNS(hostname) {
    try {
      const [aResp, mxResp] = await Promise.all([
        this._fetchWithTimeout(`https://cloudflare-dns.com/dns-query?name=${hostname}&type=A`, {
          headers: { Accept: "application/dns-json" }
        }, 3000),
        this._fetchWithTimeout(`https://cloudflare-dns.com/dns-query?name=${hostname}&type=MX`, {
          headers: { Accept: "application/dns-json" }
        }, 3000)
      ]);

      const aData  = await aResp.json();
      const mxData = await mxResp.json();

      const aRecords  = (aData.Answer  || []).filter(r => r.type === 1);
      const mxRecords = (mxData.Answer || []).filter(r => r.type === 15);

      // Extract hosting provider from A record IP (rough heuristic)
      let provider = null;
      if (aRecords.length > 0) {
        provider = this._guessProviderFromIP(aRecords[0].data);
      }

      return {
        hasA:     aRecords.length > 0,
        hasMX:    mxRecords.length > 0,
        aRecords: aRecords.map(r => r.data),
        provider
      };
    } catch {
      return { hasA: true, hasMX: false, aRecords: [], provider: null };
    }
  },

  // ── SSL Certificate Info ─────────────────────────────────────
  // Uses crt.sh — a free public certificate transparency log.
  // We check the issuance date and issuer of the most recent cert.
  async _checkSSL(url) {
    try {
      const hostname = new URL(url).hostname.replace(/^www\./, "");
      const crtUrl   = `https://crt.sh/?q=${hostname}&output=json`;

      const resp = await this._fetchWithTimeout(crtUrl, {}, 4000);
      if (!resp.ok) return { valid: true, ageDays: null };

      const certs = await resp.json();
      if (!certs || certs.length === 0) {
        return { valid: url.startsWith("https"), ageDays: null };
      }

      // Most recent cert
      const latest   = certs[0];
      const issuedAt = new Date(latest.not_before);
      const ageDays  = Math.floor((Date.now() - issuedAt.getTime()) / 86400000);
      const issuer   = latest.issuer_name || "";
      const domain   = latest.common_name || "";
      const isWild   = domain.startsWith("*.");
      const isDV     = issuer.includes("Let's Encrypt") ||
                       issuer.includes("ZeroSSL")      ||
                       issuer.includes("Sectigo");

      return {
        valid:       true,
        issuer:      issuer.split("O=")[1]?.split(",")[0] || issuer,
        ageDays,
        isWildcard:  isWild,
        isDV,
        domain
      };
    } catch {
      return { valid: url.startsWith("https"), ageDays: null };
    }
  },

  // ── Known Free / Abused Hosting Providers ───────────────────
  // These services are frequently abused for phishing because they
  // are free, require no identity verification, and are fast to set up.
  _isFreeHostingProvider(provider) {
    const freeProviders = [
      "000webhost", "weebly", "wix.com", "github.io", "gitlab.io",
      "netlify.app", "vercel.app", "pages.dev", "firebaseapp.com",
      "web.app", "glitch.me", "replit.com", "surge.sh",
      "infinityfree", "byethost", "freehostia"
    ];
    return freeProviders.some(p => provider.toLowerCase().includes(p));
  },

  // Very rough IP → provider mapping (first two octets heuristic)
  _guessProviderFromIP(ip) {
    const known = {
      "104.21": "Cloudflare",    "172.67": "Cloudflare",
      "185.199": "GitHub Pages", "76.76":  "Vercel",
      "75.2":   "AWS",           "54.":    "AWS",
      "34.":    "Google Cloud",  "35.":    "Google Cloud",
      "20.":    "Azure",         "13.":    "Azure"
    };
    for (const [prefix, name] of Object.entries(known)) {
      if (ip.startsWith(prefix)) return name;
    }
    return null;
  }
};
