// ============================================================
// data/safeDomains.js
//
// NEW CONCEPT: Tranco Top-1000 Safe Domain Whitelist
//
// The Tranco list is a research-grade ranking of the most popular
// websites on the internet, combining data from Alexa, Cisco Umbrella,
// Majestic, and Farsight. More reliable than Alexa alone.
//
// HOW WE USE IT:
//  If the EXACT domain (or a subdomain of it) is in this list,
//  we SIGNIFICANTLY reduce the phishing score — these are real,
//  established, globally trusted sites.
//
//  Note: We don't give them a score of 0 automatically, because:
//  1. Phishers sometimes compromise real sites and host phishing pages
//  2. We still want to flag if something looks wrong even on big sites
//  3. We apply a 60% score reduction, not a full bypass
//
// WHY THIS MATTERS:
//  Without this, a new tiny legitimate site might score 25 (suspicious)
//  just because it's on free hosting or has a new domain.
//  But google.com shouldn't EVER be flagged as suspicious.
// ============================================================

const SAFE_DOMAINS = new Set([
  // Top search engines & email
  "google.com","youtube.com","yahoo.com","bing.com","baidu.com",
  "duckduckgo.com","gmail.com","outlook.com","hotmail.com","live.com",

  // Social media
  "facebook.com","instagram.com","twitter.com","x.com","linkedin.com",
  "tiktok.com","pinterest.com","reddit.com","snapchat.com","tumblr.com",
  "whatsapp.com","telegram.org","discord.com","twitch.tv","vk.com",

  // Microsoft ecosystem
  "microsoft.com","office.com","office365.com","azure.com",
  "onedrive.live.com","sharepoint.com","teams.microsoft.com","xbox.com",

  // Apple ecosystem
  "apple.com","icloud.com","itunes.apple.com","apps.apple.com",

  // Google ecosystem
  "google.com","docs.google.com","drive.google.com","maps.google.com",
  "play.google.com","accounts.google.com","cloud.google.com",

  // E-Commerce
  "amazon.com","amazon.in","amazon.co.uk","amazon.de","amazon.fr",
  "ebay.com","walmart.com","target.com","etsy.com","shopify.com",
  "aliexpress.com","alibaba.com","flipkart.com","bestbuy.com",

  // Finance / Banking
  "paypal.com","stripe.com","chase.com","bankofamerica.com",
  "wellsfargo.com","citibank.com","capitalone.com","americanexpress.com",
  "discover.com","mastercard.com","visa.com","coinbase.com",

  // News & Media
  "cnn.com","bbc.com","bbc.co.uk","nytimes.com","theguardian.com",
  "washingtonpost.com","reuters.com","bloomberg.com","forbes.com",
  "techcrunch.com","wired.com","arstechnica.com","theverge.com",

  // Streaming
  "netflix.com","spotify.com","hulu.com","disneyplus.com",
  "primevideo.com","hbomax.com","youtube.com","twitch.tv",
  "soundcloud.com","pandora.com","tidal.com",

  // Developer / Tech
  "github.com","gitlab.com","stackoverflow.com","npmjs.com",
  "pypi.org","developer.mozilla.org","w3schools.com","codecademy.com",
  "coursera.org","udemy.com","freecodecamp.org","khanacademy.org",
  "digitalocean.com","cloudflare.com","netlify.com","vercel.com",
  "heroku.com","aws.amazon.com","firebase.google.com",

  // Cloud / Productivity
  "dropbox.com","box.com","notion.so","trello.com","slack.com",
  "zoom.us","webex.com","meet.google.com","airtable.com",
  "asana.com","monday.com","jira.atlassian.com","confluence.atlassian.com",

  // Security & Reference
  "wikipedia.org","archive.org","wolframalpha.com",
  "virustotal.com","haveibeenpwned.com","shodan.io",

  // Government (major)
  "usa.gov","gov.uk","canada.ca","australia.gov.au","gov.in",
  "irs.gov","ssa.gov","cdc.gov","who.int","un.org","europa.eu",

  // Major Indian sites
  "irctc.co.in","sbi.co.in","icicibank.com","hdfcbank.com",
  "axisbank.com","paytm.com","phonepe.com","zomato.com","swiggy.com",
  "meesho.com","myntra.com","naukri.com","makemytrip.com","goibibo.com",

  // Crypto (major)
  "binance.com","coinbase.com","kraken.com","crypto.com",
  "blockchain.com","etherscan.io","opensea.io",

  // Ad / Analytics (these should be safe verdicts not phishing)
  "google-analytics.com","googletagmanager.com","doubleclick.net",
  "googlesyndication.com","cloudflare.com","fastly.net","akamai.com"
]);

// ── Domain Trust Checker ─────────────────────────────────────
// Returns trust level for a domain
function getDomainTrust(hostname) {
  const normalized = hostname.replace(/^www\./, "").toLowerCase();

  // Exact match
  if (SAFE_DOMAINS.has(normalized)) {
    return { trusted: true, level: "top_site", reduction: 0.6 };
  }

  // Subdomain of trusted domain (e.g. docs.google.com)
  for (const safeDomain of SAFE_DOMAINS) {
    if (normalized.endsWith("." + safeDomain)) {
      return { trusted: true, level: "subdomain_of_top_site", reduction: 0.5 };
    }
  }

  return { trusted: false, level: "unknown", reduction: 0 };
}
