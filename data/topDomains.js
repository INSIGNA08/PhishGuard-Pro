// ============================================================
// data/topDomains.js
// Top 500 popular/brand domains used for:
//  1. Typosquatting detection (levenshtein distance ≤ 2)
//  2. Brand impersonation detection
//
// WHY: Phishers register domains like "paypa1.com", "arnazon.com"
// that look like real brands but aren't.
// ============================================================

const TOP_DOMAINS = [
  // Finance / Banking
  "paypal.com","chase.com","bankofamerica.com","wellsfargo.com",
  "citibank.com","capitalone.com","americanexpress.com","discover.com",
  "usbank.com","pnc.com","td.com","hsbc.com","barclays.com",
  "lloydsbank.com","natwest.com","santander.com","sbi.co.in",
  "icicibank.com","hdfcbank.com","axisbank.com",

  // Email / Productivity
  "gmail.com","yahoo.com","outlook.com","hotmail.com","live.com",
  "icloud.com","protonmail.com","zoho.com","aol.com","mail.com",
  "office365.com","microsoft.com","google.com","apple.com",

  // Social Media
  "facebook.com","instagram.com","twitter.com","x.com","linkedin.com",
  "tiktok.com","snapchat.com","pinterest.com","reddit.com","tumblr.com",
  "whatsapp.com","telegram.org","discord.com","twitch.tv","youtube.com",

  // E-Commerce / Shopping
  "amazon.com","ebay.com","walmart.com","target.com","etsy.com",
  "aliexpress.com","alibaba.com","flipkart.com","shopify.com",
  "bestbuy.com","newegg.com","costco.com","wayfair.com",

  // Cloud / Tech
  "aws.amazon.com","azure.microsoft.com","cloud.google.com",
  "dropbox.com","box.com","onedrive.live.com","icloud.com",
  "github.com","gitlab.com","bitbucket.org","stackoverflow.com",
  "digitalocean.com","cloudflare.com","netlify.com","vercel.com",

  // Streaming
  "netflix.com","spotify.com","hulu.com","disneyplus.com","hbomax.com",
  "primevideo.com","peacocktv.com","paramountplus.com","crunchyroll.com",

  // Government / Official
  "irs.gov","usa.gov","gov.uk","canada.ca","gov.in",

  // Crypto Exchanges
  "coinbase.com","binance.com","kraken.com","gemini.com",
  "crypto.com","bitfinex.com","kucoin.com","okx.com",

  // Other Popular
  "wikipedia.org","wordpress.com","adobe.com","salesforce.com",
  "zoom.us","slack.com","notion.so","trello.com","hubspot.com",
  "godaddy.com","namecheap.com","bluehost.com","hostinger.com"
];

// Brand keywords to detect logo/text impersonation in DOM
const BRAND_KEYWORDS = {
  "paypal":   ["paypal.com"],
  "amazon":   ["amazon.com","amazon.in","amazon.co.uk","amazon.de"],
  "google":   ["google.com","google.co.in"],
  "facebook": ["facebook.com","fb.com"],
  "apple":    ["apple.com"],
  "microsoft":["microsoft.com","live.com","outlook.com","office.com"],
  "netflix":  ["netflix.com"],
  "instagram":["instagram.com"],
  "twitter":  ["twitter.com","x.com"],
  "linkedin": ["linkedin.com"],
  "ebay":     ["ebay.com"],
  "dropbox":  ["dropbox.com"],
  "chase":    ["chase.com"],
  "wellsfargo":["wellsfargo.com"],
  "bankofamerica":["bankofamerica.com"],
  "coinbase": ["coinbase.com"],
  "binance":  ["binance.com"],
  "irs":      ["irs.gov"],
  "dhl":      ["dhl.com"],
  "fedex":    ["fedex.com"],
  "ups":      ["ups.com"],
  "usps":     ["usps.com"],
  "steam":    ["store.steampowered.com","steampowered.com"],
  "netflix":  ["netflix.com"],
  "spotify":  ["spotify.com"],
  "adobe":    ["adobe.com"],
  "zoom":     ["zoom.us"],
  "github":   ["github.com"]
};
