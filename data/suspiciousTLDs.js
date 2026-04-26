// ============================================================
// data/suspiciousTLDs.js
// TLDs heavily abused by phishers because they are:
//  - Free to register (Freenom: .tk, .ml, .ga, .cf, .gq)
//  - Cheap to register
//  - Anonymous registration allowed
//  - Historically low trust scores
//
// Source: Spamhaus Domain Block List analysis, APWG reports
// ============================================================

const SUSPICIOUS_TLDS = new Set([
  // Freenom free TLDs — most abused in phishing campaigns
  ".tk", ".ml", ".ga", ".cf", ".gq",

  // Frequently abused ccTLDs
  ".xyz", ".top", ".club", ".online", ".site", ".website",
  ".space", ".tech", ".store", ".live", ".click", ".link",
  ".download", ".stream", ".science", ".racing", ".win",
  ".bid", ".webcam", ".review", ".trade", ".date", ".loan",
  ".work", ".party", ".cricket", ".accountant", ".faith",

  // New gTLDs with high abuse rates
  ".buzz", ".icu", ".uno", ".monster", ".cyou", ".vip",
  ".rest", ".pw", ".cc" // .cc and .pw have high abuse rates
]);

// Known phishing infrastructure patterns in hostnames
const SUSPICIOUS_HOSTNAME_PATTERNS = [
  /^(\d{1,3}\.){3}\d{1,3}$/,           // Raw IP address
  /secure.*update/i,
  /account.*verify/i,
  /login.*secure/i,
  /bank.*online.*secure/i,
  /paypal.*(?!paypal\.com)/i,
  /signin.*(?:account|secure)/i,
  /-{3,}/,                              // Too many hyphens: a---b.com
  /\.(php|html|aspx)\./i,               // Extension in domain: evil.php.com
];

// Character substitution map for homograph detection
// Phishers use look-alike characters to fool users
const HOMOGRAPH_MAP = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', // Cyrillic
  'ο': 'o', 'ρ': 'p', 'α': 'a', 'ε': 'e',                       // Greek
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',             // Leetspeak
  'vv': 'w', 'rn': 'm'                                           // Visual tricks
};
