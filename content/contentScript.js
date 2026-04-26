// ============================================================
// content/contentScript.js  (v2 — Enhanced)
//
// NEW ADDITIONS in v2:
//  12. Clipboard Hijacking Detection
//  13. Keyboard Event Monitoring (keylogger detection)
//  14. Fake Browser Warning Detection
//  15. Fake CAPTCHA Detection
//  16. CSS Cloaking Detection
//  17. Overlay/Clickjacking Attack Detection
//  18. Fake Social Login Button Detection
//  19. Canvas Fingerprinting Detection
//  20. localStorage Sensitive Data Patterns
//  21. Missing Content Security Policy
//  22. DevTools Blocking Detection
// ============================================================

(function () {
  "use strict";
  if (!window.location.hostname) return;

  const analyzeDelay = document.readyState === "complete" ? 500 : 2000;
  setTimeout(analyzeDOM, analyzeDelay);

  function analyzeDOM() {
    let totalRisk = 0;
    const features  = {};
    const breakdown = [];

    const currentHost = window.location.hostname.replace(/^www\./, "");
    const isHTTPS     = window.location.protocol === "https:";
    const pageText    = (document.body?.innerText || "").substring(0, 10000);
    const allHTML     = document.documentElement.outerHTML.substring(0, 50000);
    const allScripts  = [...document.querySelectorAll("script")].map(s => s.textContent || "").join(" ");

    // ── Check 1: Password on HTTP ────────────────────────
    const passwordFields = document.querySelectorAll('input[type="password"]');
    features.passwordFieldCount = passwordFields.length;
    if (passwordFields.length > 0 && !isHTTPS) { totalRisk += 25; breakdown.push("Password field on HTTP page (+25)"); }
    if (passwordFields.length > 1)              { totalRisk += 15; breakdown.push(`${passwordFields.length} password fields (+15)`); }

    // ── Check 2: External Form Actions ───────────────────
    let externalFormCount = 0;
    for (const form of document.querySelectorAll("form")) {
      if (!form.action) continue;
      try {
        const actionHost = new URL(form.action).hostname.replace(/^www\./, "");
        if (actionHost && actionHost !== currentHost) externalFormCount++;
      } catch {}
    }
    features.externalFormActions = externalFormCount;
    if (externalFormCount > 0) {
      totalRisk += 20 * Math.min(externalFormCount, 2);
      breakdown.push(`${externalFormCount} form(s) submit to external domain (+${20 * Math.min(externalFormCount, 2)})`);
    }

    // ── Check 3: Hidden Iframes ───────────────────────────
    let hiddenIframeCount = 0;
    for (const iframe of document.querySelectorAll("iframe")) {
      const style = window.getComputedStyle(iframe);
      const w = parseInt(style.width) || 0, h = parseInt(style.height) || 0;
      if (style.display === "none" || style.visibility === "hidden" ||
          (w < 5 && h < 5) || style.opacity === "0") hiddenIframeCount++;
    }
    features.hiddenIframeCount = hiddenIframeCount;
    if (hiddenIframeCount > 0) { totalRisk += 12 * Math.min(hiddenIframeCount, 2); breakdown.push(`${hiddenIframeCount} hidden iframe(s) (+${12*Math.min(hiddenIframeCount,2)})`); }

    // ── Check 4: External Favicon ─────────────────────────
    const favicon = document.querySelector('link[rel*="icon"]');
    if (favicon?.href) {
      try {
        const fHost = new URL(favicon.href).hostname.replace(/^www\./, "");
        if (fHost && fHost !== currentHost) { totalRisk += 10; breakdown.push(`External favicon: ${fHost} (+10)`); features.faviconExternal = fHost; }
      } catch {}
    }

    // ── Check 5: Meta Refresh ─────────────────────────────
    const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');
    if (metaRefresh) {
      const redirectTo = (metaRefresh.content || "").split("url=")[1];
      if (redirectTo) {
        try {
          const rHost = new URL(redirectTo.trim()).hostname.replace(/^www\./, "");
          if (rHost !== currentHost) { totalRisk += 15; breakdown.push(`Meta refresh to ${rHost} (+15)`); features.metaRedirectDomain = rHost; }
        } catch {}
      }
    }

    // ── Check 6: Right-click Disabled ────────────────────
    const noRightClick = /oncontextmenu\s*=\s*['"]?return\s+false/i.test(document.body?.outerHTML || "") ||
                         /addEventListener\s*\(\s*['"]contextmenu['"]/i.test(allScripts);
    features.disablesRightClick = noRightClick;
    if (noRightClick) { totalRisk += 10; breakdown.push("Right-click disabled (+10)"); }

    // ── Check 7: Few Internal Links ───────────────────────
    const allLinks = document.querySelectorAll("a[href]");
    const internalLinks = [...allLinks].filter(a => {
      try { return new URL(a.href).hostname.replace(/^www\./, "") === currentHost; }
      catch { return a.href.startsWith("#") || a.href.startsWith("/"); }
    });
    features.internalLinkCount = internalLinks.length;
    if (allLinks.length < 5 && (document.body?.innerHTML?.length || 0) > 3000) {
      totalRisk += 10; breakdown.push(`Very few links (${allLinks.length}) (+10)`);
    }

    // ── Check 8: Brand Impersonation ─────────────────────
    const images  = document.querySelectorAll("img");
    const imgData = [...images].map(i => (i.src+" "+i.alt+" "+i.className).toLowerCase()).join(" ");
    const brands  = {
      paypal:["paypal.com"], amazon:["amazon.com","amazon.in"], google:["google.com"],
      facebook:["facebook.com"], apple:["apple.com"], microsoft:["microsoft.com","office.com"],
      netflix:["netflix.com"], chase:["chase.com"], wellsfargo:["wellsfargo.com"],
      coinbase:["coinbase.com"], irs:["irs.gov"], dhl:["dhl.com"], fedex:["fedex.com"],
      ups:["ups.com"], instagram:["instagram.com"], twitter:["twitter.com","x.com"],
      linkedin:["linkedin.com"], dropbox:["dropbox.com"], zoom:["zoom.us"],
      github:["github.com"], binance:["binance.com"], steam:["steampowered.com"],
    };
    for (const [brand, valid] of Object.entries(brands)) {
      const inPage  = new RegExp(brand,"i").test(imgData + " " + pageText.substring(0,2000));
      const onValid = valid.some(d => currentHost === d || currentHost.endsWith("."+d));
      if (inPage && !onValid) {
        totalRisk += 20; breakdown.push(`Brand impersonation: "${brand}" (+20)`);
        features.impersonatedBrand = brand; break;
      }
    }

    // ── Check 9: Urgency Language ─────────────────────────
    const urgentPatterns = [
      /verify.{0,20}(now|immediately|urgent)/i,
      /account.{0,20}(suspend|terminat|clos|block)/i,
      /(limited|expires?|24 hours?|48 hours?).{0,20}(action|time|left)/i,
      /your.{0,10}(password|account).{0,20}(expir|reset|compromis)/i,
      /security.{0,15}(alert|warning|notice|threat)/i,
      /unauthorized.{0,15}(access|login|activity)/i,
      /confirm.{0,20}(identit|account|email|information)/i,
    ];
    let urgencyCount = 0;
    for (const p of urgentPatterns) { if (p.test(pageText)) urgencyCount++; }
    features.urgencyMatchCount = urgencyCount;
    if (urgencyCount >= 3)      { totalRisk += 15; breakdown.push(`${urgencyCount} urgency patterns (+15)`); }
    else if (urgencyCount > 0)  { totalRisk += 8;  breakdown.push(`${urgencyCount} urgency pattern(s) (+8)`); }

    // ── Check 10: Sensitive Form Fields ───────────────────
    const inputLabels = [...document.querySelectorAll("input")].map(i =>
      (i.name+" "+i.id+" "+i.placeholder+" "+(i.closest("label")?.textContent||"")).toLowerCase()
    ).join(" ");
    const hasCCField  = /card.?number|credit.?card|cvv|cvc|expir/i.test(inputLabels);
    const hasSSNField = /social.?security|ssn|tax.?id|passport/i.test(inputLabels);
    features.hasCCField  = hasCCField;
    features.hasSSNField = hasSSNField;
    if (hasCCField && !isHTTPS) { totalRisk += 30; breakdown.push("CC form on HTTP (+30)"); }
    else if (hasCCField)        { totalRisk += 10; breakdown.push("Credit card form (+10)"); }
    if (hasSSNField)            { totalRisk += 20; breakdown.push("SSN/Tax ID form (+20)"); }

    // ── Check 11: Obfuscated JavaScript ──────────────────
    const hasEvalAtob = /eval\s*\(\s*atob\s*\(/i.test(allScripts);
    const hasLongB64  = /[A-Za-z0-9+/]{500,}={0,2}/.test(allScripts);
    features.obfuscatedJs = hasEvalAtob || hasLongB64;
    if (features.obfuscatedJs) { totalRisk += 18; breakdown.push("Obfuscated JS (+18)"); }

    // ─────── NEW CHECKS v2 ─────────────────────────────────

    // ── Check 12: Clipboard Hijacking ────────────────────
    // Phishers intercept copy events to replace copied crypto
    // wallet addresses with their own address.
    const clipboardHijack =
      /document\.addEventListener\s*\(\s*['"]copy['"]/i.test(allScripts) ||
      /navigator\.clipboard\.write/i.test(allScripts) ||
      /oncopy\s*=/i.test(allHTML) ||
      /execCommand\s*\(\s*['"]copy['"]/i.test(allScripts);
    features.clipboardHijack = clipboardHijack;
    if (clipboardHijack) { totalRisk += 22; breakdown.push("Clipboard hijacking code (+22)"); }

    // ── Check 13: Keyboard Monitoring on Sensitive Pages ──
    // Keylogger = capturing every keypress → stealing passwords
    const keyEvents = [
      /document\.addEventListener\s*\(\s*['"]key(down|up|press)['"]/i,
      /window\.addEventListener\s*\(\s*['"]key(down|up|press)['"]/i,
    ].filter(p => p.test(allScripts)).length;
    features.keyEventListeners = keyEvents;
    if (keyEvents >= 2 && (hasCCField || passwordFields.length > 0)) {
      totalRisk += 25; breakdown.push("Keyboard monitoring on sensitive form page (+25)");
    }

    // ── Check 14: Fake Browser/Security Warning ───────────
    // Tech support scam pattern: "Your computer is infected! Call us!"
    const fakeWarnings = [
      /microsoft.{0,20}(detected|blocked|warning|virus|infected)/i,
      /your computer.{0,30}(virus|infected|hack|compromis)/i,
      /call.{0,10}(support|microsoft|apple|google).{0,20}(number|now|immediately)/i,
      /(trojan|malware|spyware).{0,30}detected/i,
      /windows.{0,20}(defender|firewall).{0,20}(block|alert)/i,
    ].filter(p => p.test(pageText)).length;
    features.fakeWarningCount = fakeWarnings;
    if (fakeWarnings >= 2) { totalRisk += 30; breakdown.push(`Fake security warning (${fakeWarnings} patterns) (+30)`); }
    else if (fakeWarnings === 1) { totalRisk += 15; breakdown.push("Possible fake security warning (+15)"); }

    // ── Check 15: Fake CAPTCHA ────────────────────────────
    // Real reCAPTCHA ALWAYS loads from google.com/recaptcha
    // Fake ones are just images or custom HTML to look legit
    const hasCaptchaText   = /captcha|i am not a robot|verify you.{0,5}re human/i.test(pageText);
    const hasRealRecaptcha = !!(document.querySelector('script[src*="google.com/recaptcha"]') ||
                                document.querySelector('.g-recaptcha') ||
                                document.querySelector('[data-sitekey]'));
    const hasFakeCaptchaImg = [...images].some(img =>
      /captcha|recaptcha/i.test(img.src+img.alt) && !img.src.includes("google.com")
    );
    features.fakeCaptcha = hasCaptchaText && !hasRealRecaptcha && hasFakeCaptchaImg;
    if (features.fakeCaptcha) { totalRisk += 25; breakdown.push("Fake CAPTCHA (not from Google) (+25)"); }

    // ── Check 16: CSS Cloaking ────────────────────────────
    // Hide real content from security crawlers/bots
    const cloakedEls = document.querySelectorAll(
      '[style*="text-indent:-9999"],[style*="text-indent: -9999"],[style*="left:-9999"]'
    ).length;
    features.cloakedElementCount = cloakedEls;
    if (cloakedEls > 3) { totalRisk += 12; breakdown.push(`${cloakedEls} CSS-cloaked elements (+12)`); }

    // ── Check 17: Transparent Overlay (Clickjacking) ──────
    // Invisible full-page div captures all user clicks
    // Below it: a legitimate site in an iframe
    const overlays = [...document.querySelectorAll("div,span,section")].filter(el => {
      const s = window.getComputedStyle(el);
      return s.position === "fixed" &&
             parseInt(s.zIndex||0) > 1000 &&
             parseInt(s.width||0)  > window.innerWidth  * 0.8 &&
             parseInt(s.height||0) > window.innerHeight * 0.8 &&
             (s.opacity === "0" || s.backgroundColor === "transparent" || s.visibility === "hidden");
    }).length;
    features.overlayCount = overlays;
    if (overlays > 0) { totalRisk += 28; breakdown.push(`Full-screen overlay (clickjacking) (+28)`); }

    // ── Check 18: Fake Social Login Buttons ───────────────
    // "Login with Google" button that doesn't go to accounts.google.com
    const socialBtns = [...document.querySelectorAll("a,button")];
    for (const btn of socialBtns) {
      const text = (btn.textContent+" "+btn.className+" "+(btn.href||"")).toLowerCase();
      const isSocialLogin = /(login|sign.?in).{0,10}(google|facebook|apple|microsoft)/i.test(text) ||
                            /(google|facebook|apple|microsoft).{0,10}(login|sign.?in)/i.test(text);
      if (!isSocialLogin) continue;
      const href = (btn.href || btn.getAttribute("onclick") || "").toLowerCase();
      const isReal = href.includes("accounts.google.com") ||
                     href.includes("facebook.com/login") ||
                     href.includes("appleid.apple.com") ||
                     href.includes("login.microsoftonline.com");
      if (!isReal && href && !href.startsWith("#")) {
        totalRisk += 20; breakdown.push("Fake social login button (+20)");
        features.fakeSocialLogin = true; break;
      }
    }

    // ── Check 19: Canvas Fingerprinting on Sensitive Page ──
    // Bots see differently than humans → phishing kit evades detection
    const canvasFP = /getContext\s*\(\s*['"]2d['"]\s*\)/.test(allScripts) &&
                     /toDataURL/.test(allScripts);
    features.canvasFingerprint = canvasFP;
    if (canvasFP && (hasCCField || passwordFields.length > 0)) {
      totalRisk += 12; breakdown.push("Canvas fingerprinting on sensitive page (+12)");
    }

    // ── Check 20: localStorage Credential Storage ─────────
    // Phishing kits store captured passwords in localStorage before sending
    const localStorageAbuse =
      /localStorage\s*\.setItem\s*\(\s*['"][^'"]{0,20}(pass|pwd|token|auth|cred)/i.test(allScripts);
    features.localStorageAbuse = localStorageAbuse;
    if (localStorageAbuse) { totalRisk += 20; breakdown.push("Credentials stored in localStorage (+20)"); }

    // ── Check 21: DevTools Blocking ───────────────────────
    // Phishing kits block DevTools so you can't inspect their code
    const devToolsBlock = /setInterval.*debugger/i.test(allScripts) ||
                          /window\.devtools/i.test(allScripts);
    features.disablesDevTools = devToolsBlock;
    if (devToolsBlock) { totalRisk += 15; breakdown.push("DevTools blocking detected (+15)"); }

    // ── Check 22: Form Auto-Submit ────────────────────────
    // Some phishing pages auto-submit forms to collect data immediately
    const autoSubmit = /\.submit\s*\(\s*\)/i.test(allScripts) &&
                       document.querySelectorAll("form").length > 0 &&
                       passwordFields.length > 0;
    features.autoSubmit = autoSubmit;
    if (autoSubmit) { totalRisk += 18; breakdown.push("Automatic form submission detected (+18)"); }


    // ─────── NEW CHECKS v3 ─────────────────────────────────

    // ── Check 23: TabNapping Detection ───────────────────
    // TabNapping: page listens for visibility/focus events
    // and silently replaces itself with a fake login page
    // when you look away and come back.
    // Attacker: You think you left Gmail open → you see login → enter password
    const tabNappingPatterns = [
      /document\.addEventListener\s*\(\s*['"]visibilitychange['"]/i,
      /document\.addEventListener\s*\(\s*['"]blur['"]/i,
      /window\.addEventListener\s*\(\s*['"]blur['"]/i,
      /document\.hidden/i,
      /visibilityState/i,
    ];
    const tabNappingCount = tabNappingPatterns.filter(p => p.test(allScripts)).length;
    features.tabNappingSignals = tabNappingCount;
    // TabNapping only suspicious when combined with a login form
    if (tabNappingCount >= 2 && passwordFields.length > 0) {
      totalRisk += 22;
      breakdown.push(`TabNapping signals (${tabNappingCount} patterns) on login page (+22)`);
    }

    // ── Check 24: Missing Subresource Integrity ───────────
    // SRI (Subresource Integrity) = hash check on external scripts.
    // Real sites add integrity="sha384-..." to CDN scripts.
    // Missing SRI = external script could be tampered without detection.
    // We only flag when loading from CDN but missing SRI on a login page.
    const externalScripts = [...document.querySelectorAll('script[src]')]
      .filter(s => {
        try { return new URL(s.src).hostname !== currentHost; } catch { return false; }
      });
    const missingIntegrity = externalScripts.filter(s => !s.integrity).length;
    features.missingIntegrityCount = missingIntegrity;
    if (missingIntegrity >= 3 && passwordFields.length > 0 && !isHTTPS) {
      totalRisk += 12;
      breakdown.push(`${missingIntegrity} external scripts without SRI on login page (+12)`);
    }

    // ── Check 25: DOM Mutation on Focus ──────────────────
    // Phishing kits replace form action or input targets dynamically
    // using MutationObserver to avoid static analysis.
    const usesMutationObserver = /new\s+MutationObserver/i.test(allScripts) &&
                                  document.querySelectorAll("form").length > 0;
    features.mutationObserver = usesMutationObserver;
    if (usesMutationObserver && externalFormCount > 0) {
      totalRisk += 18;
      breakdown.push("MutationObserver on page with external form submission (+18)");
    }

    // ── Check 26: Fake Progress Bar / Loading Screen ──────
    // Many phishing kits show a fake "Verifying..." loading bar
    // to make the page look more legitimate and keep user engaged.
    const fakeProgress =
      /progress.{0,20}(verif|check|load|process)/i.test(pageText) &&
      (document.querySelectorAll('[class*="progress"],[class*="loader"],[class*="spinner"]').length > 0) &&
      externalFormCount > 0;
    features.fakeProgress = fakeProgress;
    if (fakeProgress) {
      totalRisk += 15;
      breakdown.push("Fake progress/verification UI with external form (+15)");
    }

    // ── Check 27: Window Popup Spam ───────────────────────
    // Phishing pages open many popup windows to confuse users.
    // Detect: multiple window.open() calls in scripts.
    const windowOpenCount = (allScripts.match(/window\.open\s*\(/g) || []).length;
    features.windowOpenCount = windowOpenCount;
    if (windowOpenCount >= 3) {
      totalRisk += 15;
      breakdown.push(`${windowOpenCount} window.open() calls (popup spam) (+15)`);
    }

    // ── Check 28: Fake HTTPS Padlock in Page Content ──────
    // Scammers show a padlock emoji or image INSIDE the page content
    // to trick users into thinking HTTP page is secure.
    // "🔒 Your connection is secure" — but actually HTTP!
    const fakePadlock =
      (pageText.includes("🔒") || /secure connection|ssl.{0,10}protect/i.test(pageText)) &&
      !isHTTPS;
    features.fakePadlock = fakePadlock;
    if (fakePadlock) {
      totalRisk += 25;
      breakdown.push("Fake security/padlock indicator on HTTP page (+25)");
    }

    // ── Check 29: Credential Autofill Blocking ────────────
    // Phishing pages set autocomplete="off" on ALL fields
    // to prevent password managers from flagging wrong domain.
    // (Password managers won't fill paypal credentials on fake-paypal.tk)
    const allInputsArr = [...document.querySelectorAll("input")];
    const autocompleteOff = allInputsArr.filter(i =>
      i.autocomplete === "off" || i.getAttribute("autocomplete") === "off"
    ).length;
    const hasLoginInputs = passwordFields.length > 0 || allInputsArr.some(i =>
      /email|username|user|login/i.test(i.name + i.id + i.type)
    );
    features.autocompleteOffCount = autocompleteOff;
    if (autocompleteOff >= 2 && hasLoginInputs) {
      totalRisk += 15;
      breakdown.push(`autocomplete="off" on ${autocompleteOff} inputs (blocks password manager) (+15)`);
    }

    // ── Check 30: Send Page Text for TF-IDF Analysis ─────
    // We send the page text to background.js for TF-IDF analysis.
    // This is done separately — it arrives as a separate message type.
    // (Keeps the DOM scan fast, text analysis is async)
    const extractedText = (document.body?.innerText || "").substring(0, 8000);
    if (extractedText.length > 100) {
      browser.runtime.sendMessage({
        type: "PAGE_TEXT",
        text: extractedText,
      }).catch(() => {});
    }

    // ── Normalize & Send (v3 — 29 checks) ────────────────

    // ── Check 23: NEW — Popup Storm ──────────────────────────
    // Phishing pages open many popups to confuse / trap the user.
    const popupCount = (allScripts.match(/window\.open\s*\(/g) || []).length;
    features.popupCallCount = popupCount;
    if (popupCount >= 3) {
      totalRisk += 20;
      breakdown.push(`${popupCount} window.open() calls — popup storm (+20)`);
    }

    // ── Check 24: NEW — Fake Download Trigger ─────────────────
    // Phishing kits trick users into downloading malware disguised
    // as "required security updates" or "browser plugins".
    const fakeDownload =
      /\.click\s*\(\s*\)/i.test(allScripts) &&
      /<a[^>]+download[^>]*>/i.test(allHTML) &&
      /(update|plugin|security|flash|chrome).{0,20}(required|needed|install)/i.test(pageText);
    features.fakeDownload = fakeDownload;
    if (fakeDownload) {
      totalRisk += 25;
      breakdown.push("Fake download trigger detected (+25)");
    }

    // ── Check 25: NEW — Page Title Brand Mismatch (inline) ───
    // Quick check before sending to VisualBrandAnalyzer in background.
    // Catches: <title>PayPal - Log In</title> on evil.tk domain.
    const pageTitle = document.title || "";
    const titleLow  = pageTitle.toLowerCase();
    const quickBrands = [
      "paypal","amazon","google","facebook","apple","microsoft",
      "netflix","chase","coinbase","binance","instagram","twitter",
      "wellsfargo","bankofamerica","linkedin","dropbox","discord","steam"
    ];
    for (const brand of quickBrands) {
      if (titleLow.includes(brand) && !currentHost.includes(brand)) {
        totalRisk += 25;
        breakdown.push(`Page title claims "${brand}" on wrong domain (+25)`);
        features.titleBrandMismatch = brand;
        break;
      }
    }

    // ── Check 26: NEW — Suspicious iframe Sandwich ────────────
    // Real site loaded in iframe + transparent overlay on top = clickjacking.
    // The iframe loads the real bank, overlay captures credentials.
    const iframesWithSrc = [...document.querySelectorAll("iframe[src]")];
    for (const fr of iframesWithSrc) {
      try {
        const frHost = new URL(fr.src).hostname.replace(/^www\./, "");
        if (frHost && frHost !== currentHost && frHost.length > 3) {
          const style = window.getComputedStyle(fr);
          const w = parseInt(style.width) || 0;
          const h = parseInt(style.height) || 0;
          if (w > 300 && h > 200) {
            totalRisk += 20;
            breakdown.push(`Large iframe loading ${frHost} (iframe sandwich) (+20)`);
            features.iframeSandwich = frHost;
            break;
          }
        }
      } catch {}
    }

    // ── Check 27: NEW — Anti-Analysis Techniques ──────────────
    // Phishing kits detect security researchers and bots to avoid detection:
    //  - Checking screen resolution (bots have unusual resolutions)
    //  - Checking if navigator.webdriver is true (Selenium/puppeteer)
    //  - Checking battery level (bots often have null battery)
    //  - Timezone-based country filtering
    const antiAnalysis =
      /navigator\.webdriver/i.test(allScripts) ||
      /screen\.(width|height)\s*[<>]=?\s*\d{3}/i.test(allScripts) ||
      /navigator\.getBattery/i.test(allScripts) ||
      /Intl\.DateTimeFormat.*timeZone/i.test(allScripts);
    features.antiAnalysis = antiAnalysis;
    if (antiAnalysis) {
      totalRisk += 18;
      breakdown.push("Anti-analysis/bot-detection code found (+18)");
    }

    // ── Collect page metadata for VisualBrandAnalyzer ─────────
    const pageMeta = {
      title:    pageTitle,
      metaDesc: document.querySelector('meta[name="description"]')?.content || "",
      ogSite:   document.querySelector('meta[property="og:site_name"]')?.content || "",
      ogTitle:  document.querySelector('meta[property="og:title"]')?.content || "",
      lang:     document.documentElement.lang || "",
      headings: [...document.querySelectorAll("h1,h2")].map(h => h.textContent.trim()).slice(0, 5),
      bodyText: (document.body?.innerText || "").substring(0, 3000)
    };


    // ─────── NEW CHECKS v3 ─────────────────────────────────

    // ── Check 23: TabNapping Detection ───────────────────
    // TabNapping: page listens for visibility/focus events
    // and silently replaces itself with a fake login page
    // when you look away and come back.
    // Attacker: You think you left Gmail open → you see login → enter password
    const tabNappingPatterns = [
      /document\.addEventListener\s*\(\s*['"]visibilitychange['"]/i,
      /document\.addEventListener\s*\(\s*['"]blur['"]/i,
      /window\.addEventListener\s*\(\s*['"]blur['"]/i,
      /document\.hidden/i,
      /visibilityState/i,
    ];
    const tabNappingCount = tabNappingPatterns.filter(p => p.test(allScripts)).length;
    features.tabNappingSignals = tabNappingCount;
    // TabNapping only suspicious when combined with a login form
    if (tabNappingCount >= 2 && passwordFields.length > 0) {
      totalRisk += 22;
      breakdown.push(`TabNapping signals (${tabNappingCount} patterns) on login page (+22)`);
    }

    // ── Check 24: Missing Subresource Integrity ───────────
    // SRI (Subresource Integrity) = hash check on external scripts.
    // Real sites add integrity="sha384-..." to CDN scripts.
    // Missing SRI = external script could be tampered without detection.
    // We only flag when loading from CDN but missing SRI on a login page.
    const externalScripts = [...document.querySelectorAll('script[src]')]
      .filter(s => {
        try { return new URL(s.src).hostname !== currentHost; } catch { return false; }
      });
    const missingIntegrity = externalScripts.filter(s => !s.integrity).length;
    features.missingIntegrityCount = missingIntegrity;
    if (missingIntegrity >= 3 && passwordFields.length > 0 && !isHTTPS) {
      totalRisk += 12;
      breakdown.push(`${missingIntegrity} external scripts without SRI on login page (+12)`);
    }

    // ── Check 25: DOM Mutation on Focus ──────────────────
    // Phishing kits replace form action or input targets dynamically
    // using MutationObserver to avoid static analysis.
    const usesMutationObserver = /new\s+MutationObserver/i.test(allScripts) &&
                                  document.querySelectorAll("form").length > 0;
    features.mutationObserver = usesMutationObserver;
    if (usesMutationObserver && externalFormCount > 0) {
      totalRisk += 18;
      breakdown.push("MutationObserver on page with external form submission (+18)");
    }

    // ── Check 26: Fake Progress Bar / Loading Screen ──────
    // Many phishing kits show a fake "Verifying..." loading bar
    // to make the page look more legitimate and keep user engaged.
    const fakeProgress =
      /progress.{0,20}(verif|check|load|process)/i.test(pageText) &&
      (document.querySelectorAll('[class*="progress"],[class*="loader"],[class*="spinner"]').length > 0) &&
      externalFormCount > 0;
    features.fakeProgress = fakeProgress;
    if (fakeProgress) {
      totalRisk += 15;
      breakdown.push("Fake progress/verification UI with external form (+15)");
    }

    // ── Check 27: Window Popup Spam ───────────────────────
    // Phishing pages open many popup windows to confuse users.
    // Detect: multiple window.open() calls in scripts.
    const windowOpenCount = (allScripts.match(/window\.open\s*\(/g) || []).length;
    features.windowOpenCount = windowOpenCount;
    if (windowOpenCount >= 3) {
      totalRisk += 15;
      breakdown.push(`${windowOpenCount} window.open() calls (popup spam) (+15)`);
    }

    // ── Check 28: Fake HTTPS Padlock in Page Content ──────
    // Scammers show a padlock emoji or image INSIDE the page content
    // to trick users into thinking HTTP page is secure.
    // "🔒 Your connection is secure" — but actually HTTP!
    const fakePadlock =
      (pageText.includes("🔒") || /secure connection|ssl.{0,10}protect/i.test(pageText)) &&
      !isHTTPS;
    features.fakePadlock = fakePadlock;
    if (fakePadlock) {
      totalRisk += 25;
      breakdown.push("Fake security/padlock indicator on HTTP page (+25)");
    }

    // ── Check 29: Credential Autofill Blocking ────────────
    // Phishing pages set autocomplete="off" on ALL fields
    // to prevent password managers from flagging wrong domain.
    // (Password managers won't fill paypal credentials on fake-paypal.tk)
    const allInputsArr = [...document.querySelectorAll("input")];
    const autocompleteOff = allInputsArr.filter(i =>
      i.autocomplete === "off" || i.getAttribute("autocomplete") === "off"
    ).length;
    const hasLoginInputs = passwordFields.length > 0 || allInputsArr.some(i =>
      /email|username|user|login/i.test(i.name + i.id + i.type)
    );
    features.autocompleteOffCount = autocompleteOff;
    if (autocompleteOff >= 2 && hasLoginInputs) {
      totalRisk += 15;
      breakdown.push(`autocomplete="off" on ${autocompleteOff} inputs (blocks password manager) (+15)`);
    }

    // ── Check 30: Send Page Text for TF-IDF Analysis ─────
    // We send the page text to background.js for TF-IDF analysis.
    // This is done separately — it arrives as a separate message type.
    // (Keeps the DOM scan fast, text analysis is async)
    const extractedText = (document.body?.innerText || "").substring(0, 8000);
    if (extractedText.length > 100) {
      browser.runtime.sendMessage({
        type: "PAGE_TEXT",
        text: extractedText,
      }).catch(() => {});
    }

    // ── Normalize & Send (v3 — 29 checks) ─────────────────────
    const score = Math.min(100, Math.round((totalRisk / 160) * 100));

    browser.runtime.sendMessage({
      type: "DOM_RESULT",
      data: { score, features, breakdown, rawRisk: totalRisk, pageMeta }
    }).catch(() => {});
  }
})();
