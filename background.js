// background.js - PhishGuard (Manifest V3 service worker)
// Robust typosquat detection + storage-backed trusted domains + notifications + badge updates

// ---------- Defaults / Config ----------
let TRUSTED_REGISTERED_DOMAINS = new Set([
    'facebook.com',
    'tiktok.com'
]);

const DEFAULT_TRUSTED = Array.from(TRUSTED_REGISTERED_DOMAINS);

const TYPOSQUAT_DISTANCE_THRESHOLD = 0.30; // smaller => stricter
const TYPOSQUAT_SCORE_BUMP = 0.75;

// keep track of notifications sent per alert id (e.g. link)
const notificationsSent = {}; // { [alertId]: count }

// ---------- Utilities ----------
function safeGetHostname(urlOrHost) {
    try {
        if (!urlOrHost) return '';
        if (!/^https?:\/\//i.test(urlOrHost)) {
            if (/^[a-z0-9.-]+$/i.test(urlOrHost)) return urlOrHost.toLowerCase();
            urlOrHost = 'https://' + urlOrHost;
        }
        return new URL(urlOrHost).hostname.toLowerCase();
    } catch (e) {
        return (urlOrHost || '').toString().toLowerCase();
    }
}

function getLabels(hostname) {
    return (hostname || '').split('.').filter(Boolean);
}

function getRegisteredDomain(hostname) {
    const parts = getLabels(hostname);
    if (parts.length >= 2) return parts.slice(-2).join('.');
    return hostname || '';
}

function getSecondLevelLabel(hostname) {
    const parts = getLabels(hostname);
    if (!parts.length) return '';
    if (parts.length >= 2) return parts[parts.length - 2].toLowerCase();
    return parts[0].toLowerCase();
}

function isIpAddress(hostname) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
}

function isPunycode(hostname) {
    return typeof hostname === 'string' && hostname.includes('xn--');
}

function getTld(hostname) {
    const parts = (hostname || '').split('.');
    return parts.length ? parts[parts.length - 1].toLowerCase() : '';
}

function normalizeText(s) {
    return (s || '').toString().trim().toLowerCase();
}

// Levenshtein distance (iterative)
function levenshtein(a = '', b = '') {
    if (a === b) return 0;
    if (!a.length) return b.length;
    if (!b.length) return a.length;
    const v0 = new Array(b.length + 1);
    const v1 = new Array(b.length + 1);
    for (let i = 0; i <= b.length; i++) v0[i] = i;
    for (let i = 0; i < a.length; i++) {
        v1[0] = i + 1;
        for (let j = 0; j < b.length; j++) {
            const cost = a[i] === b[j] ? 0 : 1;
            v1[j + 1] = Math.min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost);
        }
        for (let j = 0; j <= b.length; j++) v0[j] = v1[j];
    }
    return v1[b.length];
}

function normalizedDistance(a = '', b = '') {
    const A = (a || '').toString();
    const B = (b || '').toString();
    const maxLen = Math.max(A.length, B.length, 1);
    return levenshtein(A, B) / maxLen;
}

// ---------- Heuristics ----------
const RISKY_TLDS = new Set([
    'xyz', 'top', 'club', 'pw', 'icu', 'work', 'gq', 'cf', 'tk', 'ml', 'ga', 'biz', 'click', 'win', 'loan', 'party'
]);

function hostIsTrustedExact(hostname) {
    if (!hostname) return false;
    const reg = getRegisteredDomain(hostname).toLowerCase();
    return TRUSTED_REGISTERED_DOMAINS.has(reg);
}

// ---------- Link analysis ----------
function linkIsSuspicious(linkUrl, pageHostnameNormalized, reasons) {
    try {
        const url = new URL(linkUrl, 'https://' + (pageHostnameNormalized || 'example.com'));
        const host = (url.hostname || '').toLowerCase();
        const path = (url.pathname || '').toLowerCase();

        if (!host) {
            reasons.push(`Empty host for link: ${linkUrl}`);
            return 0.02;
        }

        if (isIpAddress(host)) {
            reasons.push(`Link uses raw IP address (${host})`);
            return 0.20;
        }

        if (isPunycode(host)) {
            reasons.push(`Link contains punycode domain (${host})`);
            return 0.18;
        }

        const tld = getTld(host);
        if (RISKY_TLDS.has(tld)) {
            reasons.push(`Link uses uncommon TLD .${tld} (${host})`);
            return 0.12;
        }

        const suspiciousPathPatterns = ['verify', 'confirm', 'signin', 'login', 'account', 'secure', 'billing', 'payment'];
        for (const p of suspiciousPathPatterns) {
            if (path.includes(p)) {
                reasons.push(`Link path contains suspicious token "${p}" (${url.pathname})`);
                return 0.10;
            }
        }

        const brandTokens = ['secure', 'login', 'paypal', 'bank', 'apple', 'google', 'microsoft'];
        if (host !== pageHostnameNormalized) {
            for (const t of brandTokens) {
                if (host.includes(t)) {
                    reasons.push(`External link appears to impersonate brand token "${t}" (${host})`);
                    return 0.14;
                }
            }
        }

        return 0;
    } catch (e) {
        reasons.push(`Malformed/relative link flagged: ${linkUrl}`);
        return 0.05;
    }
}

// ---------- Main analysis function (pure) ----------
function analyzeProfileCore(data = {}, trustedSet = null) {
    const TRUSTED = trustedSet instanceof Set ? trustedSet : TRUSTED_REGISTERED_DOMAINS;

    const usernameRaw = data.username || data.handle || data.user || '';
    const username = normalizeText(usernameRaw).replace(/^@/, '');
    const displayName = normalizeText(data.displayName || data.fullName || data.title || '');
    const url = data.url || data.pageUrl || data.origin || '';
    const pageHostname = safeGetHostname(url) || (data.hostname ? safeGetHostname(data.hostname) : '');
    const links = Array.isArray(data.links) ? data.links : (data.linkList || []);
    const forms = Array.isArray(data.forms) ? data.forms : (data.formList || []);
    const textSample = (data.textSample || '').toString().slice(0, 4000);

    const reasons = [];
    const trustedExact = hostIsTrustedExact(pageHostname);
    let score = trustedExact ? 0.02 : 0.25;
    let suspicious = false;

    // ---------- Typosquat detection (SLD-first) ----------
    try {
        const currentReg = getRegisteredDomain(pageHostname).toLowerCase();
        const currentSld = getSecondLevelLabel(pageHostname);

        if (!TRUSTED.has(currentReg)) {
            let best = { domain: null, dist: 1.0, sld: null };
            for (const td of TRUSTED) {
                const tdSld = getSecondLevelLabel(td);
                const d = normalizedDistance(currentSld, tdSld);
                if (d < best.dist) best = { domain: td, dist: d, sld: tdSld };
            }

            if (best.domain && best.dist <= TYPOSQUAT_DISTANCE_THRESHOLD) {
                reasons.push(`Domain SLD "${currentSld}" closely resembles trusted SLD "${best.sld}" (distance ${best.dist.toFixed(2)}). Treated as typosquat (${currentReg} ~ ${best.domain}).`);
                suspicious = true;
                score = Math.max(score, TYPOSQUAT_SCORE_BUMP);
            } else {
                let bestFull = { domain: null, dist: 1.0 };
                for (const td of TRUSTED) {
                    const d = normalizedDistance(currentReg, td);
                    if (d < bestFull.dist) bestFull = { domain: td, dist: d };
                }
                if (bestFull.domain && bestFull.dist <= TYPOSQUAT_DISTANCE_THRESHOLD) {
                    reasons.push(`Registered domain "${currentReg}" somewhat resembles trusted domain "${bestFull.domain}" (distance ${bestFull.dist.toFixed(2)}).`);
                    suspicious = true;
                    score = Math.max(score, TYPOSQUAT_SCORE_BUMP);
                } else {
                    reasons.push('No similarity to trusted domains detected');
                }
            }

            const BRAND_KEYWORDS = {
                'facebook': ['faceb', 'fbk', 'fb', 'facebok', 'faceboek', 'faceboook'],
                'tiktok': ['tiktok', 'ttk', 'tik-tok']
            };
            for (const [brand, keywords] of Object.entries(BRAND_KEYWORDS)) {
                for (const kw of keywords) {
                    if ((currentSld && currentSld.includes(kw)) && !TRUSTED.has(currentReg)) {
                        reasons.push(`Domain SLD "${currentSld}" contains brand-like token "${kw}" (looks like ${brand})`);
                        suspicious = true;
                        score = Math.max(score, 0.65);
                    }
                }
            }
        } else {
            reasons.push('Exact registered domain is trusted');
        }
    } catch (e) {
        reasons.push('Error during typosquat check');
    }

    // ---------- HTTPS check ----------
    if (!/^https:/i.test(url)) {
        reasons.push('Page not served over HTTPS');
        score += 0.20;
        if (trustedExact && !suspicious) score = Math.min(score, 0.05);
    }

    // ---------- Forms ----------
    for (const f of forms) {
        try {
            if (f.hasPassword && f.action) {
                const actionHost = safeGetHostname(f.action);
                if (actionHost && actionHost !== pageHostname && !actionHost.includes(pageHostname.split('.').slice(-2).join('.'))) {
                    reasons.push(`Login form posts to external host (${actionHost})`);
                    score += 0.40;
                    suspicious = true;
                }
            } else if (f.inputCount > 0 && !f.hasPassword && f.action) {
                reasons.push('Form with inputs but no password field (possible data harvesting)');
                score += trustedExact ? 0.02 : 0.06;
            }
        } catch (e) {
            reasons.push('Malformed form action detected');
            score += 0.04;
        }
    }

    // ---------- Links ----------
    if (links && links.length) {
        let linkRiskSum = 0;
        const maxLinkContribution = trustedExact ? 0.15 : 0.40;
        for (const L of links.slice(0, 40)) {
            const linkScore = linkIsSuspicious(L, pageHostname, reasons);
            linkRiskSum += linkScore;
        }
        const linkContribution = Math.min(maxLinkContribution, linkRiskSum / Math.max(1, links.length));
        score += linkContribution;
        if (linkContribution >= 0.3) suspicious = true;
    }

    // ---------- Text heuristics ----------
    if (textSample) {
        const lower = textSample.toLowerCase();
        const redFlags = [
            'your account will be locked', 'verify your account', 'click here to verify',
            'confirm your identity', 'payment required', 'suspend', 'urgent action required'
        ];
        for (const f of redFlags) {
            if (lower.includes(f)) {
                reasons.push(`Suspicious page text matched: "${f}"`);
                score += trustedExact ? 0.20 : 0.08;
                suspicious = true;
            }
        }
    }

    // ---------- Misc hostname checks ----------
    if (isPunycode(pageHostname)) {
        reasons.push('Page hostname uses punycode');
        score += 0.40;
        suspicious = true;
    }
    if (isIpAddress(pageHostname)) {
        reasons.push('Page served from IP address');
        score += 0.40;
        suspicious = true;
    }

    // ---------- Canonical/OG mismatch ----------
    if (data.ogUrl || data.canonical) {
        try {
            const canonical = data.ogUrl || data.canonical;
            const canonicalHost = safeGetHostname(canonical);
            if (canonicalHost && pageHostname) {
                const norm = normalizedDistance(canonicalHost.replace(/^www\./, ''), pageHostname.replace(/^www\./, ''));
                if (norm > 0.35) {
                    reasons.push(`Canonical/OG domain mismatch (normalized distance ${norm.toFixed(2)})`);
                    score += trustedExact ? 0.20 : 0.12;
                    suspicious = true;
                } else {
                    if (!trustedExact) reasons.push('Canonical/OG domain matches page');
                }
            }
        } catch (e) { /* ignore */ }
    }

    // ---------- Final trustedExact handling ----------
    if (trustedExact && !suspicious) {
        const weakPatterns = [/hyphen/i, /subdomain/i, /depth/i, /no similarity to trusted domains detected/i, /multiple capitalized tokens/i];
        for (let i = reasons.length - 1; i >= 0; i--) {
            if (weakPatterns.some(rx => rx.test(reasons[i]))) reasons.splice(i, 1);
        }
        score = Math.min(score, 0.05);
    }

    score = Math.max(0, Math.min(1, score));
    if (suspicious || score >= 0.55) suspicious = true;
    else suspicious = false;

    const details = {
        username,
        displayName,
        isVerified: !!data.isVerified,
        isBrand: !!data.isBrand,
        pageHostname,
        url,
        linksCount: links.length,
        formsCount: forms.length
    };

    return { suspicious, score, reasons, details };
}

// ---------- Notification helper ----------
function createPhishNotification(alertId, origin, result, rawMsg) {
    try {
        // ensure max 2 notifications per alertId
        const idKey = alertId || origin || `a-${Date.now()}`;
        notificationsSent[idKey] = notificationsSent[idKey] || 0;
        if (notificationsSent[idKey] >= 2) return false;
        notificationsSent[idKey]++;

        const title = result && result.suspicious ? 'Possible phishing detected' : 'Site looks OK';
        const message = rawMsg || (result && result.suspicious
            ? `Suspicion ${Math.round(result.score * 100)}% for ${origin}. Click to review.`
            : `Checked ${origin}: score ${Math.round(result.score * 100)}%`);

        const options = { type: 'basic', iconUrl: 'icons/icon128.png', title, message };
        chrome.notifications.create(`phish-${Date.now()}`, options, (nid) => { setTimeout(() => chrome.notifications.clear(nid), 8000); });
        return true;
    } catch (e) { console.warn('createPhishNotification failed', e); return false; }
}

// ---------- Badge helper ----------
function updateBadgeForTab(tabId, suspicious) {
    try {
        if (chrome.action && chrome.action.setBadgeText) {
            chrome.action.setBadgeText({ tabId, text: suspicious ? '!' : '' });
            chrome.action.setBadgeBackgroundColor({ color: suspicious ? '#d93025' : '#34a853' });
        }
    } catch (e) { console.warn('Badge update failed', e); }
}

// ---------- Storage helpers ----------
function saveLastResultForOrigin(originHost, result) {
    try {
        if (!originHost) return;
        const key = `lastResult:${originHost}`;
        const toSave = {};
        toSave[key] = { result, timestamp: Date.now() };
        chrome.storage.local.set(toSave);
    } catch (e) { console.warn('saveLastResultForOrigin failed', e); }
}

// ---------- Message listener ----------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    (async () => {
        try {
            if (!message || typeof message !== 'object') { sendResponse({ ok: false, error: 'invalid_message' }); return; }
            const msgType = (message.type || '').toString();
            if (!msgType) { sendResponse({ ok: false, error: 'missing_type' }); return; }

            const loadTrusted = () => new Promise((resolve) => {
                chrome.storage.sync.get({ trustedDomains: DEFAULT_TRUSTED }, (res) => {
                    try {
                        const arr = Array.isArray(res.trustedDomains) ? res.trustedDomains : DEFAULT_TRUSTED.slice();
                        const set = new Set(arr.map(s => {
                            try { return getRegisteredDomain(s.toString().toLowerCase()); } catch { return s.toString().toLowerCase(); }
                        }).filter(Boolean));
                        resolve(set);
                    } catch (e) { resolve(new Set(DEFAULT_TRUSTED)); }
                });
            });

            if (msgType === 'analyzeProfile') {
                const data = message.data || {};
                const trustedSet = await loadTrusted();
                TRUSTED_REGISTERED_DOMAINS = new Set(trustedSet);

                const result = analyzeProfileCore(data, trustedSet);

                try {
                    const origin = safeGetHostname(data.url || (sender && sender.tab && sender.tab.url) || '');
                    if (origin) saveLastResultForOrigin(origin, result);
                } catch (e) { /* ignore */ }

                try { if (sender && sender.tab && typeof sender.tab.id === 'number') updateBadgeForTab(sender.tab.id, result.suspicious); } catch (e) { }

                if (result.suspicious) {
                    const origin = safeGetHostname(data.url || (sender && sender.tab && sender.tab.url) || '') || data.url || 'site';
                    // do not auto-notify here; content may request a phish_alert message separately.
                    // But we can optionally create a notification here if desired:
                    // createPhishNotification(origin, origin, result);
                }

                sendResponse({ ok: true, result });
                return;
            }

            if (msgType === 'phish_alert') {
                // Expect message to include: { id: string, msg: string, origin?: string, result?: object }
                const alertId = (message.id || '').toString();
                const rawMsg = message.msg || 'Possible phishing detected';
                const origin = message.origin || '';
                const result = message.result || null;

                const created = createPhishNotification(alertId || origin, origin, result, rawMsg);
                sendResponse({ ok: true, notified: !!created });
                return;
            }

            if (msgType === 'check_host') {
                chrome.storage.sync.get('optedSites', (res) => { sendResponse({ ok: true, optedSites: res.optedSites || {} }); });
                return;
            }

            sendResponse({ ok: false, reason: 'unknown_type', receivedType: msgType });
            return;
        } catch (err) {
            console.error('Exception in background onMessage handler:', err);
            sendResponse({ ok: false, error: 'exception', message: (err && err.message) || String(err) });
            return;
        }
    })();
    return true;
});

// ---------- Notification click handler ----------
chrome.notifications.onClicked.addListener((notificationId) => {
    try { chrome.tabs.create({ url: 'popup.html' }); } catch (e) { console.warn(e); }
});
