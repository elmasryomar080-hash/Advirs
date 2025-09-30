// content.js - detect phishing links in Facebook redirectors (Advirs)

(function () {
    const detectedLinksInfo = new Map();
    let __advirs_payload = null;

    function buildPayload() {
        const url = location.href;
        const hostname = location.hostname.toLowerCase();
        const title = document.querySelector("title")?.innerText || "";
        const bodyText = document.body?.innerText || "";
        const rawHTML = document.documentElement.innerHTML || "";

        const handleMatch = bodyText.match(/@[A-Za-z0-9_.-]{2,40}/);
        const username = handleMatch ? handleMatch[0] : "";

        const domLinks = Array.from(document.querySelectorAll("a[href]"))
            .map(a => {
                try { return new URL(a.getAttribute("href"), url).href; } catch { return null; }
            })
            .filter(Boolean);

        const textLinks = (bodyText.match(/https?:\/\/[^\s"'<>]+/gi) || []);

        const roleLinks = [];
        const roleRegex = /role="link"[^>]*>(https?:\/\/[^\s"'<>]+)</gi;
        let m;
        while ((m = roleRegex.exec(rawHTML)) !== null) {
            roleLinks.push(m[1]);
        }

        let allLinks = Array.from(new Set([...domLinks, ...textLinks, ...roleLinks]));

        const decodedLinks = [];
        allLinks.forEach(href => {
            try {
                const u = new URL(href);
                if (u.hostname.includes("facebook.com") && u.pathname.startsWith("/l.php")) {
                    const real = u.searchParams.get("u");
                    if (real) decodedLinks.push(decodeURIComponent(real));
                }
            } catch { }
        });
        allLinks = Array.from(new Set([...allLinks, ...decodedLinks]));

        const forms = Array.from(document.forms).slice(0, 20).map(f => {
            const inputs = f.querySelectorAll("input, textarea, select");
            return {
                action: f.action || "",
                method: (f.method || "").toLowerCase(),
                inputCount: inputs.length,
                hasPassword: !!f.querySelector("input[type='password']")
            };
        });

        return {
            url,
            hostname,
            username,
            displayName: title.slice(0, 120),
            isVerified: !!document.querySelector("[aria-label*='verified'], .verified, .badge--verified, [title*='Verified']"),
            links: allLinks,
            forms,
            textSample: bodyText.slice(0, 4000),
            timestamp: Date.now()
        };
    }

    function analyzeLink(href) {
        if (!href) return;
        const info = detectedLinksInfo.get(href) || { count: 0, lastSeen: 0 };
        if (info.count >= 2) {
            info.lastSeen = Date.now();
            detectedLinksInfo.set(href, info);
            return;
        }

        chrome.runtime.sendMessage({ type: "analyzeProfile", data: { url: href } }, (resp) => {
            if (resp && resp.result && resp.result.suspicious) {
                chrome.runtime.sendMessage({
                    type: "phish_alert",
                    id: href,
                    origin: href,
                    result: resp.result,
                    msg: `⚠️ تم اكتشاف رابط مشبوه:\n${href}\nالسبب: ${(resp.result.reasons || []).join("، ")}`
                }, (r) => {
                    if (r && r.ok) {
                        const updated = detectedLinksInfo.get(href) || { count: 0, lastSeen: 0 };
                        updated.count = Math.min(2, (updated.count || 0) + (r.notified ? 1 : 0));
                        updated.lastSeen = Date.now();
                        detectedLinksInfo.set(href, updated);
                    }
                });
            } else {
                info.lastSeen = Date.now();
                detectedLinksInfo.set(href, info);
            }
        });
    }

    function analyzePayload(payload) {
        chrome.runtime.sendMessage({ type: "analyzeProfile", data: payload }, (resp) => {
            if (resp && resp.result && resp.result.suspicious) {
                chrome.runtime.sendMessage({
                    type: "phish_alert",
                    id: payload.url || payload.hostname || `page-${Date.now()}`,
                    origin: payload.url,
                    result: resp.result,
                    msg: `⚠️ تم اكتشاف صفحة مشبوهة:\n${payload.url}\nالسبب: ${(resp.result.reasons || []).join("، ")}`
                });
            }
        });

        payload.links.slice(0, 40).forEach(href => analyzeLink(href));
    }

    // Run immediately
    __advirs_payload = buildPayload();
    analyzePayload(__advirs_payload);

    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
        if (!msg || typeof msg !== "object") return;
        if (msg.type === "getPayload") {
            sendResponse({ ok: true, payload: __advirs_payload });
        }
        if (msg.type === "analyzeNow") {
            analyzePayload(__advirs_payload);
            sendResponse({ ok: true });
            return true;
        }
        return true;
    });

    const observer = new MutationObserver(() => {
        const newPayload = buildPayload();
        newPayload.links.forEach(href => {
            if (document.body.innerHTML.includes(href)) {
                analyzeLink(href);
            }
        });
        __advirs_payload = newPayload;

        const now = Date.now();
        for (const [link, info] of detectedLinksInfo.entries()) {
            if ((now - (info.lastSeen || 0)) > (10 * 60 * 1000)) {
                detectedLinksInfo.delete(link);
            }
        }
    });

    observer.observe(document.body, { childList: true, subtree: true });
})();
