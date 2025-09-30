// options.js — logic for PhishGuard options page
// Uses chrome.storage.sync to persist settings

const DEFAULTS = {
    trustedDomains: ["tiktok.com", "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com", "youtube.com"],
    enabledSites: {}, // map of origin -> true (opt-in)
    showInlineBadge: false
};

document.addEventListener("DOMContentLoaded", () => {
    const trustedListEl = document.getElementById("trustedList");
    const trustedInput = document.getElementById("trustedInput");
    const addTrustedBtn = document.getElementById("addTrusted");
    const clearTrustedBtn = document.getElementById("clearTrusted");

    const enabledListEl = document.getElementById("enabledList");
    const enabledInput = document.getElementById("enabledInput");
    const addEnabledBtn = document.getElementById("addEnabled");
    const clearEnabledBtn = document.getElementById("clearEnabled");

    const showInlineEl = document.getElementById("showInlineBadge");
    const saveBtn = document.getElementById("saveBtn");
    const restoreBtn = document.getElementById("restoreBtn");
    const statusEl = document.getElementById("status");

    const jsonBox = document.getElementById("jsonBox");
    const exportBtn = document.getElementById("exportBtn");
    const importBtn = document.getElementById("importBtn");

    let state = { ...DEFAULTS };

    // Helpers
    function hostOnly(s) {
        if (!s) return "";
        s = s.trim();
        // remove protocol if present
        try {
            const u = new URL(s);
            return u.hostname.toLowerCase();
        } catch (e) {
            // fallback: strip path if contains /
            return s.split("/")[0].toLowerCase();
        }
    }

    function renderTrusted() {
        trustedListEl.innerHTML = "";
        state.trustedDomains.forEach((d, i) => {
            const item = document.createElement("div");
            item.className = "item";
            const span = document.createElement("span");
            span.textContent = d;
            const rem = document.createElement("button");
            rem.textContent = "Remove";
            rem.addEventListener("click", () => {
                state.trustedDomains.splice(i, 1);
                renderTrusted();
            });
            item.appendChild(span);
            item.appendChild(rem);
            trustedListEl.appendChild(item);
        });
    }

    function renderEnabled() {
        enabledListEl.innerHTML = "";
        const keys = Object.keys(state.enabledSites || {});
        if (!keys.length) {
            const n = document.createElement("div");
            n.className = "muted";
            n.textContent = "No enabled sites configured (empty = allow all pages to be scanned).";
            enabledListEl.appendChild(n);
            return;
        }
        keys.forEach((h) => {
            const item = document.createElement("div");
            item.className = "item";
            const span = document.createElement("span");
            span.textContent = h;
            const rem = document.createElement("button");
            rem.textContent = "Remove";
            rem.addEventListener("click", () => {
                delete state.enabledSites[h];
                renderEnabled();
            });
            item.appendChild(span);
            item.appendChild(rem);
            enabledListEl.appendChild(item);
        });
    }

    function setStatus(msg, timeout = 2000) {
        statusEl.textContent = msg;
        if (timeout) setTimeout(() => { if (statusEl.textContent === msg) statusEl.textContent = ""; }, timeout);
    }

    // Load saved
    chrome.storage.sync.get(DEFAULTS, (res) => {
        state.trustedDomains = Array.isArray(res.trustedDomains) ? res.trustedDomains : DEFAULTS.trustedDomains.slice();
        state.enabledSites = typeof res.enabledSites === "object" && res.enabledSites ? res.enabledSites : {};
        state.showInlineBadge = !!res.showInlineBadge;
        showInlineEl.checked = state.showInlineBadge;
        renderTrusted();
        renderEnabled();
    });

    // Add trusted
    addTrustedBtn.addEventListener("click", () => {
        const v = hostOnly(trustedInput.value);
        if (!v) return setStatus("Enter a valid hostname");
        if (!state.trustedDomains.includes(v)) state.trustedDomains.push(v);
        trustedInput.value = "";
        renderTrusted();
    });
    clearTrustedBtn.addEventListener("click", () => {
        if (!confirm("Clear all trusted domains?")) return;
        state.trustedDomains = [];
        renderTrusted();
    });

    // Add enabled
    addEnabledBtn.addEventListener("click", () => {
        let v = (enabledInput.value || "").trim();
        if (!v) return setStatus("Enter a valid site origin or hostname");
        // normalize
        try {
            const u = new URL(v);
            v = u.origin;
        } catch (e) {
            // accept just hostname
            v = hostOnly(v);
        }
        if (!v) return setStatus("Invalid host/origin");
        state.enabledSites[v] = true;
        enabledInput.value = "";
        renderEnabled();
    });
    clearEnabledBtn.addEventListener("click", () => {
        if (!confirm("Clear all enabled sites?")) return;
        state.enabledSites = {};
        renderEnabled();
    });

    // Save
    saveBtn.addEventListener("click", () => {
        state.showInlineBadge = !!showInlineEl.checked;
        chrome.storage.sync.set({
            trustedDomains: state.trustedDomains,
            enabledSites: state.enabledSites,
            showInlineBadge: state.showInlineBadge
        }, () => {
            setStatus("Saved");
        });
    });

    // Restore defaults
    restoreBtn.addEventListener("click", () => {
        if (!confirm("Restore defaults? This will replace current settings.")) return;
        state = { ...DEFAULTS, trustedDomains: DEFAULTS.trustedDomains.slice(), enabledSites: {} };
        showInlineEl.checked = state.showInlineBadge;
        renderTrusted();
        renderEnabled();
        chrome.storage.sync.set({ trustedDomains: state.trustedDomains, enabledSites: state.enabledSites, showInlineBadge: state.showInlineBadge }, () => {
            setStatus("Defaults restored");
        });
    });

    // Export settings to JSON
    exportBtn.addEventListener("click", () => {
        const data = {
            trustedDomains: state.trustedDomains,
            enabledSites: state.enabledSites,
            showInlineBadge: state.showInlineBadge
        };
        jsonBox.value = JSON.stringify(data, null, 2);
        setStatus("Export ready in box");
    });

    // Import settings from JSON in textarea
    importBtn.addEventListener("click", () => {
        const txt = (jsonBox.value || "").trim();
        if (!txt) return setStatus("Paste JSON to import");
        try {
            const parsed = JSON.parse(txt);
            if (Array.isArray(parsed.trustedDomains)) state.trustedDomains = parsed.trustedDomains.map(hostOnly).filter(Boolean);
            if (parsed.enabledSites && typeof parsed.enabledSites === "object") state.enabledSites = parsed.enabledSites;
            state.showInlineBadge = !!parsed.showInlineBadge;
            showInlineEl.checked = state.showInlineBadge;
            renderTrusted();
            renderEnabled();
            chrome.storage.sync.set({ trustedDomains: state.trustedDomains, enabledSites: state.enabledSites, showInlineBadge: state.showInlineBadge }, () => {
                setStatus("Imported and saved");
            });
        } catch (e) {
            setStatus("Invalid JSON: " + e.message);
        }
    });
});