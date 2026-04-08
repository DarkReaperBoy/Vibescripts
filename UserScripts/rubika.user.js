// ==UserScript==
// @name         Rubika Bridge — E2E Encryption + Connectivity Fix
// @namespace    http://tampermonkey.net/
// @version      5.0
// @description  E2E encryption (ECDH key exchange, per-chat keys, Markdown), connectivity fix (fast DC racing, keepalive, reconnect, resync), draft blocker.
// @author       You
// @match        *://web.rubika.ir/*
// @grant        none
// @run-at       document-start
// ==/UserScript==

// ╔══════════════════════════════════════════════════════════════╗
// ║  PHASE 1: CONNECTIVITY FIX (runs at document-start)        ║
// ║  Patches WebSocket before Angular bootstraps.               ║
// ╚══════════════════════════════════════════════════════════════╝

(function(){
"use strict";

const _W = typeof unsafeWindow !== "undefined" ? unsafeWindow : window;
const OrigWebSocket = _W.WebSocket;
const DC_URL = "https://getdcmess.iranlms.ir/";

// ── DC Racing: test all endpoints in parallel, rank by speed ──

let _rankedApiUrls = [];   // sorted fastest→slowest
let _rankedSocketUrls = []; // sorted fastest→slowest
let _apiIdx = 0;           // current index into ranked list
let _socketIdx = 0;
let _allApiUrls = [];
let _allSocketUrls = [];
let _dcReady = false;
let _failedSockets = new Set(); // blacklist dead sockets temporarily

function getBestApiUrl() { return _rankedApiUrls[_apiIdx] || _rankedApiUrls[0] || null; }
function getBestSocketUrl() {
    // Skip blacklisted sockets
    for (let i = 0; i < _rankedSocketUrls.length; i++) {
        const idx = (_socketIdx + i) % _rankedSocketUrls.length;
        if (!_failedSockets.has(_rankedSocketUrls[idx])) return _rankedSocketUrls[idx];
    }
    return _rankedSocketUrls[0] || null; // everything failed, try first anyway
}

function rotateApiUrl() {
    if (_rankedApiUrls.length > 1) {
        _apiIdx = (_apiIdx + 1) % _rankedApiUrls.length;
        console.log(`[RB-Fix] Rotated API → ${_rankedApiUrls[_apiIdx]}`);
    }
}

function rotateSocketUrl(failedUrl) {
    if (failedUrl) {
        _failedSockets.add(failedUrl);
        // Unblacklist after 30s — it might recover
        setTimeout(() => _failedSockets.delete(failedUrl), 30000);
    }
    if (_rankedSocketUrls.length > 1) {
        _socketIdx = (_socketIdx + 1) % _rankedSocketUrls.length;
        console.log(`[RB-Fix] Rotated socket → ${getBestSocketUrl()}`);
    }
}

async function raceDCs() {
    try {
        const resp = await fetch(DC_URL, {
            headers: {"User-Agent": navigator.userAgent},
            signal: AbortSignal.timeout(12000)
        });
        const json = await resp.json();
        const d = json.data || json;

        // Collect all API URLs
        if (d.API) _allApiUrls = Object.values(d.API).filter(u => u);
        if (d.default_api) {
            const da = String(d.default_api);
            if (d.API && d.API[da]) _allApiUrls.unshift(d.API[da]);
        }
        if (d.default_apis) {
            for (const code of d.default_apis) {
                if (d.API && d.API[String(code)]) _allApiUrls.unshift(d.API[String(code)]);
            }
        }

        // Collect all Socket URLs
        if (d.socket) _allSocketUrls = Object.values(d.socket).filter(u => u);
        if (d.Socket) _allSocketUrls = Object.values(d.Socket).filter(u => u);
        if (d.default_socket) {
            const ds = String(d.default_socket);
            if ((d.socket||d.Socket) && (d.socket||d.Socket)[ds]) _allSocketUrls.unshift((d.socket||d.Socket)[ds]);
        }

        // Deduplicate
        _allApiUrls = [...new Set(_allApiUrls.map(u => u.endsWith("/") ? u : u + "/"))];
        _allSocketUrls = [...new Set(_allSocketUrls)];

        // Race ALL endpoints in parallel — rank by response time
        if (_allApiUrls.length > 0) {
            _rankedApiUrls = await rankEndpoints(_allApiUrls, "api");
        }
        if (_allSocketUrls.length > 0) {
            _rankedSocketUrls = await rankSocketEndpoints(_allSocketUrls);
        }

        _dcReady = true;
        console.log("[RB-Fix] DC race complete. API ranked:", _rankedApiUrls, "Socket ranked:", _rankedSocketUrls);
    } catch(e) {
        console.log("[RB-Fix] DC race failed:", e.message);
    }
}

async function rankEndpoints(urls, type) {
    // Race all, collect results with latency, sort fastest→slowest
    const results = await Promise.allSettled(urls.map(async url => {
        const start = performance.now();
        const resp = await fetch(url, {
            method: "POST",
            headers: {"Content-Type": "text/plain"},
            body: "{}",
            signal: AbortSignal.timeout(10000)
        });
        const latency = performance.now() - start;
        console.log(`[RB-Fix] ${type} ${url} → ${Math.round(latency)}ms`);
        return { url, latency };
    }));

    const ranked = results
        .filter(r => r.status === "fulfilled")
        .map(r => r.value)
        .sort((a, b) => a.latency - b.latency)
        .map(r => r.url);

    // Append any that failed (as fallbacks at the end)
    const responded = new Set(ranked);
    for (const url of urls) {
        if (!responded.has(url)) ranked.push(url);
    }
    return ranked;
}

async function rankSocketEndpoints(urls) {
    // Race all sockets, rank by open time
    return new Promise(resolve => {
        const results = [];
        const starts = {};
        let pending = urls.length;
        const sockets = [];

        const timeout = setTimeout(() => finish(), 10000);

        function finish() {
            clearTimeout(timeout);
            for (const s of sockets) try { s.close(); } catch(_) {}
            // Sort by open time, append any that didn't open
            const ranked = results.sort((a, b) => a.latency - b.latency).map(r => r.url);
            const opened = new Set(ranked);
            for (const url of urls) {
                if (!opened.has(url)) ranked.push(url);
            }
            resolve(ranked);
        }

        for (const url of urls) {
            try {
                starts[url] = performance.now();
                const ws = new OrigWebSocket(url);
                sockets.push(ws);
                ws.onopen = () => {
                    results.push({ url, latency: performance.now() - starts[url] });
                    console.log(`[RB-Fix] socket ${url} → ${Math.round(results[results.length-1].latency)}ms`);
                    pending--;
                    if (pending <= 0) finish();
                };
                ws.onerror = () => { pending--; if (pending <= 0) finish(); };
            } catch(_) { pending--; }
        }

        if (pending <= 0) finish();
    });
}

// Start racing immediately
raceDCs();

// ── Connectivity state ──

let activeSocket = null;
let activeSocketUrl = null;
let pingTimer = null;
let pongTimer = null;
let reconnectAttempts = 0;
let lastMessageTime = Date.now();
let lastVisibleTime = Date.now();
let wasHidden = false;
let statusEl = null;
let statusHideTimer = null;
let statusGraceTimer = null;
let handshakeData = null;

// Adaptive RTT tracking
let rttSamples = [];
let lastPingSentAt = 0;
const RTT_WINDOW = 10; // keep last 10 samples

function getAdaptivePongTimeout() {
    if (rttSamples.length < 3) return 12000; // conservative default until we have data
    const sorted = [...rttSamples].sort((a,b) => a - b);
    const p90 = sorted[Math.floor(sorted.length * 0.9)]; // 90th percentile
    return Math.max(5000, Math.min(20000, p90 * 3)); // 3x p90, clamped 5s–20s
}

function getAdaptivePingInterval() {
    if (rttSamples.length < 3) return 15000;
    const avg = rttSamples.reduce((a,b) => a+b, 0) / rttSamples.length;
    // Slower connections get less frequent pings to avoid congestion
    return Math.max(10000, Math.min(25000, avg * 8));
}

function recordRtt(ms) {
    rttSamples.push(ms);
    if (rttSamples.length > RTT_WINDOW) rttSamples.shift();
}

const CONN = {
    RECONNECT_BASE: 1000,
    RECONNECT_MAX: 30000,
    RECONNECT_MULT: 1.5,
    VISIBILITY_GRACE: 5000,
    STATUS_SHOW_MS: 4000,
    DISCONNECT_GRACE: 3000, // don't show "disconnected" for blips shorter than this
    PRECONNECT_RTT_THRESH: 3, // if pong takes >3x avg RTT, preemptively prepare backup
};

// ── Status indicator with grace period ──

function ensureStatusUI() {
    if (statusEl && document.body && document.body.contains(statusEl)) return;
    if (!document.body) return;
    statusEl = document.createElement("div");
    statusEl.id = "rb-conn-status";
    Object.assign(statusEl.style, {
        position:"fixed",top:"8px",left:"50%",
        transform:"translateX(-50%) translateY(-50px)",
        background:"rgba(0,0,0,0.85)",color:"#fff",
        padding:"6px 16px",borderRadius:"20px",fontSize:"12px",
        fontWeight:"600",fontFamily:"inherit",zIndex:"9999999",
        pointerEvents:"none",transition:"transform .3s cubic-bezier(.2,.8,.2,1),opacity .3s",
        opacity:"0",whiteSpace:"nowrap",backdropFilter:"blur(8px)",
        WebkitBackdropFilter:"blur(8px)",letterSpacing:".02em"
    });
    document.body.appendChild(statusEl);
}

function showStatus(text, color, persistent) {
    ensureStatusUI();
    if (!statusEl) return;
    statusEl.textContent = text;
    statusEl.style.background = color || "rgba(0,0,0,0.85)";
    statusEl.style.transform = "translateX(-50%) translateY(0)";
    statusEl.style.opacity = "1";
    clearTimeout(statusHideTimer);
    if (!persistent) statusHideTimer = setTimeout(hideStatus, CONN.STATUS_SHOW_MS);
}

// Show disconnect status only after grace period (avoids flashing on brief blips)
function showDisconnectGraceful(text, color) {
    clearTimeout(statusGraceTimer);
    statusGraceTimer = setTimeout(() => {
        // Only show if still disconnected
        if (!activeSocket || activeSocket.readyState !== OrigWebSocket.OPEN) {
            showStatus(text, color, true);
        }
    }, CONN.DISCONNECT_GRACE);
}

function cancelDisconnectGrace() {
    clearTimeout(statusGraceTimer);
}

function hideStatus() {
    if (!statusEl) return;
    statusEl.style.transform = "translateX(-50%) translateY(-50px)";
    statusEl.style.opacity = "0";
}

// ── Pre-connect: open backup DC before current one fully dies ──

let backupSocket = null;
let backupSocketUrl = null;

function preconnectBackup() {
    if (backupSocket && backupSocket.readyState <= OrigWebSocket.OPEN) return; // already have one
    const nextUrl = getBestSocketUrl();
    if (!nextUrl || nextUrl === activeSocketUrl) {
        // Try the one after current
        rotateSocketUrl(null); // don't blacklist, just rotate index
        const alt = getBestSocketUrl();
        if (!alt || alt === activeSocketUrl) return;
        backupSocketUrl = alt;
    } else {
        backupSocketUrl = nextUrl;
    }

    console.log(`[RB-Fix] Pre-connecting backup socket: ${backupSocketUrl}`);
    try {
        backupSocket = new OrigWebSocket(backupSocketUrl);
        backupSocket.onopen = () => {
            console.log(`[RB-Fix] Backup socket ready: ${backupSocketUrl}`);
            // Send handshake to keep it warm
            if (handshakeData) {
                try { backupSocket.send(handshakeData); } catch(_) {}
            }
        };
        backupSocket.onerror = () => { backupSocket = null; backupSocketUrl = null; };
        backupSocket.onclose = () => { backupSocket = null; backupSocketUrl = null; };
        // Auto-close backup after 60s if not used (don't waste resources)
        setTimeout(() => {
            if (backupSocket && activeSocket && activeSocket.readyState === OrigWebSocket.OPEN) {
                try { backupSocket.close(); } catch(_) {}
                backupSocket = null; backupSocketUrl = null;
            }
        }, 60000);
    } catch(_) { backupSocket = null; backupSocketUrl = null; }
}

// ── WebSocket interceptor ──

function clearTimers() {
    clearInterval(pingTimer); clearTimeout(pongTimer);
    pingTimer = null; pongTimer = null;
}

function PatchedWebSocket(url, protocols) {
    // If we have a faster socket URL and this is a Rubika socket, swap it
    const best = getBestSocketUrl();
    if (best && url && url.includes("iranlms.ir") && !url.includes("getdcmess")) {
        console.log(`[RB-Fix] Redirecting socket: ${url} → ${best}`);
        url = best;
    }

    const ws = protocols !== undefined
        ? new OrigWebSocket(url, protocols)
        : new OrigWebSocket(url);

    if (!url || !url.includes("iranlms.ir")) return ws;

    activeSocket = ws;
    activeSocketUrl = url;
    reconnectAttempts = 0;
    lastMessageTime = Date.now();
    cancelDisconnectGrace();
    console.log("[RB-Fix] Intercepted socket:", url);

    const origSend = ws.send.bind(ws);
    ws.send = function(data) {
        try {
            if (typeof data === "string") {
                let p = JSON.parse(data);
                if (p.method === "handShake") handshakeData = data;
            }
        } catch(_) {}
        return origSend(data);
    };

    function setupPing() {
        clearTimers();
        const interval = getAdaptivePingInterval();
        pingTimer = setInterval(() => {
            if (ws.readyState === OrigWebSocket.OPEN) {
                lastPingSentAt = performance.now();
                try { origSend("{}"); } catch(_) {}
                clearTimeout(pongTimer);
                const timeout = getAdaptivePongTimeout();
                pongTimer = setTimeout(() => {
                    console.log(`[RB-Fix] Pong timeout (adaptive: ${Math.round(timeout)}ms)`);
                    // Don't flash disconnect — just quietly switch
                    showStatus("\ud83d\udd04 Switching...", "rgba(210,153,34,.95)", true);
                    try { ws.close(4000, "pong_timeout"); } catch(_) {}
                }, timeout);
            }
        }, interval);
        console.log(`[RB-Fix] Ping interval: ${Math.round(interval)}ms, pong timeout: ${Math.round(getAdaptivePongTimeout())}ms`);
    }

    // Wrap event handlers set by Angular (via property assignment)
    let _onopen=null, _onclose=null, _onerror=null, _onmessage=null;

    Object.defineProperty(ws, "onopen", { get:()=>_onopen, set(fn){
        _onopen = function(e) {
            console.log("[RB-Fix] Socket opened");
            cancelDisconnectGrace();
            showStatus("\u2705 Connected", "rgba(0,171,128,.9)");
            reconnectAttempts = 0; lastMessageTime = Date.now();
            setupPing();
            if (fn) fn.call(ws, e);
        };
    }});

    Object.defineProperty(ws, "onmessage", { get:()=>_onmessage, set(fn){
        _onmessage = function(e) {
            const now = performance.now();
            lastMessageTime = Date.now();
            cancelDisconnectGrace();

            // Record RTT if this is a pong response to our ping
            if (lastPingSentAt > 0) {
                const rtt = now - lastPingSentAt;
                recordRtt(rtt);
                lastPingSentAt = 0;

                // If RTT is degrading badly, pre-connect a backup
                if (rttSamples.length >= 3) {
                    const avg = rttSamples.slice(0, -1).reduce((a,b)=>a+b,0) / (rttSamples.length-1);
                    if (rtt > avg * CONN.PRECONNECT_RTT_THRESH) {
                        console.log(`[RB-Fix] RTT spike: ${Math.round(rtt)}ms (avg: ${Math.round(avg)}ms) — pre-connecting backup`);
                        preconnectBackup();
                    }
                }
            }

            clearTimeout(pongTimer); pongTimer = null;
            if (fn) fn.call(ws, e);
        };
    }});

    Object.defineProperty(ws, "onclose", { get:()=>_onclose, set(fn){
        _onclose = function(e) {
            console.log("[RB-Fix] Socket closed:", e.code, e.reason);
            clearTimers();
            // Blacklist this DC and rotate to next one for the reconnect
            rotateSocketUrl(url);

            // Use graceful disconnect display — don't flash for brief reconnects
            showDisconnectGraceful("\u274c Disconnected — reconnecting...", "rgba(211,47,47,.9)");

            activeSocket = null;
            activeSocketUrl = null;
            if (fn) fn.call(ws, e);
        };
    }});

    Object.defineProperty(ws, "onerror", { get:()=>_onerror, set(fn){
        _onerror = function(e) { if (fn) fn.call(ws, e); };
    }});

    ws.addEventListener("message", () => {
        lastMessageTime = Date.now();
        clearTimeout(pongTimer); pongTimer = null;
    });
    ws.addEventListener("open", () => {
        reconnectAttempts = 0; lastMessageTime = Date.now();
        cancelDisconnectGrace();
        setupPing();
    });

    return ws;
}

PatchedWebSocket.CONNECTING = OrigWebSocket.CONNECTING;
PatchedWebSocket.OPEN = OrigWebSocket.OPEN;
PatchedWebSocket.CLOSING = OrigWebSocket.CLOSING;
PatchedWebSocket.CLOSED = OrigWebSocket.CLOSED;
PatchedWebSocket.prototype = OrigWebSocket.prototype;
_W.WebSocket = PatchedWebSocket;

// ── Intercept XHR to redirect API calls to fastest endpoint ──

const OrigOpen = XMLHttpRequest.prototype.open;
const OrigXhrSend = XMLHttpRequest.prototype.send;

XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    this._rbOrigUrl = url;
    const bestApi = getBestApiUrl();
    if (bestApi && typeof url === "string" && url.includes("iranlms.ir") && !url.includes("getdcmess") && method === "POST") {
        try {
            const u = new URL(url);
            const best = new URL(bestApi);
            if (u.hostname !== best.hostname) {
                const newUrl = best.origin + u.pathname + u.search;
                url = newUrl;
            }
        } catch(_) {}
        this.timeout = 15000;
    }
    return OrigOpen.call(this, method, url, ...rest);
};

// On XHR error, rotate API endpoint so next request tries a different DC
XMLHttpRequest.prototype.send = function(...args) {
    this.addEventListener("error", () => {
        if (this._rbOrigUrl && this._rbOrigUrl.includes("iranlms.ir")) {
            rotateApiUrl();
        }
    }, {once: true});
    this.addEventListener("timeout", () => {
        if (this._rbOrigUrl && this._rbOrigUrl.includes("iranlms.ir")) {
            rotateApiUrl();
        }
    }, {once: true});
    return OrigXhrSend.apply(this, args);
};

// ── Visibility + network handlers ──

function forceResync() {
    try { window.dispatchEvent(new HashChangeEvent("hashchange")); } catch(_) {}
    try {
        let ac = document.querySelector(".chatlist-chat.active");
        if (ac) { ac.dispatchEvent(new MouseEvent("mousedown",{bubbles:true})); setTimeout(()=>{ ac.dispatchEvent(new MouseEvent("mouseup",{bubbles:true})); ac.dispatchEvent(new MouseEvent("click",{bubbles:true})); },50); }
    } catch(_) {}
    try { window.dispatchEvent(new Event("focus")); } catch(_) {}
}

function triggerReconnect() {
    if (activeSocket && activeSocket.readyState === OrigWebSocket.OPEN) {
        showStatus("\u2705 Connected", "rgba(0,171,128,.9)");
        forceResync();
        return;
    }
    window.dispatchEvent(new Event("online"));
    setTimeout(forceResync, 500);
}

document.addEventListener("visibilitychange", () => {
    if (document.hidden) { wasHidden = true; lastVisibleTime = Date.now(); }
    else {
        let dur = Date.now() - lastVisibleTime;
        if (wasHidden && dur > CONN.VISIBILITY_GRACE) {
            if (!activeSocket || activeSocket.readyState !== OrigWebSocket.OPEN) {
                // Don't flash — just quietly reconnect
                triggerReconnect();
            } else if (Date.now() - lastMessageTime > getAdaptivePingInterval() * 2) {
                // Socket might be stale — probe it
                lastPingSentAt = performance.now();
                try { activeSocket.send("{}"); } catch(_) {}
                clearTimeout(pongTimer);
                pongTimer = setTimeout(() => {
                    // Stale — preconnect was hopefully already warming up a backup
                    try { activeSocket.close(4000, "stale"); } catch(_) {}
                }, getAdaptivePongTimeout());
            } else { forceResync(); }
        }
        wasHidden = false;
    }
});

_W.addEventListener("online", () => {
    cancelDisconnectGrace();
    showStatus("\ud83c\udf10 Network restored", "rgba(0,171,128,.9)");
    setTimeout(() => { reconnectAttempts = 0; triggerReconnect(); }, 500);
});
_W.addEventListener("offline", () => {
    showDisconnectGraceful("\u274c No network", "rgba(211,47,47,.9)");
});

if (navigator.connection) {
    navigator.connection.addEventListener("change", () => {
        if (navigator.onLine) {
            setTimeout(() => { reconnectAttempts = 0; triggerReconnect(); }, 300);
        }
    });
}

// Adaptive health check — interval adjusts to connection speed
setInterval(() => {
    if (!activeSocket || activeSocket.readyState !== OrigWebSocket.OPEN) return;
    const pingInt = getAdaptivePingInterval();
    if (Date.now() - lastMessageTime > pingInt * 2.5) {
        console.log("[RB-Fix] Health check — probing");
        lastPingSentAt = performance.now();
        try { activeSocket.send("{}"); } catch(_) {}
        clearTimeout(pongTimer);
        pongTimer = setTimeout(() => {
            try { activeSocket.close(4000, "health"); } catch(_) {}
        }, getAdaptivePongTimeout());
    }
}, 20000); // check every 20s regardless

// Retry DC discovery if initial race failed (important for flaky intranet)
setTimeout(() => {
    if (!_dcReady) {
        console.log("[RB-Fix] DC race didn't complete — retrying");
        raceDCs();
    }
}, 15000);
setTimeout(() => {
    if (!_dcReady) {
        console.log("[RB-Fix] DC race retry 2");
        raceDCs();
    }
}, 45000);

// ╔══════════════════════════════════════════════════════════════╗
// ║  PHASE 1.5: UI POLISH (inject CSS early to prevent FOUC)   ║
// ╚══════════════════════════════════════════════════════════════╝

const _uiCSS = document.createElement("style");
_uiCSS.id = "rb-ui-polish";
_uiCSS.textContent = `
/* ═══ Telegram Web A-inspired overhaul for Rubika ═══
   All resources inline — works on Iran intranet.
   Overrides via CSS variables + targeted selectors. */

/* ── Foundations: Typography + Smoothing ── */

html {
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    text-rendering: optimizeLegibility;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif !important;
    letter-spacing: -0.01em;
}

/* ── Color refinements (light mode) ── */

:root {
    --primary-color: #3390ec;
    --surface-color: #ffffff;
    --background-color: #ffffff;
    --body-background-color: #f4f4f5;
    --border-color: #e6e6e6;
    --secondary-text-color: #8a8a8a;
    --message-out-background-color: #eeffde;
    --message-out-primary-color: #4fae4e;
    --message-background-color: #ffffff;
    --scrollbar-color: rgba(0,0,0,0.15);
    --chatlist-pinned-color: #b0b5ba;
    --ripple-color: rgba(0,0,0,0.06);
    --hover-alpha: 0.04;
    --line-height: 1.375;
    --transition-standard-in-time: .25s;
    --layer-transition: .2s cubic-bezier(.4,0,.2,1);
}

/* ── Color refinements (dark mode) ── */

html.night {
    --surface-color: #212121;
    --background-color: #181818;
    --body-background-color: #0e0e0e;
    --border-color: #2a2a2a;
    --secondary-text-color: #8a8a8a;
    --scrollbar-color: rgba(255,255,255,0.12);
    --ripple-color: rgba(255,255,255,0.06);
}

/* ── Scrollbars: thin, Telegram-style ── */

::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb {
    background: var(--scrollbar-color);
    border-radius: 3px;
    transition: background .2s;
}
::-webkit-scrollbar-thumb:hover { background: rgba(0,0,0,0.3); }
html.night ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.25); }

* { scrollbar-width: thin; scrollbar-color: var(--scrollbar-color) transparent; }

/* ── Sidebar / Chat List ── */

.sidebar-left-section {
    background: var(--surface-color) !important;
}

.chatlist-chat {
    border-radius: 10px !important;
    margin: 1px 6px !important;
    padding: 8px 10px !important;
    transition: background .15s ease !important;
}

.chatlist-chat:hover {
    background: rgba(0,0,0,0.04) !important;
}
html.night .chatlist-chat:hover {
    background: rgba(255,255,255,0.06) !important;
}

.chatlist-chat.active,
.chatlist-chat.open {
    background: var(--primary-color) !important;
    border-radius: 10px !important;
}

.chatlist-chat.active *,
.chatlist-chat.open * {
    color: #fff !important;
}

.chatlist-chat.active .unread,
.chatlist-chat.open .unread {
    background: #fff !important;
    color: var(--primary-color) !important;
}

/* Unread badge */
.unread:not(.is-muted) {
    background: var(--primary-color) !important;
    font-weight: 600 !important;
    min-width: 22px !important;
    height: 22px !important;
    border-radius: 11px !important;
    font-size: 12px !important;
}

/* Dialog preview text */
.im_dialog_message,
.dialog-subtitle {
    font-size: 14px !important;
    line-height: 1.35 !important;
    opacity: 0.75;
}

/* Chat title in list */
.user-title {
    font-weight: 600 !important;
    font-size: 15px !important;
}

/* Dialog date */
.im_dialog_date {
    font-size: 12px !important;
    font-weight: 500 !important;
    opacity: 0.55;
}

/* Avatars — rounder, slightly larger */
.dialog-avatar img,
.avatar-photo,
rb-avatar .avatar-photo {
    border-radius: 50% !important;
}

/* Search bar */
.sidebar-header .input-search {
    border-radius: 22px !important;
    background: var(--input-search-background-color) !important;
    border: 1.5px solid var(--input-search-border-color) !important;
    padding: 8px 16px !important;
    transition: border-color .2s, box-shadow .2s !important;
}

.sidebar-header .input-search:focus-within {
    border-color: var(--primary-color) !important;
    box-shadow: 0 0 0 3px rgba(51,144,236,0.12) !important;
}
html.night .sidebar-header .input-search:focus-within {
    box-shadow: 0 0 0 3px rgba(135,116,225,0.15) !important;
}

/* ── Message Bubbles ── */

.bubble-content {
    border-radius: 12px !important;
    box-shadow: 0 1px 2px rgba(0,0,0,0.08) !important;
    padding: 6px 10px !important;
    max-width: min(85vw, 520px) !important;
}

html.night .bubble-content {
    box-shadow: 0 1px 3px rgba(0,0,0,0.25) !important;
}

/* Outgoing bubble — green tint like Telegram */
.bubble.is-out .bubble-content {
    background-color: var(--message-out-background-color) !important;
    border-bottom-right-radius: 4px !important;
}

/* Incoming bubble */
.bubble:not(.is-out) .bubble-content {
    background-color: var(--message-background-color) !important;
    border-bottom-left-radius: 4px !important;
}

/* Service/date messages */
.bubble.service .bubble-content,
.bubble.is-date .bubble-content {
    background: rgba(0,0,0,0.35) !important;
    color: #fff !important;
    border-radius: 16px !important;
    box-shadow: none !important;
    padding: 4px 12px !important;
    font-size: 13px !important;
    font-weight: 500 !important;
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
}

/* Message text */
div[rb-copyable] {
    font-size: var(--messages-text-size, 16px) !important;
    line-height: var(--line-height, 1.375) !important;
}

/* Message time */
.time {
    font-size: 11px !important;
    opacity: 0.55 !important;
    font-weight: 500 !important;
}

.bubble.is-out .time {
    color: var(--message-out-primary-color) !important;
}

/* Reactions */
.bubble-hover-reaction,
.bubble-hover-reaction-sticker {
    border-radius: 50% !important;
    transition: transform .2s cubic-bezier(.2,1,.2,1), opacity .15s !important;
}

/* ── Bubble tails ── */

.bubble-tail {
    opacity: 0.85;
}

/* ── Chat area background ── */

.bubbles {
    background-color: var(--body-background-color) !important;
}

/* ── Reply bar ── */

.reply-wrapper {
    border-radius: 8px 8px 0 0 !important;
    transition: height .2s ease !important;
}

.reply-border {
    border-radius: 2px !important;
}

/* ── Top bar ── */

.topbar,
.sidebar-header {
    backdrop-filter: blur(16px) saturate(180%) !important;
    -webkit-backdrop-filter: blur(16px) saturate(180%) !important;
}

/* ── Chat Input area ── */

.chat-input {
    background: var(--surface-color) !important;
    border-top: 1px solid var(--border-color) !important;
}

.input-message-input {
    font-size: var(--messages-text-size, 16px) !important;
    line-height: var(--line-height, 1.375) !important;
    caret-color: var(--primary-color) !important;
    padding: 10px 12px !important;
}

.input-message-container {
    border-radius: 18px !important;
    background: var(--input-search-background-color, var(--surface-color)) !important;
    border: 1.5px solid var(--border-color) !important;
    transition: border-color .2s, box-shadow .2s !important;
    margin: 4px 0 !important;
}

.input-message-container:focus-within {
    border-color: var(--primary-color) !important;
    box-shadow: 0 0 0 3px rgba(51,144,236,0.1) !important;
}
html.night .input-message-container:focus-within {
    box-shadow: 0 0 0 3px rgba(135,116,225,0.12) !important;
}

/* Send button — circular, Telegram-style */
.btn-send-container .btn-send {
    border-radius: 50% !important;
    width: 42px !important;
    height: 42px !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    transition: transform .2s cubic-bezier(.2,1,.2,1), background .15s !important;
}

.btn-send-container .btn-send.send {
    background: var(--primary-color) !important;
    color: #fff !important;
    transform: scale(1) !important;
}

.btn-send-container .btn-send.send .rbico-send {
    color: #fff !important;
}

.btn-send-container .btn-send:active {
    transform: scale(0.92) !important;
}

/* ── Modals & Popups ── */

#bb-modal-overlay {
    backdrop-filter: blur(8px) !important;
    -webkit-backdrop-filter: blur(8px) !important;
}

#bb-modal-card {
    border-radius: 16px !important;
    box-shadow: 0 16px 48px rgba(0,0,0,0.18), 0 0 0 1px rgba(0,0,0,0.05) !important;
}

html.night #bb-modal-card {
    box-shadow: 0 16px 48px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.06) !important;
}

/* ── Context menu ── */

#bale-bridge-menu {
    border-radius: 10px !important;
    box-shadow: 0 4px 20px rgba(0,0,0,0.15) !important;
    overflow: hidden !important;
}

html.night #bale-bridge-menu {
    background: #2a2a2a !important;
    border-color: #3a3a3a !important;
    box-shadow: 0 4px 20px rgba(0,0,0,0.4) !important;
}

.bale-menu-item {
    padding: 11px 16px !important;
    font-size: 14px !important;
    transition: background .12s !important;
}

/* ── Pinned message bar ── */

.pinned-container {
    backdrop-filter: blur(12px) !important;
    -webkit-backdrop-filter: blur(12px) !important;
}

/* ── Selection mode ── */

.bubble-select-checkbox {
    border-radius: 50% !important;
    transition: transform .15s, opacity .15s !important;
}

/* ── Floating action buttons ── */

.bubbles-go-down,
.btn-circle {
    border-radius: 50% !important;
    box-shadow: 0 2px 8px rgba(0,0,0,0.15) !important;
    transition: transform .2s cubic-bezier(.2,1,.2,1), box-shadow .2s !important;
}

.bubbles-go-down:hover,
.btn-circle:hover {
    transform: scale(1.05) !important;
    box-shadow: 0 4px 12px rgba(0,0,0,0.2) !important;
}

/* ── Ripple effect — subtler ── */

.c-ripple__circle {
    opacity: 0.06 !important;
}
html.night .c-ripple__circle {
    opacity: 0.08 !important;
}

/* ── Folder tabs ── */

.chat-folders {
    border-bottom: 1px solid var(--border-color) !important;
}

.chat-folders .chat-folder {
    border-radius: 0 !important;
    font-weight: 600 !important;
    font-size: 14px !important;
    transition: color .2s, border-color .2s !important;
    border-bottom: 2px solid transparent;
    padding: 10px 16px !important;
}

.chat-folders .chat-folder.active {
    color: var(--primary-color) !important;
    border-bottom-color: var(--primary-color) !important;
}

/* ── Sticker/Emoji panel ── */

.composer_emoji_tooltip {
    border-radius: 12px 12px 0 0 !important;
    box-shadow: 0 -2px 12px rgba(0,0,0,0.1) !important;
}

/* ── Selection highlight ── */

::selection {
    background: rgba(51,144,236,0.25);
}
html.night ::selection {
    background: rgba(135,116,225,0.3);
}

/* ── Smooth transitions on everything interactive ── */

button, [role="button"], .rp {
    transition: background .15s, transform .15s, opacity .15s !important;
}

/* ── Link styling ── */

a:not([class]) {
    color: var(--link-color) !important;
    text-decoration: none !important;
    transition: opacity .15s !important;
}
a:not([class]):hover {
    opacity: 0.8 !important;
    text-decoration: underline !important;
}

/* ── Connection status (our custom element) ── */

#rb-conn-status {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
}

/* ── Encryption overlay — match new input style ── */

#secure-input-overlay {
    border-radius: 18px !important;
    border-width: 1.5px !important;
    font-family: inherit !important;
    transition: border-color .2s, box-shadow .2s !important;
}

#secure-input-overlay:focus {
    box-shadow: 0 0 0 3px rgba(0,171,128,0.15) !important;
}

#bb-no-key-notice {
    border-radius: 18px !important;
}

/* ── Smooth page transitions ── */

.tabs-tab {
    transition: opacity .25s, transform .25s !important;
}

/* ── Voice chat / call bar ── */

.topbar-call {
    border-radius: 0 0 12px 12px !important;
}

/* ── Empty chat placeholder ── */

.chatlist-empty {
    opacity: 0.6;
    font-size: 14px !important;
}
`;

(document.head || document.documentElement).appendChild(_uiCSS);
console.log("[RB-Fix] UI polish CSS injected");

console.log("[RB-Fix] Connectivity fix loaded (document-start)");
})();


// ╔══════════════════════════════════════════════════════════════╗
// ║  PHASE 2: E2E ENCRYPTION (deferred until DOM ready)        ║
// ╚══════════════════════════════════════════════════════════════╝

function _initEncryption() {
"use strict";

const CFG = Object.freeze({
    KEY_LEN:32, MAX_ENC:4000, TOAST_MS:4500, LONG_PRESS:400,
    SEND_DLY:60, POST_DLY:100, MAX_DEPTH:10, KCACHE:16,
    CHARS:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_+=~",
    B85:"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~",
    PFX_E:"@@", PFX_E2:"@@+", PFX_H:"!!", HS_EXP:86400, HS_CLEANUP:86400000
});

const ALGO = "AES-GCM";
const COMPRESS = "deflate";
const SETTINGS_PREFIX = "rubika_bridge_settings_";
const BASE85_CHARS = CFG.B85;
const KEY_CHARS = CFG.CHARS;
const HTML_ESC = {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"};
const URL_RE = /https?:\/\/[^\s<>"{}|\\^`[\]]+/g;

const _W = typeof unsafeWindow !== "undefined" ? unsafeWindow : window;
const _C = crypto, _S = crypto.subtle;

function u8(ab){ const v = new Uint8Array(ab), c = new Uint8Array(v.length); c.set(v); return c; }

// ── Base64url encoding (@@+ format) ──

function toB64(buf){ let b = ""; const a = buf instanceof Uint8Array ? buf : new Uint8Array(buf); for(let i=0;i<a.byteLength;i++) b += String.fromCharCode(a[i]); return btoa(b).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,""); }
function fromB64(s){ let c = s.replace(/[^A-Za-z0-9\-_]/g,"").replace(/-/g,"+").replace(/_/g,"/"); c += "=".repeat((4-(c.length%4))%4); const b = atob(c), a = new Uint8Array(b.length); for(let i=0;i<b.length;i++) a[i]=b.charCodeAt(i); return a; }
function fromStdB64(s){ const c = s.replace(/[^A-Za-z0-9+/=]/g,""), b = atob(c), a = new Uint8Array(b.length); for(let i=0;i<b.length;i++) a[i]=b.charCodeAt(i); return a; }
function fromLegacyB64(s){ let c = s.replace(/[^A-Za-z0-9\-_.+/=]/g,"").replace(/-/g,"+").replace(/_/g,"/").replace(/\./g,"=").replace(/=+$/,""); c += "=".repeat((4-(c.length%4))%4); const b = atob(c), a = new Uint8Array(b.length); for(let i=0;i<b.length;i++) a[i]=b.charCodeAt(i); return a; }
function decodeB64Smart(s){ try{const r=fromB64(s);if(r.length>0)return r;}catch(_){} try{const r=fromLegacyB64(s);if(r.length>0)return r;}catch(_){} try{const r=fromStdB64(s);if(r.length>0)return r;}catch(_){} return null; }

// ── Crypto helpers for bridge ──

async function digest(d){ return u8(await _S.digest("SHA-256",d)); }
function toHex(b){ return Array.from(b).map(x=>x.toString(16).padStart(2,"0")).join(""); }
function fromHex(h){ if(!h) return new Uint8Array(0); const a=new Uint8Array(h.length/2); for(let i=0;i<h.length;i+=2) a[i/2]=parseInt(h.substring(i,i+2),16); return a; }
function concatBytes(...a){ let t=a.reduce((s,x)=>s+x.length,0),r=new Uint8Array(t),o=0; for(const x of a){r.set(x,o);o+=x.length;} return r; }
async function getFpStr(pub){ return toHex(await digest(pub)).slice(0,8).toUpperCase(); }
async function ecSign(priv,buf){ return u8(await _S.sign({name:"ECDSA",hash:"SHA-256"},priv,buf)); }
async function ecVerify(pubRaw,sig,buf){ try{ const p=await _S.importKey("raw",pubRaw,{name:"ECDSA",namedCurve:"P-256"},false,["verify"]); return await _S.verify({name:"ECDSA",hash:"SHA-256"},p,sig,buf); }catch(_){return false;} }

async function deriveSymmetric(myPrivBuf,theirPubRaw,nonce,initIdPub,respIdPub,initEphPub,respEphPub){
    const myPriv=await _S.importKey("pkcs8",myPrivBuf,{name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
    const theirPub=await _S.importKey("raw",theirPubRaw,{name:"ECDH",namedCurve:"P-256"},true,[]);
    const shared=await _S.deriveBits({name:"ECDH",public:theirPub},myPriv,256);
    const hkdfKey=await _S.importKey("raw",shared,{name:"HKDF"},false,["deriveBits"]);
    const info=concatBytes(initEphPub,respEphPub,nonce,initIdPub,respIdPub);
    const salt=u8(await _S.digest("SHA-256",concatBytes(nonce,initIdPub,respIdPub)));
    const material=u8(await _S.deriveBits({name:"HKDF",hash:"SHA-256",salt,info},hkdfKey,96*8));
    const keyMat=material.slice(0,64),hmacMat=material.slice(64,96);
    const c=CFG.CHARS,cl=c.length,mx=(cl*Math.floor(256/cl))|0,r=[]; let f=0;
    for(let i=0;i<keyMat.length&&f<CFG.KEY_LEN;i++) if(keyMat[i]<mx) r[f++]=c[keyMat[i]%cl];
    if(f<CFG.KEY_LEN) throw new Error("Key Exhaustion");
    return {sessionKey:r.join(""), hmacKeyBytes:hmacMat};
}

// ── IndexedDB storage ──

function safeClone(obj){
    if(obj==null||typeof obj!=="object") return obj;
    try{return structuredClone(obj);}catch(_){}
    try{return JSON.parse(JSON.stringify(obj));}catch(_){}
    try{ if(Array.isArray(obj)) return obj.map(safeClone); const o={}; let keys; try{keys=Object.keys(obj);}catch(_){keys=[];for(const k in obj)keys.push(k);} for(const k of keys) try{o[k]=typeof obj[k]==="object"&&obj[k]!==null?safeClone(obj[k]):obj[k];}catch(_){} return o; }catch(_){return obj;}
}

let _db,_memDB={identity:{},contacts:{},handshakes:{}},_useMem=false;
async function getDB(){
    if(_useMem) return null; if(_db) return _db;
    return new Promise((res,rej)=>{
        const rq=indexedDB.open("rubika_bridge_db",2);
        rq.onupgradeneeded=e=>{const d=e.target.result; if(e.oldVersion<2){for(const n of["identity","contacts","handshakes"])if(d.objectStoreNames.contains(n))d.deleteObjectStore(n);} for(const[n,k]of[["identity","id"],["contacts","id"],["handshakes","nonce"]])if(!d.objectStoreNames.contains(n))d.createObjectStore(n,{keyPath:k});};
        rq.onsuccess=e=>{_db=e.target.result;res(_db);}; rq.onerror=()=>{_useMem=true;rej(rq.error);};
    });
}
async function dbOp(s,o,v){
    try{ const d=await getDB(); if(!d) throw 0; return new Promise((res,rej)=>{ const tx=d.transaction(s,o==="get"||o==="getAll"?"readonly":"readwrite"),st=tx.objectStore(s); let rq; if(o==="get")rq=st.get(v);else if(o==="put")rq=st.put(safeClone(v));else if(o==="del")rq=st.delete(v);else rq=st.getAll(); rq.onsuccess=()=>{try{res(rq.result!=null&&typeof rq.result==="object"?safeClone(rq.result):rq.result);}catch(_){res(rq.result);}}; rq.onerror=()=>rej(rq.error); });
    }catch(_){ _useMem=true; if(o==="get") return _memDB[s][v]?safeClone(_memDB[s][v]):undefined; if(o==="put"){_memDB[s][v.id||v.nonce]=safeClone(v);return v;} if(o==="del"){delete _memDB[s][v];return;} return Object.values(_memDB[s]).map(safeClone); }
}

// ── Identity & trust ──

async function getMyId(){
    let rec=await dbOp("identity","get","self");
    if(rec&&rec.pubHex&&rec.privHex){ try{ const pubBuf=fromHex(rec.pubHex),privBuf=fromHex(rec.privHex); const pub=await _S.importKey("raw",pubBuf,{name:"ECDSA",namedCurve:"P-256"},true,["verify"]); const priv=await _S.importKey("pkcs8",privBuf,{name:"ECDSA",namedCurve:"P-256"},true,["sign"]); return {pub,priv,pubRaw:pubBuf,fp:await getFpStr(pubBuf)}; }catch(_){} }
    const kp=await _S.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
    const pubRaw=u8(await _S.exportKey("raw",kp.publicKey)),privPkcs8=u8(await _S.exportKey("pkcs8",kp.privateKey));
    await dbOp("identity","put",{id:"self",pubHex:toHex(pubRaw),privHex:toHex(privPkcs8),createdAt:Date.now()});
    return {pub:kp.publicKey,priv:kp.privateKey,pubRaw,fp:await getFpStr(pubRaw)};
}

async function getTrustInfo(idPubRaw,chatId){
    const h=toHex(await digest(idPubRaw)),cid=h.slice(0,16),fp=h.slice(0,8).toUpperCase(),all=await dbOp("contacts","getAll");
    const ex=all.find(c=>c.id===cid); if(ex) return {state:"known",fp,cid};
    const oc=all.find(c=>c.chatId===chatId); if(oc) return {state:"changed",fp,cid,oldFp:oc.id.slice(0,8).toUpperCase()};
    return {state:"new",fp,cid};
}

let _hsLock=Promise.resolve();
function hsLock(fn){ let unlock; const prev=_hsLock; _hsLock=new Promise(r=>unlock=r); return prev.then(()=>fn()).finally(()=>unlock()); }

function formatError(e){ if(!e) return "Unknown Error"; return (e.name?e.name+": ":"")+( e.message||String(e)); }

function tsBuf(){ const ts=Math.floor(Date.now()/1000); return new Uint8Array([(ts>>>24)&255,(ts>>>16)&255,(ts>>>8)&255,ts&255]); }

let cachedChatId = null;
let cachedSettings = null;

function isMobile() {
    return document.body.classList.contains("is-mobile");
}

function getChatId() {
    let h = location.hash;
    if (h.startsWith("#c=")) return h.slice(3);
    let p = new URLSearchParams(location.search);
    return p.get("uid") || p.get("groupId") || p.get("channelId") || location.pathname.split("/").pop() || "global";
}

function getSettings() {
    let id = getChatId();
    if (id === cachedChatId && cachedSettings !== null) return cachedSettings;
    let raw = localStorage.getItem(SETTINGS_PREFIX + id);
    cachedSettings = raw ? JSON.parse(raw) : { enabled: true, customKey: "" };
    cachedChatId = id;
    return cachedSettings;
}

function saveSettings(s) {
    let id = getChatId();
    cachedSettings = s;
    cachedChatId = id;
    localStorage.setItem(SETTINGS_PREFIX + id, JSON.stringify(s));
}

const chatType = () => { const h = location.hash; if(h.includes("g0")) return "group"; if(h.includes("c0")) return "channel"; return "dm"; };
const isGroup = () => chatType() === "group";

function getKey() {
    let s = getSettings();
    return s.enabled && s.customKey && s.customKey.length === CFG.KEY_LEN ? s.customKey : null;
}

function isEnabled() {
    return getSettings().enabled;
}

function genKey(){ const c=CFG.CHARS,cl=c.length,mx=(cl*Math.floor(256/cl))|0,r=[]; let f=0; while(f<CFG.KEY_LEN){const b=new Uint8Array(64);_C.getRandomValues(b);for(let i=0;i<64&&f<CFG.KEY_LEN;i++)if(b[i]<mx)r[f++]=c[b[i]%cl];} return r.join(""); }

// ── Try all stored keys for preview decryption ──
function getAllStoredKeys() {
    let keys = new Set();
    let current = getKey();
    if (current) keys.add(current);
    for (let i = 0; i < localStorage.length; i++) {
        let k = localStorage.key(i);
        if (k && k.startsWith(SETTINGS_PREFIX)) {
            try {
                let s = JSON.parse(localStorage.getItem(k));
                if (s && s.enabled && s.customKey && s.customKey.length === 32) {
                    keys.add(s.customKey);
                }
            } catch {}
        }
    }
    return [...keys];
}

async function tryDecryptWithAllKeys(text) {
    if (!text.startsWith(CFG.PFX_E)) return text;
    let keys = getAllStoredKeys();
    if (!keys.length) return text;
    for (let k of keys) {
        try {
            let b;
            if (text.startsWith(CFG.PFX_E2)) b = decodeB64Smart(text.slice(3));
            else b = base85decode(text.slice(2).replace(/[^\x21-\x7E]/g,""));
            if (!b || b.length < 13) continue;
            let aesKey = await deriveKey(k);
            let dec = await crypto.subtle.decrypt({ name: ALGO, iv: b.subarray(0,12) }, aesKey, b.subarray(12));
            return await decompress(new Uint8Array(dec));
        } catch {}
    }
    return text;
}

const keyCache = new Map();

async function deriveKey(k) {
    if (keyCache.has(k)) return keyCache.get(k);
    let raw = new Uint8Array(32);
    raw.set(new TextEncoder().encode(k).subarray(0, 32));
    let key = await crypto.subtle.importKey("raw", raw, { name: ALGO }, false, ["encrypt", "decrypt"]);
    keyCache.set(k, key);
    return key;
}

async function compress(text) {
    let cs = new CompressionStream(COMPRESS);
    let w = cs.writable.getWriter();
    w.write(new TextEncoder().encode(text));
    w.close();
    return new Uint8Array(await new Response(cs.readable).arrayBuffer());
}

async function decompress(data) {
    let ds = new DecompressionStream(COMPRESS);
    let w = ds.writable.getWriter();
    w.write(data);
    w.close();
    return new TextDecoder().decode(await new Response(ds.readable).arrayBuffer());
}

const B85_DECODE = new Uint8Array(128);
for (let i = 0; i < BASE85_CHARS.length; i++) B85_DECODE[BASE85_CHARS.charCodeAt(i)] = i;

function base85encode(bytes) {
    let n = bytes.length, rem = n % 4;
    let out = Array(5 * (n >>> 2) + (rem ? rem + 1 : 0));
    let idx = 0;
    for (let i = 0; i < n; i += 4) {
        let cnt = Math.min(4, n - i), val = 0;
        for (let j = 0; j < 4; j++) val = (val << 8) | (i + j < n ? bytes[i + j] : 0);
        val >>>= 0;
        let outCnt = cnt < 4 ? cnt + 1 : 5;
        let tmp = [,,,,, ];
        for (let j = 4; j >= 0; j--) { tmp[j] = BASE85_CHARS[val % 85]; val = Math.floor(val / 85); }
        for (let j = 0; j < outCnt; j++) out[idx++] = tmp[j];
    }
    return out.join("");
}

function base85decode(str) {
    let n = str.length, rem = n % 5;
    let out = new Uint8Array(4 * Math.floor(n / 5) + (rem ? rem - 1 : 0));
    let idx = 0;
    for (let i = 0; i < n; i += 5) {
        let end = Math.min(i + 5, n), skip = 5 - (end - i), val = 0;
        for (let j = 0; j < 5; j++) {
            let ch = i + j < n ? str.charCodeAt(i + j) : 126;
            val = val * 85 + B85_DECODE[ch];
        }
        let cnt = 4 - skip;
        if (cnt >= 1) out[idx++] = (val >>> 24) & 0xFF;
        if (cnt >= 2) out[idx++] = (val >>> 16) & 0xFF;
        if (cnt >= 3) out[idx++] = (val >>> 8) & 0xFF;
        if (cnt >= 4) out[idx++] = val & 0xFF;
    }
    return out.subarray(0, idx);
}

async function encrypt(text) {
    let k = getKey();
    if (!k) return null;
    let iv = crypto.getRandomValues(new Uint8Array(12));
    let comp = await compress(text);
    let aesKey = await deriveKey(k);
    let enc = new Uint8Array(await crypto.subtle.encrypt({ name: ALGO, iv }, aesKey, comp));
    let combined = new Uint8Array(12 + enc.length);
    combined.set(iv);
    combined.set(enc, 12);
    return CFG.PFX_E2 + toB64(combined);
}

async function decrypt(text) {
    if (!text.startsWith(CFG.PFX_E)) return text;
    let k = getKey();
    if (!k) return text;
    try {
        let b;
        if (text.startsWith(CFG.PFX_E2)) b = decodeB64Smart(text.slice(3));
        else b = base85decode(text.slice(2).replace(/[^\x21-\x7E]/g,""));
        if (!b || b.length < 13) return text;
        let aesKey = await deriveKey(k);
        let dec = await crypto.subtle.decrypt({ name: ALGO, iv: b.subarray(0,12) }, aesKey, b.subarray(12));
        return await decompress(new Uint8Array(dec));
    } catch { return text; }
}

async function splitEncrypt(text) {
    let result = await encrypt(text);
    if (!result) return null;
    if (result.length <= 4000) return [result];
    let mid = Math.floor(text.length / 2);
    let splitAt = text.lastIndexOf("\n", mid);
    if (splitAt <= 0) splitAt = text.lastIndexOf(" ", mid);
    if (splitAt <= 0) splitAt = mid;
    let a = await splitEncrypt(text.slice(0, splitAt).trim());
    let b = await splitEncrypt(text.slice(splitAt).trim());
    return a && b ? [...a, ...b] : null;
}

// ── Bridge / Handshake system ──

function renderHS(el,text,cc,fp="",trust="",onAction=null,btnText="Accept & Connect"){
    const c=cc==="ac"?"#00ab80":cc==="wrn"?"#d29922":cc==="err"?"#d32f2f":"#888";
    const bg=cc==="ac"?"rgba(0,171,128,0.1)":cc==="wrn"?"rgba(210,153,34,0.1)":cc==="err"?"rgba(248,81,73,0.1)":"rgba(255,255,255,0.05)";
    let h=`<div style="border:1px solid ${c};background:${bg};border-radius:10px;padding:12px;margin:6px 0;font-size:13px;line-height:1.4"><span style="display:block;font-weight:700;margin-bottom:${fp?"6px":"0"};font-size:14px;color:${c}">${escapeHtml(text)}</span>`;
    if(fp){ h+=`<div style="font-family:monospace;font-size:11.5px;margin-bottom:4px;font-weight:600;color:#00ab80">Fingerprint: ${escapeHtml(fp)}</div>`; const tc=trust.includes("\u26a0\ufe0f")?"#d32f2f":"#888"; h+=`<div style="color:${tc};font-weight:${trust.includes("\u26a0\ufe0f")?"700":"500"};margin-bottom:${onAction?"8px":"0"}">${escapeHtml(trust)}</div>`; }
    if(onAction) h+=`<button class="bb-hs-btn" style="display:inline-block;border:none;padding:7px 14px;border-radius:8px;cursor:pointer;font-weight:600;font-size:13px;background:${c};color:#fff">${escapeHtml(btnText)}</button>`;
    h+="</div>"; el.innerHTML=h;
    if(onAction){ const btn=el.querySelector(".bb-hs-btn"); if(btn) btn.onclick=e=>{e.preventDefault();e.stopPropagation();btn.disabled=true;btn.innerText="Processing...";onAction();}; }
}

async function startBridge(){
    const id=await getMyId(), eph=await _S.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
    const ephPub=u8(await _S.exportKey("raw",eph.publicKey)),ephPriv=u8(await _S.exportKey("pkcs8",eph.privateKey));
    const nonce=new Uint8Array(16); _C.getRandomValues(nonce);
    const payload=concatBytes(new Uint8Array([1,1]),nonce,tsBuf(),id.pubRaw,ephPub);
    const sig=await ecSign(id.priv,payload), msg=concatBytes(payload,sig);
    const hsRec={nonce:toHex(nonce),chatId:getChatId(),role:"initiator",stage:"invited",ephPrivHex:toHex(ephPriv),ephPubHex:toHex(ephPub),initIdPubHex:toHex(id.pubRaw),theirIdentityKeyHex:null,createdAt:Date.now(),payloadHashHex:toHex(await digest(payload)),chatType:chatType()};
    if(isGroup()) hsRec.groupKey=genKey();
    await dbOp("handshakes","put",hsRec);
    await sendViaBridge(CFG.PFX_H+" "+toB64(msg)); toast(isGroup()?"Group bridge invite sent!":"Bridge invite sent!"); refreshUI();
}

async function acceptBridge(data,el){
    const id=await getMyId(), eph=await _S.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
    const ephPub=u8(await _S.exportKey("raw",eph.publicKey)),ephPriv=u8(await _S.exportKey("pkcs8",eph.privateKey));
    const {sessionKey,hmacKeyBytes}=await deriveSymmetric(ephPriv,data.theirEphPubRaw,data.nonce,data.theirIdPubRaw,id.pubRaw,data.theirEphPubRaw,ephPub);
    const payload=concatBytes(new Uint8Array([1,2]),data.nonce,tsBuf(),data.payloadHash,id.pubRaw,ephPub);
    const sig=await ecSign(id.priv,payload), msg=concatBytes(payload,sig);
    await dbOp("handshakes","put",{nonce:toHex(data.nonce),chatId:getChatId(),role:"responder",stage:"accepted",derivedKey:sessionKey,hmacKeyHex:toHex(hmacKeyBytes),theirIdentityKeyHex:toHex(data.theirIdPubRaw),createdAt:Date.now()});
    renderHS(el,"\ud83d\udd04 Bridge accepted \u2014 waiting for confirmation","wrn");
    await sendViaBridge(CFG.PFX_H+" "+toB64(msg));
}

async function processAccept(data,hs,el){
    const id=await getMyId();
    const hsNonce=fromHex(hs.nonce),hsInitPub=fromHex(hs.initIdPubHex),hsEphPub=fromHex(hs.ephPubHex),myPriv=fromHex(hs.ephPrivHex);
    const {sessionKey,hmacKeyBytes}=await deriveSymmetric(myPriv,data.theirEphPubRaw,hsNonce,hsInitPub,data.theirIdPubRaw,hsEphPub,data.theirEphPubRaw);
    const hmacKey=await _S.importKey("raw",hmacKeyBytes,{name:"HMAC",hash:"SHA-256"},false,["sign"]);
    const hmacVal=u8(await _S.sign("HMAC",hmacKey,concatBytes(new Uint8Array([0x63,0x6f,0x6e,0x66]),hsNonce)));
    const useGroupKey=hs.chatType==="group"&&hs.groupKey;
    const activeSessionKey=useGroupKey?hs.groupKey:sessionKey;
    let payload,encBlob;
    if(useGroupKey){
        const pairwiseAes=await _S.importKey("raw",new TextEncoder().encode(sessionKey),{name:"AES-GCM"},false,["encrypt"]);
        const gkIv=new Uint8Array(12); _C.getRandomValues(gkIv);
        const gkCt=u8(await _S.encrypt({name:"AES-GCM",iv:gkIv},pairwiseAes,new TextEncoder().encode(hs.groupKey)));
        encBlob=concatBytes(gkIv,gkCt);
        payload=concatBytes(new Uint8Array([1,4]),hsNonce,tsBuf(),hmacVal,encBlob);
    }else{
        payload=concatBytes(new Uint8Array([1,3]),hsNonce,tsBuf(),hmacVal);
    }
    const sig=await ecSign(id.priv,payload), msg=concatBytes(payload,sig);
    saveSettings({enabled:true,customKey:activeSessionKey});
    await dbOp("contacts","put",{id:data.cid,chatId:getChatId(),pubHex:toHex(data.theirIdPubRaw),lastSeen:Date.now()});
    delete hs.ephPrivHex; hs.derivedKey=sessionKey; hs.stage="confirmed"; await dbOp("handshakes","put",hs);
    refreshUI(); await sendViaBridge(CFG.PFX_H+" "+toB64(msg)); renderHS(el,useGroupKey?"\u2705 Group bridge \u2014 key delivered":"\u2705 Bridge established","ac");
    setTimeout(async()=>{ const tc=await splitEncrypt("\u2705 Bridge Established! Fingerprints: "+id.fp+" \u2194 "+data.fp); if(tc) for(const c of tc) await sendViaBridge(c); },CFG.SEND_DLY+400);
}

async function processConfirm(data,hs,el){
    const hmacKey=await _S.importKey("raw",fromHex(hs.hmacKeyHex),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
    const expected=u8(await _S.sign("HMAC",hmacKey,concatBytes(new Uint8Array([0x63,0x6f,0x6e,0x66]),fromHex(hs.nonce))));
    if(toHex(data.hmac)!==toHex(expected)) throw new Error("HMAC Verification Failed");
    saveSettings({enabled:true,customKey:hs.derivedKey});
    const fpInfo=await getTrustInfo(fromHex(hs.theirIdentityKeyHex),getChatId());
    await dbOp("contacts","put",{id:fpInfo.cid,chatId:getChatId(),pubHex:hs.theirIdentityKeyHex,lastSeen:Date.now()});
    delete hs.hmacKeyHex; hs.stage="confirmed"; await dbOp("handshakes","put",hs);
    refreshUI(); renderHS(el,"\u2705 Bridge established","ac");
}

async function processGroupConfirm(data,hs,el){
    const hmacKey=await _S.importKey("raw",fromHex(hs.hmacKeyHex),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
    const expected=u8(await _S.sign("HMAC",hmacKey,concatBytes(new Uint8Array([0x63,0x6f,0x6e,0x66]),fromHex(hs.nonce))));
    if(toHex(data.hmac)!==toHex(expected)) throw new Error("HMAC Verification Failed");
    const pairwiseAes=await _S.importKey("raw",new TextEncoder().encode(hs.derivedKey),{name:"AES-GCM"},false,["decrypt"]);
    const gkIv=data.encBlob.slice(0,12),gkCt=data.encBlob.slice(12);
    const groupKey=new TextDecoder().decode(u8(await _S.decrypt({name:"AES-GCM",iv:gkIv},pairwiseAes,gkCt)));
    if(groupKey.length!==CFG.KEY_LEN) throw new Error("Invalid group key length");
    saveSettings({enabled:true,customKey:groupKey});
    const fpInfo=await getTrustInfo(fromHex(hs.theirIdentityKeyHex),getChatId());
    await dbOp("contacts","put",{id:fpInfo.cid,chatId:getChatId(),pubHex:hs.theirIdentityKeyHex,lastSeen:Date.now()});
    delete hs.hmacKeyHex; hs.stage="confirmed"; hs.groupKey=groupKey; await dbOp("handshakes","put",hs);
    refreshUI(); renderHS(el,"\u2705 Group bridge established","ac");
}

async function handleHandshake(b64,el){
    if(el._isDecrypted) return; el._isDecrypted=true;
    try{
        const bytes=decodeB64Smart(b64); if(!bytes||bytes.length<118) return;
        const ver=bytes[0],type=bytes[1]; if(ver!==1) return;
        const nonce=bytes.slice(2,18),hexNonce=toHex(nonce);
        const myId=await getMyId(), hs=await dbOp("handshakes","get",hexNonce);

        if(type===1){
            if(bytes.length!==216) return;
            const payload=bytes.slice(0,152),sig=bytes.slice(152,216),idPub=bytes.slice(22,87),ephPub=bytes.slice(87,152);
            if(!await ecVerify(idPub,sig,payload)) return;
            if(toHex(idPub)===toHex(myId.pubRaw)) return renderHS(el,"\ud83d\udd04 Bridge invite sent","txM");
            if(hs){ if(hs.stage==="accepted") return renderHS(el,"\ud83d\udd04 Waiting for confirmation","wrn"); if(hs.stage==="confirmed") return renderHS(el,"\u2705 Bridge established","ac"); return renderHS(el,"\ud83e\udd1d Processed","txM"); }
            const trust=await getTrustInfo(idPub,getChatId()), hsList=await dbOp("handshakes","getAll");
            const out=hsList.find(h=>h.chatId===getChatId()&&h.role==="initiator"&&h.stage==="invited");
            if(out){ if(myId.fp<trust.fp) return renderHS(el,"\ud83e\udd1d Collision avoided","txM"); else if(myId.fp>trust.fp) await dbOp("handshakes","del",out.nonce); else return; }
            const tStr=trust.state==="new"?"\ud83c\udd95 New contact":trust.state==="known"?"\u2705 Known contact":`\u26a0\ufe0f IDENTITY CHANGED \u2014 old: ${trust.oldFp}, new: ${trust.fp}`;
            renderHS(el,isGroup()?"\ud83d\udee1\ufe0f Group Bridge Request":"\ud83d\udee1\ufe0f Secure Bridge Request","ac",trust.fp,tStr,async()=>{
                try{await acceptBridge({nonce,theirIdPubRaw:idPub,theirEphPubRaw:ephPub,payloadHash:await digest(payload)},el);}catch(e){renderHS(el,"\u274c "+formatError(e),"err");}
            },isGroup()?"Join Group Bridge":"Accept & Connect");
        }else if(type===2){
            if(bytes.length!==248) return;
            const payload=bytes.slice(0,184),sig=bytes.slice(184,248),invHash=bytes.slice(22,54),idPub=bytes.slice(54,119),ephPub=bytes.slice(119,184);
            if(!await ecVerify(idPub,sig,payload)) return;
            if(toHex(idPub)===toHex(myId.pubRaw)) return renderHS(el,"\ud83d\udd04 Bridge accept sent","txM");
            if(!hs||hs.role!=="initiator"||hs.stage!=="invited"){ if(hs&&hs.stage==="confirmed") return renderHS(el,"\u2705 Bridge established","ac"); return renderHS(el,"\ud83e\udd1d Processed","txM"); }
            if(toHex(invHash)!==toHex(fromHex(hs.payloadHashHex))) return;
            const trust=await getTrustInfo(idPub,getChatId());
            const doAccept=async()=>{ try{await processAccept({nonce,theirIdPubRaw:idPub,theirEphPubRaw:ephPub,fp:trust.fp,cid:trust.cid},hs,el);}catch(e){renderHS(el,"\u274c "+formatError(e),"err");} };
            if(trust.state==="changed") renderHS(el,"\u26a0\ufe0f Identity Changed!","err",trust.fp,`Old: ${trust.oldFp}, New: ${trust.fp}`,doAccept,"Acknowledge & Connect");
            else{ renderHS(el,"\u2705 Bridge completing...","ac"); await doAccept(); }
        }else if(type===3){
            if(bytes.length!==118) return;
            const payload=bytes.slice(0,54),sig=bytes.slice(54,118),hmac=bytes.slice(22,54);
            if(hs&&hs.role==="responder"&&hs.stage==="accepted"){
                if(!await ecVerify(fromHex(hs.theirIdentityKeyHex),sig,payload)) return;
                try{await processConfirm({hmac},hs,el);}catch(e){renderHS(el,"\u274c "+formatError(e),"err");}
            }else{ if(hs&&hs.stage==="confirmed") return renderHS(el,"\u2705 Bridge established","ac"); renderHS(el,"\ud83e\udd1d Processed","txM"); }
        }else if(type===4){
            if(bytes.length<178) return;
            const hmac=bytes.slice(22,54),encBlob=bytes.slice(54,bytes.length-64);
            const payload=bytes.slice(0,bytes.length-64),sig=bytes.slice(bytes.length-64);
            if(hs&&hs.role==="responder"&&hs.stage==="accepted"){
                if(!await ecVerify(fromHex(hs.theirIdentityKeyHex),sig,payload)) return;
                try{await processGroupConfirm({hmac,encBlob},hs,el);}catch(e){renderHS(el,"\u274c "+formatError(e),"err");}
            }else{ if(hs&&hs.stage==="confirmed") return renderHS(el,"\u2705 Group bridge established","ac"); renderHS(el,"\ud83e\udd1d Processed","txM"); }
        }
    }catch(e){ renderHS(el,"\u274c "+formatError(e),"err"); }
}

// sendViaBridge - raw text injection for handshake messages
async function sendViaBridge(text){
    let textarea = findTextarea();
    if(!textarea) return;
    let hideTarget = findInputWrapper() || textarea;
    hideTarget.classList.remove("rb-locked-input");
    hideTarget.style.cssText = "position:absolute!important;top:0!important;left:0!important;opacity:0!important;pointer-events:none!important;z-index:-1!important";
    textarea.focus();
    document.execCommand("selectAll", false, null);
    document.execCommand("insertText", false, text);
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
    let enterEvt = { bubbles: true, cancelable: true, key: "Enter", keyCode: 13, which: 13 };
    textarea.dispatchEvent(new KeyboardEvent("keydown", enterEvt));
    textarea.dispatchEvent(new KeyboardEvent("keyup", enterEvt));
    await delay(200);
    let btn = findSendButton();
    if(btn){
        let evtOpts = { bubbles: true, cancelable: true, view: window };
        btn.dispatchEvent(new PointerEvent("pointerdown", evtOpts));
        btn.dispatchEvent(new MouseEvent("mousedown", evtOpts));
        btn.dispatchEvent(new PointerEvent("pointerup", evtOpts));
        btn.dispatchEvent(new MouseEvent("mouseup", evtOpts));
        btn.dispatchEvent(new MouseEvent("click", evtOpts));
        btn.click();
    }
    await delay(300);
    textarea.focus();
    document.execCommand("selectAll", false, null);
    document.execCommand("insertText", false, "");
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
    hideTarget.style.cssText = "";
    hideTarget.classList.add("rb-locked-input");
}

function toast(m,d=CFG.TOAST_MS){ const el=document.createElement("div"); el.textContent=m; Object.assign(el.style,{position:"fixed",bottom:"80px",left:"50%",transform:"translateX(-50%) translateY(12px)",background:"rgba(0,0,0,.85)",color:"#fff",padding:"10px 22px",borderRadius:"12px",fontSize:"13px",fontFamily:"inherit",zIndex:"9999999",opacity:"0",pointerEvents:"none",transition:"opacity .2s,transform .2s",whiteSpace:"nowrap",backdropFilter:"blur(16px)",WebkitBackdropFilter:"blur(16px)"}); document.body.appendChild(el); requestAnimationFrame(()=>{el.style.opacity="1";el.style.transform="translateX(-50%) translateY(0)";}); setTimeout(()=>{el.style.opacity="0";el.style.transform="translateX(-50%) translateY(8px)";setTimeout(()=>el.remove(),250);},d); }

function stripInvisibles(s){return s.replace(/[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF\u00AD\u034F\u061C\u180E\uFFF9-\uFFFB]/g,"");}

function escapeHtml(s) { return s.replace(/[&<>"]/g, c => HTML_ESC[c]); }

function renderInline(s) {
    return s
        .replace(/``([^`]+)``|`([^`]+)`/g, (_, a, b) =>
            `<code style="background:var(--color-neutrals-n-20,#f4f5f7);border-radius:4px;padding:1px 5px;font-family:monospace;font-size:.92em">${a ?? b}</code>`)
        .replace(/\|\|(.+?)\|\|/g, (_, t) =>
            `<span class="bb-spoiler" style="background:var(--color-neutrals-n-400,#42526e);color:transparent;border-radius:3px;padding:0 3px;cursor:pointer;user-select:none" title="Click to reveal">${t}</span>`)
        .replace(/\*\*\*(.+?)\*\*\*/g, (_, t) => `<strong><em>${t}</em></strong>`)
        .replace(/\*\*(.+?)\*\*/g, (_, t) => `<strong>${t}</strong>`)
        .replace(/(?<![_a-zA-Z0-9])__(.+?)__(?![_a-zA-Z0-9])/g, (_, t) => `<u>${t}</u>`)
        .replace(/\*([^*\n]+)\*/g, (_, t) => `<em>${t}</em>`)
        .replace(/(^|[^a-zA-Z0-9_])_([^_\n]+?)_(?=[^a-zA-Z0-9_]|$)/g, (_, p, t) => `${p}<em>${t}</em>`)
        .replace(/~~(.+?)~~/g, (_, t) => `<del>${t}</del>`)
        .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, (_, t, u) =>
            `<a href="${escapeHtml(u)}" target="_blank" rel="noopener noreferrer" style="color:#00ab80;text-decoration:underline">${t}</a>`);
}

function renderWithUrls(s) {
    let parts = [], last = 0;
    URL_RE.lastIndex = 0;
    let m;
    while ((m = URL_RE.exec(s)) !== null) {
        parts.push(renderInline(escapeHtml(s.slice(last, m.index))));
        let u = escapeHtml(m[0]);
        parts.push(`<a href="${u}" target="_blank" rel="noopener noreferrer" style="color:#00ab80;text-decoration:underline;word-break:break-all">${u}</a>`);
        last = m.index + m[0].length;
    }
    parts.push(renderInline(escapeHtml(s.slice(last))));
    return parts.join("");
}

function renderMarkdown(text) {
    let lines = text.split("\n"), result = [], i = 0;
    const wrapBlock = html => `<span dir="auto" class="bb-block" style="display:block;unicode-bidi:plaintext;">${html}</span>`;

    while (i < lines.length) {
        let line = lines[i];
        if (/^```/.test(line)) {
            let lang = line.slice(3).trim(); i++;
            let code = [];
            while (i < lines.length && !/^```\s*$/.test(lines[i])) code.push(lines[i++]);
            if (i < lines.length) i++;
            let langTag = lang ? `<span style="display:block;padding:4px 12px;font-size:10px;font-weight:600;color:#888;background:#f0f0f0;border-bottom:1px solid #ddd;text-transform:uppercase;letter-spacing:.04em">${escapeHtml(lang)}</span>` : "";
            result.push(`<div class="bb-cblk" style="position:relative;background:#f8f8f8;border:1px solid #ddd;border-radius:8px;margin:4px 0;overflow:hidden">${langTag}<pre style="margin:0;padding:10px 12px;overflow-x:auto;font-family:monospace;font-size:12.5px;line-height:1.5;white-space:pre;tab-size:4"><code style="font-family:inherit;font-size:inherit;background:none;border:none;padding:0">${escapeHtml(code.join("\n"))}</code></pre><span class="bb-cblk-copy" title="Copy" style="position:absolute;top:4px;right:8px;cursor:pointer;font-size:12px;opacity:.4;transition:opacity .15s;z-index:1">\ud83d\udccb</span></div>`);
            continue;
        }
        if (line.startsWith("> ") || line === ">") {
            let qLines = [];
            while (i < lines.length && (lines[i].startsWith("> ") || lines[i] === ">"))
                qLines.push(lines[i++].replace(/^> ?/, ""));
            result.push(`<span dir="auto" class="bb-quote" style="display:block;border-inline-start:3px solid #00ab80;padding:2px 10px;margin:2px 0;font-style:italic;opacity:0.9;unicode-bidi:plaintext;">${qLines.map(renderWithUrls).join("<br>")}</span>`);
            continue;
        }
        if (/^[-*+] /.test(line)) {
            let items = [];
            while (i < lines.length && /^[-*+] /.test(lines[i]))
                items.push(`<li style="margin:2px 0;padding-inline-start:2px">${renderWithUrls(lines[i++].slice(2))}</li>`);
            result.push(`<ul dir="auto" style="margin:4px 0;padding-inline-start:22px;list-style:disc;unicode-bidi:plaintext;">${items.join("")}</ul>`);
            continue;
        }
        if (/^\d+\. /.test(line)) {
            let items = [];
            while (i < lines.length && /^\d+\. /.test(lines[i]))
                items.push(`<li style="margin:2px 0;padding-inline-start:2px">${renderWithUrls(lines[i++].replace(/^\d+\. /, ""))}</li>`);
            result.push(`<ol dir="auto" style="margin:4px 0;padding-inline-start:22px;list-style:decimal;unicode-bidi:plaintext;">${items.join("")}</ol>`);
            continue;
        }
        let hMatch = line.match(/^(#{1,3}) (.+)/);
        if (hMatch) {
            let sizes = ["1.25em", "1.1em", "1em"];
            let lvl = Math.min(hMatch[1].length, 3) - 1;
            result.push(wrapBlock(`<span style="font-weight:700;font-size:${sizes[lvl]}">${renderWithUrls(hMatch[2])}</span>`));
            i++; continue;
        }
        if (/^([-*_])\1{2,}$/.test(line.trim())) {
            result.push('<span style="display:block;border-top:1px solid #ccc;margin:6px 0;"></span>');
            i++; continue;
        }
        if (line.trim() !== "") {
            result.push(wrapBlock(renderWithUrls(line)));
            i++; continue;
        }
        result.push('<span style="display:block;height:0.4em;"></span>');
        i++;
    }
    return result.join("");
}

let ctxMenu = null;

function showCtxMenu(x, y) {
    Object.assign(ctxMenu.style, {
        display: "flex",
        left: Math.min(x, innerWidth - 210) + "px",
        top: Math.min(y, innerHeight - 120) + "px"
    });
}

function hideCtxMenu() { ctxMenu.style.display = "none"; }

function openSettings() {
    document.getElementById("bb-modal-overlay")?.remove();
    let s = getSettings();
    document.body.insertAdjacentHTML("beforeend", `
    <div id="bb-modal-overlay">
        <div id="bb-modal-card">
            <h3 class="bb-modal-title">Shield Settings 🛡️</h3>
            <p class="bb-modal-desc">Configure encryption for this chat. When enabled, a 32-character key is required.</p>
            <label class="bb-toggle-lbl">
                <input type="checkbox" id="bb-enable-enc" ${s.enabled ? "checked" : ""} style="width:16px;height:16px;accent-color:#00ab80">
                <span>Enable Encryption Here</span>
            </label>
            <div id="bb-key-section" style="margin-top:16px;border-top:1px solid #f4f5f7;padding-top:16px">
                <label style="font-size:12px;color:#151515;font-weight:600">Encryption Key <span style="color:#d32f2f">*</span></label>
                <div class="bb-key-row">
                    <input type="password" id="bb-custom-key" class="bb-input" placeholder="Enter exactly 32 characters…" maxlength="32" value="${s.customKey || ""}">
                    <button class="bb-icon-btn" id="bb-toggle-vis" title="Show / hide key">👁</button>
                    <button class="bb-icon-btn" id="bb-copy-key" title="Copy key">📋</button>
                </div>
                <div class="bb-key-tools">
                    <button class="bb-tool-btn" id="bb-gen-key">⚡ Generate Random Key</button>
                </div>
                <div class="bb-key-meta">
                    <span class="bb-key-error" id="bb-key-error"></span>
                    <span class="bb-key-counter" id="bb-key-counter">0 / 32</span>
                </div>
            </div>
            <div id="bb-bridge-section" style="margin-top:16px;border-top:1px solid #f4f5f7;padding-top:16px">
                <div style="font-size:14px;font-weight:700;margin-bottom:4px">\ud83e\udd1d Automatic Key Exchange</div>
                <div style="font-size:12px;color:#888;margin-bottom:10px" id="bb-bridge-desc">Establish encryption automatically with your contact.</div>
                <button class="bb-tool-btn" id="bb-bridge-btn" style="width:100%;margin-top:8px">Loading...</button>
            </div>
            <div class="bb-actions">
                <button class="bb-btn bb-btn-cancel" id="bb-btn-cancel">Cancel</button>
                <button class="bb-btn bb-btn-save" id="bb-btn-save">Save</button>
            </div>
        </div>
    </div>`);

    let overlay = document.getElementById("bb-modal-overlay");
    let keyInput = document.getElementById("bb-custom-key");
    let keySection = document.getElementById("bb-key-section");
    let bridgeSection = document.getElementById("bb-bridge-section");
    let bridgeBtn = document.getElementById("bb-bridge-btn");
    let bridgeDesc = document.getElementById("bb-bridge-desc");
    let counter = document.getElementById("bb-key-counter");
    let error = document.getElementById("bb-key-error");
    let saveBtn = document.getElementById("bb-btn-save");
    let enableChk = document.getElementById("bb-enable-enc");
    let copyBtn = document.getElementById("bb-copy-key");
    let genBtn = document.getElementById("bb-gen-key");
    let visBtn = document.getElementById("bb-toggle-vis");

    let _ig = isGroup();
    if(_ig) {
        bridgeDesc.textContent = "Start a group bridge \u2014 each member joins individually. You generate the key, others receive it securely.";
    }

    function validate() {
        let len = keyInput.value.length;
        let on = enableChk.checked;
        counter.textContent = `${len} / 32`;
        counter.className = "bb-key-counter" + (len === 32 ? " exact" : "");
        keySection.style.display = on ? "" : "none";
        bridgeSection.style.display = on ? "" : "none";
        if (!on) { error.textContent = ""; saveBtn.disabled = false; return; }
        if (len === 0) { error.textContent = "A key is required when encryption is enabled."; saveBtn.disabled = true; }
        else if (len !== 32) { error.textContent = `Key must be exactly 32 characters (currently ${len}).`; saveBtn.disabled = true; }
        else { error.textContent = ""; saveBtn.disabled = false; }
    }

    async function updateBridgeUI(){
        try{
            const hsList=await dbOp("handshakes","getAll");
            const ahs=hsList.find(h=>h.chatId===getChatId()&&h.stage!=="confirmed"&&Date.now()-h.createdAt<CFG.HS_EXP*1000);
            if(ahs){
                bridgeBtn.textContent="\ud83d\udd04 Waiting for response... (Cancel)";
                bridgeBtn.style.color="#d29922";
                bridgeBtn.style.borderColor="#d29922";
                bridgeBtn.onclick=async()=>{await dbOp("handshakes","del",ahs.nonce);updateBridgeUI();};
            }else{
                const ch=hsList.find(h=>h.chatId===getChatId()&&h.stage==="confirmed"&&(h.derivedKey===keyInput.value||h.groupKey===keyInput.value));
                if(ch&&keyInput.value.length===CFG.KEY_LEN){
                    bridgeBtn.textContent=_ig?"\u2705 Group bridge active (Re-key)":"\u2705 Connected via Bridge (Re-key)";
                    bridgeBtn.style.color="#00ab80";
                    bridgeBtn.style.borderColor="#00ab80";
                }else{
                    bridgeBtn.textContent=_ig?"\ud83e\udd1d Start Group Bridge":"\ud83e\udd1d Start Bridge";
                    bridgeBtn.style.color="inherit";
                    bridgeBtn.style.borderColor="#ccc";
                }
                bridgeBtn.onclick=async()=>{overlay.remove();try{await startBridge();}catch(_){toast("Bridge error!");}};
            }
        }catch(_){bridgeBtn.textContent="Bridge unavailable";bridgeBtn.disabled=true;}
    }
    updateBridgeUI();

    keyInput.addEventListener("input", ()=>{validate();updateBridgeUI();});
    enableChk.addEventListener("change", validate);
    validate();

    visBtn.addEventListener("click", () => {
        let show = keyInput.type === "password";
        keyInput.type = show ? "text" : "password";
        visBtn.textContent = show ? "\ud83d\ude48" : "\ud83d\udc41";
    });

    copyBtn.addEventListener("click", () => {
        if (keyInput.value) {
            navigator.clipboard.writeText(keyInput.value).then(() => {
                copyBtn.textContent = "\u2705";
                copyBtn.classList.add("copied");
                setTimeout(() => { copyBtn.textContent = "\ud83d\udccb"; copyBtn.classList.remove("copied"); }, 1500);
            });
        }
    });

    genBtn.addEventListener("click", () => {
        keyInput.value = genKey();
        keyInput.type = "text";
        visBtn.textContent = "\ud83d\ude48";
        validate();
        updateBridgeUI();
    });

    document.getElementById("bb-btn-cancel").onclick = () => overlay.remove();
    saveBtn.onclick = () => {
        if (saveBtn.disabled) return;
        saveSettings({ enabled: enableChk.checked, customKey: keyInput.value });
        overlay.remove();
        refreshUI();
    };
    overlay.onclick = e => { if(e.target===overlay) overlay.remove(); };
}

const ICONS = {
    active: `<svg viewBox="0 0 24 24" fill="#00ab80"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>`,
    missingKey: `<svg viewBox="0 0 24 24" fill="#d32f2f"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h1.39v4.19H10.6v-4.19H12zM12 9.17c-.77 0-1.39-.62-1.39-1.39 0-.77.62-1.39 1.39-1.39.77 0 1.39.62 1.39 1.39 0 .77-.62 1.39-1.39 1.39z"/></svg>`,
    disabled: `<svg viewBox="0 0 24 24" fill="#888"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 19.93c-3.95-1.17-6.9-5.11-7.7-9.43l7.7-3.42 7.7 3.42c-.8 4.32-3.75 8.26-7.7 9.43z"/></svg>`
};

function findTextarea() {
    return document.querySelector(".composer_rich_textarea[contenteditable]");
}

function findInputContainer() {
    return document.querySelector(".input-message-container");
}

function findInputWrapper() {
    return document.querySelector(".input-message-input.scrollable");
}

function findSendButton() {
    return document.querySelector(".btn-send-container .btn-send") ||
           document.querySelector(".btn-send") ||
           document.querySelector(".btn-send-container");
}

function findEmojiButton() {
    return document.querySelector("button.toggle-emoticons");
}

function findNewMessageWrapper() {
    return document.querySelector(".new-message-wrapper");
}

function setSendButtonState(hasText) {
    let btn = findSendButton();
    if (!btn) return;

    if (hasText) {
        if (btn.classList.contains("send") && !btn.classList.contains("record")) return;
        btn.classList.remove("record");
        btn.classList.add("send");
        let mic = btn.querySelector(".rbico-microphone");
        if (mic) mic.setAttribute("hidden", "true");
        let send = btn.querySelector(".rbico-send");
        if (send) send.removeAttribute("hidden");
        let rrRipple = btn.querySelector(".rr.c-ripple");
        let ttRipple = btn.querySelector(".tt.c-ripple");
        if (rrRipple) rrRipple.removeAttribute("hidden");
        if (ttRipple) ttRipple.setAttribute("hidden", "true");
    } else {
        if (btn.classList.contains("record") && !btn.classList.contains("send")) return;
        btn.classList.remove("send");
        btn.classList.add("record");
        let send = btn.querySelector(".rbico-send");
        if (send) send.setAttribute("hidden", "true");
        let mic = btn.querySelector(".rbico-microphone");
        if (mic) mic.removeAttribute("hidden");
        let rrRipple = btn.querySelector(".rr.c-ripple");
        let ttRipple = btn.querySelector(".tt.c-ripple");
        if (rrRipple) rrRipple.setAttribute("hidden", "true");
        if (ttRipple) ttRipple.removeAttribute("hidden");
    }
}

function refreshUI() {
    let inputContainer = findInputContainer();
    if (!inputContainer) return;

    let inputWrapper = findInputWrapper();
    let overlay = document.getElementById("secure-input-overlay");
    let notice = document.getElementById("bb-no-key-notice");
    let shieldBtn = document.getElementById("bb-settings-btn");
    let textarea = findTextarea();

    if (!inputWrapper && !textarea) return;

    let on = isEnabled();
    let hasKey = !!getKey();

    if (shieldBtn) {
        if (on && hasKey) { shieldBtn.innerHTML = ICONS.active; shieldBtn.title = "Encryption Active - Click to configure"; }
        else if (on && !hasKey) { shieldBtn.innerHTML = ICONS.missingKey; shieldBtn.title = "Encryption Active (No Key) - Click to configure"; }
        else { shieldBtn.innerHTML = ICONS.disabled; shieldBtn.title = "Encryption Disabled - Click to enable"; }
    }

    let hideTarget = inputWrapper || textarea;

    if (on) {
        if (hasKey) {
            if (hideTarget) hideTarget.classList.add("rb-locked-input");
            if (overlay) overlay.style.display = "";
            if (notice) notice.style.display = "none";
        } else {
            if (hideTarget) hideTarget.classList.add("rb-locked-input");
            if (overlay) overlay.style.display = "none";
            if (notice) notice.style.display = "flex";
        }
    } else {
        if (hideTarget) hideTarget.classList.remove("rb-locked-input");
        if (overlay) overlay.style.display = "none";
        if (notice) notice.style.display = "none";
    }
}

let isSending = false;
let hasContent = false;
let isBypass = false;

function overlayHasContent() {
    let el = document.getElementById("secure-input-overlay");
    return !!el && !!el.innerText.trim();
}

function isSendTarget(el) {
    return !!el.closest(".btn-send-container") || !!el.closest(".btn-send") ||
           (el.classList && (el.classList.contains("btn-send") || el.classList.contains("btn-send-container")));
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

(function() {
    let origSend = WebSocket.prototype.send;
    WebSocket.prototype.send = function(data) {
        try {
            let str = typeof data === "string" ? data : new TextDecoder().decode(data);
            if (str.includes("EditParameter") && str.includes("drafts_")) return;
        } catch {}
        return origSend.apply(this, arguments);
    };
})();

document.head.insertAdjacentHTML("beforeend", `<style>
button.toggle-emoticons { display: none !important; }

.rb-locked-input {
    position: absolute !important;
    left: -9999px !important;
    top: -9999px !important;
    opacity: 0 !important;
    pointer-events: none !important;
    z-index: -1 !important;
    width: 0 !important;
    height: 0 !important;
    overflow: hidden !important;
}

#bb-settings-btn.bb-shield-btn {
    position: relative;
    box-sizing: border-box;
    min-width: 40px;
    min-height: 40px;
}

#bb-settings-btn.bb-shield-btn::after {
    content: "";
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    border-radius: 50%;
    width: max(120%, 48px);
    height: max(120%, 48px);
}

@media (pointer: coarse) {
    #bb-settings-btn.bb-shield-btn::after {
        width: max(135%, 56px);
        height: max(135%, 56px);
    }
}

#bb-settings-btn.bb-shield-btn svg {
    width: clamp(20px, 55%, 28px);
    height: clamp(20px, 55%, 28px);
    flex-shrink: 0;
    pointer-events: none;
}

#secure-input-overlay {
    flex: 1; width: 100%; box-sizing: border-box;
    min-height: 40px; max-height: 150px; overflow-y: auto;
    background-color: transparent;
    border: 2px solid #00ab80; border-radius: 16px;
    padding: 10px 16px;
    font-family: inherit; font-size: 14px;
    outline: none; white-space: pre-wrap; word-break: break-word;
    color: inherit; z-index: 100; position: relative;
    transition: box-shadow .2s ease, border-color .2s ease;
    margin: 5px 0; cursor: text;
    -webkit-user-select: text;
    user-select: text;
    -webkit-overflow-scrolling: touch;
}
#secure-input-overlay:focus {
    box-shadow: 0 4px 16px rgba(0,171,128,.3);
    border-color: #00916d;
}
#secure-input-overlay:empty::before {
    content: attr(data-placeholder);
    color: #888; pointer-events: none; display: block;
}

.is-mobile #secure-input-overlay {
    min-height: 36px;
    padding: 8px 12px;
    font-size: 16px;
    border-radius: 20px;
    margin: 3px 0;
}

#bb-no-key-notice {
    display: none; align-items: flex-start; gap: 10px; flex: 1;
    width: 100%; box-sizing: border-box; padding: 10px 14px;
    background: rgba(211,47,47,0.1); border: 2px solid #d32f2f;
    border-radius: 16px; font-family: inherit; font-size: 13px;
    color: inherit; line-height: 1.5;
    position: relative; z-index: 101; margin: 5px 0;
}
#bb-no-key-notice .bb-notice-icon { font-size: 20px; flex-shrink: 0; margin-top: 1px; }
#bb-no-key-notice .bb-notice-body { flex: 1; }
#bb-no-key-notice strong { display: block; font-size: 13px; margin-bottom: 3px; color: #d32f2f; }
#bb-no-key-notice .bb-notice-btn {
    display: inline-block; margin-top: 7px; padding: 5px 12px;
    border-radius: 8px; border: none;
    background: #d32f2f; color: #fff;
    font-size: 12px; font-weight: 700; cursor: pointer;
    transition: background .15s;
}
#bb-no-key-notice .bb-notice-btn:hover { background: #b71c1c; }

/* Decrypted preview badge in reply & chat list */
.bb-preview-lock {
    font-size: 11px;
    font-style: italic;
    opacity: 0.7;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.bb-preview-lock.bb-decrypted {
    opacity: 0.85;
    font-style: normal;
}

#bale-bridge-menu {
    position: fixed; z-index: 999999; background: #fff;
    border: 1px solid #dfe1e6; border-radius: 12px;
    box-shadow: 0 8px 24px rgba(0,0,0,.15);
    display: none; flex-direction: column; overflow: hidden;
    font-family: inherit; color: #091e42; min-width: 180px;
    animation: bb-pop .2s cubic-bezier(.2,.8,.2,1);
}
.bale-menu-item {
    padding: 14px 18px; cursor: pointer; font-size: 14px;
    font-weight: 500; transition: background .15s;
    display: flex; align-items: center; gap: 12px;
}
.bale-menu-item:hover { background: #f4f5f7; }
.bale-menu-item:active { background: #e8e8e8; }

#bb-modal-overlay {
    position: fixed; inset: 0; background: rgba(0,0,0,.4);
    backdrop-filter: blur(3px);
    display: flex; align-items: center; justify-content: center;
    z-index: 9999999; animation: bb-fade .2s ease-out;
}
#bb-modal-card {
    background: #fff; padding: 24px; border-radius: 20px;
    width: 360px; max-width: 92vw;
    box-shadow: 0 10px 40px rgba(0,0,0,.25);
    color: #151515; font-family: inherit;
    animation: bb-pop .3s cubic-bezier(.2,.8,.2,1);
    max-height: 90vh; overflow-y: auto;
}
.bb-modal-title { margin: 0 0 10px; font-size: 18px; font-weight: bold; }
.bb-modal-desc { margin: 0 0 20px; font-size: 13px; color: #888; }
.bb-input {
    width: 100%; padding: 10px 12px; border-radius: 8px;
    border: 1px solid #ccc; box-sizing: border-box;
    background: transparent; color: inherit;
    font-family: monospace; font-size: 13px;
    transition: border-color .2s; letter-spacing: .04em;
}
.bb-input:focus { outline: none; border-color: #00ab80; }
.bb-key-row { display: flex; gap: 8px; align-items: center; margin-top: 6px; }
.bb-key-row .bb-input { flex: 1; margin-top: 0; }
.bb-icon-btn {
    flex-shrink: 0; padding: 0; width: 36px; height: 36px;
    border-radius: 8px; border: 1px solid #ccc;
    background: transparent; cursor: pointer;
    display: flex; align-items: center; justify-content: center;
    font-size: 16px; transition: background .15s, border-color .15s;
    color: inherit;
}
.bb-icon-btn:hover { background: #f4f5f7; border-color: #00ab80; }
.bb-icon-btn.copied { background: #e8f5e9; border-color: #43a047; color: #43a047; }
.bb-key-tools { display: flex; gap: 8px; margin-top: 8px; }
.bb-tool-btn {
    flex: 1; padding: 7px 0; border-radius: 8px;
    border: 1px solid #ccc; background: transparent;
    cursor: pointer; font-size: 12px; font-weight: 600;
    display: flex; align-items: center; justify-content: center; gap: 5px;
    transition: background .15s, border-color .15s; color: inherit;
}
.bb-tool-btn:hover { background: #f4f5f7; border-color: #00ab80; }
.bb-toggle-lbl { display: flex; align-items: center; gap: 8px; font-size: 14px; cursor: pointer; }
.bb-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 24px; }
.bb-btn {
    padding: 8px 16px; border-radius: 8px; border: none;
    cursor: pointer; font-weight: 600; font-size: 14px;
    transition: background .2s, transform .1s;
}
.bb-btn:active { transform: scale(.95); }
.bb-btn-cancel { background: transparent; color: #888; }
.bb-btn-cancel:hover { background: #f4f5f7; }
.bb-btn-save { background: #00ab80; color: #fff; }
.bb-btn-save:hover { background: #00916d; }
.bb-btn-save:disabled { background: #ccc; cursor: not-allowed; transform: none; }
.bb-key-meta { display: flex; justify-content: space-between; align-items: center; margin-top: 6px; font-size: 11px; }
.bb-key-counter { color: #888; }
.bb-key-counter.exact { color: #00ab80; font-weight: 600; }
.bb-key-error { color: #d32f2f; font-weight: 500; font-size: 11px; min-height: 16px; }

@keyframes bb-fade { from { opacity: 0; } to { opacity: 1; } }
@keyframes bb-pop { from { opacity: 0; transform: scale(.95); } to { opacity: 1; transform: scale(1); } }
</style>`);

document.addEventListener("click", e => {
    let sp = e.target.closest(".bb-spoiler");
    if (sp) { sp.style.color = "inherit"; sp.style.background = "#dfe1e6"; }
    let cb = e.target.closest(".bb-cblk-copy");
    if (cb) { e.preventDefault(); e.stopPropagation(); let pre = cb.closest(".bb-cblk")?.querySelector("code"); if(pre) navigator.clipboard.writeText(pre.textContent).then(()=>{cb.textContent="\u2705";setTimeout(()=>cb.textContent="\ud83d\udccb",1200);}).catch(()=>{}); }
}, true);

ctxMenu = document.createElement("div");
ctxMenu.id = "bale-bridge-menu";
ctxMenu.innerHTML = `
    <div class="bale-menu-item" id="bale-menu-enc">🔒 Send Encrypted</div>
    <div class="bale-menu-item" id="bale-menu-plain">⚠️ Send Unencrypted</div>`;
document.body.appendChild(ctxMenu);

document.getElementById("bale-menu-enc").onclick = () => { hideCtxMenu(); window._bbSendMessage?.(true); };
document.getElementById("bale-menu-plain").onclick = () => { hideCtxMenu(); window._bbSendMessage?.(false); };

document.addEventListener("click", e => { if (!ctxMenu.contains(e.target)) hideCtxMenu(); });

document.addEventListener("mousedown", e => {
    if (e.button === 0 && !isSending && isSendTarget(e.target) && isEnabled() && overlayHasContent()) {
        e.preventDefault(); e.stopPropagation();
        window._bbSendMessage?.(true);
    }
}, true);

document.addEventListener("contextmenu", e => {
    if (isSendTarget(e.target) && !isSending && isEnabled() && overlayHasContent()) {
        e.preventDefault(); e.stopPropagation();
        showCtxMenu(e.clientX, e.clientY);
    }
}, true);

let longPressTimer = null;
let touchHandled = false;

document.addEventListener("touchstart", e => {
    if (!isSendTarget(e.target) || isSending) return;
    if (!isEnabled() || !overlayHasContent()) return;

    touchHandled = false;

    longPressTimer = setTimeout(() => {
        touchHandled = true;
        e.preventDefault();
        let touch = e.touches[0];
        showCtxMenu(touch.clientX, touch.clientY);
    }, 500);
}, { passive: false, capture: true });

document.addEventListener("touchend", e => {
    clearTimeout(longPressTimer);
    if (!isSendTarget(e.target) || isSending) return;
    if (!isEnabled() || !overlayHasContent()) return;

    if (touchHandled) {
        touchHandled = false;
        e.preventDefault();
        e.stopPropagation();
        return;
    }

    e.preventDefault();
    e.stopPropagation();
    window._bbSendMessage?.(true);
}, { passive: false, capture: true });

document.addEventListener("touchmove", () => {
    clearTimeout(longPressTimer);
    touchHandled = false;
}, true);

document.addEventListener("click", e => {
    if (isSendTarget(e.target) && !isSending && isEnabled() && overlayHasContent()) {
        e.preventDefault();
        e.stopPropagation();
    }
}, true);

// ── Auto-decrypt main messages + handshake detection ──
const _infly=new WeakSet();

function decryptMessages() {
    let nodes = document.body.querySelectorAll("div[rb-copyable]");
    for (let node of nodes) {
        if (node._isDecrypting || _infly.has(node)) continue;
        let text = node.textContent.trim();
        let ct = stripInvisibles(text);

        // Detect handshake messages (!! prefix)
        let hi = ct.indexOf(CFG.PFX_H);
        if (hi !== -1 && !node._isDecrypted) {
            let raw = ct.slice(hi + CFG.PFX_H.length).trim().split(/\s+/)[0].replace(/[^A-Za-z0-9\-_]/g,"");
            if (raw.length > 50) {
                _infly.add(node);
                hsLock(() => handleHandshake(raw, node).catch(() => {})).finally(() => _infly.delete(node));
                continue;
            }
        }

        if (node._isDecrypted) {
            if (!ct.startsWith(CFG.PFX_E) || node.querySelector(".bb-copy-btn")) continue;
            node._isDecrypted = false;
            node.removeAttribute("data-orig-text");
        }

        if (!ct.startsWith(CFG.PFX_E) || ct.length <= 20) continue;

        if (!node.hasAttribute("data-orig-text")) node.setAttribute("data-orig-text", text);
        let raw = node.getAttribute("data-orig-text").replace(/\s/g, "");
        node._isDecrypting = true;

        decrypt(raw).then(dec => {
            if (dec !== raw) {
                node.style.overflow = "hidden";
                node.style.overflowWrap = "anywhere";
                node.style.wordBreak = "break-word";
                node.style.maxWidth = "100%";
                node.style.color = "inherit";
                node.innerHTML = renderMarkdown(dec) + `<span style="display:inline-block;font-size:9px;opacity:0.5;letter-spacing:0.02em;font-style:italic;margin-inline-start:5px;vertical-align:middle;line-height:1;white-space:nowrap">
                    🔒 encrypted
                    <span class="bb-copy-btn" title="Copy decrypted message" style="cursor:pointer;margin-inline-start:4px;font-size:11px;font-style:normal;transition:opacity 0.2s;">📋</span>
                </span>`;
                node._isDecrypted = true;
                let copyBtn = node.querySelector(".bb-copy-btn");
                if (copyBtn) {
                    copyBtn.addEventListener("click", ev => {
                        ev.preventDefault(); ev.stopPropagation();
                        navigator.clipboard.writeText(dec).then(() => {
                            copyBtn.textContent = "✅";
                            setTimeout(() => copyBtn.textContent = "📋", 1500);
                        });
                    });
                }
            } else {
                if (!node._hasLockBadge) {
                    node.innerHTML = `
                        <span style="word-break:break-all; opacity:0.6;">${raw}</span><br>
                        <span style="font-size:11px; color:#d32f2f; font-weight:bold; margin-top:4px; display:inline-block;">
                            🔒 Encrypted (Need Key)
                        </span>`;
                    node._hasLockBadge = true;
                }
            }
        }).finally(() => { node._isDecrypting = false; });
    }
}

// ── Auto-decrypt reply previews & chat list previews ──
function decryptPreviews() {

    // ── 1. Reply subtitle previews inside message bubbles ──
    document.querySelectorAll(".reply-subtitle .im_short_message_text").forEach(node => {
        let text = node.textContent.trim();
        if (!text.startsWith("@@") || text.length <= 5 || node._bbDecrypting) return;
        node._bbDecrypting = true;

        // Strip trailing truncation dots added by Rubika
        let raw = text.replace(/\.{2,}$/, "").replace(/\u2026$/, "").replace(/\s/g, "");

        // Try all stored keys (reply might reference a message from current chat)
        tryDecryptWithAllKeys(raw).then(dec => {
            if (dec !== raw) {
                let preview = dec.replace(/\n/g, " ");
                if (preview.length > 60) preview = preview.slice(0, 60) + "…";
                node.textContent = "🔒 " + preview;
                node.classList.add("bb-preview-lock", "bb-decrypted");
            } else {
                node.textContent = "🔒 Encrypted message";
                node.classList.add("bb-preview-lock");
            }
        }).catch(() => {
            node.textContent = "🔒 Encrypted message";
            node.classList.add("bb-preview-lock");
        }).finally(() => { node._bbDecrypting = false; });
    });

    // ── 2. Reply subtitle without .im_short_message_text ──
    //    (some Rubika versions render reply text differently)
    document.querySelectorAll(".reply-subtitle").forEach(container => {
        if (container._bbPreviewDone) return;
        // Skip if already has a processed child
        if (container.querySelector(".bb-preview-lock")) return;

        let fullText = container.textContent.trim();
        if (!fullText.startsWith("@@") || fullText.length <= 5) return;

        // Find the deepest text-bearing element
        let target = container.querySelector(".im_short_message_text");
        if (target) return; // handled above

        // Walk to find leaf text node parent
        let walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
        let textNode;
        while ((textNode = walker.nextNode())) {
            let t = textNode.textContent.trim();
            if (t.startsWith("@@") && t.length > 5) {
                let span = textNode.parentElement;
                if (span._bbDecrypting) break;
                span._bbDecrypting = true;
                container._bbPreviewDone = true;

                let raw = t.replace(/\.{2,}$/, "").replace(/\u2026$/, "").replace(/\s/g, "");

                tryDecryptWithAllKeys(raw).then(dec => {
                    if (dec !== raw) {
                        let preview = dec.replace(/\n/g, " ");
                        if (preview.length > 60) preview = preview.slice(0, 60) + "…";
                        span.textContent = "🔒 " + preview;
                        span.classList.add("bb-preview-lock", "bb-decrypted");
                    } else {
                        span.textContent = "🔒 Encrypted message";
                        span.classList.add("bb-preview-lock");
                    }
                }).catch(() => {
                    span.textContent = "🔒 Encrypted message";
                    span.classList.add("bb-preview-lock");
                }).finally(() => { span._bbDecrypting = false; });
                break;
            }
        }
    });

    // ── 3. Chat list / sidebar previews ──
    document.querySelectorAll(".user-last-message").forEach(container => {
        if (container.querySelector(".bb-preview-lock")) return;

        let spans = container.querySelectorAll("span");
        for (let span of spans) {
            // Only target leaf spans (no child elements)
            if (span.children.length > 0) continue;
            let text = span.textContent.trim();
            if (!text.startsWith("@@") || text.length <= 5 || span._bbDecrypting) continue;
            span._bbDecrypting = true;

            let raw = text.replace(/\s/g, "");

            // Try all stored keys since sidebar shows all chats
            tryDecryptWithAllKeys(raw).then(dec => {
                if (dec !== raw) {
                    let preview = dec.replace(/\n/g, " ");
                    if (preview.length > 45) preview = preview.slice(0, 45) + "…";
                    span.textContent = "🔒 " + preview;
                    span.classList.add("bb-preview-lock", "bb-decrypted");
                } else {
                    span.textContent = "🔒 Encrypted";
                    span.classList.add("bb-preview-lock");
                }
            }).catch(() => {
                span.textContent = "🔒 Encrypted";
                span.classList.add("bb-preview-lock");
            }).finally(() => { span._bbDecrypting = false; });

            break; // one match per container
        }
    });
}

// ── Inject secure input UI ──
function injectUI() {
    let inputContainer = findInputContainer();
    if (!inputContainer) return;

    let textarea = findTextarea();
    let inputWrapper = findInputWrapper();
    if (!textarea) return;

    if (!document.getElementById("bb-settings-btn")) {
        let emojiBtn = findEmojiButton();
        let shieldBtn = document.createElement("button");
        shieldBtn.id = "bb-settings-btn";
        shieldBtn.className = "btn-icon rp bb-shield-btn";
        shieldBtn.style.cssText = "display:flex;align-items:center;justify-content:center;cursor:pointer;transition:all 0.2s;background:none;border:none;outline:none;flex-shrink:0;";
        shieldBtn.onclick = openSettings;

        if (emojiBtn?.parentElement) {
            emojiBtn.parentElement.insertBefore(shieldBtn, emojiBtn);
        } else {
            let wrapper = findNewMessageWrapper() || inputContainer;
            wrapper.insertBefore(shieldBtn, wrapper.firstChild);
        }
    }

    if (!document.getElementById("bb-no-key-notice")) {
        let notice = document.createElement("div");
        notice.id = "bb-no-key-notice";
        notice.innerHTML = `
            <div class="bb-notice-icon">⚠️</div>
            <div class="bb-notice-body">
                <strong>Encryption key not set — sending is blocked.</strong>
                Tap the shield icon to set up encryption or disable it.
                <br>
                <button class="bb-notice-btn" id="bb-notice-set-key">🛡 Set Encryption Key</button>
            </div>`;
        let insertTarget = inputWrapper || textarea;
        insertTarget.parentElement.insertBefore(notice, insertTarget);
        notice.querySelector("#bb-notice-set-key").onclick = openSettings;
    }

    let overlay = document.getElementById("secure-input-overlay");
    if (overlay) {
        window._bbSendMessage = overlay._triggerSend;
        refreshUI();
        return;
    }

    if (!textarea._hasStrictHijack) {
        textarea._hasStrictHijack = true;
        textarea.addEventListener("focus", () => {
            if (!isBypass && isEnabled()) {
                textarea.blur();
                document.getElementById("secure-input-overlay")?.focus();
            }
        });
    }

    if (inputWrapper && !inputWrapper._hasStrictHijack) {
        inputWrapper._hasStrictHijack = true;
        inputWrapper.addEventListener("focus", e => {
            if (!isBypass && isEnabled()) {
                e.preventDefault();
                document.getElementById("secure-input-overlay")?.focus();
            }
        }, true);
        inputWrapper.addEventListener("click", e => {
            if (!isBypass && isEnabled()) {
                e.preventDefault();
                e.stopPropagation();
                document.getElementById("secure-input-overlay")?.focus();
            }
        }, true);
    }

    let secureInput = document.createElement("div");
    secureInput.id = "secure-input-overlay";
    secureInput.contentEditable = "true";
    secureInput.dir = "auto";
    secureInput.dataset.placeholder = "🔒 پیام امن...";

    let insertParent = inputWrapper?.parentElement || textarea.parentElement;
    let insertBefore = inputWrapper || textarea;
    insertParent.insertBefore(secureInput, insertBefore);

    ["keydown", "keypress", "keyup", "paste", "drop"].forEach(evt => {
        secureInput.addEventListener(evt, e => { e.stopPropagation(); });
    });

    function getOverlayText() { return secureInput.innerText.trim(); }
    function setOverlayText(t) { secureInput.innerText = t; }

    function syncHasContent(has) {
        if (has !== hasContent) {
            hasContent = has;
            textarea.textContent = has ? "." : "";
            textarea.dispatchEvent(new Event("input", { bubbles: true }));
            setSendButtonState(has);
        }
    }

    async function injectAndSend(msgText) {
        isBypass = true;

        let hideTarget = inputWrapper || textarea;
        hideTarget.classList.remove("rb-locked-input");
        hideTarget.style.cssText = "position:absolute!important;top:0!important;left:0!important;opacity:0!important;pointer-events:none!important;z-index:-1!important";

        textarea.focus();
        document.execCommand("selectAll", false, null);
        document.execCommand("insertText", false, msgText);
        textarea.dispatchEvent(new Event("input", { bubbles: true }));

        let enterEvt = { bubbles: true, cancelable: true, key: "Enter", keyCode: 13, which: 13 };
        textarea.dispatchEvent(new KeyboardEvent("keydown", enterEvt));
        textarea.dispatchEvent(new KeyboardEvent("keyup", enterEvt));

        let sendBtn = null;
        for (let attempt = 0; attempt < 20; attempt++) {
            await delay(50);
            let btn = findSendButton();
            if (!btn) continue;
            let isReady = btn.classList.contains("send") || !btn.classList.contains("record") ||
                          !!btn.querySelector(".rbico-send:not([hidden])");
            if (isReady) { sendBtn = btn; break; }
        }

        if (sendBtn) {
            let evtOpts = { bubbles: true, cancelable: true, view: window };
            sendBtn.dispatchEvent(new PointerEvent("pointerdown", evtOpts));
            sendBtn.dispatchEvent(new MouseEvent("mousedown", evtOpts));
            sendBtn.dispatchEvent(new PointerEvent("pointerup", evtOpts));
            sendBtn.dispatchEvent(new MouseEvent("mouseup", evtOpts));
            sendBtn.dispatchEvent(new MouseEvent("click", evtOpts));
            sendBtn.click();

            if (isMobile()) {
                let ripple = sendBtn.querySelector(".rr.c-ripple");
                if (ripple) {
                    ripple.dispatchEvent(new PointerEvent("pointerdown", evtOpts));
                    ripple.dispatchEvent(new MouseEvent("mousedown", evtOpts));
                    ripple.dispatchEvent(new PointerEvent("pointerup", evtOpts));
                    ripple.dispatchEvent(new MouseEvent("mouseup", evtOpts));
                    ripple.dispatchEvent(new MouseEvent("click", evtOpts));
                }
            }
        } else {
            textarea.focus();
            ["keydown", "keypress", "keyup"].forEach(name => {
                textarea.dispatchEvent(new KeyboardEvent(name, enterEvt));
            });
        }

        await delay(300);

        textarea.focus();
        document.execCommand("selectAll", false, null);
        document.execCommand("insertText", false, "");
        textarea.dispatchEvent(new Event("input", { bubbles: true }));

        hideTarget.style.cssText = "";
        hideTarget.classList.add("rb-locked-input");
        isBypass = false;
    }

    async function triggerSend(encrypted = true) {
        if (isSending) return;
        let text = getOverlayText();
        if (!text) return;

        if (encrypted) {
            if (!getKey()) { openSettings(); return; }
            isSending = true;
            isBypass = true;
            setOverlayText("🔒 Encrypting...");
            try {
                let chunks = await splitEncrypt(text);
                if (!chunks) { setOverlayText(text); openSettings(); return; }
                for (let chunk of chunks) await injectAndSend(chunk);
                setOverlayText("");
                hasContent = false;
                syncHasContent(false);
                secureInput.focus();
            } catch (err) {
                console.error("[Rubika Bridge] Encrypted send failed:", err);
                setOverlayText(text);
                alert("Send failed!");
            } finally {
                isSending = false;
                isBypass = false;
            }
        } else {
            let confirm_ = confirm("⚠️ You are about to send this message WITHOUT encryption.\n\nThis may expose sensitive information. Are you sure?");
            if (!confirm_) return;
            isSending = true;
            isBypass = true;
            setOverlayText("🌐 Sending...");
            try {
                await injectAndSend(text);
                setOverlayText("");
                hasContent = false;
                syncHasContent(false);
                secureInput.focus();
            } catch (err) {
                console.error("[Rubika Bridge] Plain send failed:", err);
                setOverlayText(text);
                alert("Send failed!");
            } finally {
                isSending = false;
                isBypass = false;
            }
        }
    }

    secureInput._triggerSend = triggerSend;
    window._bbSendMessage = triggerSend;

    secureInput.addEventListener("input", () => {
        syncHasContent(getOverlayText().length > 0);
    });

    secureInput.addEventListener("keydown", e => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            e.stopPropagation();
            triggerSend(true);
        }
    });

    refreshUI();
}

// ── Main observer loop ──
(function startObserver() {
    let debounceTimer;
    let lastHref = location.href;

    const observer = new MutationObserver(() => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            decryptMessages();
            decryptPreviews();
            injectUI();

            if (isEnabled() && !isSending) {
                let ov = document.getElementById("secure-input-overlay");
                if (ov) setSendButtonState(ov.innerText.trim().length > 0);
            }

            if (location.href !== lastHref) {
                lastHref = location.href;
                cachedSettings = null;
                cachedChatId = null;
                refreshUI();
            }
        }, 100);
    });

    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
})();

// ── Handshake cleanup ──
function cleanupHs(){dbOp("handshakes","getAll").then(hs=>{const now=Date.now();hs.forEach(h=>{if(h.stage!=="confirmed"&&now-h.createdAt>CFG.HS_CLEANUP)dbOp("handshakes","del",h.nonce);});}).catch(()=>{});}
setTimeout(cleanupHs,2000);setInterval(cleanupHs,CFG.HS_CLEANUP);

} // end _initEncryption

// ── Bootstrap: run encryption init when DOM is ready ──
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => setTimeout(_initEncryption, 100));
} else {
    setTimeout(_initEncryption, 100);
}
