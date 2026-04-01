// ==UserScript==
// @name         Bale Bridge Encryptor (Secure ECDH & Anti-XSS)
// @namespace    http://tampermonkey.net/
// @version      13.1
// @description  Fast dark UI, ECDH Bridge, Anti-XSS, no glow.
// @author       You
// @match        *://web.bale.ai/*
// @match        *://*.bale.ai/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

(function () {
    "use strict";

    const CFG = Object.freeze({
        KEY_LEN: 32, MAX_ENC: 4000, HS_EXP: 300, TOAST_MS: 4500,
        LONG_PRESS: 400, SEND_DLY: 30, POST_DLY: 100, MAX_HASHES: 50,
        MAX_DEPTH: 10, KCACHE: 16,
        CHARS: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_+=~",
        B85: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~",
        HS_REQ: 1, HS_RES: 2, PFX_E: "@@", PFX_H: "!!",
    });

    // Palette — muted slate-blue accent, no glow
    const P = Object.freeze({
        ac: "#7c8af6", acDim: "#636fcc", acSoft: "rgba(124,138,246,.10)",
        bg: "#0d1117", card: "#161b22", srf: "#1c2128",
        bdr: "#30363d", bdrLt: "#3d444d",
        tx: "#e6edf3", txD: "#8b949e", txM: "#484f58",
        err: "#f85149", wrn: "#d29922", wrnBg: "rgba(210,153,34,.10)",
        glass: "rgba(22,27,34,.88)", glassBdr: "rgba(240,246,252,.06)",
    });

    // ── WebSocket draft blocker ───────────────────────────────────────────────
    const _wsSend = WebSocket.prototype.send;
    const _draftRx = /EditParameter[\s\S]*drafts_|drafts_[\s\S]*EditParameter/;
    WebSocket.prototype.send = function (d) {
        try {
            let t = typeof d === "string" ? d : (d instanceof ArrayBuffer || ArrayBuffer.isView(d)) ? new TextDecoder().decode(d) : "";
            if (t && _draftRx.test(t)) return;
        } catch (_) {}
        return _wsSend.apply(this, arguments);
    };

    // ── Settings ──────────────────────────────────────────────────────────────
    const _safeId = /^[a-zA-Z0-9_\-]+$/;
    const getChatId = () => {
        const p = new URLSearchParams(location.search);
        const r = p.get("uid") || p.get("groupId") || p.get("channelId") || location.pathname.split("/").pop() || "global";
        return _safeId.test(r) ? r : "global";
    };
    let _scId = null, _sc = null;
    const getS = () => {
        const id = getChatId();
        if (id === _scId && _sc) return _sc;
        try {
            const r = localStorage.getItem("bale_bridge_settings_" + id);
            if (r) { const o = JSON.parse(r); if (o && typeof o.enabled === "boolean" && typeof o.customKey === "string" && o.customKey.length <= CFG.KEY_LEN) { _sc = { enabled: o.enabled, customKey: o.customKey }; _scId = id; return _sc; } }
        } catch (_) {}
        _sc = { enabled: true, customKey: "" }; _scId = id; return _sc;
    };
    const setS = s => { const id = getChatId(); _sc = { enabled: !!s.enabled, customKey: String(s.customKey || "") }; _scId = id; localStorage.setItem("bale_bridge_settings_" + id, JSON.stringify(_sc)); };
    const activeKey = () => { const s = getS(); return s.enabled && s.customKey?.length === CFG.KEY_LEN ? s.customKey : null; };
    const encOn = () => getS().enabled;
    const fp = () => { const k = activeKey(); return k ? k.substring(0, 5).toUpperCase() : "NONE"; };

    // ── Crypto ────────────────────────────────────────────────────────────────
    const _kc = new Map();
    async function getKey(k) {
        let c = _kc.get(k); if (c) return c;
        const e = new TextEncoder().encode(k);
        if (e.length !== CFG.KEY_LEN) throw new RangeError("Bad key");
        c = await crypto.subtle.importKey("raw", e, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
        if (_kc.size >= CFG.KCACHE) _kc.delete(_kc.keys().next().value);
        _kc.set(k, c); return c;
    }
    function genKey() {
        const c = CFG.CHARS, cl = c.length, mx = (cl * Math.floor(256 / cl)) | 0, r = []; let f = 0;
        while (f < CFG.KEY_LEN) { const b = crypto.getRandomValues(new Uint8Array(64)); for (let i = 0; i < 64 && f < CFG.KEY_LEN; i++) if (b[i] < mx) r[f++] = c[b[i] % cl]; }
        return r.join("");
    }

    // Base85
    const B85 = CFG.B85, B85D = new Uint8Array(128).fill(255);
    for (let i = 0; i < 85; i++) B85D[B85.charCodeAt(i)] = i;
    function b85e(buf) {
        const l = buf.length, o = []; let p = 0;
        for (let i = 0; i < l; i += 4) {
            const r = l - i < 4 ? l - i : 4; let a = 0;
            for (let j = 0; j < 4; j++) a = (a << 8) | (i + j < l ? buf[i + j] : 0);
            a >>>= 0; const n = r < 4 ? r + 1 : 5, t = [0,0,0,0,0];
            for (let j = 4; j >= 0; j--) { t[j] = B85[a % 85]; a = (a / 85) | 0; }
            for (let j = 0; j < n; j++) o[p++] = t[j];
        }
        return o.join("");
    }
    function b85d(s) {
        const sl = s.length; if (!sl) return new Uint8Array(0);
        if (sl % 5 === 1) throw new RangeError("Bad b85");
        const fl = (sl / 5) | 0, rm = sl % 5, est = fl * 4 + (rm ? rm - 1 : 0), o = new Uint8Array(est); let w = 0;
        for (let i = 0; i < sl; i += 5) {
            const e = i + 5 < sl ? i + 5 : sl, pd = 5 - (e - i); let a = 0;
            for (let j = 0; j < 5; j++) { const c = i + j < sl ? s.charCodeAt(i + j) : 126; if (c > 127 || B85D[c] === 255) throw new RangeError("Bad b85 @" + (i + j)); a = a * 85 + B85D[c]; }
            const b = 4 - pd;
            if (b >= 1) o[w++] = (a >>> 24) & 255; if (b >= 2) o[w++] = (a >>> 16) & 255;
            if (b >= 3) o[w++] = (a >>> 8) & 255; if (b >= 4) o[w++] = a & 255;
        }
        return o.subarray(0, w);
    }

    // Compression
    async function cmp(t) {
        if (typeof CompressionStream === "undefined") return new TextEncoder().encode(t);
        const c = new CompressionStream("deflate"), w = c.writable.getWriter();
        w.write(new TextEncoder().encode(t)); w.close();
        return new Uint8Array(await new Response(c.readable).arrayBuffer());
    }
    async function dcmp(b) {
        if (typeof DecompressionStream === "undefined") return new TextDecoder().decode(b);
        try { const d = new DecompressionStream("deflate"), w = d.writable.getWriter(); w.write(b); w.close(); return new TextDecoder().decode(await new Response(d.readable).arrayBuffer()); }
        catch (_) { return new TextDecoder().decode(b); }
    }

    async function enc(t) {
        const k = activeKey(); if (!k) return null;
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await getKey(k), await cmp(t)));
        const p = new Uint8Array(12 + ct.length); p.set(iv); p.set(ct, 12);
        return CFG.PFX_E + b85e(p);
    }
    async function dec(t) {
        if (!t.startsWith(CFG.PFX_E)) return t;
        const k = activeKey(); if (!k) return t;
        try { const b = b85d(t.slice(2)); if (b.length < 13) return t; return await dcmp(new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: b.subarray(0, 12) }, await getKey(k), b.subarray(12)))); }
        catch (_) { return t; }
    }
    async function encChunk(t, d = 0) {
        if (d > CFG.MAX_DEPTH) return null;
        const r = await enc(t); if (!r) return null;
        if (r.length <= CFG.MAX_ENC) return [r];
        const m = t.length >> 1; let s = t.lastIndexOf("\n", m); if (s <= 0) s = t.lastIndexOf(" ", m); if (s <= 0) s = m;
        const a = await encChunk(t.slice(0, s).trim(), d + 1), b = await encChunk(t.slice(s).trim(), d + 1);
        return a && b ? [...a, ...b] : null;
    }

    // ── ECDH ──────────────────────────────────────────────────────────────────
    let _hsLock = Promise.resolve();
    function hsLock(fn) { let u; const p = _hsLock; _hsLock = new Promise(r => u = r); return p.then(() => fn()).finally(() => u()); }
    const hsPair = () => crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const hsPubRaw = async k => new Uint8Array(await crypto.subtle.exportKey("raw", k));
    const hsPubImp = b => crypto.subtle.importKey("raw", b, { name: "ECDH", namedCurve: "P-256" }, false, []);

    async function hsDerive(priv, theirBytes) {
        const pub = await hsPubImp(theirBytes);
        const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256);
        let hash;
        try {
            const ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
            hash = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new TextEncoder().encode("bale-bridge-v14"), info: new TextEncoder().encode("aes-key") }, ikm, 512));
        } catch (_) { const h = new Uint8Array(await crypto.subtle.digest("SHA-256", shared)); hash = new Uint8Array(64); hash.set(h); }
        const c = CFG.CHARS, cl = c.length, mx = (cl * Math.floor(256 / cl)) | 0;
        let key = "", i = 0;
        while (key.length < CFG.KEY_LEN) { if (i >= hash.length) throw new Error("No entropy"); if (hash[i] < mx) key += c[hash[i] % cl]; i++; }
        return key;
    }

    function toast(m, d = CFG.TOAST_MS) {
        const el = document.createElement("div"); el.textContent = m;
        Object.assign(el.style, {
            position: "fixed", bottom: "80px", left: "50%", transform: "translateX(-50%) translateY(12px)",
            background: P.glass, color: P.tx, padding: "10px 22px", borderRadius: "12px",
            fontSize: "13px", fontFamily: "inherit", zIndex: "9999999", opacity: "0", pointerEvents: "none",
            transition: "opacity .2s,transform .2s", whiteSpace: "nowrap",
            border: `1px solid ${P.glassBdr}`, backdropFilter: "blur(16px)", WebkitBackdropFilter: "blur(16px)",
        });
        document.body.appendChild(el);
        requestAnimationFrame(() => { el.style.opacity = "1"; el.style.transform = "translateX(-50%) translateY(0)"; });
        setTimeout(() => { el.style.opacity = "0"; el.style.transform = "translateX(-50%) translateY(8px)"; setTimeout(() => el.remove(), 250); }, d);
    }

    function vizHs(el, txt) {
        el.textContent = "";
        const b = document.createElement("span"); b.textContent = txt;
        Object.assign(b.style, {
            display: "inline-block", margin: "2px 0", padding: "4px 12px", fontSize: "11px", fontWeight: "600",
            fontFamily: "monospace", color: P.ac, background: P.srf, borderRadius: "8px",
            border: `1px solid ${P.bdr}`, userSelect: "none",
        });
        el.appendChild(b); el.style.display = "block"; el.style.textAlign = "center"; el._isDecrypted = true;
    }

    // Hash tracking
    function mHash(cid, h) {
        const k = "bb_phs_" + cid;
        try { const a = JSON.parse(localStorage.getItem(k) || "[]"); if (!Array.isArray(a)) { localStorage.setItem(k, JSON.stringify([h])); return; } if (!a.includes(h)) { a.push(h); while (a.length > CFG.MAX_HASHES) a.shift(); localStorage.setItem(k, JSON.stringify(a)); } }
        catch (_) { localStorage.setItem(k, JSON.stringify([h])); }
    }
    function isH(cid, h) { try { const a = JSON.parse(localStorage.getItem("bb_phs_" + cid) || "[]"); return Array.isArray(a) && a.includes(h); } catch (_) { return false; } }
    function cH(s) { let h = 0; for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0; return h; }
    function tsB() { const t = (Date.now() / 1000) | 0; return new Uint8Array([(t >>> 24) & 255, (t >>> 16) & 255, (t >>> 8) & 255, t & 255]); }
    function rdTs(b) { return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0; }

    // ── Send ──────────────────────────────────────────────────────────────────
    const _taSet = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set;
    const getReal = () => document.getElementById("editable-message-text") || document.getElementById("main-message-input");
    const isMob = el => el?.tagName === "TEXTAREA";

    async function sendRaw(text) {
        const real = getReal(); if (!real) return;
        const mob = isMob(real), ws = isSyncing; isSyncing = true;
        unlockI(real);
        if (mob) { _taSet?.call(real, text); real.dispatchEvent(new Event("input", { bubbles: true })); }
        else { real.focus(); document.execCommand("selectAll", false, null); document.execCommand("insertText", false, text); real.dispatchEvent(new Event("input", { bubbles: true })); }
        await new Promise(r => setTimeout(r, CFG.SEND_DLY));
        let btn = document.querySelector('[aria-label="send-button"]') || document.querySelector('.RaTWwR'), sent = false;
        if (btn) {
            const rk = Object.keys(btn).find(k => k.startsWith('__reactProps$'));
            if (rk && typeof btn[rk]?.onClick === 'function') { try { btn[rk].onClick({ preventDefault() {}, stopPropagation() {} }); sent = true; } catch (_) {} }
            if (!sent) { for (const t of ["mousedown", "pointerdown", "mouseup", "pointerup", "click"]) btn.dispatchEvent(new MouseEvent(t, { bubbles: true, cancelable: true, view: window })); sent = true; }
        }
        if (!sent) real.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, key: "Enter", code: "Enter", keyCode: 13, which: 13 }));
        await new Promise(r => setTimeout(r, CFG.POST_DLY));
        if (mob) { if (real.value !== "") { _taSet?.call(real, ""); real.dispatchEvent(new Event("input", { bubbles: true })); } }
        else { if (real.innerText.trim()) { real.focus(); document.execCommand("selectAll", false, null); document.execCommand("delete", false, null); real.dispatchEvent(new Event("input", { bubbles: true })); } }
        if (encOn()) lockI(real); isSyncing = ws;
    }

    // ── Handshake ─────────────────────────────────────────────────────────────
    async function startHs() {
        return hsLock(async () => {
            try {
                const cid = getChatId(), pair = await hsPair(), pub = await hsPubRaw(pair.publicKey);
                sessionStorage.setItem("bb_hs_" + cid, JSON.stringify(await crypto.subtle.exportKey("jwk", pair.privateKey)));
                const pay = new Uint8Array(1 + 4 + pub.length); pay[0] = CFG.HS_REQ; pay.set(tsB(), 1); pay.set(pub, 5);
                const b64 = btoa(String.fromCharCode(...pay)); mHash(cid, cH(b64));
                await sendRaw(CFG.PFX_H + b64); toast("⏳ Waiting for friend to accept…");
            } catch (e) { console.error("[BB]", e); toast("❌ Bridge failed"); }
        });
    }

    function renderAccept(el, them, mh, cid) {
        el.textContent = ""; el._isDecrypted = true;
        const box = document.createElement("div");
        Object.assign(box.style, {
            border: `1px solid ${P.ac}`, padding: "14px 18px", borderRadius: "12px",
            background: P.card, display: "inline-block", fontFamily: "inherit", margin: "4px 0", maxWidth: "320px",
        });
        const t = document.createElement("strong"); t.textContent = "🛡️ Secure Bridge Request";
        Object.assign(t.style, { color: P.ac, display: "block", marginBottom: "6px", fontSize: "14px" });
        const d = document.createElement("span"); d.textContent = "Your friend wants End-to-End Encryption.";
        Object.assign(d.style, { fontSize: "12px", color: P.txD, display: "block", marginBottom: "10px", lineHeight: "1.4" });
        const b = document.createElement("button"); b.textContent = "Accept & Connect";
        Object.assign(b.style, {
            background: P.ac, color: P.bg, border: "none", padding: "8px 16px", borderRadius: "8px",
            cursor: "pointer", fontWeight: "bold", fontSize: "13px", transition: "opacity .15s",
        });
        b.onmouseenter = () => b.style.opacity = ".85"; b.onmouseleave = () => b.style.opacity = "1";
        b.onclick = async e => {
            e.preventDefault(); e.stopPropagation(); b.disabled = true; b.textContent = "⏳ Connecting…"; b.style.opacity = ".6";
            try {
                await hsLock(async () => {
                    const pair = await hsPair(), myPub = await hsPubRaw(pair.publicKey);
                    const key = await hsDerive(pair.privateKey, them);
                    setS({ enabled: true, customKey: key }); syncVis();
                    const rp = new Uint8Array(1 + 4 + myPub.length); rp[0] = CFG.HS_RES; rp.set(tsB(), 1); rp.set(myPub, 5);
                    const rb = btoa(String.fromCharCode(...rp));
                    mHash(cid, mh); mHash(cid, cH(rb));
                    await sendRaw(CFG.PFX_H + rb);
                    vizHs(el, "✅ Bridge Accepted"); toast("🛡️ Fingerprint: " + fp(), 6000);
                });
            } catch (err) { console.error("[BB]", err); b.disabled = false; b.textContent = "Retry"; b.style.opacity = "1"; }
        };
        box.appendChild(t); box.appendChild(d); box.appendChild(b); el.appendChild(box); el.style.display = "block";
    }

    async function handleHs(b64, el) {
        const cid = getChatId(), mh = cH(b64);
        if (isH(cid, mh)) { vizHs(el, "🤝 Processed"); return; }
        return hsLock(async () => {
            if (isH(cid, mh)) { vizHs(el, "🤝 Processed"); return; }
            try {
                const bin = atob(b64), raw = new Uint8Array(bin.length);
                for (let i = 0; i < bin.length; i++) raw[i] = bin.charCodeAt(i);
                if (raw.length < 70) { mHash(cid, mh); vizHs(el, "❌ Malformed"); return; }
                const type = raw[0], ts = rdTs(raw.subarray(1, 5)), them = raw.subarray(5);
                const age = ((Date.now() / 1000) | 0) - ts;
                if (age > CFG.HS_EXP || age < -60) { mHash(cid, mh); vizHs(el, "⌛ Expired"); return; }
                if (type === CFG.HS_REQ) { if (!el._hsBound) { renderAccept(el, them, mh, cid); el._hsBound = true; } }
                else if (type === CFG.HS_RES) {
                    const ps = sessionStorage.getItem("bb_hs_" + cid);
                    if (!ps) { mHash(cid, mh); vizHs(el, "❌ Orphaned"); return; }
                    let pj; try { pj = JSON.parse(ps); } catch (_) { mHash(cid, mh); vizHs(el, "❌ Corrupt"); return; }
                    const pk = await crypto.subtle.importKey("jwk", pj, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
                    const key = await hsDerive(pk, them); sessionStorage.removeItem("bb_hs_" + cid);
                    setS({ enabled: true, customKey: key }); syncVis(); mHash(cid, mh);
                    vizHs(el, "✅ Bridge Complete"); toast("🛡️ Code: " + fp(), 6000);
                    setTimeout(async () => {
                        try { const f = fp(), ch = await encChunk(`✅ Bridge Established!\n🛡️ Both must see:\n# ${f}\nDifferent = intercepted.`); if (ch) for (const c of ch) await sendRaw(c); } catch (_) {}
                    }, 800);
                } else { mHash(cid, mh); vizHs(el, "❌ Unknown"); }
            } catch (e) { console.error("[BB]", e); vizHs(el, "❌ Failed"); }
        });
    }

    // ── Renderer ──────────────────────────────────────────────────────────────
    const _esc = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
    const esc = s => s.replace(/[&<>"']/g, c => _esc[c]);
    function safeUrl(u) { try { const p = new URL(u); if (p.protocol === "http:" || p.protocol === "https:") return esc(p.href); } catch (_) {} return "#"; }

    const _mdRules = [
        [/``([^`]+)``|`([^`]+)`/g, (_, a, b) => `<code class="bb-code">${a ?? b}</code>`],
        [/\|\|(.+?)\|\|/g, (_, t) => `<span class="bb-spoiler" title="Click">${t}</span>`],
        [/\*\*\*(.+?)\*\*\*/g, (_, t) => `<b><i>${t}</i></b>`],
        [/\*\*(.+?)\*\*/g, (_, t) => `<b>${t}</b>`],
        [/(?<![_a-zA-Z0-9])__(.+?)__(?![_a-zA-Z0-9])/g, (_, t) => `<u>${t}</u>`],
        [/\*([^*\n]+)\*/g, (_, t) => `<i>${t}</i>`],
        [/(^|[^a-zA-Z0-9_])_([^_\n]+?)_(?=[^a-zA-Z0-9_]|$)/g, (_, p, t) => `${p}<i>${t}</i>`],
        [/~~(.+?)~~/g, (_, t) => `<del>${t}</del>`],
        [/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, (_, l, u) => `<a href="${safeUrl(u)}" target="_blank" rel="noopener noreferrer" class="bb-link">${l}</a>`],
    ];
    function inlMd(s) { for (const [rx, fn] of _mdRules) s = s.replace(rx, fn); return s; }

    const _urlRx = /https?:\/\/[^\s<>"{}|\\^`[\]]+/g;
    function procLine(raw) {
        const parts = []; let last = 0; _urlRx.lastIndex = 0; let m;
        while ((m = _urlRx.exec(raw)) !== null) {
            parts.push(inlMd(esc(raw.slice(last, m.index))));
            const su = safeUrl(m[0]); parts.push(`<a href="${su}" target="_blank" rel="noopener noreferrer" class="bb-link" style="word-break:break-all">${su}</a>`);
            last = m.index + m[0].length;
        }
        parts.push(inlMd(esc(raw.slice(last)))); return parts.join("");
    }

    function renderDec(plain) {
        const lines = plain.split("\n"), out = []; let i = 0;
        const blk = h => `<span dir="auto" class="bb-block">${h}</span>`;
        while (i < lines.length) {
            const L = lines[i];
            if (L.startsWith("> ") || L === ">") { const q = []; while (i < lines.length && (lines[i].startsWith("> ") || lines[i] === ">")) q.push(lines[i++].replace(/^> ?/, "")); out.push(`<span dir="auto" class="bb-quote">${q.map(procLine).join("<br>")}</span>`); continue; }
            if (/^[-*+] /.test(L)) { const it = []; while (i < lines.length && /^[-*+] /.test(lines[i])) it.push(`<li class="bb-li">${procLine(lines[i++].slice(2))}</li>`); out.push(`<ul dir="auto" class="bb-ul">${it.join("")}</ul>`); continue; }
            if (/^\d+\. /.test(L)) { const it = []; while (i < lines.length && /^\d+\. /.test(lines[i])) it.push(`<li class="bb-li">${procLine(lines[i++].replace(/^\d+\. /, ""))}</li>`); out.push(`<ol dir="auto" class="bb-ol">${it.join("")}</ol>`); continue; }
            const hm = L.match(/^(#{1,3}) (.+)/);
            if (hm) { const sz = ["1.2em", "1.1em", "1em"][Math.min(hm[1].length, 3) - 1]; out.push(blk(`<span style="font-weight:700;font-size:${sz}">${procLine(hm[2])}</span>`)); i++; continue; }
            if (/^([-*_])\1{2,}$/.test(L.trim())) { out.push(`<span class="bb-hr"></span>`); i++; continue; }
            if (!L.trim()) { out.push(`<span class="bb-spacer"></span>`); i++; continue; }
            out.push(blk(procLine(L))); i++;
        }
        return out.join("");
    }

    // ── Spoiler ───────────────────────────────────────────────────────────────
    document.addEventListener("click", e => { const s = e.target.closest(".bb-spoiler"); if (s) { s.style.color = "inherit"; s.style.background = P.bdr; } }, true);

    // ── Scan ──────────────────────────────────────────────────────────────────
    const SKIP = new Set(["secure-input-overlay", "secure-edit-overlay", "editable-message-text", "main-message-input", "bb-no-key-notice", "bale-bridge-menu", "bb-modal-overlay"]);
    const _infly = new WeakSet();
    const _hsRx = /^!!([A-Za-z0-9+/=]{40,})/;

    function scan(root) {
        const tw = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT, {
            acceptNode(node) {
                if (node._isDecrypted || _infly.has(node) || SKIP.has(node.id)) return NodeFilter.FILTER_REJECT;
                return NodeFilter.FILTER_ACCEPT;
            }
        });
        let el;
        while ((el = tw.nextNode())) {
            const tc = el.textContent; if (tc.length <= 20) continue;
            const trim = tc.trim();

            const mh = trim.match(_hsRx);
            if (mh) {
                let skip = false; for (const c of el.children) if (c.textContent.includes("!!")) { skip = true; break; }
                if (skip) continue;
                el._isDecrypted = true; handleHs(mh[1], el).catch(e => console.error("[BB]", e)); continue;
            }
            if (trim.charCodeAt(0) === 64 && trim.charCodeAt(1) === 64 && trim.length > 20) {
                let skip = false; for (const c of el.children) if (c.textContent.trim() === trim) { skip = true; break; }
                if (skip) continue;
                _infly.add(el);
                dec(trim).then(plain => {
                    if (plain !== trim) {
                        if (!el._bbO) { Object.assign(el.style, { overflow: "hidden", overflowWrap: "anywhere", wordBreak: "break-word", maxWidth: "100%" }); el.classList.add("bb-msg-container"); el._bbO = true; }
                        el.innerHTML = renderDec(plain) + `<span class="bb-enc-badge">🔒 encrypted <span class="bb-copy-btn" title="Copy">📋</span></span>`;
                        el.style.color = "inherit"; el._isDecrypted = true;
                        const cb = el.querySelector(".bb-copy-btn");
                        if (cb) cb.onclick = ev => { ev.preventDefault(); ev.stopPropagation(); navigator.clipboard.writeText(plain).then(() => { cb.textContent = "✅"; setTimeout(() => cb.textContent = "📋", 1200); }).catch(() => {}); };
                    }
                }).catch(() => {}).finally(() => _infly.delete(el));
            }
        }
    }

    // ── Styles ─────────────────────────────────────────────────────────────────
    const sty = document.createElement("style");
    sty.textContent = `
#secure-input-overlay{width:100%;box-sizing:border-box;min-height:42px;max-height:150px;overflow-y:auto;background:${P.srf};border:1.5px solid ${P.ac};border-radius:14px;padding:10px 16px;font-family:inherit;font-size:inherit;outline:none;white-space:pre-wrap;word-break:break-word;margin-right:10px;resize:none;color:${P.tx};z-index:100;position:relative;transition:border-color .15s;display:block}
#secure-input-overlay:focus{border-color:${P.acDim}}
div#secure-input-overlay:empty::before{content:attr(data-placeholder);color:${P.txM};pointer-events:none;display:block}
#bb-no-key-notice{display:none;align-items:flex-start;gap:10px;width:100%;box-sizing:border-box;padding:11px 15px;margin-right:10px;background:${P.wrnBg};border:1.5px solid ${P.wrn};border-radius:14px;font-family:inherit;font-size:13px;color:${P.wrn};line-height:1.5;position:relative;z-index:101}
#bb-no-key-notice .bb-notice-icon{font-size:18px;flex-shrink:0;margin-top:1px}
#bb-no-key-notice .bb-notice-body{flex:1}
#bb-no-key-notice strong{display:block;font-size:13px;margin-bottom:2px}
#bb-no-key-notice .bb-notice-btn{display:inline-block;margin-top:6px;padding:5px 12px;border-radius:8px;border:none;background:${P.wrn};color:${P.bg};font-size:12px;font-weight:700;cursor:pointer;transition:opacity .15s}
#bb-no-key-notice .bb-notice-btn:hover{opacity:.85}
#bale-bridge-menu{position:fixed;z-index:999999;background:${P.glass};border:1px solid ${P.glassBdr};border-radius:12px;box-shadow:0 12px 40px rgba(0,0,0,.45);display:none;flex-direction:column;overflow:hidden;font-family:inherit;color:${P.tx};min-width:195px;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);animation:bb-pop .15s ease-out}
.bale-menu-item{padding:13px 18px;cursor:pointer;font-size:14px;font-weight:500;transition:background .1s;display:flex;align-items:center;gap:10px}
.bale-menu-item:hover{background:rgba(255,255,255,.05)}
#bb-modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.55);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);display:flex;align-items:center;justify-content:center;z-index:9999999;animation:bb-fade .15s ease-out}
#bb-modal-card{background:${P.card};padding:26px;border-radius:20px;width:370px;max-width:92vw;box-shadow:0 20px 60px rgba(0,0,0,.5),0 0 0 1px ${P.glassBdr};color:${P.tx};font-family:inherit;animation:bb-pop .2s ease-out}
.bb-modal-title{margin:0 0 6px;font-size:18px;font-weight:700;letter-spacing:-.01em}
.bb-modal-desc{margin:0 0 18px;font-size:13px;color:${P.txD};line-height:1.5}
.bb-input{width:100%;padding:9px 13px;border-radius:8px;border:1px solid ${P.bdr};box-sizing:border-box;background:${P.srf};color:${P.tx};font-family:monospace;font-size:13px;transition:border-color .15s;letter-spacing:.03em}
.bb-input:focus{outline:none;border-color:${P.ac}}
.bb-key-row{display:flex;gap:7px;align-items:center;margin-top:7px}
.bb-key-row .bb-input{flex:1;margin-top:0}
.bb-icon-btn{flex-shrink:0;padding:0;width:36px;height:36px;border-radius:8px;border:1px solid ${P.bdr};background:${P.srf};cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:15px;transition:border-color .15s,background .15s;color:${P.tx}}
.bb-icon-btn:hover{border-color:${P.ac};background:${P.acSoft}}
.bb-icon-btn.copied{border-color:${P.ac};color:${P.ac}}
.bb-key-tools{display:flex;gap:7px;margin-top:9px}
.bb-tool-btn{flex:1;padding:7px 0;border-radius:8px;border:1px solid ${P.bdr};background:${P.srf};cursor:pointer;font-size:12px;font-weight:600;display:flex;align-items:center;justify-content:center;gap:5px;transition:border-color .15s,color .15s;color:${P.tx}}
.bb-tool-btn:hover{border-color:${P.ac};color:${P.ac}}
.bb-tool-btn.bridge{border-color:${P.ac};color:${P.ac}}
.bb-toggle-lbl{display:flex;align-items:center;gap:9px;font-size:14px;cursor:pointer}
.bb-toggle-lbl input[type="checkbox"]{width:16px;height:16px;accent-color:${P.ac};cursor:pointer}
.bb-actions{display:flex;justify-content:flex-end;gap:9px;margin-top:22px}
.bb-btn{padding:8px 16px;border-radius:8px;border:none;cursor:pointer;font-weight:600;font-size:14px;transition:opacity .15s,transform .1s}
.bb-btn:active{transform:scale(.97)}
.bb-btn-cancel{background:transparent;color:${P.txD};border:1px solid ${P.bdr}}
.bb-btn-cancel:hover{background:${P.srf};color:${P.tx}}
.bb-btn-save{background:${P.ac};color:${P.bg}}
.bb-btn-save:hover{opacity:.9}
.bb-btn-save:disabled{background:${P.bdr};color:${P.txM};cursor:not-allowed;transform:none}
.bb-key-meta{display:flex;justify-content:space-between;align-items:center;margin-top:8px;font-size:11px}
.bb-key-error{color:${P.err};font-weight:500;font-size:11px;min-height:15px}
.bb-section-divider{margin-top:16px;border-top:1px solid ${P.bdr};padding-top:16px}
@keyframes bb-fade{from{opacity:0}to{opacity:1}}
@keyframes bb-pop{from{opacity:0;transform:scale(.97) translateY(6px)}to{opacity:1;transform:none}}
.bb-block{display:block;unicode-bidi:plaintext}
.bb-quote{display:block;border-inline-start:3px solid ${P.ac};padding:2px 10px;margin:2px 0;font-style:italic;opacity:.85;unicode-bidi:plaintext;background:${P.acSoft};border-radius:0 6px 6px 0}
.bb-ul{margin:3px 0;padding-inline-start:20px;list-style:disc;unicode-bidi:plaintext}
.bb-ol{margin:3px 0;padding-inline-start:20px;list-style:decimal;unicode-bidi:plaintext}
.bb-li{margin:1px 0;padding-inline-start:2px}
.bb-hr{display:block;border:none;border-top:1px solid ${P.bdr};margin:6px 0}
.bb-spacer{display:block;height:.35em}
.bb-code{background:${P.srf};border:1px solid ${P.bdr};border-radius:5px;padding:1px 5px;font-family:monospace;font-size:.9em;color:${P.ac}}
.bb-spoiler{background:${P.txM};color:transparent;border-radius:3px;padding:0 3px;cursor:pointer;user-select:none;transition:color .15s,background .15s}
.bb-link{color:${P.ac};text-decoration:underline;text-decoration-color:rgba(124,138,246,.25);transition:text-decoration-color .15s}
.bb-link:hover{text-decoration-color:${P.ac}}
.bb-enc-badge{display:inline-block;font-size:9px;opacity:.4;letter-spacing:.02em;font-style:italic;margin-inline-start:5px;vertical-align:middle;line-height:1;white-space:nowrap}
.bb-copy-btn{cursor:pointer;margin-inline-start:3px;font-size:10px;font-style:normal;transition:opacity .15s;opacity:.65}
.bb-copy-btn:hover{opacity:1!important}
.BAsWs0 .bb-block,.MRlMpm .bb-block,.dialog-item-content .bb-block,.aqFHpt .bb-block,
.BAsWs0 .bb-quote,.MRlMpm .bb-quote,.dialog-item-content .bb-quote,.aqFHpt .bb-quote,
.BAsWs0 .bb-ul,.MRlMpm .bb-ul,.dialog-item-content .bb-ul,.aqFHpt .bb-ul,
.BAsWs0 .bb-ol,.MRlMpm .bb-ol,.dialog-item-content .bb-ol,.aqFHpt .bb-ol,
.BAsWs0 .bb-li,.MRlMpm .bb-li,.dialog-item-content .bb-li,.aqFHpt .bb-li{display:inline!important;margin:0!important;padding:0!important;border:none!important;background:none!important}
.BAsWs0 .bb-spacer,.MRlMpm .bb-spacer,.dialog-item-content .bb-spacer,.aqFHpt .bb-spacer,
.BAsWs0 .bb-hr,.MRlMpm .bb-hr,.dialog-item-content .bb-hr,.aqFHpt .bb-hr,
.BAsWs0 .bb-copy-btn,.MRlMpm .bb-copy-btn,.dialog-item-content .bb-copy-btn,.aqFHpt .bb-copy-btn{display:none!important}
.BAsWs0 .bb-li::after,.MRlMpm .bb-li::after,.dialog-item-content .bb-li::after,.aqFHpt .bb-li::after{content:" \\00a0•\\00a0 "}
.BAsWs0 .bb-msg-container,.MRlMpm .bb-msg-container,.dialog-item-content .bb-msg-container,.aqFHpt .bb-msg-container{display:-webkit-box!important;-webkit-line-clamp:2!important;-webkit-box-orient:vertical!important;white-space:normal!important}
`;
    document.head.appendChild(sty);

    // ── Menu ──────────────────────────────────────────────────────────────────
    const menu = document.createElement("div"); menu.id = "bale-bridge-menu";
    const m1 = document.createElement("div"); m1.className = "bale-menu-item"; m1.textContent = "🔒 Send Encrypted";
    m1.onclick = () => { menu.style.display = "none"; window._bbSend?.(true); };
    const m2 = document.createElement("div"); m2.className = "bale-menu-item"; m2.textContent = "⚠️ Send Unencrypted";
    m2.onclick = () => { menu.style.display = "none"; window._bbSend?.(false); };
    menu.appendChild(m1); menu.appendChild(m2); document.body.appendChild(menu);
    const showMenu = (x, y) => Object.assign(menu.style, { display: "flex", left: Math.min(x, innerWidth - 210) + "px", top: Math.min(y, innerHeight - 130) + "px" });
    document.addEventListener("click", e => { if (!menu.contains(e.target)) menu.style.display = "none"; });

    // ── Settings Modal ────────────────────────────────────────────────────────
    function openSettings() {
        document.getElementById("bb-modal-overlay")?.remove();
        const s = getS(), fv = s.enabled && s.customKey?.length === CFG.KEY_LEN ? s.customKey.substring(0, 5).toUpperCase() : "N/A";
        const ov = document.createElement("div"); ov.id = "bb-modal-overlay";
        const cd = document.createElement("div"); cd.id = "bb-modal-card";
        const t = document.createElement("h3"); t.className = "bb-modal-title"; t.textContent = "🛡️ Shield Settings";
        const d = document.createElement("p"); d.className = "bb-modal-desc"; d.textContent = "Configure encryption for this chat.";
        const elbl = document.createElement("label"); elbl.className = "bb-toggle-lbl";
        const ecb = document.createElement("input"); ecb.type = "checkbox"; ecb.checked = s.enabled;
        const etxt = document.createElement("span"); etxt.textContent = "Enable Encryption";
        elbl.appendChild(ecb); elbl.appendChild(etxt);
        const ksec = document.createElement("div"); ksec.className = "bb-section-divider";
        const klbl = document.createElement("label"); Object.assign(klbl.style, { fontSize: "12px", color: P.txD, fontWeight: "600", display: "block", marginBottom: "2px" });
        klbl.textContent = "Encryption Key "; const req = document.createElement("span"); req.style.color = P.err; req.textContent = "*"; klbl.appendChild(req);
        const krow = document.createElement("div"); krow.className = "bb-key-row";
        const kinp = document.createElement("input"); kinp.type = "password"; kinp.className = "bb-input"; kinp.placeholder = "32 characters…"; kinp.maxLength = 32; kinp.value = s.customKey || "";
        const vb = document.createElement("button"); vb.className = "bb-icon-btn"; vb.title = "Toggle"; vb.textContent = "👁";
        const cpb = document.createElement("button"); cpb.className = "bb-icon-btn"; cpb.title = "Copy"; cpb.textContent = "📋";
        krow.appendChild(kinp); krow.appendChild(vb); krow.appendChild(cpb);
        const kt = document.createElement("div"); kt.className = "bb-key-tools";
        const gb = document.createElement("button"); gb.className = "bb-tool-btn"; gb.textContent = "⚡ Random Key";
        const hb = document.createElement("button"); hb.className = "bb-tool-btn bridge"; hb.textContent = "🤝 Auto Bridge";
        kt.appendChild(gb); kt.appendChild(hb);
        const km = document.createElement("div"); km.className = "bb-key-meta"; km.style.marginTop = "8px";
        const errEl = document.createElement("span"); errEl.className = "bb-key-error";
        const fpW = document.createElement("span"); fpW.style.cssText = `font-size:11px;color:${P.txD}`;
        fpW.textContent = "Fingerprint: ";
        const fpEl = document.createElement("strong"); fpEl.style.cssText = `font-family:monospace;color:${P.ac}`; fpEl.textContent = fv;
        fpW.appendChild(fpEl); km.appendChild(errEl); km.appendChild(fpW);
        ksec.appendChild(klbl); ksec.appendChild(krow); ksec.appendChild(kt); ksec.appendChild(km);
        const acts = document.createElement("div"); acts.className = "bb-actions";
        const canB = document.createElement("button"); canB.className = "bb-btn bb-btn-cancel"; canB.textContent = "Cancel";
        const savB = document.createElement("button"); savB.className = "bb-btn bb-btn-save"; savB.textContent = "Save";
        acts.appendChild(canB); acts.appendChild(savB);
        cd.appendChild(t); cd.appendChild(d); cd.appendChild(elbl); cd.appendChild(ksec); cd.appendChild(acts);
        ov.appendChild(cd); document.body.appendChild(ov);

        const validate = () => {
            const v = kinp.value, l = v.length, on = ecb.checked;
            ksec.style.display = on ? "" : "none";
            fpEl.textContent = l === CFG.KEY_LEN ? v.substring(0, 5).toUpperCase() : "N/A";
            if (!on) { errEl.textContent = ""; savB.disabled = false; return; }
            if (!l) { errEl.textContent = "Key required."; savB.disabled = true; }
            else if (l !== CFG.KEY_LEN) { errEl.textContent = `Need ${CFG.KEY_LEN} chars (${l}).`; savB.disabled = true; }
            else { errEl.textContent = ""; savB.disabled = false; }
        };
        kinp.oninput = validate; ecb.onchange = validate; validate();
        vb.onclick = () => { const h = kinp.type === "password"; kinp.type = h ? "text" : "password"; vb.textContent = h ? "🙈" : "👁"; };
        cpb.onclick = () => { if (!kinp.value) return; navigator.clipboard.writeText(kinp.value).then(() => { cpb.textContent = "✅"; cpb.classList.add("copied"); setTimeout(() => { cpb.textContent = "📋"; cpb.classList.remove("copied"); }, 1200); }).catch(() => {}); };
        gb.onclick = () => { kinp.value = genKey(); kinp.type = "text"; vb.textContent = "🙈"; validate(); };
        hb.onclick = () => { ov.remove(); startHs(); };
        canB.onclick = () => ov.remove();
        savB.onclick = () => { if (savB.disabled) return; try { setS({ enabled: ecb.checked, customKey: kinp.value }); } catch (e) { toast("Error: " + e.message); return; } ov.remove(); syncVis(); };
        ov.onclick = e => { if (e.target === ov) ov.remove(); };
    }

    // ── Input System ──────────────────────────────────────────────────────────
    let isSending = false, lastHasText = false, isSyncing = false;
    const lockI = el => Object.assign(el.style, { position: "absolute", opacity: "0", pointerEvents: "none", height: "0", width: "0", overflow: "hidden", zIndex: "-9999" });
    const unlockI = el => { el.style.position = ""; el.style.opacity = "1"; el.style.pointerEvents = "auto"; el.style.height = ""; el.style.width = "100%"; el.style.overflow = "auto"; el.style.zIndex = ""; };

    function syncVis() {
        const real = getReal(), sec = document.getElementById("secure-input-overlay"),
            notice = document.getElementById("bb-no-key-notice"), btn = document.getElementById("bb-settings-btn");
        if (!real) return;
        if (!encOn()) { unlockI(real); if (sec) sec.style.display = "none"; if (notice) notice.style.display = "none"; if (btn) btn.style.color = P.txD; }
        else if (activeKey()) { lockI(real); if (sec) sec.style.display = ""; if (notice) notice.style.display = "none"; if (btn) btn.style.color = P.ac; }
        else { lockI(real); if (sec) sec.style.display = "none"; if (notice) notice.style.display = "flex"; if (btn) btn.style.color = P.wrn; }
    }

    function ensureInput() {
        const ri = getReal(); if (!ri) return;
        const mob = isMob(ri), wrap = ri.parentElement; if (!wrap) return;
        const emoji = document.querySelector('[aria-label="emoji-icon"]') || document.querySelector(".MmBErq");
        if (emoji && encOn()) emoji.style.display = "none"; else if (emoji) emoji.style.display = "";

        if (emoji && !document.getElementById("bb-settings-btn")) {
            const sb = document.createElement("div"); sb.id = "bb-settings-btn"; sb.className = emoji.className;
            sb.setAttribute("role", "button"); sb.setAttribute("tabindex", "0"); sb.setAttribute("aria-label", "Encryption settings");
            Object.assign(sb.style, { display: "flex", alignItems: "center", justifyContent: "center", cursor: "pointer", transition: "color .15s" });
            const iw = document.createElement("div"); Object.assign(iw.style, { borderRadius: "50%", lineHeight: "0", position: "relative" });
            iw.innerHTML = `<svg width="24" height="24" fill="currentColor" viewBox="0 0 24 24"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>`;
            sb.appendChild(iw); sb.onclick = openSettings;
            sb.onkeydown = e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openSettings(); } };
            emoji.parentElement.insertBefore(sb, emoji);
        }

        if (!document.getElementById("bb-no-key-notice")) {
            const n = document.createElement("div"); n.id = "bb-no-key-notice";
            const ni = document.createElement("div"); ni.className = "bb-notice-icon"; ni.textContent = "⚠️";
            const nb = document.createElement("div"); nb.className = "bb-notice-body";
            const ns = document.createElement("strong"); ns.textContent = "Encryption key not set.";
            nb.appendChild(ns); nb.appendChild(document.createTextNode(" Tap 🔒 to set up."));
            nb.appendChild(document.createElement("br"));
            const nbtn = document.createElement("button"); nbtn.className = "bb-notice-btn"; nbtn.textContent = "🛡 Set Key";
            nbtn.onclick = openSettings; nb.appendChild(nbtn);
            n.appendChild(ni); n.appendChild(nb); wrap.insertBefore(n, ri);
        }

        const existing = document.getElementById("secure-input-overlay");
        if (existing) { window._bbSend = existing._triggerSend; syncVis(); return; }

        if (!ri._bbHij) {
            ri._bbHij = true;
            ri.addEventListener("focus", () => { if (!isSyncing && encOn()) { ri.blur(); document.getElementById("secure-input-overlay")?.focus(); } });
            for (const ev of ["keydown", "keypress", "keyup", "paste", "drop"])
                ri.addEventListener(ev, e => { if (!isSyncing && encOn()) { e.preventDefault(); e.stopPropagation(); } }, true);
        }

        let si;
        if (mob) {
            si = document.createElement("textarea"); si.dir = "auto"; si.placeholder = "🔒 پیام امن..."; si.rows = 1;
            si.addEventListener("input", () => { si.style.height = "auto"; si.style.height = Math.min(si.scrollHeight, 150) + "px"; });
        } else {
            si = document.createElement("div"); si.contentEditable = "true"; si.dir = "auto";
            si.dataset.placeholder = "🔒 پیام امن..."; wrap.style.overflow = "visible";
        }
        si.id = "secure-input-overlay"; si.className = ri.className;
        wrap.insertBefore(si, ri);

        const getT = () => mob ? si.value.trim() : si.innerText.trim();
        const setT = v => { if (mob) si.value = v; else si.innerText = v; };

        const syncH = has => {
            if (has === lastHasText) return; lastHasText = has; isSyncing = true;
            if (mob) { _taSet?.call(ri, has ? " " : ""); ri.dispatchEvent(new Event("input", { bubbles: true })); }
            else {
                const sel = window.getSelection(); let mk = null;
                if (sel.rangeCount > 0 && si.contains(sel.getRangeAt(0).commonAncestorContainer)) {
                    mk = document.createElement("span"); mk.id = "bb-caret-mk"; sel.getRangeAt(0).insertNode(mk);
                }
                ri.focus(); document.execCommand("selectAll", false, null);
                if (has) document.execCommand("insertText", false, " "); else document.execCommand("delete", false, null);
                ri.dispatchEvent(new Event("input", { bubbles: true })); si.focus();
                if (mk?.parentNode) { const r = document.createRange(); r.setStartBefore(mk); r.collapse(true); sel.removeAllRanges(); sel.addRange(r); mk.remove(); si.normalize(); }
                else { const r = document.createRange(); r.selectNodeContents(si); r.collapse(false); sel.removeAllRanges(); sel.addRange(r); }
            }
            isSyncing = false;
        };
        si.addEventListener("input", e => { if (!e.isComposing) syncH(getT().length > 0); });
        si.addEventListener("compositionend", () => syncH(getT().length > 0));

        const triggerSend = async (doEnc = true) => {
            if (isSending) return; const text = getT(); if (!text) return;
            if (doEnc) {
                if (!activeKey()) { openSettings(); return; }
                isSending = true; setT("🔒 …");
                try { const ch = await encChunk(text); if (!ch) { setT(text); openSettings(); return; } for (const c of ch) await sendRaw(c); setT(""); lastHasText = false; si.focus(); }
                catch (e) { console.error("[BB]", e); setT(text); toast("Send failed!"); }
                finally { isSending = false; } return;
            }
            if (!confirm("⚠️ Send WITHOUT encryption?")) return;
            isSending = true; setT("🌐 …");
            try { await sendRaw(text); setT(""); lastHasText = false; si.focus(); }
            catch (_) { setT(text); toast("Send failed!"); }
            finally { isSending = false; }
        };
        si._triggerSend = triggerSend; window._bbSend = triggerSend;
        si.addEventListener("keydown", e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); e.stopPropagation(); triggerSend(true); } });
        syncVis();
    }

    // ── Edit/Caption ──────────────────────────────────────────────────────────
    function ensureEdit() {
        const real = document.querySelector('textarea[aria-label="File Description"]');
        if (!real || real._bbE) return; real._bbE = true;
        const se = document.createElement("textarea"); se.id = "secure-edit-overlay"; se.className = real.className;
        se.placeholder = "🔒 " + (real.placeholder || "ویرایش امن..."); se.dir = real.dir || "auto"; se.style.cssText = real.style.cssText;
        se.addEventListener("input", () => { se.style.height = "auto"; se.style.height = Math.min(se.scrollHeight, 150) + "px"; });
        real.parentElement.insertBefore(se, real); lockI(real); se.focus();
        const ex = real.value.trim(); _taSet?.call(real, ""); real.dispatchEvent(new Event("input", { bubbles: true }));
        if (ex.startsWith(CFG.PFX_E)) dec(ex).then(p => { if (p !== ex) se.value = p; }).catch(() => {}); else se.value = ex;

        const encFwd = async btn => {
            if (se._busy) return; const text = se.value.trim(); if (!text) return;
            if (!activeKey()) { openSettings(); return; }
            se._busy = true; const prev = se.value; se.value = "🔒 …";
            try {
                const out = await enc(text); if (!out) { se.value = prev; openSettings(); return; }
                se.value = ""; unlockI(real); _taSet?.call(real, out);
                real.dispatchEvent(new Event("input", { bubbles: true })); real.dispatchEvent(new Event("change", { bubbles: true }));
                await new Promise(r => setTimeout(r, CFG.SEND_DLY));
                const rk = Object.keys(btn).find(k => k.startsWith('__reactProps$'));
                if (rk && typeof btn[rk]?.onClick === 'function') btn[rk].onClick({ preventDefault() {}, stopPropagation() {} });
                else for (const t of ["mousedown", "pointerdown", "mouseup", "pointerup", "click"]) btn.dispatchEvent(new MouseEvent(t, { bubbles: true, cancelable: true, view: window }));
            } catch (e) { console.error("[BB]", e); se.value = prev; toast("Failed!"); }
            finally { se._busy = false; }
        };
        const isConf = t => t.closest('[data-testid="confirm-button"]') || (t.closest('button[aria-label="Send"]') && !t.closest('#chat_footer'));
        const eh = e => { if (!e.isTrusted) return; const b = isConf(e.target); if (!b || !se.value.trim()) return; if (se._busy) { e.preventDefault(); e.stopPropagation(); return; } e.preventDefault(); e.stopPropagation(); encFwd(b); };
        document.addEventListener("click", eh, true); document.addEventListener("mousedown", eh, true);
        const eo = new MutationObserver(() => { if (!document.contains(se)) { document.removeEventListener("click", eh, true); document.removeEventListener("mousedown", eh, true); eo.disconnect(); } });
        eo.observe(document.body, { childList: true, subtree: true });
        se.addEventListener("keydown", e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); e.stopPropagation(); const b = document.querySelector('[data-testid="confirm-button"]') || document.querySelector('button[aria-label="Send"]:not(#chat_footer button)'); if (b) encFwd(b); } });
    }

    // ── Send Button Intercept ─────────────────────────────────────────────────
    const secTxt = () => { const s = document.getElementById("secure-input-overlay"); return s ? (s.tagName === "TEXTAREA" ? s.value.trim() : s.innerText.trim()) : ""; };
    const isSnB = t => !!(t.closest('[aria-label="send-button"]') || t.closest('.RaTWwR'));

    let tTmr = null, isLng = false;
    for (const ev of ["mousedown", "mouseup", "click", "pointerdown", "pointerup"]) {
        document.addEventListener(ev, e => {
            if (!e.isTrusted || !isSnB(e.target) || !encOn() || !secTxt()) return;
            if (isSending) { e.preventDefault(); e.stopPropagation(); return; }
            e.preventDefault(); e.stopPropagation();
            if (ev === "click" && e.button === 0) window._bbSend?.(true);
        }, true);
    }
    document.addEventListener("touchstart", e => {
        if (!e.isTrusted || !isSnB(e.target) || !encOn() || !secTxt()) return;
        if (isSending) { e.preventDefault(); e.stopPropagation(); return; }
        e.preventDefault(); e.stopPropagation(); isLng = false;
        if (tTmr !== null) clearTimeout(tTmr);
        tTmr = setTimeout(() => { isLng = true; if (e.touches?.length) showMenu(e.touches[0].clientX, e.touches[0].clientY); }, CFG.LONG_PRESS);
    }, { passive: false, capture: true });
    document.addEventListener("touchend", e => {
        if (!e.isTrusted || !isSnB(e.target) || !encOn() || !secTxt()) return;
        if (isSending) { e.preventDefault(); e.stopPropagation(); return; }
        e.preventDefault(); e.stopPropagation();
        if (tTmr !== null) { clearTimeout(tTmr); tTmr = null; }
        if (!isLng) window._bbSend?.(true);
    }, { passive: false, capture: true });
    document.addEventListener("touchmove", e => {
        if (!e.isTrusted || !isSnB(e.target)) return;
        if (tTmr !== null) { clearTimeout(tTmr); tTmr = null; } isLng = true;
    }, { passive: false, capture: true });
    document.addEventListener("contextmenu", e => {
        if (isSending || !isSnB(e.target) || !encOn() || !secTxt()) return;
        e.preventDefault(); e.stopPropagation(); showMenu(e.clientX, e.clientY);
    }, true);

    // ── Observer ──────────────────────────────────────────────────────────────
    let _dirty = false, _raf = 0, lastUrl = location.href;
    function tick() {
        _raf = 0; _dirty = false;
        try {
            scan(document.body); ensureInput(); ensureEdit();
            if (location.href !== lastUrl) { lastUrl = location.href; _sc = null; _scId = null; syncVis(); }
        } catch (e) { console.error("[BB]", e); }
    }
    new MutationObserver(() => {
        if (!_dirty) { _dirty = true; if (_raf) cancelAnimationFrame(_raf); _raf = requestAnimationFrame(tick); }
    }).observe(document.body, { childList: true, subtree: true, characterData: true });

    try { scan(document.body); ensureInput(); ensureEdit(); } catch (e) { console.error("[BB] init", e); }
})();
