// ==UserScript==
// @name         Bale Bridge Encryptor (Secure ECDH & Anti-XSS)
// @namespace    http://tampermonkey.net/
// @version      13.0
// @description  Dark Glassmorphism UI, Fixed Send, ECDH Bridge, Anti-XSS.
// @author       You
// @match        *://web.bale.ai/*
// @match        *://*.bale.ai/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

(function () {
    "use strict";

    // ─── 0. CONFIG ────────────────────────────────────────────────────────────
    const CFG = Object.freeze({
        KEY_LEN: 32,
        MAX_ENC_LEN: 4000,
        HS_EXPIRY: 300,
        TOAST_DUR: 5000,
        SCAN_MS: 120,
        LONG_PRESS: 400,
        SEND_DLY: 80,
        POST_DLY: 200,
        MAX_HASHES: 50,
        MAX_CHUNK_DEPTH: 10,
        KEY_CACHE_MAX: 16,
        CHARS: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_+=~",
        B85: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~",
        HS_REQ: 0x01,
        HS_RES: 0x02,
        PFX_ENC: "@@",
        PFX_HS: "!!",
    });

    // ─── 0a. Accent palette ───────────────────────────────────────────────────
    const PAL = Object.freeze({
        accent:    "#00e6a0",
        accentDim: "#00c488",
        accentGlow:"rgba(0,230,160,.25)",
        bg:        "#0d1117",
        card:      "#161b22",
        surface:   "#1c2128",
        border:    "#30363d",
        borderLit: "#3d444d",
        text:      "#e6edf3",
        textDim:   "#8b949e",
        textMuted: "#484f58",
        danger:    "#f85149",
        dangerDim: "#da3633",
        warn:      "#d29922",
        warnBg:    "rgba(210,153,34,.12)",
        glass:     "rgba(22,27,34,.82)",
        glassBorder:"rgba(240,246,252,.08)",
    });

    // ─── 0b. WebSocket Draft Blocker ──────────────────────────────────────────
    const _origWsSend = WebSocket.prototype.send;
    const _draftRx = /EditParameter[\s\S]*drafts_|drafts_[\s\S]*EditParameter/;

    WebSocket.prototype.send = function (data) {
        try {
            let t = "";
            if (typeof data === "string") t = data;
            else if (data instanceof ArrayBuffer) t = new TextDecoder().decode(data);
            else if (ArrayBuffer.isView(data)) t = new TextDecoder().decode(data);
            if (t && _draftRx.test(t)) return;
        } catch (_) {}
        return _origWsSend.apply(this, arguments);
    };

    // ─── 1. Settings ──────────────────────────────────────────────────────────
    const SAFE_ID = /^[a-zA-Z0-9_\-]+$/;
    const getChatId = () => {
        const p = new URLSearchParams(location.search);
        const raw = p.get("uid") || p.get("groupId") || p.get("channelId") || location.pathname.split("/").pop() || "global";
        return SAFE_ID.test(raw) ? raw : "global";
    };

    let _scId = null, _sc = null;
    const getChatSettings = () => {
        const id = getChatId();
        if (id === _scId && _sc) return _sc;
        try {
            const raw = localStorage.getItem("bale_bridge_settings_" + id);
            if (raw) {
                const o = JSON.parse(raw);
                if (o && typeof o.enabled === "boolean" && typeof o.customKey === "string" && o.customKey.length <= CFG.KEY_LEN) {
                    _sc = { enabled: o.enabled, customKey: o.customKey };
                    _scId = id;
                    return _sc;
                }
            }
        } catch (_) {}
        _sc = { enabled: true, customKey: "" };
        _scId = id;
        return _sc;
    };

    const saveChatSettings = (s) => {
        const id = getChatId();
        _sc = { enabled: !!s.enabled, customKey: String(s.customKey || "") };
        _scId = id;
        localStorage.setItem("bale_bridge_settings_" + id, JSON.stringify(_sc));
    };

    const getActiveKey = () => {
        const s = getChatSettings();
        return s.enabled && s.customKey && s.customKey.length === CFG.KEY_LEN ? s.customKey : null;
    };
    const isEncOn = () => getChatSettings().enabled;
    const getFingerprint = () => {
        const k = getActiveKey();
        return k ? k.substring(0, 5).toUpperCase() : "NONE";
    };

    // ─── 2. Crypto ────────────────────────────────────────────────────────────
    const keyCache = new Map();
    async function getCryptoKey(k) {
        if (keyCache.has(k)) return keyCache.get(k);
        const enc = new TextEncoder().encode(k);
        if (enc.length !== CFG.KEY_LEN) throw new RangeError("Bad key length");
        const key = await crypto.subtle.importKey("raw", enc, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
        if (keyCache.size >= CFG.KEY_CACHE_MAX) keyCache.delete(keyCache.keys().next().value);
        keyCache.set(k, key);
        return key;
    }

    function generateKey() {
        const c = CFG.CHARS, cl = c.length, mx = Math.floor(256 / cl) * cl;
        const r = []; let f = 0;
        while (f < CFG.KEY_LEN) {
            const b = crypto.getRandomValues(new Uint8Array(CFG.KEY_LEN * 2));
            for (let i = 0; i < b.length && f < CFG.KEY_LEN; i++) if (b[i] < mx) r[f++] = c[b[i] % cl];
        }
        return r.join("");
    }

    // Base85
    const B85 = CFG.B85, B85D = new Uint8Array(128).fill(255);
    for (let i = 0; i < B85.length; i++) B85D[B85.charCodeAt(i)] = i;

    function b85enc(buf) {
        const len = buf.length, out = [];
        for (let i = 0; i < len; i += 4) {
            const rem = Math.min(len - i, 4);
            let acc = 0;
            for (let j = 0; j < 4; j++) acc = (acc << 8) | (i + j < len ? buf[i + j] : 0);
            acc >>>= 0;
            const cnt = rem < 4 ? rem + 1 : 5, tmp = Array(5);
            for (let j = 4; j >= 0; j--) { tmp[j] = B85[acc % 85]; acc = Math.floor(acc / 85); }
            for (let j = 0; j < cnt; j++) out.push(tmp[j]);
        }
        return out.join("");
    }

    function b85dec(str) {
        const sl = str.length; if (!sl) return new Uint8Array(0);
        const rm = sl % 5; if (rm === 1) throw new RangeError("Bad b85 length");
        const full = Math.floor(sl / 5), est = full * 4 + (rm ? rm - 1 : 0), out = new Uint8Array(est);
        let w = 0;
        for (let i = 0; i < sl; i += 5) {
            const end = Math.min(i + 5, sl), pad = 5 - (end - i);
            let acc = 0;
            for (let j = 0; j < 5; j++) {
                const ci = i + j < sl ? str.charCodeAt(i + j) : 126;
                if (ci >= 128 || B85D[ci] === 255) throw new RangeError("Bad b85 char at " + (i + j));
                acc = acc * 85 + B85D[ci];
            }
            const bytes = 4 - pad;
            if (bytes >= 1) out[w++] = (acc >>> 24) & 0xff;
            if (bytes >= 2) out[w++] = (acc >>> 16) & 0xff;
            if (bytes >= 3) out[w++] = (acc >>> 8) & 0xff;
            if (bytes >= 4) out[w++] = acc & 0xff;
        }
        return out.subarray(0, w);
    }

    // Compression
    async function compress(text) {
        if (typeof CompressionStream === "undefined") return new TextEncoder().encode(text);
        const cs = new CompressionStream("deflate"), w = cs.writable.getWriter();
        w.write(new TextEncoder().encode(text)); w.close();
        return new Uint8Array(await new Response(cs.readable).arrayBuffer());
    }
    async function decompress(buf) {
        if (typeof DecompressionStream === "undefined") return new TextDecoder().decode(buf);
        try {
            const ds = new DecompressionStream("deflate"), w = ds.writable.getWriter();
            w.write(buf); w.close();
            return new TextDecoder().decode(await new Response(ds.readable).arrayBuffer());
        } catch (_) { return new TextDecoder().decode(buf); }
    }

    async function encrypt(text) {
        const k = getActiveKey(); if (!k) return null;
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await getCryptoKey(k), await compress(text)));
        const p = new Uint8Array(12 + ct.length); p.set(iv); p.set(ct, 12);
        return CFG.PFX_ENC + b85enc(p);
    }

    async function decrypt(text) {
        if (!text.startsWith(CFG.PFX_ENC)) return text;
        const k = getActiveKey(); if (!k) return text;
        try {
            const buf = b85dec(text.slice(2));
            if (buf.length < 13) return text;
            return await decompress(new Uint8Array(await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: buf.subarray(0, 12) }, await getCryptoKey(k), buf.subarray(12))));
        } catch (_) { return text; }
    }

    async function encryptChunked(text, depth = 0) {
        if (depth > CFG.MAX_CHUNK_DEPTH) return null;
        const r = await encrypt(text); if (!r) return null;
        if (r.length <= CFG.MAX_ENC_LEN) return [r];
        const mid = Math.floor(text.length / 2);
        let sp = text.lastIndexOf("\n", mid);
        if (sp <= 0) sp = text.lastIndexOf(" ", mid);
        if (sp <= 0) sp = mid;
        const a = await encryptChunked(text.slice(0, sp).trim(), depth + 1);
        const b = await encryptChunked(text.slice(sp).trim(), depth + 1);
        return a && b ? [...a, ...b] : null;
    }

    // ─── 3. ECDH ──────────────────────────────────────────────────────────────
    let _hsLock = Promise.resolve();
    function withHsLock(fn) {
        let unlock;
        const prev = _hsLock;
        _hsLock = new Promise(r => unlock = r);
        return prev.then(() => fn()).finally(() => unlock());
    }

    const _hsNewPair = () => crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const _hsPubRaw = async (k) => new Uint8Array(await crypto.subtle.exportKey("raw", k));
    const _hsPubImport = (b) => crypto.subtle.importKey("raw", b, { name: "ECDH", namedCurve: "P-256" }, false, []);

    async function _hsDeriveKey(myPriv, theirPubBytes) {
        const theirPub = await _hsPubImport(theirPubBytes);
        const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: theirPub }, myPriv, 256);
        let hash;
        if (crypto.subtle.importKey && typeof crypto.subtle.deriveBits === 'function') {
            try {
                const ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
                hash = new Uint8Array(await crypto.subtle.deriveBits({
                    name: "HKDF", hash: "SHA-256",
                    salt: new TextEncoder().encode("bale-bridge-v13"),
                    info: new TextEncoder().encode("aes-key"),
                }, ikm, 512));
            } catch (_) {
                hash = new Uint8Array(await crypto.subtle.digest("SHA-256", shared));
                const pad = new Uint8Array(64); pad.set(hash); hash = pad;
            }
        } else {
            hash = new Uint8Array(await crypto.subtle.digest("SHA-256", shared));
            const pad = new Uint8Array(64); pad.set(hash); hash = pad;
        }
        const c = CFG.CHARS, cl = c.length, mx = Math.floor(256 / cl) * cl;
        let key = "", idx = 0;
        while (key.length < CFG.KEY_LEN) {
            if (idx >= hash.length) throw new Error("Not enough entropy");
            if (hash[idx] < mx) key += c[hash[idx] % cl];
            idx++;
        }
        return key;
    }

    function toast(msg, dur = CFG.TOAST_DUR) {
        const el = document.createElement("div");
        el.textContent = msg;
        Object.assign(el.style, {
            position:"fixed",bottom:"88px",left:"50%",transform:"translateX(-50%) translateY(16px)",
            background:PAL.glass,color:PAL.text,padding:"12px 24px",borderRadius:"24px",
            fontSize:"14px",fontFamily:"inherit",zIndex:"9999999",opacity:"0",pointerEvents:"none",
            transition:"all .3s cubic-bezier(.2,.8,.2,1)",whiteSpace:"nowrap",
            boxShadow:`0 8px 32px rgba(0,0,0,.5), inset 0 0 0 1px ${PAL.glassBorder}`,
            backdropFilter:"blur(20px)",WebkitBackdropFilter:"blur(20px)",border:`1px solid ${PAL.glassBorder}`,
        });
        document.body.appendChild(el);
        requestAnimationFrame(() => { el.style.opacity = "1"; el.style.transform = "translateX(-50%) translateY(0)"; });
        setTimeout(() => { el.style.opacity = "0"; el.style.transform = "translateX(-50%) translateY(10px)"; setTimeout(() => el.remove(), 300); }, dur);
    }

    function _vizHs(el, text) {
        el.textContent = "";
        const badge = document.createElement("span");
        badge.textContent = text;
        Object.assign(badge.style, {
            display:"inline-block",margin:"2px 0",padding:"4px 12px",fontSize:"11px",fontWeight:"600",
            fontFamily:"monospace",color:PAL.accent,background:PAL.surface,borderRadius:"20px",
            border:`1px solid ${PAL.accent}`,opacity:"0.9",userSelect:"none",
            boxShadow:`0 0 12px ${PAL.accentGlow}`,
        });
        el.appendChild(badge);
        el.style.display = "block"; el.style.textAlign = "center";
        el._isDecrypted = true;
    }

    // Hash tracking
    function markHash(cid, h) {
        const k = "bb_phs_" + cid;
        try {
            const a = JSON.parse(localStorage.getItem(k) || "[]");
            if (!Array.isArray(a)) { localStorage.setItem(k, JSON.stringify([h])); return; }
            if (!a.includes(h)) { a.push(h); while (a.length > CFG.MAX_HASHES) a.shift(); localStorage.setItem(k, JSON.stringify(a)); }
        } catch (_) { localStorage.setItem(k, JSON.stringify([h])); }
    }
    function isHashed(cid, h) { try { const a = JSON.parse(localStorage.getItem("bb_phs_" + cid) || "[]"); return Array.isArray(a) && a.includes(h); } catch (_) { return false; } }
    function cHash(s) { let h = 0; for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0; return h; }

    function tsBytes() { const t = Math.floor(Date.now() / 1000); return new Uint8Array([(t>>>24)&0xff,(t>>>16)&0xff,(t>>>8)&0xff,t&0xff]); }
    function readTs(b) { return ((b[0]<<24)|(b[1]<<16)|(b[2]<<8)|b[3])>>>0; }

    // ─── Send helpers ─────────────────────────────────────────────────────────
    const _taSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set;
    const getRealInput = () => document.getElementById("editable-message-text") || document.getElementById("main-message-input");
    const isMobile = (el) => el?.tagName === "TEXTAREA";

    async function _sendRaw(text) {
        const real = getRealInput(); if (!real) return;
        const mob = isMobile(real), wasSyncing = isSyncing;
        isSyncing = true;
        unlockInput(real);

        if (mob) {
            _taSetter?.call(real, text);
            real.dispatchEvent(new Event("input", { bubbles: true, cancelable: true }));
        } else {
            real.focus();
            document.execCommand("selectAll", false, null);
            document.execCommand("insertText", false, text);
            real.dispatchEvent(new Event("input", { bubbles: true, cancelable: true }));
        }
        await new Promise(r => setTimeout(r, CFG.SEND_DLY));

        let btn = document.querySelector('[aria-label="send-button"]') || document.querySelector('.RaTWwR');
        let sent = false;
        if (btn) {
            const rk = Object.keys(btn).find(k => k.startsWith('__reactProps$'));
            if (rk && typeof btn[rk]?.onClick === 'function') {
                try { btn[rk].onClick({ preventDefault(){}, stopPropagation(){} }); sent = true; } catch(_){}
            }
            if (!sent) {
                for (const t of ["mousedown","pointerdown","mouseup","pointerup","click"])
                    btn.dispatchEvent(new MouseEvent(t, { bubbles:true, cancelable:true, view:window }));
                sent = true;
            }
        }
        if (!sent) real.dispatchEvent(new KeyboardEvent("keydown", { bubbles:true, cancelable:true, key:"Enter", code:"Enter", keyCode:13, which:13 }));

        await new Promise(r => setTimeout(r, CFG.POST_DLY));

        if (mob) {
            if (real.value !== "") { _taSetter?.call(real, ""); real.dispatchEvent(new Event("input", { bubbles:true, cancelable:true })); }
        } else {
            if (real.innerText.trim() !== "") {
                real.focus(); document.execCommand("selectAll", false, null); document.execCommand("delete", false, null);
                real.dispatchEvent(new Event("input", { bubbles:true, cancelable:true }));
            }
        }
        if (isEncOn()) lockInput(real);
        isSyncing = wasSyncing;
    }

    // ─── Handshake Protocol ───────────────────────────────────────────────────
    async function startHandshake() {
        return withHsLock(async () => {
            try {
                const cid = getChatId(), pair = await _hsNewPair(), pub = await _hsPubRaw(pair.publicKey);
                const priv = await crypto.subtle.exportKey("jwk", pair.privateKey);
                sessionStorage.setItem("bb_hs_" + cid, JSON.stringify(priv));
                const pay = new Uint8Array(1 + 4 + pub.length);
                pay[0] = CFG.HS_REQ; pay.set(tsBytes(), 1); pay.set(pub, 5);
                const b64 = btoa(String.fromCharCode(...pay));
                markHash(cid, cHash(b64));
                await _sendRaw(CFG.PFX_HS + b64);
                toast("⏳ Requesting bridge. Waiting for friend...");
            } catch (e) { console.error("[BB] HS start fail", e); toast("❌ Bridge setup failed"); }
        });
    }

    function renderAcceptBtn(el, theirPub, mh, cid) {
        el.textContent = ""; el._isDecrypted = true;
        const box = document.createElement("div");
        Object.assign(box.style, {
            border:`2px solid ${PAL.accent}`,padding:"14px 18px",borderRadius:"16px",
            background:PAL.card,display:"inline-block",fontFamily:"inherit",margin:"4px 0",
            boxShadow:`0 0 20px ${PAL.accentGlow}`,maxWidth:"320px",
        });
        const t = document.createElement("strong");
        t.textContent = "🛡️ Secure Bridge Request";
        Object.assign(t.style, { color:PAL.accent,display:"block",marginBottom:"6px",fontSize:"14px" });
        const d = document.createElement("span");
        d.textContent = "Your friend wants to enable End-to-End Encryption.";
        Object.assign(d.style, { fontSize:"12px",color:PAL.textDim,display:"block",marginBottom:"10px",lineHeight:"1.4" });
        const b = document.createElement("button");
        b.textContent = "Accept & Connect";
        Object.assign(b.style, {
            background:`linear-gradient(135deg, ${PAL.accent}, ${PAL.accentDim})`,color:PAL.bg,border:"none",
            padding:"8px 16px",borderRadius:"10px",cursor:"pointer",fontWeight:"bold",fontSize:"13px",
            transition:"all .2s",boxShadow:`0 4px 16px ${PAL.accentGlow}`,
        });
        b.onmouseenter = () => b.style.transform = "scale(1.03)";
        b.onmouseleave = () => b.style.transform = "";
        b.onclick = async (e) => {
            e.preventDefault(); e.stopPropagation();
            b.disabled = true; b.textContent = "⏳ Connecting..."; b.style.opacity = ".7";
            try {
                await withHsLock(async () => {
                    const pair = await _hsNewPair(), myPub = await _hsPubRaw(pair.publicKey);
                    const key = await _hsDeriveKey(pair.privateKey, theirPub);
                    saveChatSettings({ enabled:true, customKey:key }); syncVis();
                    const rp = new Uint8Array(1+4+myPub.length);
                    rp[0] = CFG.HS_RES; rp.set(tsBytes(),1); rp.set(myPub,5);
                    const rb = btoa(String.fromCharCode(...rp));
                    markHash(cid, mh); markHash(cid, cHash(rb));
                    await _sendRaw(CFG.PFX_HS + rb);
                    _vizHs(el, "✅ Bridge Accepted");
                    toast("🛡️ Secured! Fingerprint: " + getFingerprint(), 7000);
                });
            } catch (err) { console.error("[BB] Accept fail", err); b.disabled = false; b.textContent = "Retry"; b.style.opacity = "1"; }
        };
        box.appendChild(t); box.appendChild(d); box.appendChild(b);
        el.appendChild(box); el.style.display = "block";
    }

    async function _handleHS(b64, el) {
        const cid = getChatId(), mh = cHash(b64);
        if (isHashed(cid, mh)) { _vizHs(el, "🤝 Processed"); return; }
        return withHsLock(async () => {
            if (isHashed(cid, mh)) { _vizHs(el, "🤝 Processed"); return; }
            try {
                const bin = atob(b64), raw = new Uint8Array(bin.length);
                for (let i = 0; i < bin.length; i++) raw[i] = bin.charCodeAt(i);
                if (raw.length < 70) { markHash(cid,mh); _vizHs(el,"❌ Malformed"); return; }
                const type = raw[0], ts = readTs(raw.subarray(1,5)), them = raw.subarray(5);
                const age = Math.floor(Date.now()/1000) - ts;
                if (age > CFG.HS_EXPIRY || age < -60) { markHash(cid,mh); _vizHs(el,"⌛ Expired"); return; }
                if (type === CFG.HS_REQ) {
                    if (!el._hsBound) { renderAcceptBtn(el, them, mh, cid); el._hsBound = true; }
                } else if (type === CFG.HS_RES) {
                    const ps = sessionStorage.getItem("bb_hs_" + cid);
                    if (!ps) { markHash(cid,mh); _vizHs(el,"❌ Orphaned"); return; }
                    let pj; try { pj = JSON.parse(ps); } catch(_) { markHash(cid,mh); _vizHs(el,"❌ Corrupt key"); return; }
                    const pk = await crypto.subtle.importKey("jwk", pj, { name:"ECDH", namedCurve:"P-256" }, false, ["deriveBits"]);
                    const key = await _hsDeriveKey(pk, them);
                    sessionStorage.removeItem("bb_hs_" + cid);
                    saveChatSettings({ enabled:true, customKey:key }); syncVis();
                    markHash(cid, mh);
                    _vizHs(el, "✅ Bridge Complete");
                    toast("🛡️ Secured! Code: " + getFingerprint(), 7000);
                    setTimeout(async () => {
                        try {
                            const fp = getFingerprint();
                            const msg = `✅ Secure Bridge Established!\n\n🛡️ MITM Check — both sides must see:\n\n# ${fp}\n\nDifferent code = interception.`;
                            const chunks = await encryptChunked(msg);
                            if (chunks) for (const c of chunks) await _sendRaw(c);
                        } catch(_){}
                    }, 1000);
                } else { markHash(cid,mh); _vizHs(el,"❌ Unknown type"); }
            } catch (e) { console.error("[BB] HS error", e); _vizHs(el, "❌ Failed"); }
        });
    }

    // ─── 4. DOM Scanner & Renderer ────────────────────────────────────────────
    const ESC = Object.freeze({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"});
    const esc = s => s.replace(/[&<>"']/g, c => ESC[c]);

    function safeUrl(url) {
        try { const u = new URL(url); if (u.protocol === "http:" || u.protocol === "https:") return esc(u.href); } catch(_){} return "#";
    }

    function inlineMd(s) {
        return s
            .replace(/``([^`]+)``|`([^`]+)`/g, (_,a,b) => `<code class="bb-code">${a??b}</code>`)
            .replace(/\|\|(.+?)\|\|/g, (_,t) => `<span class="bb-spoiler" title="Click to reveal">${t}</span>`)
            .replace(/\*\*\*(.+?)\*\*\*/g, (_,t) => `<strong><em>${t}</em></strong>`)
            .replace(/\*\*(.+?)\*\*/g, (_,t) => `<strong>${t}</strong>`)
            .replace(/(?<![_a-zA-Z0-9])__(.+?)__(?![_a-zA-Z0-9])/g, (_,t) => `<u>${t}</u>`)
            .replace(/\*([^*\n]+)\*/g, (_,t) => `<em>${t}</em>`)
            .replace(/(^|[^a-zA-Z0-9_])_([^_\n]+?)_(?=[^a-zA-Z0-9_]|$)/g, (_,p,t) => `${p}<em>${t}</em>`)
            .replace(/~~(.+?)~~/g, (_,t) => `<del>${t}</del>`)
            .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, (_,l,u) => `<a href="${safeUrl(u)}" target="_blank" rel="noopener noreferrer" class="bb-link">${l}</a>`);
    }

    const URL_RX = /https?:\/\/[^\s<>"{}|\\^`[\]]+/g;
    function procLine(rawLine) {
        const parts = []; let last = 0; URL_RX.lastIndex = 0; let m;
        while ((m = URL_RX.exec(rawLine)) !== null) {
            parts.push(inlineMd(esc(rawLine.slice(last, m.index))));
            const su = safeUrl(m[0]);
            parts.push(`<a href="${su}" target="_blank" rel="noopener noreferrer" class="bb-link" style="word-break:break-all">${su}</a>`);
            last = m.index + m[0].length;
        }
        parts.push(inlineMd(esc(rawLine.slice(last))));
        return parts.join("");
    }

    function renderDec(plain) {
        const lines = plain.split("\n"), out = []; let i = 0;
        const blk = h => `<span dir="auto" class="bb-block">${h}</span>`;
        while (i < lines.length) {
            const L = lines[i];
            if (L.startsWith("> ") || L === ">") {
                const q = [];
                while (i < lines.length && (lines[i].startsWith("> ") || lines[i] === ">")) q.push(lines[i++].replace(/^> ?/,""));
                out.push(`<span dir="auto" class="bb-quote">${q.map(procLine).join("<br>")}</span>`); continue;
            }
            if (/^[-*+] /.test(L)) {
                const it = [];
                while (i < lines.length && /^[-*+] /.test(lines[i])) it.push(`<li class="bb-li">${procLine(lines[i++].slice(2))}</li>`);
                out.push(`<ul dir="auto" class="bb-ul">${it.join("")}</ul>`); continue;
            }
            if (/^\d+\. /.test(L)) {
                const it = [];
                while (i < lines.length && /^\d+\. /.test(lines[i])) it.push(`<li class="bb-li">${procLine(lines[i++].replace(/^\d+\. /,""))}</li>`);
                out.push(`<ol dir="auto" class="bb-ol">${it.join("")}</ol>`); continue;
            }
            const hm = L.match(/^(#{1,3}) (.+)/);
            if (hm) { const sz=["1.25em","1.1em","1em"][Math.min(hm[1].length,3)-1]; out.push(blk(`<span style="font-weight:700;font-size:${sz}">${procLine(hm[2])}</span>`)); i++; continue; }
            if (/^([-*_])\1{2,}$/.test(L.trim())) { out.push(`<span class="bb-hr"></span>`); i++; continue; }
            if (L.trim() === "") { out.push(`<span class="bb-spacer"></span>`); i++; continue; }
            out.push(blk(procLine(L))); i++;
        }
        return out.join("");
    }

    const SKIP_IDS = new Set(["secure-input-overlay","secure-edit-overlay","editable-message-text","main-message-input","bb-no-key-notice","bale-bridge-menu","bb-modal-overlay"]);
    const _inflight = new WeakSet();

    function scanTree(root) {
        const els = Array.from(root.getElementsByTagName("*"));
        for (const el of els) {
            if (el._isDecrypted || _inflight.has(el)) continue;
            if (SKIP_IDS.has(el.id)) continue;
            const txt = el.textContent; if (txt.length <= 20) continue;
            const trim = txt.trim();

            const mhs = trim.match(/^!!([A-Za-z0-9+/=]{40,})/);
            if (mhs) {
                let skip = false;
                for (const c of el.children) { if (c.textContent.includes("!!")) { skip = true; break; } }
                if (skip) continue;
                el._isDecrypted = true;
                _handleHS(mhs[1], el).catch(e => console.error("[BB]", e));
                continue;
            }
            if (trim.startsWith(CFG.PFX_ENC) && trim.length > 20) {
                let skip = false;
                for (const c of el.children) { if (c.textContent.trim() === trim) { skip = true; break; } }
                if (skip) continue;
                _inflight.add(el);
                decrypt(trim).then(plain => {
                    if (plain !== trim) {
                        if (!el._bbOvf) {
                            Object.assign(el.style, { overflow:"hidden", overflowWrap:"anywhere", wordBreak:"break-word", maxWidth:"100%" });
                            el.classList.add("bb-msg-container"); el._bbOvf = true;
                        }
                        el.innerHTML = renderDec(plain) + `<span class="bb-enc-badge">🔒<span class="bb-copy-btn" title="Copy">📋</span></span>`;
                        el.style.color = "inherit"; el._isDecrypted = true;
                        const cb = el.querySelector(".bb-copy-btn");
                        if (cb) cb.onclick = (e) => { e.preventDefault(); e.stopPropagation(); navigator.clipboard.writeText(plain).then(() => { cb.textContent = "✅"; setTimeout(() => cb.textContent = "📋", 1500); }).catch(()=>{}); };
                    }
                }).catch(e => console.error("[BB]", e)).finally(() => _inflight.delete(el));
            }
        }
    }

    // ─── 5. Spoiler handler ───────────────────────────────────────────────────
    document.addEventListener("click", e => {
        const sp = e.target.closest(".bb-spoiler");
        if (sp) { sp.style.color = "inherit"; sp.style.background = PAL.border; }
    }, true);

    // ─── 6. Styles ────────────────────────────────────────────────────────────
    const sty = document.createElement("style");
    sty.textContent = `
/* ─── Secure Input ─── */
#secure-input-overlay {
    width:100%;box-sizing:border-box;min-height:44px;max-height:150px;overflow-y:auto;
    background:${PAL.surface};border:2px solid ${PAL.accent};
    box-shadow:0 0 20px ${PAL.accentGlow}, inset 0 0 0 1px rgba(0,230,160,.05);
    border-radius:16px;padding:10px 16px;font-family:inherit;font-size:inherit;outline:none;
    white-space:pre-wrap;word-break:break-word;margin-right:10px;resize:none;
    color:${PAL.text};z-index:100;position:relative;
    transition:box-shadow .3s,border-color .3s;display:block;
}
#secure-input-overlay:focus {
    box-shadow:0 0 30px ${PAL.accentGlow}, 0 0 60px rgba(0,230,160,.08);
    border-color:${PAL.accent};
}
div#secure-input-overlay:empty::before {
    content:attr(data-placeholder);color:${PAL.textMuted};pointer-events:none;display:block;
}

/* ─── No-Key Notice ─── */
#bb-no-key-notice {
    display:none;align-items:flex-start;gap:10px;width:100%;box-sizing:border-box;
    padding:12px 16px;margin-right:10px;
    background:${PAL.warnBg};border:2px solid ${PAL.warn};border-radius:16px;
    font-family:inherit;font-size:13px;color:${PAL.warn};line-height:1.5;
    position:relative;z-index:101;backdrop-filter:blur(8px);
}
#bb-no-key-notice .bb-notice-icon{font-size:20px;flex-shrink:0;margin-top:1px}
#bb-no-key-notice .bb-notice-body{flex:1}
#bb-no-key-notice strong{display:block;font-size:13px;margin-bottom:3px;color:${PAL.warn}}
#bb-no-key-notice .bb-notice-btn{
    display:inline-block;margin-top:7px;padding:6px 14px;border-radius:10px;border:none;
    background:linear-gradient(135deg,${PAL.warn},#e6a817);color:${PAL.bg};
    font-size:12px;font-weight:700;cursor:pointer;transition:all .2s;
    box-shadow:0 4px 16px rgba(210,153,34,.25);
}
#bb-no-key-notice .bb-notice-btn:hover{transform:scale(1.03);box-shadow:0 6px 20px rgba(210,153,34,.35)}

/* ─── Context Menu ─── */
#bale-bridge-menu {
    position:fixed;z-index:999999;
    background:${PAL.glass};border:1px solid ${PAL.glassBorder};border-radius:16px;
    box-shadow:0 16px 48px rgba(0,0,0,.5);display:none;flex-direction:column;overflow:hidden;
    font-family:inherit;color:${PAL.text};min-width:200px;
    backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
    animation:bb-pop .2s cubic-bezier(.2,.8,.2,1);
}
.bale-menu-item {
    padding:14px 20px;cursor:pointer;font-size:14px;font-weight:500;
    transition:all .15s;display:flex;align-items:center;gap:12px;
}
.bale-menu-item:hover{background:rgba(255,255,255,.06)}
.bale-menu-item:active{background:rgba(255,255,255,.1)}

/* ─── Modal ─── */
#bb-modal-overlay {
    position:fixed;inset:0;background:rgba(0,0,0,.6);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);
    display:flex;align-items:center;justify-content:center;z-index:9999999;
    animation:bb-fade .2s ease-out;
}
#bb-modal-card {
    background:${PAL.card};padding:28px;border-radius:24px;
    width:380px;max-width:92vw;
    box-shadow:0 24px 80px rgba(0,0,0,.6), 0 0 0 1px ${PAL.glassBorder};
    color:${PAL.text};font-family:inherit;
    animation:bb-pop .3s cubic-bezier(.2,.8,.2,1);
}
.bb-modal-title{margin:0 0 8px;font-size:20px;font-weight:700;letter-spacing:-.02em}
.bb-modal-desc{margin:0 0 20px;font-size:13px;color:${PAL.textDim};line-height:1.5}
.bb-input {
    width:100%;padding:10px 14px;border-radius:10px;
    border:1px solid ${PAL.border};box-sizing:border-box;
    background:${PAL.surface};color:${PAL.text};
    font-family:monospace;font-size:13px;transition:all .2s;letter-spacing:.04em;
}
.bb-input:focus{outline:none;border-color:${PAL.accent};box-shadow:0 0 0 3px ${PAL.accentGlow}}
.bb-key-row{display:flex;gap:8px;align-items:center;margin-top:8px}
.bb-key-row .bb-input{flex:1;margin-top:0}
.bb-icon-btn {
    flex-shrink:0;padding:0;width:38px;height:38px;border-radius:10px;
    border:1px solid ${PAL.border};background:${PAL.surface};cursor:pointer;
    display:flex;align-items:center;justify-content:center;font-size:16px;
    transition:all .2s;color:${PAL.text};
}
.bb-icon-btn:hover{border-color:${PAL.accent};background:rgba(0,230,160,.08);box-shadow:0 0 12px ${PAL.accentGlow}}
.bb-icon-btn.copied{border-color:${PAL.accent};background:rgba(0,230,160,.15);color:${PAL.accent}}
.bb-key-tools{display:flex;gap:8px;margin-top:10px}
.bb-tool-btn {
    flex:1;padding:8px 0;border-radius:10px;border:1px solid ${PAL.border};
    background:${PAL.surface};cursor:pointer;font-size:12px;font-weight:600;
    display:flex;align-items:center;justify-content:center;gap:6px;
    transition:all .2s;color:${PAL.text};
}
.bb-tool-btn:hover{border-color:${PAL.accent};background:rgba(0,230,160,.06);color:${PAL.accent}}
.bb-tool-btn.bridge{border-color:${PAL.accent};color:${PAL.accent}}
.bb-tool-btn.bridge:hover{background:rgba(0,230,160,.12)}
.bb-toggle-lbl{display:flex;align-items:center;gap:10px;font-size:14px;cursor:pointer}
.bb-toggle-lbl input[type="checkbox"]{width:18px;height:18px;accent-color:${PAL.accent};cursor:pointer}
.bb-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:24px}
.bb-btn{padding:9px 18px;border-radius:10px;border:none;cursor:pointer;font-weight:600;font-size:14px;transition:all .2s}
.bb-btn:active{transform:scale(.96)}
.bb-btn-cancel{background:transparent;color:${PAL.textDim};border:1px solid ${PAL.border}}
.bb-btn-cancel:hover{background:${PAL.surface};color:${PAL.text}}
.bb-btn-save{background:linear-gradient(135deg,${PAL.accent},${PAL.accentDim});color:${PAL.bg};box-shadow:0 4px 16px ${PAL.accentGlow}}
.bb-btn-save:hover{box-shadow:0 6px 24px rgba(0,230,160,.35);transform:translateY(-1px)}
.bb-btn-save:disabled{background:${PAL.border};color:${PAL.textMuted};cursor:not-allowed;transform:none;box-shadow:none}
.bb-key-meta{display:flex;justify-content:space-between;align-items:center;margin-top:8px;font-size:11px}
.bb-key-error{color:${PAL.danger};font-weight:500;font-size:11px;min-height:16px}
.bb-section-divider{margin-top:18px;border-top:1px solid ${PAL.border};padding-top:18px}

@keyframes bb-fade{from{opacity:0}to{opacity:1}}
@keyframes bb-pop{from{opacity:0;transform:scale(.96) translateY(8px)}to{opacity:1;transform:scale(1) translateY(0)}}

/* ─── Message Rendering ─── */
.bb-block{display:block;unicode-bidi:plaintext}
.bb-quote{display:block;border-inline-start:3px solid ${PAL.accent};padding:3px 12px;margin:3px 0;font-style:italic;opacity:.85;unicode-bidi:plaintext;background:rgba(0,230,160,.04);border-radius:0 8px 8px 0}
.bb-ul{margin:4px 0;padding-inline-start:22px;list-style:disc;unicode-bidi:plaintext}
.bb-ol{margin:4px 0;padding-inline-start:22px;list-style:decimal;unicode-bidi:plaintext}
.bb-li{margin:2px 0;padding-inline-start:2px}
.bb-hr{display:block;border:none;border-top:1px solid ${PAL.border};margin:8px 0}
.bb-spacer{display:block;height:.4em}
.bb-code{background:${PAL.surface};border:1px solid ${PAL.border};border-radius:6px;padding:1px 6px;font-family:monospace;font-size:.9em;color:${PAL.accent}}
.bb-spoiler{background:${PAL.textMuted};color:transparent;border-radius:4px;padding:0 4px;cursor:pointer;user-select:none;transition:all .2s}
.bb-link{color:${PAL.accent};text-decoration:underline;text-decoration-color:rgba(0,230,160,.3);transition:text-decoration-color .2s}
.bb-link:hover{text-decoration-color:${PAL.accent}}
.bb-enc-badge{display:inline-block;font-size:9px;opacity:.45;letter-spacing:.02em;font-style:italic;margin-inline-start:6px;vertical-align:middle;line-height:1;white-space:nowrap}
.bb-copy-btn{cursor:pointer;margin-inline-start:4px;font-size:11px;font-style:normal;transition:opacity .2s;opacity:.7}
.bb-copy-btn:hover{opacity:1!important}

/* ─── Chat list previews ─── */
.BAsWs0 .bb-block,.MRlMpm .bb-block,.dialog-item-content .bb-block,.aqFHpt .bb-block,
.BAsWs0 .bb-quote,.MRlMpm .bb-quote,.dialog-item-content .bb-quote,.aqFHpt .bb-quote,
.BAsWs0 .bb-ul,.MRlMpm .bb-ul,.dialog-item-content .bb-ul,.aqFHpt .bb-ul,
.BAsWs0 .bb-ol,.MRlMpm .bb-ol,.dialog-item-content .bb-ol,.aqFHpt .bb-ol,
.BAsWs0 .bb-li,.MRlMpm .bb-li,.dialog-item-content .bb-li,.aqFHpt .bb-li{
    display:inline!important;margin:0!important;padding:0!important;border:none!important;background:none!important
}
.BAsWs0 .bb-spacer,.MRlMpm .bb-spacer,.dialog-item-content .bb-spacer,.aqFHpt .bb-spacer,
.BAsWs0 .bb-hr,.MRlMpm .bb-hr,.dialog-item-content .bb-hr,.aqFHpt .bb-hr,
.BAsWs0 .bb-copy-btn,.MRlMpm .bb-copy-btn,.dialog-item-content .bb-copy-btn,.aqFHpt .bb-copy-btn{display:none!important}
.BAsWs0 .bb-li::after,.MRlMpm .bb-li::after,.dialog-item-content .bb-li::after,.aqFHpt .bb-li::after{content:" \\00a0•\\00a0 "}
.BAsWs0 .bb-msg-container,.MRlMpm .bb-msg-container,.dialog-item-content .bb-msg-container,.aqFHpt .bb-msg-container{
    display:-webkit-box!important;-webkit-line-clamp:2!important;-webkit-box-orient:vertical!important;white-space:normal!important
}
`;
    document.head.appendChild(sty);

    // ─── 7. Context Menu ──────────────────────────────────────────────────────
    const popMenu = document.createElement("div");
    popMenu.id = "bale-bridge-menu";
    const mi1 = document.createElement("div"); mi1.className = "bale-menu-item"; mi1.textContent = "🔒 Send Encrypted";
    mi1.onclick = () => { popMenu.style.display = "none"; window._bbSend?.(true); };
    const mi2 = document.createElement("div"); mi2.className = "bale-menu-item"; mi2.textContent = "⚠️ Send Unencrypted";
    mi2.onclick = () => { popMenu.style.display = "none"; window._bbSend?.(false); };
    popMenu.appendChild(mi1); popMenu.appendChild(mi2);
    document.body.appendChild(popMenu);
    const showMenu = (x, y) => Object.assign(popMenu.style, { display:"flex", left:Math.min(x,innerWidth-220)+"px", top:Math.min(y,innerHeight-130)+"px" });
    document.addEventListener("click", e => { if (!popMenu.contains(e.target)) popMenu.style.display = "none"; });

    // ─── 8. Settings Modal ────────────────────────────────────────────────────
    function openSettings() {
        document.getElementById("bb-modal-overlay")?.remove();
        const s = getChatSettings();
        const fp = s.enabled && s.customKey?.length === CFG.KEY_LEN ? s.customKey.substring(0,5).toUpperCase() : "N/A";

        const ov = document.createElement("div"); ov.id = "bb-modal-overlay";
        const cd = document.createElement("div"); cd.id = "bb-modal-card";

        const t = document.createElement("h3"); t.className = "bb-modal-title"; t.textContent = "🛡️ Shield Settings";
        const d = document.createElement("p"); d.className = "bb-modal-desc"; d.textContent = "Configure encryption for this chat. A 32-character key is required when enabled.";

        const elbl = document.createElement("label"); elbl.className = "bb-toggle-lbl";
        const ecb = document.createElement("input"); ecb.type = "checkbox"; ecb.checked = s.enabled;
        const etxt = document.createElement("span"); etxt.textContent = "Enable Encryption";
        elbl.appendChild(ecb); elbl.appendChild(etxt);

        const ksec = document.createElement("div"); ksec.className = "bb-section-divider";

        const klbl = document.createElement("label");
        Object.assign(klbl.style, { fontSize:"12px", color:PAL.textDim, fontWeight:"600", display:"block", marginBottom:"2px" });
        klbl.textContent = "Encryption Key ";
        const req = document.createElement("span"); req.style.color = PAL.danger; req.textContent = "*"; klbl.appendChild(req);

        const krow = document.createElement("div"); krow.className = "bb-key-row";
        const kinp = document.createElement("input"); kinp.type = "password"; kinp.className = "bb-input";
        kinp.placeholder = "Exactly 32 characters…"; kinp.maxLength = 32; kinp.value = s.customKey || "";

        const vbtn = document.createElement("button"); vbtn.className = "bb-icon-btn"; vbtn.title = "Toggle visibility"; vbtn.textContent = "👁";
        const cbtn = document.createElement("button"); cbtn.className = "bb-icon-btn"; cbtn.title = "Copy key"; cbtn.textContent = "📋";
        krow.appendChild(kinp); krow.appendChild(vbtn); krow.appendChild(cbtn);

        const ktools = document.createElement("div"); ktools.className = "bb-key-tools";
        const gbtn = document.createElement("button"); gbtn.className = "bb-tool-btn"; gbtn.textContent = "⚡ Random Key";
        const hbtn = document.createElement("button"); hbtn.className = "bb-tool-btn bridge"; hbtn.textContent = "🤝 Auto Bridge";
        ktools.appendChild(gbtn); ktools.appendChild(hbtn);

        const kmeta = document.createElement("div"); kmeta.className = "bb-key-meta"; kmeta.style.marginTop = "10px";
        const errEl = document.createElement("span"); errEl.className = "bb-key-error";
        const fpWrap = document.createElement("span"); fpWrap.style.cssText = `font-size:11px;color:${PAL.textDim}`;
        fpWrap.textContent = "Fingerprint: ";
        const fpEl = document.createElement("strong"); fpEl.style.cssText = `font-family:monospace;color:${PAL.accent}`; fpEl.textContent = fp;
        fpWrap.appendChild(fpEl);
        kmeta.appendChild(errEl); kmeta.appendChild(fpWrap);

        ksec.appendChild(klbl); ksec.appendChild(krow); ksec.appendChild(ktools); ksec.appendChild(kmeta);

        const acts = document.createElement("div"); acts.className = "bb-actions";
        const canBtn = document.createElement("button"); canBtn.className = "bb-btn bb-btn-cancel"; canBtn.textContent = "Cancel";
        const savBtn = document.createElement("button"); savBtn.className = "bb-btn bb-btn-save"; savBtn.textContent = "Save";
        acts.appendChild(canBtn); acts.appendChild(savBtn);

        cd.appendChild(t); cd.appendChild(d); cd.appendChild(elbl); cd.appendChild(ksec); cd.appendChild(acts);
        ov.appendChild(cd); document.body.appendChild(ov);

        const validate = () => {
            const val = kinp.value, len = val.length, on = ecb.checked;
            ksec.style.display = on ? "" : "none";
            fpEl.textContent = len === CFG.KEY_LEN ? val.substring(0,5).toUpperCase() : "N/A";
            if (!on) { errEl.textContent = ""; savBtn.disabled = false; return; }
            if (len === 0) { errEl.textContent = "Key required."; savBtn.disabled = true; }
            else if (len !== CFG.KEY_LEN) { errEl.textContent = `Need ${CFG.KEY_LEN} chars (${len}).`; savBtn.disabled = true; }
            else { errEl.textContent = ""; savBtn.disabled = false; }
        };
        kinp.addEventListener("input", validate); ecb.addEventListener("change", validate); validate();

        vbtn.onclick = () => { const h = kinp.type === "password"; kinp.type = h ? "text" : "password"; vbtn.textContent = h ? "🙈" : "👁"; };
        cbtn.onclick = () => { if (!kinp.value) return; navigator.clipboard.writeText(kinp.value).then(() => { cbtn.textContent = "✅"; cbtn.classList.add("copied"); setTimeout(() => { cbtn.textContent = "📋"; cbtn.classList.remove("copied"); }, 1500); }).catch(()=>{}); };
        gbtn.onclick = () => { kinp.value = generateKey(); kinp.type = "text"; vbtn.textContent = "🙈"; validate(); };
        hbtn.onclick = () => { ov.remove(); startHandshake(); };
        canBtn.onclick = () => ov.remove();
        savBtn.onclick = () => {
            if (savBtn.disabled) return;
            try { saveChatSettings({ enabled: ecb.checked, customKey: kinp.value }); } catch (e) { toast("Save failed: " + e.message, 3000); return; }
            ov.remove(); syncVis();
        };
        ov.addEventListener("click", e => { if (e.target === ov) ov.remove(); });
    }

    // ─── 9. Input System ──────────────────────────────────────────────────────
    let isSending = false, lastHasText = false, isSyncing = false;

    const lockInput = el => Object.assign(el.style, { position:"absolute",opacity:"0",pointerEvents:"none",height:"0px",width:"0px",overflow:"hidden",zIndex:"-9999" });
    const unlockInput = el => { el.style.position=""; el.style.opacity="1"; el.style.pointerEvents="auto"; el.style.height=""; el.style.width="100%"; el.style.overflow="auto"; el.style.zIndex=""; };

    function syncVis() {
        const real = getRealInput(), sec = document.getElementById("secure-input-overlay"),
              notice = document.getElementById("bb-no-key-notice"), btn = document.getElementById("bb-settings-btn");
        if (!real) return;
        if (!isEncOn()) {
            unlockInput(real);
            if (sec) sec.style.display = "none";
            if (notice) notice.style.display = "none";
            if (btn) btn.style.color = PAL.textDim;
        } else if (getActiveKey()) {
            lockInput(real);
            if (sec) sec.style.display = "";
            if (notice) notice.style.display = "none";
            if (btn) btn.style.color = PAL.accent;
        } else {
            lockInput(real);
            if (sec) sec.style.display = "none";
            if (notice) notice.style.display = "flex";
            if (btn) btn.style.color = PAL.warn;
        }
    }

    function ensureSecureInput() {
        const realInput = getRealInput(); if (!realInput) return;
        const mob = isMobile(realInput), wrapper = realInput.parentElement;
        if (!wrapper) return;

        const emojiBtn = document.querySelector('[aria-label="emoji-icon"]') || document.querySelector(".MmBErq");
        if (emojiBtn && isEncOn()) emojiBtn.style.display = "none";
        else if (emojiBtn) emojiBtn.style.display = "";

        if (emojiBtn && !document.getElementById("bb-settings-btn")) {
            const sb = document.createElement("div"); sb.id = "bb-settings-btn";
            sb.className = emojiBtn.className; sb.setAttribute("role","button"); sb.setAttribute("tabindex","0");
            sb.setAttribute("aria-label","Encryption settings");
            Object.assign(sb.style, { display:"flex",alignItems:"center",justifyContent:"center",cursor:"pointer",transition:"color .2s" });
            const iw = document.createElement("div");
            Object.assign(iw.style, { borderRadius:"50%",lineHeight:"0",position:"relative" });
            iw.innerHTML = `<svg width="24" height="24" fill="currentColor" viewBox="0 0 24 24"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>`;
            sb.appendChild(iw);
            sb.onclick = openSettings;
            sb.onkeydown = e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openSettings(); } };
            emojiBtn.parentElement.insertBefore(sb, emojiBtn);
        }

        if (!document.getElementById("bb-no-key-notice")) {
            const n = document.createElement("div"); n.id = "bb-no-key-notice";
            const ni = document.createElement("div"); ni.className = "bb-notice-icon"; ni.textContent = "⚠️";
            const nb = document.createElement("div"); nb.className = "bb-notice-body";
            const ns = document.createElement("strong"); ns.textContent = "Encryption key not set — sending blocked.";
            nb.appendChild(ns); nb.appendChild(document.createTextNode(" Tap 🔒 to set up."));
            nb.appendChild(document.createElement("br"));
            const nbtn = document.createElement("button"); nbtn.className = "bb-notice-btn"; nbtn.textContent = "🛡 Set Key";
            nbtn.onclick = openSettings; nb.appendChild(nbtn);
            n.appendChild(ni); n.appendChild(nb);
            wrapper.insertBefore(n, realInput);
        }

        const existing = document.getElementById("secure-input-overlay");
        if (existing) { window._bbSend = existing._triggerSend; syncVis(); return; }

        if (!realInput._bbHijacked) {
            realInput._bbHijacked = true;
            realInput.addEventListener("focus", () => { if (!isSyncing && isEncOn()) { realInput.blur(); document.getElementById("secure-input-overlay")?.focus(); } });
            for (const evt of ["keydown","keypress","keyup","paste","drop"]) {
                realInput.addEventListener(evt, e => { if (!isSyncing && isEncOn()) { e.preventDefault(); e.stopPropagation(); } }, true);
            }
        }

        let si;
        if (mob) {
            si = document.createElement("textarea"); si.dir = "auto"; si.placeholder = "🔒 پیام امن..."; si.rows = 1;
            si.addEventListener("input", () => { si.style.height = "auto"; si.style.height = Math.min(si.scrollHeight, 150) + "px"; });
        } else {
            si = document.createElement("div"); si.contentEditable = "true"; si.dir = "auto";
            si.dataset.placeholder = "🔒 پیام امن..."; wrapper.style.overflow = "visible";
        }
        si.id = "secure-input-overlay"; si.className = realInput.className;
        wrapper.insertBefore(si, realInput);

        const getT = () => mob ? si.value.trim() : si.innerText.trim();
        const setT = v => { if (mob) si.value = v; else si.innerText = v; };

        const syncHas = has => {
            if (has === lastHasText) return;
            lastHasText = has; isSyncing = true;
            if (mob) { _taSetter?.call(realInput, has ? " " : ""); realInput.dispatchEvent(new Event("input", { bubbles:true })); }
            else {
                const sel = window.getSelection(); let marker = null;
                if (sel.rangeCount > 0 && si.contains(sel.getRangeAt(0).commonAncestorContainer)) {
                    marker = document.createElement("span"); marker.id = "bb-caret-marker";
                    sel.getRangeAt(0).insertNode(marker);
                }
                realInput.focus(); document.execCommand("selectAll", false, null);
                if (has) document.execCommand("insertText", false, " "); else document.execCommand("delete", false, null);
                realInput.dispatchEvent(new Event("input", { bubbles:true, cancelable:true }));
                si.focus();
                if (marker && marker.parentNode) {
                    const nr = document.createRange(); nr.setStartBefore(marker); nr.collapse(true);
                    sel.removeAllRanges(); sel.addRange(nr); marker.remove(); si.normalize();
                } else {
                    const nr = document.createRange(); nr.selectNodeContents(si); nr.collapse(false);
                    sel.removeAllRanges(); sel.addRange(nr);
                }
            }
            isSyncing = false;
        };
        si.addEventListener("input", e => { if (!e.isComposing) syncHas(getT().length > 0); });
        si.addEventListener("compositionend", () => syncHas(getT().length > 0));

        const triggerSend = async (doEnc = true) => {
            if (isSending) return;
            const text = getT(); if (!text) return;
            if (doEnc) {
                if (!getActiveKey()) { openSettings(); return; }
                isSending = true; setT("🔒 Encrypting...");
                try {
                    const chunks = await encryptChunked(text);
                    if (!chunks) { setT(text); openSettings(); return; }
                    for (const c of chunks) await _sendRaw(c);
                    setT(""); lastHasText = false; si.focus();
                } catch (e) { console.error("[BB]", e); setT(text); toast("Send failed!", 3000); }
                finally { isSending = false; }
                return;
            }
            if (!confirm("⚠️ Send WITHOUT encryption?")) return;
            isSending = true; setT("🌐 Sending...");
            try { await _sendRaw(text); setT(""); lastHasText = false; si.focus(); }
            catch (e) { setT(text); toast("Send failed!", 3000); }
            finally { isSending = false; }
        };
        si._triggerSend = triggerSend; window._bbSend = triggerSend;
        si.addEventListener("keydown", e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); e.stopPropagation(); triggerSend(true); } });
        syncVis();
    }

    // ─── 9b. Edit/Caption Input ───────────────────────────────────────────────
    function ensureEditInput() {
        const real = document.querySelector('textarea[aria-label="File Description"]');
        if (!real || real._bbEdit) return;
        real._bbEdit = true;

        const se = document.createElement("textarea"); se.id = "secure-edit-overlay";
        se.className = real.className; se.placeholder = "🔒 " + (real.placeholder || "ویرایش امن...");
        se.dir = real.dir || "auto"; se.style.cssText = real.style.cssText;
        se.addEventListener("input", () => { se.style.height = "auto"; se.style.height = Math.min(se.scrollHeight, 150) + "px"; });

        real.parentElement.insertBefore(se, real); lockInput(real); se.focus();

        const ex = real.value.trim();
        _taSetter?.call(real, ""); real.dispatchEvent(new Event("input", { bubbles:true }));
        if (ex.startsWith(CFG.PFX_ENC)) decrypt(ex).then(p => { if (p !== ex) se.value = p; }).catch(()=>{});
        else se.value = ex;

        const encFwd = async (btn) => {
            if (se._busy) return;
            const text = se.value.trim(); if (!text) return;
            if (!getActiveKey()) { openSettings(); return; }
            se._busy = true; const prev = se.value; se.value = "🔒 Encrypting...";
            try {
                const out = await encrypt(text);
                if (!out) { se.value = prev; openSettings(); return; }
                se.value = ""; unlockInput(real);
                _taSetter?.call(real, out); real.dispatchEvent(new Event("input", { bubbles:true })); real.dispatchEvent(new Event("change", { bubbles:true }));
                await new Promise(r => setTimeout(r, CFG.SEND_DLY));
                const rk = Object.keys(btn).find(k => k.startsWith('__reactProps$'));
                if (rk && typeof btn[rk]?.onClick === 'function') btn[rk].onClick({ preventDefault(){}, stopPropagation(){} });
                else for (const t of ["mousedown","pointerdown","mouseup","pointerup","click"]) btn.dispatchEvent(new MouseEvent(t, { bubbles:true, cancelable:true, view:window }));
            } catch(e) { console.error("[BB]", e); se.value = prev; toast("Encryption failed!", 3000); }
            finally { se._busy = false; }
        };

        const isConfBtn = t => t.closest('[data-testid="confirm-button"]') || (t.closest('button[aria-label="Send"]') && !t.closest('#chat_footer'));
        const editHandler = e => {
            if (!e.isTrusted) return;
            const btn = isConfBtn(e.target); if (!btn || !se.value.trim()) return;
            if (se._busy) { e.preventDefault(); e.stopPropagation(); return; }
            e.preventDefault(); e.stopPropagation(); encFwd(btn);
        };
        document.addEventListener("click", editHandler, true);
        document.addEventListener("mousedown", editHandler, true);

        const eObs = new MutationObserver(() => {
            if (!document.contains(se)) { document.removeEventListener("click", editHandler, true); document.removeEventListener("mousedown", editHandler, true); eObs.disconnect(); }
        });
        eObs.observe(document.body, { childList:true, subtree:true });

        se.addEventListener("keydown", e => {
            if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault(); e.stopPropagation();
                const btn = document.querySelector('[data-testid="confirm-button"]') || document.querySelector('button[aria-label="Send"]:not(#chat_footer button)');
                if (btn) encFwd(btn);
            }
        });
    }

    // ─── 10. Send Button Interception ─────────────────────────────────────────
    const getSecTxt = () => { const s = document.getElementById("secure-input-overlay"); return s ? (s.tagName==="TEXTAREA" ? s.value.trim() : s.innerText.trim()) : ""; };
    const isSendBtn = t => !!(t.closest('[aria-label="send-button"]') || t.closest('.RaTWwR'));

    let touchTmr = null, isLong = false;

    for (const evt of ["mousedown","mouseup","click","pointerdown","pointerup"]) {
        document.addEventListener(evt, e => {
            if (!e.isTrusted) return;
            if (!isSendBtn(e.target)) return;
            if (!isEncOn() || !getSecTxt()) return;
            if (isSending) { e.preventDefault(); e.stopPropagation(); return; }
            e.preventDefault(); e.stopPropagation();
            if (evt === "click" && e.button === 0) window._bbSend?.(true);
        }, true);
    }

    document.addEventListener("touchstart", e => {
        if (!e.isTrusted || !isSendBtn(e.target) || !isEncOn() || !getSecTxt()) return;
        if (isSending) { e.preventDefault(); e.stopPropagation(); return; }
        e.preventDefault(); e.stopPropagation();
        isLong = false; if (touchTmr !== null) clearTimeout(touchTmr);
        touchTmr = setTimeout(() => { isLong = true; if (e.touches?.length) showMenu(e.touches[0].clientX, e.touches[0].clientY); }, CFG.LONG_PRESS);
    }, { passive:false, capture:true });

    document.addEventListener("touchend", e => {
        if (!e.isTrusted || !isSendBtn(e.target) || !isEncOn() || !getSecTxt()) return;
        if (isSending) { e.preventDefault(); e.stopPropagation(); return; }
        e.preventDefault(); e.stopPropagation();
        if (touchTmr !== null) { clearTimeout(touchTmr); touchTmr = null; }
        if (!isLong) window._bbSend?.(true);
    }, { passive:false, capture:true });

    document.addEventListener("touchmove", e => {
        if (!e.isTrusted || !isSendBtn(e.target)) return;
        if (touchTmr !== null) { clearTimeout(touchTmr); touchTmr = null; }
        isLong = true;
    }, { passive:false, capture:true });

    document.addEventListener("contextmenu", e => {
        if (isSending || !isSendBtn(e.target) || !isEncOn() || !getSecTxt()) return;
        e.preventDefault(); e.stopPropagation(); showMenu(e.clientX, e.clientY);
    }, true);

    // ─── 11. Observer ─────────────────────────────────────────────────────────
    let scanTO = null, lastUrl = location.href;
    new MutationObserver(() => {
        if (scanTO !== null) clearTimeout(scanTO);
        scanTO = setTimeout(() => {
            scanTO = null;
            try {
                scanTree(document.body); ensureSecureInput(); ensureEditInput();
                if (location.href !== lastUrl) { lastUrl = location.href; _sc = null; _scId = null; syncVis(); }
            } catch(e) { console.error("[BB]", e); }
        }, CFG.SCAN_MS);
    }).observe(document.body, { childList:true, subtree:true, characterData:true });

    try { scanTree(document.body); ensureSecureInput(); ensureEditInput(); } catch(e) { console.error("[BB] init", e); }
})();
