// ==UserScript==
// @name         Bale Bridge Encryptor (Secure & Anti-XSS)
// @namespace    http://tampermonkey.net/
// @version      16.9
// @description  Fast dark UI, Invisible Char Immunity, Anti-XSS, Auto ECDH Bridge (Ultimate Xray Bypass).
// @author       You
// @match        *://web.bale.ai/*
// @match        *://*.bale.ai/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

(function () {
    "use strict";

    const CFG = Object.freeze({
        KEY_LEN: 32, MAX_ENC: 4000, TOAST_MS: 4500,
        LONG_PRESS: 400, SEND_DLY: 60, POST_DLY: 100,
        MAX_DEPTH: 10, KCACHE: 16,
        CHARS: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_+=~",
        B85: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~",
        PFX_E: "@@", PFX_E2: "@@+",
        PFX_H: "!!", HS_EXP: 86400, HS_CLEANUP_INTERVAL: 86400000
    });

    const P = Object.freeze({
        ac: "#7c8af6", acDim: "#636fcc", acSoft: "rgba(124,138,246,.10)",
        bg: "#0d1117", card: "#161b22", srf: "#1c2128",
        bdr: "#30363d", bdrLt: "#3d444d",
        tx: "#e6edf3", txD: "#8b949e", txM: "#484f58",
        err: "#f85149", wrn: "#d29922", wrnBg: "rgba(210,153,34,.10)",
        glass: "rgba(22,27,34,.88)", glassBdr: "rgba(240,246,252,.06)",
    });

    // =========================================================================================
    // FIREFOX XRAY WRAPPER BYPASS (v16.9)
    // Prevents unprivileged page objects from polluting WebCrypto or throwing 'constructor' errors
    // =========================================================================================
    const _W = typeof unsafeWindow !== 'undefined' ? unsafeWindow : window;
    const _wsSend = _W.WebSocket.prototype.send;
    const _draftRx = /EditParameter[\s\S]*drafts_|drafts_[\s\S]*EditParameter/;
    _W.WebSocket.prototype.send = function (d) {
        try {
            if (typeof d === "string" && _draftRx.test(d)) return;
        } catch (_) {}
        return _wsSend.apply(this, arguments);
    };

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

    function toB64(buf) {
        let binary = '';
        const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function fromB64(s) {
        let cleaned = s.replace(/[^A-Za-z0-9\-_]/g, '');
        cleaned = cleaned.replace(/-/g, '+').replace(/_/g, '/');
        const pad = (4 - (cleaned.length % 4)) % 4;
        cleaned += '='.repeat(pad);
        const bin = atob(cleaned);
        const arr = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
        return arr;
    }

    function fromStdB64(s) {
        const cleaned = s.replace(/[^A-Za-z0-9+/=]/g, '');
        const bin = atob(cleaned);
        const arr = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
        return arr;
    }

    function fromLegacyB64(s) {
        let cleaned = s.replace(/[^A-Za-z0-9\-_.+/=]/g, '');
        cleaned = cleaned.replace(/-/g, '+').replace(/_/g, '/').replace(/\./g, '=');
        const noPad = cleaned.replace(/=+$/, '');
        const pad = (4 - (noPad.length % 4)) % 4;
        cleaned = noPad + '='.repeat(pad);
        const bin = atob(cleaned);
        const arr = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
        return arr;
    }

    function decodeB64Smart(s) {
        try { const r = fromB64(s); if (r.length > 0) return r; } catch (_) {}
        try { const r = fromLegacyB64(s); if (r.length > 0) return r; } catch (_) {}
        try { const r = fromStdB64(s); if (r.length > 0) return r; } catch (_) {}
        return null;
    }

    const _kc = new Map();
    async function getKey(k) {
        let c = _kc.get(k); if (c) return c;
        const e = new TextEncoder().encode(k);
        c = await crypto.subtle.importKey("raw", e, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
        if (_kc.size >= CFG.KCACHE) _kc.delete(_kc.keys().next().value);
        _kc.set(k, c); return c;
    }

    function genKey() {
        const c = CFG.CHARS, cl = c.length, mx = (cl * Math.floor(256 / cl)) | 0, r = []; let f = 0;
        while (f < CFG.KEY_LEN) { 
            const b = new Uint8Array(64); 
            crypto.getRandomValues(b); 
            for (let i = 0; i < 64 && f < CFG.KEY_LEN; i++) if (b[i] < mx) r[f++] = c[b[i] % cl]; 
        }
        return r.join("");
    }

    const B85 = CFG.B85, B85D = new Uint8Array(128).fill(255);
    for (let i = 0; i < 85; i++) B85D[B85.charCodeAt(i)] = i;

    function b85d(s) {
        const sl = s.length; if (!sl) return new Uint8Array(0);
        const fl = (sl / 5) | 0, rm = sl % 5, est = fl * 4 + (rm ? rm - 1 : 0), o = new Uint8Array(est); let w = 0;
        for (let i = 0; i < sl; i += 5) {
            const e = i + 5 < sl ? i + 5 : sl, pd = 5 - (e - i); let a = 0;
            for (let j = 0; j < 5; j++) { const c = i + j < sl ? s.charCodeAt(i + j) : 126; a = a * 85 + B85D[c]; }
            const b = 4 - pd;
            if (b >= 1) o[w++] = (a >>> 24) & 255; if (b >= 2) o[w++] = (a >>> 16) & 255;
            if (b >= 3) o[w++] = (a >>> 8) & 255; if (b >= 4) o[w++] = a & 255;
        }
        return o.subarray(0, w);
    }

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
        const iv = new Uint8Array(12);
        crypto.getRandomValues(iv);
        const data = await cmp(t);
        const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, await getKey(k), data);
        const ct = new Uint8Array(ctBuf);
        const p = new Uint8Array(12 + ct.length); 
        p.set(iv); 
        p.set(ct, 12);
        return CFG.PFX_E2 + toB64(p);
    }

    async function dec(t) {
        if (!t.startsWith(CFG.PFX_E)) return t;
        const k = activeKey(); if (!k) return t;
        try {
            let b;
            if (t.startsWith(CFG.PFX_E2)) b = decodeB64Smart(t.slice(3));
            else b = b85d(t.slice(2).replace(/[^\x21-\x7E]/g, ''));
            if (!b || b.length < 13) return t;
            const iv = b.subarray(0, 12);
            const data = b.subarray(12);
            return await dcmp(new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, await getKey(k), data)));
        } catch (_) { return t; }
    }

    async function encChunk(t, d = 0) {
        if (d > CFG.MAX_DEPTH) return null;
        const r = await enc(t); if (!r) return null;
        if (r.length <= CFG.MAX_ENC) return [r];
        const m = t.length >> 1; let s = t.lastIndexOf("\n", m); if (s <= 0) s = t.lastIndexOf(" ", m); if (s <= 0) s = m;
        const a = await encChunk(t.slice(0, s).trim(), d + 1), b = await encChunk(t.slice(s).trim(), d + 1);
        return a && b ? [...a, ...b] : null;
    }

    const S = crypto.subtle;
    async function digest(data) { return new Uint8Array(await S.digest("SHA-256", data)); }
    
    function toHex(buf) { return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join(''); }
    function fromHex(h) {
        if (!h) return new Uint8Array(0);
        const a = new Uint8Array(h.length / 2);
        for (let i = 0; i < h.length; i += 2) a[i / 2] = parseInt(h.substring(i, i + 2), 16);
        return a;
    }

    function concatBytes(...arrays) {
        let t = arrays.reduce((a, b) => a + b.length, 0), r = new Uint8Array(t), o = 0;
        for (let a of arrays) { r.set(a, o); o += a.length; }
        return r;
    }
    
    async function getFpStr(pubRaw) { return toHex(await digest(pubRaw)).slice(0, 8).toUpperCase(); }
    async function ecSign(priv, buf) { return new Uint8Array(await S.sign({name: "ECDSA", hash: "SHA-256"}, priv, buf)); }
    async function ecVerify(pubRaw, sig, buf) {
        try {
            const p = await S.importKey("raw", pubRaw, {name: "ECDSA", namedCurve: "P-256"}, false, ["verify"]);
            return await S.verify({name: "ECDSA", hash: "SHA-256"}, p, sig, buf);
        } catch(e) { return false; }
    }
    
    async function deriveSymmetric(myEphPrivBuf, theirEphPubRaw, nonce, initIdPub, respIdPub, initEphPub, respEphPub) {
        const myPriv = await S.importKey("pkcs8", myEphPrivBuf, {name: "ECDH", namedCurve: "P-256"}, true, ["deriveBits"]);
        const theirPub = await S.importKey("raw", theirEphPubRaw, {name: "ECDH", namedCurve: "P-256"}, true, []);
        
        const shared = await S.deriveBits({name: "ECDH", public: theirPub}, myPriv, 256);
        const hkdfKey = await S.importKey("raw", shared, {name: "HKDF"}, false, ["deriveBits"]);
        
        const infoStr = new TextEncoder().encode("aes-session-key");
        const info = concatBytes(infoStr, nonce, initIdPub, respIdPub, initEphPub, respEphPub);
        const salt = new TextEncoder().encode("bale-bridge-v16");
        
        const material = new Uint8Array(await S.deriveBits({
            name: "HKDF", hash: "SHA-256", salt: salt, info: info
        }, hkdfKey, 96 * 8));
        
        const keyMat = material.slice(0, 64);
        const hmacMat = material.slice(64, 96);
        const c = CFG.CHARS, cl = c.length, mx = (cl * Math.floor(256 / cl)) | 0, r = [];
        let f = 0;
        for (let i = 0; i < keyMat.length && f < CFG.KEY_LEN; i++) {
            if (keyMat[i] < mx) r[f++] = c[keyMat[i] % cl];
        }
        if (f < CFG.KEY_LEN) throw new Error("Key Exhaustion");
        return { sessionKey: r.join(''), hmacKeyBytes: hmacMat };
    }

    let _db, _memDB = { identity: {}, contacts: {}, handshakes: {} }, _useMem = false;
    async function getDB() {
        if (_useMem) return null;
        if (_db) return _db;
        return new Promise((res, rej) => {
            const req = indexedDB.open("bale_bridge_db", 2);
            req.onupgradeneeded = e => {
                const d = e.target.result;
                if (e.oldVersion < 2) {
                    if (d.objectStoreNames.contains("identity")) d.deleteObjectStore("identity");
                    if (d.objectStoreNames.contains("contacts")) d.deleteObjectStore("contacts");
                    if (d.objectStoreNames.contains("handshakes")) d.deleteObjectStore("handshakes");
                }
                if (!d.objectStoreNames.contains("identity")) d.createObjectStore("identity", { keyPath: "id" });
                if (!d.objectStoreNames.contains("contacts")) d.createObjectStore("contacts", { keyPath: "id" });
                if (!d.objectStoreNames.contains("handshakes")) d.createObjectStore("handshakes", { keyPath: "nonce" });
            };
            req.onsuccess = e => { _db = e.target.result; res(_db); };
            req.onerror = e => { _useMem = true; rej(req.error); };
        });
    }

    async function dbOp(s, o, v) {
        try {
            const d = await getDB();
            if (!d) throw new Error("DB Fail");
            return new Promise((res, rej) => {
                const tx = d.transaction(s, o === "get" || o === "getAll" ? "readonly" : "readwrite");
                const st = tx.objectStore(s);
                let rq;
                if (o === "get") rq = st.get(v); 
                else if (o === "put") rq = st.put(JSON.parse(JSON.stringify(v))); 
                else if (o === "del") rq = st.delete(v); 
                else if (o === "getAll") rq = st.getAll();
                rq.onsuccess = () => {
                    try {
                        if (rq.result !== undefined && rq.result !== null && typeof rq.result === 'object') {
                            res(JSON.parse(JSON.stringify(rq.result))); // Deep clone to detach from Firefox Xray page constraints
                        } else { res(rq.result); }
                    } catch (e) { res(rq.result); }
                };
                rq.onerror = () => rej(rq.error);
            });
        } catch (e) {
            _useMem = true;
            if (o === "get") return _memDB[s][v] ? JSON.parse(JSON.stringify(_memDB[s][v])) : undefined;
            if (o === "put") { _memDB[s][v.id || v.nonce] = JSON.parse(JSON.stringify(v)); return v; }
            if (o === "del") { delete _memDB[s][v]; return; }
            if (o === "getAll") return Object.values(_memDB[s]).map(x => JSON.parse(JSON.stringify(x)));
        }
    }

    async function getMyId() {
        let rec = await dbOp("identity", "get", "self");
        if (rec && rec.pubHex && rec.privHex) {
            try {
                const pubBuf = fromHex(rec.pubHex);
                const privBuf = fromHex(rec.privHex);
                const pub = await S.importKey("raw", pubBuf, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
                const priv = await S.importKey("pkcs8", privBuf, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
                return { pub, priv, pubRaw: pubBuf, fp: await getFpStr(pubBuf) };
            } catch (e) {}
        }
        const kp = await S.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
        const pubRaw = new Uint8Array(await S.exportKey("raw", kp.publicKey));
        const privPkcs8 = new Uint8Array(await S.exportKey("pkcs8", kp.privateKey));
        
        await dbOp("identity", "put", { id: "self", pubHex: toHex(pubRaw), privHex: toHex(privPkcs8), createdAt: Date.now() });
        return { pub: kp.publicKey, priv: kp.privateKey, pubRaw, fp: await getFpStr(pubRaw) };
    }

    async function getTrustInfo(idPubRaw, chatId) {
        const idHash = toHex(await digest(idPubRaw));
        const cid = idHash.slice(0, 16);
        const fp = idHash.slice(0, 8).toUpperCase();
        const all = await dbOp("contacts", "getAll");
        const existing = all.find(c => c.id === cid);
        if (existing) return { state: "known", fp, cid };
        const otherInChat = all.find(c => c.chatId === chatId);
        if (otherInChat) return { state: "changed", fp, cid, oldFp: otherInChat.id.slice(0, 8).toUpperCase() };
        return { state: "new", fp, cid };
    }

    let _hsLock = Promise.resolve();
    function hsLock(fn) {
        let unlock;
        const prev = _hsLock;
        _hsLock = new Promise(r => unlock = r);
        return prev.then(() => fn()).finally(() => unlock());
    }

    function formatError(e) {
        if (!e) return "Unknown Error";
        const msg = e.message || String(e);
        const name = e.name ? e.name + ": " : "";
        return name + msg;
    }

    function renderHS(el, text, colorCode, fp = "", trustStr = "", onAction = null, btnText = "Accept & Connect") {
        const c = colorCode === "ac" ? P.ac : (colorCode === "wrn" ? P.wrn : (colorCode === "err" ? P.err : P.txM));
        const bg = colorCode === "ac" ? P.acSoft : (colorCode === "wrn" ? P.wrnBg : (colorCode === "err" ? "rgba(248,81,73,0.1)" : "rgba(255,255,255,0.05)"));
        let html = `<div class="bb-hs-widget" style="border: 1px solid ${c}; background: ${bg};">`;
        html += `<span class="bb-hs-title" style="color: ${c}; margin-bottom: ${fp ? '6px' : '0'}">${esc(text)}</span>`;
        if (fp) {
            html += `<div class="bb-hs-fp" style="color: ${P.ac};">Fingerprint: ${esc(fp)}</div>`;
            const tColor = trustStr.includes('⚠️') ? P.err : P.txD;
            const tWeight = trustStr.includes('⚠️') ? '700' : '500';
            html += `<div style="color: ${tColor}; font-weight: ${tWeight}; margin-bottom: ${onAction ? '8px' : '0'}">${esc(trustStr)}</div>`;
        }
        if (onAction) {
            html += `<button class="bb-hs-btn" style="background: ${c}; color: ${P.bg};">${esc(btnText)}</button>`;
        }
        html += `</div>`;
        el.innerHTML = html;
        if (onAction) {
            const btn = el.querySelector(".bb-hs-btn");
            if (btn) btn.onclick = e => { e.preventDefault(); e.stopPropagation(); btn.disabled = true; btn.innerText = "Processing..."; onAction(); };
        }
    }

    async function startBridge() {
        const id = await getMyId();
        const eph = await S.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
        const ephPubRaw = new Uint8Array(await S.exportKey("raw", eph.publicKey));
        const ephPrivPkcs8 = new Uint8Array(await S.exportKey("pkcs8", eph.privateKey));
        
        const nonce = new Uint8Array(16);
        crypto.getRandomValues(nonce);
        
        const ts = Math.floor(Date.now() / 1000);
        const tsBuf = new Uint8Array([(ts >>> 24) & 255, (ts >>> 16) & 255, (ts >>> 8) & 255, ts & 255]);
        const payload = concatBytes(new Uint8Array([1, 1]), nonce, tsBuf, id.pubRaw, ephPubRaw);
        const sig = await ecSign(id.priv, payload);
        const finalMsg = concatBytes(payload, sig);
        
        await dbOp("handshakes", "put", { 
            nonce: toHex(nonce), 
            chatId: getChatId(), 
            role: "initiator", 
            stage: "invited", 
            ephPrivHex: toHex(ephPrivPkcs8), 
            ephPubHex: toHex(ephPubRaw), 
            initIdPubHex: toHex(id.pubRaw), 
            theirIdentityKeyHex: null, 
            createdAt: Date.now(), 
            payloadHashHex: toHex(await digest(payload)) 
        });

        await sendRaw(CFG.PFX_H + " " + toB64(finalMsg));
        toast("Bridge invite sent!");
        syncVis();
    }

    async function acceptBridge(data, el) {
        const id = await getMyId();
        const eph = await S.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
        const ephPubRaw = new Uint8Array(await S.exportKey("raw", eph.publicKey));
        const ephPrivPkcs8 = new Uint8Array(await S.exportKey("pkcs8", eph.privateKey));
        
        const { sessionKey, hmacKeyBytes } = await deriveSymmetric(ephPrivPkcs8, data.theirEphPubRaw, data.nonce, data.theirIdPubRaw, id.pubRaw, data.theirEphPubRaw, ephPubRaw);
        
        const ts = Math.floor(Date.now() / 1000);
        const tsBuf = new Uint8Array([(ts >>> 24) & 255, (ts >>> 16) & 255, (ts >>> 8) & 255, ts & 255]);
        const payload = concatBytes(new Uint8Array([1, 2]), data.nonce, tsBuf, data.payloadHash, id.pubRaw, ephPubRaw);
        const sig = await ecSign(id.priv, payload);
        const finalMsg = concatBytes(payload, sig);
        
        await dbOp("handshakes", "put", { 
            nonce: toHex(data.nonce), 
            chatId: getChatId(), 
            role: "responder", 
            stage: "accepted", 
            derivedKey: sessionKey, 
            hmacKeyHex: toHex(hmacKeyBytes), 
            theirIdentityKeyHex: toHex(data.theirIdPubRaw), 
            createdAt: Date.now() 
        });

        renderHS(el, "🔄 Bridge accepted — waiting for confirmation", "wrn");
        await sendRaw(CFG.PFX_H + " " + toB64(finalMsg));
    }

    async function processAccept(data, hs, el) {
        const id = await getMyId();
        const hsNonceBuf = fromHex(hs.nonce);
        const hsInitIdPub = fromHex(hs.initIdPubHex);
        const hsEphPubRaw = fromHex(hs.ephPubHex);
        const myPrivBuf = fromHex(hs.ephPrivHex);
        
        const { sessionKey, hmacKeyBytes } = await deriveSymmetric(myPrivBuf, data.theirEphPubRaw, hsNonceBuf, hsInitIdPub, data.theirIdPubRaw, hsEphPubRaw, data.theirEphPubRaw);
        
        const hmacKey = await S.importKey("raw", hmacKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        const hmacData = concatBytes(new TextEncoder().encode("bale-bridge-confirm"), hsNonceBuf);
        const hmacVal = new Uint8Array(await S.sign("HMAC", hmacKey, hmacData));
        
        const ts = Math.floor(Date.now() / 1000);
        const tsBuf = new Uint8Array([(ts >>> 24) & 255, (ts >>> 16) & 255, (ts >>> 8) & 255, ts & 255]);
        const payload = concatBytes(new Uint8Array([1, 3]), hsNonceBuf, tsBuf, hmacVal);
        const sig = await ecSign(id.priv, payload);
        const finalMsg = concatBytes(payload, sig);
        
        setS({ enabled: true, customKey: sessionKey });
        await dbOp("contacts", "put", { id: data.cid, chatId: getChatId(), pubHex: toHex(data.theirIdPubRaw), lastSeen: Date.now() });
        
        delete hs.ephPrivHex;
        hs.derivedKey = sessionKey;
        hs.stage = "confirmed";
        await dbOp("handshakes", "put", hs);
        
        syncVis();
        await sendRaw(CFG.PFX_H + " " + toB64(finalMsg));
        renderHS(el, "✅ Bridge established", "ac");
        setTimeout(async () => {
            const testEnc = await encChunk("✅ Bridge Established! Both sides should see fingerprints: " + id.fp + " ↔ " + data.fp);
            if (testEnc) for (let c of testEnc) await sendRaw(c);
        }, CFG.SEND_DLY + 400);
    }

    async function processConfirm(data, hs, el) {
        const hmacKeyBytes = fromHex(hs.hmacKeyHex);
        const hmacKey = await S.importKey("raw", hmacKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        const hsNonceBuf = fromHex(hs.nonce);
        const hmacData = concatBytes(new TextEncoder().encode("bale-bridge-confirm"), hsNonceBuf);
        const expectedHmac = new Uint8Array(await S.sign("HMAC", hmacKey, hmacData));
        
        if (toHex(data.hmac) !== toHex(expectedHmac)) throw new Error("HMAC Verification Failed");
        
        setS({ enabled: true, customKey: hs.derivedKey });
        
        const hsIdentityRaw = fromHex(hs.theirIdentityKeyHex);
        const fpInfo = await getTrustInfo(hsIdentityRaw, getChatId());
        
        await dbOp("contacts", "put", { id: fpInfo.cid, chatId: getChatId(), pubHex: hs.theirIdentityKeyHex, lastSeen: Date.now() });
        
        delete hs.hmacKeyHex;
        hs.stage = "confirmed";
        await dbOp("handshakes", "put", hs);
        
        syncVis();
        renderHS(el, "✅ Bridge established", "ac");
    }

    async function handleHandshake(b64, el) {
        if (el._isDecrypted) return;
        el._isDecrypted = true;
        try {
            const bytes = decodeB64Smart(b64);
            if (!bytes || bytes.length < 118) throw new Error("Invalid Payload Length");
            const ver = bytes[0], type = bytes[1];
            if (ver !== 1) throw new Error("Unknown Protocol Version");
            
            const nonce = bytes.slice(2, 18), hexNonce = toHex(nonce);
            const myId = await getMyId();
            const hs = await dbOp("handshakes", "get", hexNonce);

            if (type === 1) {
                if (bytes.length !== 216) throw new Error("Invalid Invite Payload Size");
                const payload = bytes.slice(0, 152), sig = bytes.slice(152, 216);
                const idPubRaw = bytes.slice(22, 87), ephPubRaw = bytes.slice(87, 152);
                
                if (!await ecVerify(idPubRaw, sig, payload)) throw new Error("Signature Verification Failed");
                if (toHex(idPubRaw) === toHex(myId.pubRaw)) return renderHS(el, "🔄 Bridge invite sent", "txM");
                
                if (hs) {
                    if (hs.stage === "accepted") return renderHS(el, "🔄 Waiting for confirmation", "wrn");
                    if (hs.stage === "confirmed") return renderHS(el, "✅ Bridge established", "ac");
                    return renderHS(el, "🤝 Processed", "txM");
                }
                
                const trust = await getTrustInfo(idPubRaw, getChatId());
                const hsList = await dbOp("handshakes", "getAll");
                const activeOut = hsList.find(h => h.chatId === getChatId() && h.role === "initiator" && h.stage === "invited");
                if (activeOut) {
                    if (myId.fp < trust.fp) return renderHS(el, "🤝 Collision avoided (You are initiator)", "txM");
                    else if (myId.fp > trust.fp) await dbOp("handshakes", "del", activeOut.nonce);
                    else throw new Error("Identical Fingerprint Collision");
                }
                
                let tStr = trust.state === "new" ? "🆕 New contact" : (trust.state === "known" ? "✅ Known contact" : `⚠️ IDENTITY CHANGED — old: ${trust.oldFp}, new: ${trust.fp}`);
                renderHS(el, "🛡️ Secure Bridge Request", "ac", trust.fp, tStr, async () => {
                    try { await acceptBridge({ nonce, theirIdPubRaw: idPubRaw, theirEphPubRaw: ephPubRaw, payloadHash: await digest(payload) }, el); }
                    catch (e) { 
                        console.error("[BB Error Detailed]", e);
                        renderHS(el, "❌ Error: " + formatError(e), "err"); 
                    }
                });
                
            } else if (type === 2) {
                if (bytes.length !== 248) throw new Error("Invalid Accept Payload Size");
                const payload = bytes.slice(0, 184), sig = bytes.slice(184, 248);
                const inviteHash = bytes.slice(22, 54), idPubRaw = bytes.slice(54, 119), ephPubRaw = bytes.slice(119, 184);
                
                if (!await ecVerify(idPubRaw, sig, payload)) throw new Error("Signature Verification Failed");
                if (toHex(idPubRaw) === toHex(myId.pubRaw)) return renderHS(el, "🔄 Bridge accept sent", "txM");
                
                if (!hs || hs.role !== "initiator" || hs.stage !== "invited") {
                    if (hs && hs.stage === "confirmed") return renderHS(el, "✅ Bridge established", "ac");
                    return renderHS(el, "🤝 Processed", "txM");
                }
                
                const hsPayloadHash = fromHex(hs.payloadHashHex);
                if (toHex(inviteHash) !== toHex(hsPayloadHash)) throw new Error("Invite Binding Hash Mismatch");
                
                const trust = await getTrustInfo(idPubRaw, getChatId());
                const doAccept = async () => {
                    try { await processAccept({ nonce, theirIdPubRaw: idPubRaw, theirEphPubRaw: ephPubRaw, fp: trust.fp, cid: trust.cid }, hs, el); }
                    catch (e) { 
                        console.error("[BB Error Detailed]", e);
                        renderHS(el, "❌ Error: " + formatError(e), "err"); 
                    }
                };
                
                if (trust.state === "changed") {
                    renderHS(el, "⚠️ Identity Changed During Bridge!", "err", trust.fp, `Old: ${trust.oldFp}, New: ${trust.fp}`, doAccept, "Acknowledge & Connect");
                } else {
                    renderHS(el, "✅ Bridge completing...", "ac");
                    await doAccept();
                }
                
            } else if (type === 3) {
                if (bytes.length !== 118) throw new Error("Invalid Confirm Payload Size");
                const payload = bytes.slice(0, 54), sig = bytes.slice(54, 118);
                const hmac = bytes.slice(22, 54);
                
                if (hs && hs.role === "responder" && hs.stage === "accepted") {
                    const hsIdentityRaw = fromHex(hs.theirIdentityKeyHex);
                    if (!await ecVerify(hsIdentityRaw, sig, payload)) throw new Error("Signature Verification Failed");
                    try { await processConfirm({ hmac }, hs, el); }
                    catch (e) { 
                        console.error("[BB Error Detailed]", e);
                        renderHS(el, "❌ Error: " + formatError(e), "err"); 
                    }
                } else {
                    if (hs && hs.stage === "confirmed") return renderHS(el, "✅ Bridge established", "ac");
                    renderHS(el, "🤝 Processed", "txM");
                }
            }
        } catch (e) { 
            console.error("[BB Error Detailed]", e);
            renderHS(el, "❌ Error: " + formatError(e), "err"); 
        }
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

    document.addEventListener("click", e => { const s = e.target.closest(".bb-spoiler"); if (s) { s.style.color = "inherit"; s.style.background = P.bdr; } }, true);

    const _taSet = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set;
    const isMob = el => el?.tagName === "TEXTAREA";

    const getReal = () => {
        const e1 = document.getElementById("editable-message-text");
        const e2 = document.getElementById("main-message-input");
        if (e1 && e1.getBoundingClientRect().height > 0) return e1;
        if (e2 && e2.getBoundingClientRect().height > 0) return e2;
        return e1 || e2;
    };

    async function sendRaw(text) {
        const real = getReal(); if (!real) return;
        const mob = isMob(real), ws = isSyncing; isSyncing = true;
        unlockI(real);
        try {
            real.focus();
            if (mob) { _taSet?.call(real, text); real.dispatchEvent(new Event("input", { bubbles: true })); }
            else { real.innerHTML = text; real.dispatchEvent(new Event("input", { bubbles: true })); }
        } catch (e) { if (!mob) { real.innerText = text; real.dispatchEvent(new Event("input", { bubbles: true })); } }
        await new Promise(r => setTimeout(r, CFG.SEND_DLY));
        const btn = document.querySelector('[aria-label="send-button"]') || document.querySelector('.RaTWwR');
        let sent = false;
        if (btn) {
            try {
                const uBtn = btn.wrappedJSObject || btn; // Xray wrapper safe guard
                const rk = Object.keys(uBtn).find(k => k.startsWith('__reactProps$') || k.startsWith('__reactFiber$'));
                if (rk) {
                    let node = uBtn[rk];
                    while (node && !node.onClick && !node.memoizedProps?.onClick) { node = node.return; }
                    let clickFn = node?.memoizedProps?.onClick || node?.onClick || uBtn[rk]?.onClick;
                    if (typeof clickFn === 'function') { clickFn({ preventDefault() {}, stopPropagation() {} }); sent = true; }
                }
            } catch (_) {}
            if (!sent) { btn.click(); sent = true; }
        }
        if (!sent) real.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, key: "Enter", code: "Enter", keyCode: 13 }));
        await new Promise(r => setTimeout(r, CFG.POST_DLY));
        if (mob) { _taSet?.call(real, ""); real.dispatchEvent(new Event("input", { bubbles: true })); }
        else { real.innerHTML = ""; real.dispatchEvent(new Event("input", { bubbles: true })); }
        if (encOn()) lockI(real);
        isSyncing = ws;
    }

    const SKIP = new Set(["secure-input-overlay", "secure-edit-overlay", "editable-message-text", "main-message-input", "bb-no-key-notice", "bale-bridge-menu", "bb-modal-overlay"]);
    const _infly = new WeakSet();

    function stripInvisibles(s) {
        return s.replace(/[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF\u00AD\u034F\u061C\u180E\uFFF9-\uFFFB]/g, '');
    }

    function scan(root) {
        const els = root.querySelectorAll('span, div, p');
        for (const el of els) {
            if (el._isDecrypted || _infly.has(el) || SKIP.has(el.id)) continue;
            let tc = el.textContent;
            if (!tc || tc.length <= 10) continue;
            const cleanTc = stripInvisibles(tc);

            const hsIdx = cleanTc.indexOf(CFG.PFX_H);
            if (hsIdx !== -1) {
                let hasMatchingChild = false;
                for (const c of el.children) if (stripInvisibles(c.textContent || '').includes(CFG.PFX_H)) { hasMatchingChild = true; break; }
                if (hasMatchingChild) continue;
                const raw = cleanTc.slice(hsIdx + CFG.PFX_H.length).trim().split(/\s+/)[0].replace(/[^A-Za-z0-9\-_]/g, '');
                if (raw.length > 50) {
                    _infly.add(el);
                    hsLock(() => handleHandshake(raw, el).catch(() => {})).finally(() => _infly.delete(el));
                    continue;
                }
            }

            if (cleanTc.includes(CFG.PFX_E)) {
                let hasMatchingChild = false;
                for (const c of el.children) if (stripInvisibles(c.textContent || '').includes(CFG.PFX_E)) { hasMatchingChild = true; break; }
                if (hasMatchingChild) continue;
                const encIdx = cleanTc.indexOf(CFG.PFX_E);
                if (encIdx !== -1) {
                    const raw = cleanTc.slice(encIdx);
                    _infly.add(el);
                    dec(raw).then(plain => {
                        if (plain !== raw) {
                            if (!el._bbO) {
                                Object.assign(el.style, { overflow: "hidden", overflowWrap: "anywhere", wordBreak: "break-word", maxWidth: "100%" });
                                el.classList.add("bb-msg-container"); el._bbO = true;
                            }
                            el.innerHTML = renderDec(plain) + `<span class="bb-enc-badge">🔒 encrypted <span class="bb-copy-btn" title="Copy">📋</span></span>`;
                            el.style.color = "inherit"; el._isDecrypted = true;
                            const cb = el.querySelector(".bb-copy-btn");
                            if (cb) cb.onclick = ev => {
                                ev.preventDefault(); ev.stopPropagation();
                                navigator.clipboard.writeText(plain).then(() => { cb.textContent = "✅"; setTimeout(() => cb.textContent = "📋", 1200); }).catch(() => {});
                            };
                        }
                    }).catch(() => {}).finally(() => _infly.delete(el));
                }
            }
        }
    }

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
.bb-hs-widget{border-radius:10px;padding:12px;margin:6px 0;font-family:inherit;font-size:13px;line-height:1.4;transition:border-color .15s}
.bb-hs-title{display:block;font-weight:700;margin-bottom:6px;font-size:14px;display:flex;align-items:center;gap:6px}
.bb-hs-fp{font-family:monospace;font-size:11.5px;margin-bottom:4px;font-weight:600}
.bb-hs-btn{display:inline-block;border:none;padding:7px 14px;border-radius:8px;cursor:pointer;font-weight:600;transition:opacity .15s,transform .1s;margin-top:8px;font-size:13px}
.bb-hs-btn:active{transform:scale(.97)}
.bb-hs-btn:hover{opacity:.85}
.bb-hs-btn:disabled{opacity:.6;cursor:not-allowed;transform:none}
`;
    document.head.appendChild(sty);

    const menu = document.createElement("div"); menu.id = "bale-bridge-menu";
    const m1 = document.createElement("div"); m1.className = "bale-menu-item"; m1.textContent = "🔒 Send Encrypted";
    m1.onclick = () => { menu.style.display = "none"; window._bbSend?.(true); };
    const m2 = document.createElement("div"); m2.className = "bale-menu-item"; m2.textContent = "⚠️ Send Unencrypted";
    m2.onclick = () => { menu.style.display = "none"; window._bbSend?.(false); };
    menu.appendChild(m1); menu.appendChild(m2); document.body.appendChild(menu);
    const showMenu = (x, y) => Object.assign(menu.style, { display: "flex", left: Math.min(x, innerWidth - 210) + "px", top: Math.min(y, innerHeight - 130) + "px" });
    document.addEventListener("click", e => { if (!menu.contains(e.target)) menu.style.display = "none"; });

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
        kt.appendChild(gb);
        const km = document.createElement("div"); km.className = "bb-key-meta"; km.style.marginTop = "8px";
        const errEl = document.createElement("span"); errEl.className = "bb-key-error";
        const fpW = document.createElement("span"); fpW.style.cssText = `font-size:11px;color:${P.txD}`;
        fpW.textContent = "Fingerprint: ";
        const fpEl = document.createElement("strong"); fpEl.style.cssText = `font-family:monospace;color:${P.ac}`; fpEl.textContent = fv;
        fpW.appendChild(fpEl); km.appendChild(errEl); km.appendChild(fpW);
        ksec.appendChild(klbl); ksec.appendChild(krow); ksec.appendChild(kt); ksec.appendChild(km);

        const bridgeSec = document.createElement("div"); bridgeSec.className = "bb-section-divider";
        const bTitle = document.createElement("div"); Object.assign(bTitle.style, { fontSize: "14px", fontWeight: "700", marginBottom: "4px" }); bTitle.textContent = "🤝 Automatic Key Exchange";
        const bDesc = document.createElement("div"); Object.assign(bDesc.style, { fontSize: "12px", color: P.txD, marginBottom: "10px" }); bDesc.textContent = "Establish encryption automatically with your contact.";
        const bBtn = document.createElement("button"); bBtn.className = "bb-tool-btn"; bBtn.style.width = "100%"; bBtn.style.marginTop = "8px"; bBtn.textContent = "Loading...";
        bridgeSec.appendChild(bTitle); bridgeSec.appendChild(bDesc); bridgeSec.appendChild(bBtn);

        const acts = document.createElement("div"); acts.className = "bb-actions";
        const canB = document.createElement("button"); canB.className = "bb-btn bb-btn-cancel"; canB.textContent = "Cancel";
        const savB = document.createElement("button"); savB.className = "bb-btn bb-btn-save"; savB.textContent = "Save";
        acts.appendChild(canB); acts.appendChild(savB);
        cd.appendChild(t); cd.appendChild(d); cd.appendChild(elbl); cd.appendChild(ksec); cd.appendChild(bridgeSec); cd.appendChild(acts);
        ov.appendChild(cd); document.body.appendChild(ov);

        const validate = () => {
            const v = kinp.value, l = v.length, on = ecb.checked;
            ksec.style.display = on ? "" : "none"; bridgeSec.style.display = on ? "" : "none";
            fpEl.textContent = l === CFG.KEY_LEN ? v.substring(0, 5).toUpperCase() : "N/A";
            if (!on) { errEl.textContent = ""; savB.disabled = false; return; }
            if (!l) { errEl.textContent = "Key required."; savB.disabled = true; }
            else if (l !== CFG.KEY_LEN) { errEl.textContent = `Need ${CFG.KEY_LEN} chars (${l}).`; savB.disabled = true; }
            else { errEl.textContent = ""; savB.disabled = false; }
        };

        const updateBridgeUI = async () => {
            try {
                const hsList = await dbOp("handshakes", "getAll");
                const activeHs = hsList.find(h => h.chatId === getChatId() && h.stage !== "confirmed" && (Date.now() - h.createdAt < CFG.HS_EXP * 1000));
                if (activeHs) {
                    bBtn.textContent = "🔄 Waiting for response... (Cancel)";
                    bBtn.style.color = P.wrn; bBtn.style.borderColor = P.wrn;
                    bBtn.onclick = async () => { await dbOp("handshakes", "del", activeHs.nonce); updateBridgeUI(); };
                } else {
                    const confHs = hsList.find(h => h.chatId === getChatId() && h.stage === "confirmed" && h.derivedKey === kinp.value);
                    if (confHs && kinp.value.length === CFG.KEY_LEN) {
                        bBtn.textContent = "✅ Connected via Bridge (Re-key)";
                        bBtn.style.color = P.ac; bBtn.style.borderColor = P.ac;
                    } else {
                        bBtn.textContent = "🤝 Start Bridge";
                        bBtn.style.color = P.tx; bBtn.style.borderColor = P.bdr;
                    }
                    bBtn.onclick = async () => {
                        ov.remove();
                        try { await startBridge(); } catch (e) { toast("Bridge error!"); }
                    };
                }
            } catch(e) { bBtn.textContent = "Bridge unavailable"; bBtn.disabled = true; }
        };
        updateBridgeUI();

        kinp.oninput = () => { validate(); updateBridgeUI(); }; ecb.onchange = validate; validate();
        vb.onclick = () => { const h = kinp.type === "password"; kinp.type = h ? "text" : "password"; vb.textContent = h ? "🙈" : "👁"; };
        cpb.onclick = () => { if (!kinp.value) return; navigator.clipboard.writeText(kinp.value).then(() => { cpb.textContent = "✅"; cpb.classList.add("copied"); setTimeout(() => { cpb.textContent = "📋"; cpb.classList.remove("copied"); }, 1200); }).catch(() => {}); };
        gb.onclick = () => { kinp.value = genKey(); kinp.type = "text"; vb.textContent = "🙈"; validate(); updateBridgeUI(); };
        canB.onclick = () => ov.remove();
        savB.onclick = () => { if (savB.disabled) return; try { setS({ enabled: ecb.checked, customKey: kinp.value }); } catch (e) { return; } ov.remove(); syncVis(); };
        ov.onclick = e => { if (e.target === ov) ov.remove(); };
    }

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
            else { ri.innerHTML = has ? " " : ""; ri.dispatchEvent(new Event("input", { bubbles: true })); }
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
                catch (e) { setT(text); toast("Send failed!"); }
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

    function ensureEdit() {
        const real = document.querySelector('textarea[aria-label="File Description"]');
        if (!real || real._bbE) return; real._bbE = true;
        const se = document.createElement("textarea"); se.id = "secure-edit-overlay"; se.className = real.className;
        se.placeholder = "🔒 " + (real.placeholder || "ویرایش امن..."); se.dir = real.dir || "auto"; se.style.cssText = real.style.cssText;
        se.addEventListener("input", () => { se.style.height = "auto"; se.style.height = Math.min(se.scrollHeight, 150) + "px"; });
        real.parentElement.insertBefore(se, real); lockI(real); se.focus();

        const ex = real.value ? real.value.trim() : "";
        _taSet?.call(real, ""); real.dispatchEvent(new Event("input", { bubbles: true }));
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

                let dispatched = false;
                try {
                    const uBtn = btn.wrappedJSObject || btn;
                    const rk = Object.keys(uBtn).find(k => k.startsWith('__reactProps$') || k.startsWith('__reactFiber$'));
                    if (rk) {
                        let node = uBtn[rk];
                        while (node && !node.onClick && !node.memoizedProps?.onClick) { node = node.return; }
                        let fn = node?.memoizedProps?.onClick || node?.onClick || uBtn[rk]?.onClick;
                        if (fn) { fn({ preventDefault() {}, stopPropagation() {} }); dispatched = true; }
                    }
                } catch (_) {}

                if (!dispatched) {
                    for (const t of ["mousedown", "pointerdown", "mouseup", "pointerup", "click"]) btn.dispatchEvent(new MouseEvent(t, { bubbles: true, cancelable: true, view: window }));
                }
            } catch (e) { se.value = prev; toast("Failed!"); }
            finally { se._busy = false; }
        };

        const isConf = t => t.closest('[data-testid="confirm-button"]') || (t.closest('button[aria-label="Send"]') && !t.closest('#chat_footer'));
        const eh = e => { if (!e.isTrusted) return; const b = isConf(e.target); if (!b || !se.value.trim()) return; if (se._busy) { e.preventDefault(); e.stopPropagation(); return; } e.preventDefault(); e.stopPropagation(); encFwd(b); };
        document.addEventListener("click", eh, true); document.addEventListener("mousedown", eh, true);
        const eo = new MutationObserver(() => { if (!document.contains(se)) { document.removeEventListener("click", eh, true); document.removeEventListener("mousedown", eh, true); eo.disconnect(); } });
        eo.observe(document.body, { childList: true, subtree: true });
        se.addEventListener("keydown", e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); e.stopPropagation(); const b = document.querySelector('[data-testid="confirm-button"]') || document.querySelector('button[aria-label="Send"]:not(#chat_footer button)'); if (b) encFwd(b); } });
    }

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

    let _dirty = false, _raf = 0, lastUrl = location.href;
    function tick() {
        _raf = 0; _dirty = false;
        try {
            scan(document.body); ensureInput(); ensureEdit();
            if (location.href !== lastUrl) { lastUrl = location.href; _sc = null; _scId = null; syncVis(); }
        } catch (e) {}
    }
    new MutationObserver(() => {
        if (!_dirty) { _dirty = true; if (_raf) cancelAnimationFrame(_raf); _raf = requestAnimationFrame(tick); }
    }).observe(document.body, { childList: true, subtree: true, characterData: true });

    function cleanupHs() {
        dbOp("handshakes", "getAll").then(hs => {
            const now = Date.now();
            hs.forEach(h => { 
                if (h.stage !== "confirmed" && (now - h.createdAt) > CFG.HS_CLEANUP_INTERVAL) dbOp("handshakes", "del", h.nonce); 
            });
        }).catch(() => {});
    }

    try {
        scan(document.body); ensureInput(); ensureEdit();
        setTimeout(cleanupHs, 2000); setInterval(cleanupHs, CFG.HS_CLEANUP_INTERVAL);
    } catch (e) {}
})();
