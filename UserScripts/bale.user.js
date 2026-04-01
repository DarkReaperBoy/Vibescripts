// ==UserScript==
// @name         Bale Bridge Encryptor (Stable ECDH)
// @namespace    http://tampermonkey.net/
// @version      11.3
// @description  Per-chat keys, Auto-Bridge, Material UI, Draft blocker. Fixed loops & history bugs.
// @author       You
// @match        *://web.bale.ai/*
// @match        *://*.bale.ai/*
// @grant        none
// ==/UserScript==

(function() {
    "use strict";

    // ─── 0. WebSocket Draft Blocker (Prevents Server Leaks) ───────────────────
    const _origWsSend = WebSocket.prototype.send;
    WebSocket.prototype.send = function(data) {
        try {
            let t = "";
            if (typeof data === "string") t = data;
            else if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
                t = new TextDecoder().decode(data);
            }
            if (t && t.includes("EditParameter") && t.includes("drafts_")) return;
        } catch (_) {}
        return _origWsSend.apply(this, arguments);
    };

    // ─── 1. Settings (Per-Chat) ───────────────────────────────────────────────
    const getChatId = () => {
        const p = new URLSearchParams(location.search);
        return p.get("uid") || p.get("groupId") || p.get("channelId") || location.pathname.split("/").pop() || "global";
    };

    let _settingsCacheId = null, _settingsCache = null;
    const getChatSettings = () => {
        const id = getChatId();
        if (id === _settingsCacheId && _settingsCache !== null) return _settingsCache;
        const s = localStorage.getItem("bale_bridge_settings_" + id);
        _settingsCache = s ? JSON.parse(s) : { enabled: true, customKey: "" };
        _settingsCacheId = id;
        return _settingsCache;
    };

    const saveChatSettings = (s) => {
        const id = getChatId();
        _settingsCache = s;
        _settingsCacheId = id;
        localStorage.setItem("bale_bridge_settings_" + id, JSON.stringify(s));
    };

    const getActiveKey = () => {
        const s = getChatSettings();
        if (!s.enabled) return null;
        return s.customKey && s.customKey.length === 32 ? s.customKey : null;
    };
    const isEncryptionEnabled = () => getChatSettings().enabled;

    // ─── 2. Crypto Engine (AES) ───────────────────────────────────────────────
    const keyCache = new Map();
    async function getCryptoKey(k) {
        if (keyCache.has(k)) return keyCache.get(k);
        const raw = new Uint8Array(32);
        raw.set(new TextEncoder().encode(k).subarray(0, 32));
        const key = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
        keyCache.set(k, key);
        return key;
    }

    function generateKey() {
        const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_+=~";
        const bytes = crypto.getRandomValues(new Uint8Array(32));
        return Array.from(bytes, b => chars[b % chars.length]).join("");
    }

    const B85 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
    const B85D = new Uint8Array(128);
    for (let i = 0; i < B85.length; i++) B85D[B85.charCodeAt(i)] = i;

    function b85enc(buf) {
        const len = buf.length;
        const fullChunks = (len >>> 2);
        const remainder = len & 3;
        const outLen = fullChunks * 5 + (remainder ? remainder + 1 : 0);
        const chars = new Array(outLen);
        let pos = 0;
        for (let i = 0; i < len; i += 4) {
            const rem = len - i < 4 ? len - i : 4;
            let acc = 0;
            for (let j = 0; j < 4; j++) acc = (acc << 8) | (i + j < len ? buf[i + j] : 0);
            acc >>>= 0;
            const count = rem < 4 ? rem + 1 : 5;
            const tmp = new Array(5);
            for (let j = 4; j >= 0; j--) {
                tmp[j] = B85[acc % 85];
                acc = Math.floor(acc / 85);
            }
            for (let j = 0; j < count; j++) chars[pos++] = tmp[j];
        }
        return chars.join("");
    }

    function b85dec(str) {
        const slen = str.length;
        const fullChunks = Math.floor(slen / 5);
        const remChars = slen % 5;
        const outEst = fullChunks * 4 + (remChars ? remChars - 1 : 0);
        const out = new Uint8Array(outEst);
        let wpos = 0;
        for (let i = 0; i < slen; i += 5) {
            const end = Math.min(i + 5, slen);
            const chunkLen = end - i;
            const pad = 5 - chunkLen;
            let acc = 0;
            for (let j = 0; j < 5; j++) {
                const ci = i + j < slen ? str.charCodeAt(i + j) : 126;
                acc = acc * 85 + B85D[ci];
            }
            const bytes = 4 - pad;
            if (bytes >= 1) out[wpos++] = (acc >>> 24) & 0xff;
            if (bytes >= 2) out[wpos++] = (acc >>> 16) & 0xff;
            if (bytes >= 3) out[wpos++] = (acc >>> 8) & 0xff;
            if (bytes >= 4) out[wpos++] = acc & 0xff;
        }
        return out.subarray(0, wpos);
    }

    async function compress(text) {
        if (typeof CompressionStream === 'undefined') return new TextEncoder().encode(text);
        const cs = new CompressionStream("deflate");
        const w = cs.writable.getWriter();
        w.write(new TextEncoder().encode(text));
        w.close();
        return new Uint8Array(await new Response(cs.readable).arrayBuffer());
    }

    async function decompress(buf) {
        if (typeof DecompressionStream === 'undefined') return new TextDecoder().decode(buf);
        try {
            const ds = new DecompressionStream("deflate");
            const w = ds.writable.getWriter();
            w.write(buf);
            w.close();
            return new TextDecoder().decode(await new Response(ds.readable).arrayBuffer());
        } catch(e) { return new TextDecoder().decode(buf); }
    }

    async function encrypt(text) {
        const k = getActiveKey();
        if (!k) return null;
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await getCryptoKey(k), await compress(text)));
        const payload = new Uint8Array(12 + ct.length);
        payload.set(iv); payload.set(ct, 12);
        return "@@" + b85enc(payload);
    }

    async function decrypt(text) {
        if (!text.startsWith("@@")) return text;
        const k = getActiveKey();
        if (!k) return text;
        try {
            const buf = b85dec(text.slice(2));
            const iv = buf.subarray(0, 12), data = buf.subarray(12);
            const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, await getCryptoKey(k), data);
            return await decompress(new Uint8Array(plain));
        } catch (_) { return text; }
    }

    const MAX_ENCRYPTED_LEN = 4000;
    async function encryptChunked(text) {
        const result = await encrypt(text);
        if (result === null) return null;
        if (result.length <= MAX_ENCRYPTED_LEN) return [result];
        const mid = Math.floor(text.length / 2);
        let splitAt = text.lastIndexOf("\n", mid);
        if (splitAt <= 0) splitAt = text.lastIndexOf(" ", mid);
        if (splitAt <= 0) splitAt = mid;
        const a = await encryptChunked(text.slice(0, splitAt).trim());
        const b = await encryptChunked(text.slice(splitAt).trim());
        if (!a || !b) return null;
        return [...a, ...b];
    }

    // ─── 3. ECDH Stable Auto Bridge ───────────────────────────────────────────
    let _hsBusy = false;

    async function _hsNewPair() { return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]); }
    async function _hsPubRaw(pubKey) { return new Uint8Array(await crypto.subtle.exportKey("raw", pubKey)); }
    async function _hsPubImport(bytes) { return crypto.subtle.importKey("raw", bytes, { name: "ECDH", namedCurve: "P-256" }, false, []); }
    
    async function _hsDeriveKeyStr(myPriv, theirPubBytes) {
        const theirPub = await _hsPubImport(theirPubBytes);
        const sharedBits = await crypto.subtle.deriveBits({ name: "ECDH", public: theirPub }, myPriv, 256);
        const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", sharedBits));
        const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_+=~";
        let keyStr = "";
        for (let i = 0; i < 32; i++) keyStr += chars[hash[i] % chars.length];
        return keyStr;
    }

    function _showToast(msg, dur = 5000) {
        const el = document.createElement("div");
        el.textContent = msg;
        el.style.cssText = "position:fixed;bottom:88px;left:50%;transform:translateX(-50%) translateY(16px);background:rgba(0,0,0,.85);color:#fff;padding:12px 24px;border-radius:24px;font-size:14px;font-family:inherit;z-index:9999999;opacity:0;pointer-events:none;transition:opacity .2s,transform .2s;white-space:nowrap;box-shadow:0 4px 12px rgba(0,0,0,0.3);";
        document.body.appendChild(el);
        requestAnimationFrame(() => { el.style.opacity = "1"; el.style.transform = "translateX(-50%) translateY(0)"; });
        setTimeout(() => { el.style.opacity = "0"; el.style.transform = "translateX(-50%) translateY(10px)"; setTimeout(() => el.remove(), 300); }, dur);
    }

    function _visualizeHs(el, text) {
        el.innerHTML = `<span style="display:inline-block; margin:2px 0; padding:3px 8px; font-size:11px; font-weight:600; font-family:monospace; color:var(--color-primary-p-50,#00ab80); background:var(--color-neutrals-n-20,#f4f5f7); border-radius:12px; border:1px solid var(--color-primary-p-50,#00ab80); opacity: 0.85; user-select:none;">${text}</span>`;
        el.style.display = "block";
        el.style.textAlign = "center";
        el._isDecrypted = true;
    }

    function markHashProcessed(chatId, hash) {
        const pKey = "bb_phs_" + chatId;
        const processed = JSON.parse(localStorage.getItem(pKey) || "[]");
        if (!processed.includes(hash)) {
            processed.push(hash);
            if(processed.length > 50) processed.shift();
            localStorage.setItem(pKey, JSON.stringify(processed));
        }
    }

    function isHashProcessed(chatId, hash) {
        return JSON.parse(localStorage.getItem("bb_phs_" + chatId) || "[]").includes(hash);
    }

    function getTimestampBytes() {
        const ts = Math.floor(Date.now() / 1000);
        return new Uint8Array([(ts >>> 24) & 0xFF, (ts >>> 16) & 0xFF, (ts >>> 8) & 0xFF, ts & 0xFF]);
    }

    function readTimestamp(buf) { return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]; }

    // Safe Send override bypassing messy react loops
    async function _sendRaw(text) {
        const real = getRealInput();
        if (!real) return;
        const mobile = isMobileInput(real);
        const wasSync = isSyncing;
        isSyncing = true;

        unlockInput(real);

        if (mobile) {
            _textareaSetter?.call(real, text);
            real.dispatchEvent(new Event("input", { bubbles: true, cancelable: true }));
        } else {
            real.focus();
            document.execCommand("selectAll", false, null);
            document.execCommand("insertText", false, text);
            real.dispatchEvent(new Event("input", { bubbles: true, cancelable: true }));
        }

        await new Promise(r => setTimeout(r, 60));

        let sendBtn = document.querySelector('[aria-label="send-button"]') || document.querySelector('.RaTWwR');
        let sent = false;

        if (sendBtn) {
            const btnProps = Object.keys(sendBtn).find(k => k.startsWith('__reactProps$'));
            if (btnProps && sendBtn[btnProps]?.onClick) {
                try {
                    sendBtn[btnProps].onClick({ preventDefault: () => {}, stopPropagation: () => {} });
                    sent = true;
                } catch(e) {}
            }
        }
        if (!sent && sendBtn) sendBtn.click();
        if (!sent && real) real.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, cancelable: true, key: "Enter", code: "Enter", keyCode: 13 }));

        await new Promise(r => setTimeout(r, 120));

        if (mobile) {
            _textareaSetter?.call(real, "");
            real.dispatchEvent(new Event("input", { bubbles: true, cancelable: true }));
        } else {
            real.focus();
            document.execCommand("selectAll", false, null);
            document.execCommand("delete", false, null);
            real.dispatchEvent(new Event("input", { bubbles: true, cancelable: true }));
        }

        if(isEncryptionEnabled()) lockInput(real);
        isSyncing = wasSync;
    }

    async function startHandshake() {
        if (_hsBusy) return;
        _hsBusy = true;
        try {
            const chatId = getChatId();
            const pair = await _hsNewPair();
            const pub = await _hsPubRaw(pair.publicKey);
            
            // Session storage securely survives page reloads while waiting for answer
            const exportedPriv = await crypto.subtle.exportKey("jwk", pair.privateKey);
            sessionStorage.setItem("bb_pending_hs_" + chatId, JSON.stringify(exportedPriv));

            const payload = new Uint8Array(1 + 4 + pub.length);
            payload[0] = 0x01; // Request
            payload.set(getTimestampBytes(), 1);
            payload.set(pub, 5);

            const b64 = btoa(String.fromCharCode.apply(null, payload));
            const msg = "!!" + b64;

            let msgHash = 0;
            for (let i=0; i<b64.length; i++) msgHash = Math.imul(31, msgHash) + b64.charCodeAt(i) | 0;
            markHashProcessed(chatId, msgHash); // Don't trigger on our own sent message

            await _sendRaw(msg);
            _showToast("⏳ Establishing secure bridge...");
        } catch (e) { console.error("[BB] Bridge setup failed"); }
        finally { _hsBusy = false; }
    }

    async function _handleHS(b64, el) {
        if (_hsBusy) return;
        
        const chatId = getChatId();
        let msgHash = 0;
        for (let i=0; i<b64.length; i++) msgHash = Math.imul(31, msgHash) + b64.charCodeAt(i) | 0;

        if (isHashProcessed(chatId, msgHash)) {
            _visualizeHs(el, "🤝 Bridge Signal Processed");
            return;
        }

        _hsBusy = true;
        try {
            const binary = atob(b64);
            const raw = new Uint8Array(binary.length);
            for(let i=0; i<binary.length; i++) raw[i] = binary.charCodeAt(i);

            const type = raw[0];
            const ts = readTimestamp(raw.subarray(1, 5));
            const theirPub = raw.subarray(5);

            // History Loop Bugfix: Ignore if > 5 minutes old
            if (Math.floor(Date.now() / 1000) - ts > 300) {
                markHashProcessed(chatId, msgHash);
                _visualizeHs(el, "⌛ Expired Bridge Request");
                _hsBusy = false;
                return;
            }

            if (type === 0x01) { // They requested a bridge
                const pair = await _hsNewPair();
                const myPub = await _hsPubRaw(pair.publicKey);
                const key = await _hsDeriveKeyStr(pair.privateKey, theirPub);
                
                saveChatSettings({ enabled: true, customKey: key });
                syncInputVisibility();

                const rPay = new Uint8Array(1 + 4 + myPub.length);
                rPay[0] = 0x02; // Accept
                rPay.set(getTimestampBytes(), 1);
                rPay.set(myPub, 5);

                const rB64 = btoa(String.fromCharCode.apply(null, rPay));
                const rMsg = "!!" + rB64;
                
                let rMsgHash = 0;
                for (let i=0; i<rB64.length; i++) rMsgHash = Math.imul(31, rMsgHash) + rB64.charCodeAt(i) | 0;
                
                markHashProcessed(chatId, msgHash);
                markHashProcessed(chatId, rMsgHash);

                await _sendRaw(rMsg);
                _visualizeHs(el, "🤝 Bridge Auto-Accepted");
                _showToast("🛡️ Bridge secured! Key ID: " + key.substring(0, 6).toUpperCase(), 5000);

                // Send success message to complete the loop visibly
                setTimeout(async () => {
                    const successEnc = await encryptChunked("✅ **Secure Bridge Auto-Established.** Communications are now encrypted.");
                    if(successEnc) {
                        for(const chunk of successEnc) await _sendRaw(chunk);
                    }
                }, 1000);

            } else if (type === 0x02) { // They accepted our bridge
                const privJwkStr = sessionStorage.getItem("bb_pending_hs_" + chatId);
                if (!privJwkStr) {
                    markHashProcessed(chatId, msgHash);
                    _visualizeHs(el, "❌ Orphaned Bridge Accept");
                    _hsBusy = false;
                    return;
                }
                const privJwk = JSON.parse(privJwkStr);
                const privKey = await crypto.subtle.importKey("jwk", privJwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
                
                const key = await _hsDeriveKeyStr(privKey, theirPub);
                sessionStorage.removeItem("bb_pending_hs_" + chatId);
                
                saveChatSettings({ enabled: true, customKey: key });
                syncInputVisibility();

                markHashProcessed(chatId, msgHash);
                _visualizeHs(el, "✅ Bridge Completed");
                _showToast("🛡️ Bridge secured! Key ID: " + key.substring(0, 6).toUpperCase(), 5000);
            }
        } catch (e) { console.error("[BB] Core error", e); } 
        finally { _hsBusy = false; }
    }

    // ─── 4. DOM Scanner & UI Rendering ────────────────────────────────────────
    const _URL_RE = /https?:\/\/[^\s<>"{}|\\^`[\]]+/g;
    const _ESC_MAP = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" };
    const escapeHtml = (s) => s.replace(/[&<>"]/g, c => _ESC_MAP[c]);

    function applyInlineMarkdown(s) {
        return s.replace(/``([^`]+)``|`([^`]+)`/g, (_, a, b) => `<code style="background:var(--color-neutrals-n-20,#f4f5f7);border-radius:4px;padding:1px 5px;font-family:monospace;font-size:.92em">${a ?? b}</code>`)
                .replace(/\|\|(.+?)\|\|/g, (_, t) => `<span class="bb-spoiler" style="background:var(--color-neutrals-n-400,#42526e);color:transparent;border-radius:3px;padding:0 3px;cursor:pointer;user-select:none" title="Click to reveal">${t}</span>`)
                .replace(/\*\*\*(.+?)\*\*\*/g, (_, t) => `<strong><em>${t}</em></strong>`)
                .replace(/\*\*(.+?)\*\*/g, (_, t) => `<strong>${t}</strong>`)
                .replace(/(?<![_a-zA-Z0-9])__(.+?)__(?![_a-zA-Z0-9])/g, (_, t) => `<u>${t}</u>`)
                .replace(/\*([^*\n]+)\*/g, (_, t) => `<em>${t}</em>`)
                .replace(/(^|[^a-zA-Z0-9_])_([^_\n]+?)_(?=[^a-zA-Z0-9_]|$)/g, (_, p, t) => `${p}<em>${t}</em>`)
                .replace(/~~(.+?)~~/g, (_, t) => `<del>${t}</del>`)
                .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, (_, label, url) => `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer" style="color:var(--color-primary-p-50,#00ab80);text-decoration:underline">${label}</a>`);
    }

    function processLine(line) {
        const parts = [];
        let last = 0, m;
        _URL_RE.lastIndex = 0;
        while ((m = _URL_RE.exec(line)) !== null) {
            parts.push(applyInlineMarkdown(escapeHtml(line.slice(last, m.index))));
            const safe = escapeHtml(m[0]);
            parts.push(`<a href="${safe}" target="_blank" rel="noopener noreferrer" style="color:var(--color-primary-p-50,#00ab80);text-decoration:underline;word-break:break-all">${safe}</a>`);
            last = m.index + m[0].length;
        }
        parts.push(applyInlineMarkdown(escapeHtml(line.slice(last))));
        return parts.join("");
    }

    function renderDecrypted(plain) {
        const lines = plain.split("\n");
        const out = [];
        let i = 0;
        const bidiBlock = (html) => `<span dir="auto" class="bb-block">${html}</span>`;
        while (i < lines.length) {
            const line = lines[i];
            if (line.startsWith("> ") || line === ">") {
                const qLines = [];
                while (i < lines.length && (lines[i].startsWith("> ") || lines[i] === ">")) qLines.push(lines[i++].replace(/^> ?/, ""));
                out.push(`<span dir="auto" class="bb-quote">${qLines.map(processLine).join("<br>")}</span>`);
                continue;
            }
            if (/^[-*+] /.test(line)) {
                const items = [];
                while (i < lines.length && /^[-*+] /.test(lines[i])) items.push(`<li class="bb-li">${processLine(lines[i++].slice(2))}</li>`);
                out.push(`<ul dir="auto" class="bb-ul">${items.join("")}</ul>`);
                continue;
            }
            if (/^\d+\. /.test(line)) {
                const items = [];
                while (i < lines.length && /^\d+\. /.test(lines[i])) items.push(`<li class="bb-li">${processLine(lines[i++].replace(/^\d+\. /, ""))}</li>`);
                out.push(`<ol dir="auto" class="bb-ol">${items.join("")}</ol>`);
                continue;
            }
            const hm = line.match(/^(#{1,3}) (.+)/);
            if (hm) {
                const sz = ["1.25em", "1.1em", "1em"][Math.min(hm[1].length, 3) - 1];
                out.push(bidiBlock(`<span style="font-weight:700;font-size:${sz}">${processLine(hm[2])}</span>`));
                i++;
                continue;
            }
            if (/^([-*_])\1{2,}$/.test(line.trim())) {
                out.push(`<span class="bb-hr"></span>`);
                i++;
                continue;
            }
            if (line.trim() === "") {
                out.push(`<span class="bb-spacer"></span>`);
                i++;
                continue;
            }
            out.push(bidiBlock(processLine(line)));
            i++;
        }
        return out.join("");
    }

    function scanTree(root) {
        const els = root.getElementsByTagName("*");
        for (let idx = 0, len = els.length; idx < len; idx++) {
            const el = els[idx];
            if (el._isDecrypted || el._isDecrypting) continue;
            const id = el.id;
            if (id === "secure-input-overlay" || id === "secure-edit-overlay" || id === "editable-message-text" || id === "main-message-input" || id === "bb-no-key-notice") continue;

            const text = el.textContent;
            if (text.length <= 20) continue;
            
            // Handshake Bridge Scanner (Strict extraction avoids DOM trailing spaces bug)
            const matchHs = text.trim().match(/!!([A-Za-z0-9+/=]{40,})/);
            if (matchHs) {
                let skip = false;
                for (const c of el.children) { if (c.textContent.includes("!!")) { skip = true; break; } }
                if (skip) continue;

                el._isDecrypted = true;
                _handleHS(matchHs[1], el);
                continue;
            }

            // Message Decryption Scanner
            const trimmed = text.trim();
            if (trimmed.startsWith("@@") && trimmed.length > 20) {
                let skip = false;
                for (const c of el.children) { if (c.textContent.trim() === trimmed) { skip = true; break; } }
                if (skip) continue;

                el._isDecrypting = true;
                decrypt(trimmed).then((plain) => {
                    if (plain !== trimmed) {
                        if (!el._bbOverflowSet) {
                            el.style.overflow = "hidden";
                            el.style.overflowWrap = "anywhere";
                            el.style.wordBreak = "break-word";
                            el.style.maxWidth = "100%";
                            el.classList.add("bb-msg-container");
                            el._bbOverflowSet = true;
                        }
                        el.innerHTML = renderDecrypted(plain) + `<span style="display:inline-block;font-size:9px;opacity:0.5;letter-spacing:0.02em;font-style:italic;margin-inline-start:5px;vertical-align:middle;line-height:1;white-space:nowrap">
                            🔒 encrypted
                            <span class="bb-copy-btn" title="Copy decrypted message" style="cursor:pointer;margin-inline-start:4px;font-size:11px;font-style:normal;transition:opacity 0.2s;">📋</span>
                        </span>`;
                        el.style.color = "inherit";
                        el._isDecrypted = true;

                        const copyBtn = el.querySelector('.bb-copy-btn');
                        if (copyBtn) {
                            copyBtn.addEventListener('click', (e) => {
                                e.preventDefault(); e.stopPropagation();
                                navigator.clipboard.writeText(plain).then(() => {
                                    copyBtn.textContent = "✅";
                                    setTimeout(() => copyBtn.textContent = "📋", 1500);
                                });
                            });
                        }
                    }
                }).finally(() => { el._isDecrypting = false; });
            }
        }
    }

    // ─── 5. Input Helpers & UI Styles ─────────────────────────────────────────
    const getRealInput = () => document.getElementById("editable-message-text") || document.getElementById("main-message-input");
    const isMobileInput = (el) => el?.tagName === "TEXTAREA";
    const _textareaSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set;

    document.addEventListener("click", (e) => {
        const sp = e.target.closest(".bb-spoiler");
        if (!sp) return;
        sp.style.color = "inherit";
        sp.style.background = "var(--color-neutrals-n-40,#dfe1e6)";
    }, true);

    document.head.insertAdjacentHTML("beforeend", `<style>
        #secure-input-overlay {
            width:100%;box-sizing:border-box;min-height:44px;max-height:150px;overflow-y:auto;
            background-color:var(--color-neutrals-surface,#fff);border:2px solid var(--color-primary-p-50,#00ab80);
            box-shadow:0 4px 12px rgba(0,171,128,.15);border-radius:16px;padding:10px 16px;
            font-family:inherit;font-size:inherit;outline:none;white-space:pre-wrap;word-break:break-word;
            margin-right:10px;resize:none;color:var(--color-neutrals-n-600,#151515);z-index:100;
            position:relative;transition:box-shadow .2s ease,border-color .2s ease;display:block;
        }
        #secure-input-overlay:focus{box-shadow:0 4px 16px rgba(0,171,128,.3);border-color:var(--color-primary-p-60,#00916d)}
        div#secure-input-overlay:empty::before{content:attr(data-placeholder);color:var(--color-neutrals-n-300,#888);pointer-events:none;display:block}

        #bb-no-key-notice {
            display:none;align-items:flex-start;gap:10px;
            width:100%;box-sizing:border-box;padding:10px 14px;margin-right:10px;
            background:#fff8e1;border:2px solid #f9a825;border-radius:16px;
            font-family:inherit;font-size:13px;color:#4a3400;line-height:1.5;
            position:relative;z-index:101;
        }
        #bb-no-key-notice .bb-notice-icon{font-size:20px;flex-shrink:0;margin-top:1px}
        #bb-no-key-notice .bb-notice-body{flex:1}
        #bb-no-key-notice strong{display:block;font-size:13px;margin-bottom:3px;color:#b45309}
        #bb-no-key-notice .bb-notice-btn{
            display:inline-block;margin-top:7px;padding:5px 12px;border-radius:8px;border:none;
            background:#f9a825;color:#fff;font-size:12px;font-weight:700;cursor:pointer;
            transition:background .15s;
        }
        #bb-no-key-notice .bb-notice-btn:hover{background:#f59e0b}

        #bale-bridge-menu{
            position:fixed;z-index:999999;background:var(--color-neutrals-surface,#fff);
            border:1px solid var(--color-neutrals-n-40,#dfe1e6);border-radius:12px;
            box-shadow:0 8px 24px rgba(0,0,0,.15);display:none;flex-direction:column;overflow:hidden;
            font-family:inherit;color:var(--color-neutrals-n-500,#091e42);min-width:180px;
            animation:bb-pop .2s cubic-bezier(.2,.8,.2,1);
        }
        .bale-menu-item{padding:14px 18px;cursor:pointer;font-size:14px;font-weight:500;transition:background .15s;display:flex;align-items:center;gap:12px}
        .bale-menu-item:hover{background:var(--color-neutrals-n-20,#f4f5f7)}

        #bb-modal-overlay{
            position:fixed;inset:0;background:rgba(0,0,0,.4);backdrop-filter:blur(3px);
            display:flex;align-items:center;justify-content:center;z-index:9999999;
            animation:bb-fade .2s ease-out;
        }
        #bb-modal-card{
            background:var(--color-neutrals-surface,#fff);padding:24px;border-radius:20px;
            width:360px;max-width:92vw;box-shadow:0 10px 40px rgba(0,0,0,.25);
            color:var(--color-neutrals-n-600,#151515);font-family:inherit;
            animation:bb-pop .3s cubic-bezier(.2,.8,.2,1);
        }
        .bb-modal-title{margin:0 0 10px;font-size:18px;font-weight:bold}
        .bb-modal-desc{margin:0 0 20px;font-size:13px;color:var(--color-neutrals-n-300,#888)}
        .bb-input{
            width:100%;padding:10px 12px;border-radius:8px;border:1px solid var(--color-neutrals-n-100,#ccc);
            box-sizing:border-box;background:transparent;color:inherit;
            font-family:monospace;font-size:13px;transition:border-color .2s;letter-spacing:.04em;
        }
        .bb-input:focus{outline:none;border-color:var(--color-primary-p-50,#00ab80)}
        .bb-key-row{display:flex;gap:8px;align-items:center;margin-top:6px}
        .bb-key-row .bb-input{flex:1;margin-top:0}
        .bb-icon-btn{
            flex-shrink:0;padding:0;width:36px;height:36px;border-radius:8px;border:1px solid var(--color-neutrals-n-100,#ccc);
            background:transparent;cursor:pointer;display:flex;align-items:center;justify-content:center;
            font-size:16px;transition:background .15s,border-color .15s;color:inherit;
        }
        .bb-icon-btn:hover{background:var(--color-neutrals-n-20,#f4f5f7);border-color:var(--color-primary-p-50,#00ab80)}
        .bb-icon-btn.copied{background:#e8f5e9;border-color:#43a047;color:#43a047}
        .bb-key-tools{display:flex;gap:8px;margin-top:8px}
        .bb-tool-btn{
            flex:1;padding:7px 0;border-radius:8px;border:1px solid var(--color-neutrals-n-100,#ccc);
            background:transparent;cursor:pointer;font-size:12px;font-weight:600;
            display:flex;align-items:center;justify-content:center;gap:5px;
            transition:background .15s,border-color .15s;color:inherit;
        }
        .bb-tool-btn:hover{background:var(--color-neutrals-n-20,#f4f5f7);border-color:var(--color-primary-p-50,#00ab80)}
        .bb-toggle-lbl{display:flex;align-items:center;gap:8px;font-size:14px;cursor:pointer}
        .bb-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:24px}
        .bb-btn{padding:8px 16px;border-radius:8px;border:none;cursor:pointer;font-weight:600;font-size:14px;transition:background .2s,transform .1s}
        .bb-btn:active{transform:scale(.95)}
        .bb-btn-cancel{background:transparent;color:var(--color-neutrals-n-300,#888)}
        .bb-btn-cancel:hover{background:var(--color-neutrals-n-20,#f4f5f7)}
        .bb-btn-save{background:var(--color-primary-p-50,#00ab80);color:#fff}
        .bb-btn-save:hover{background:var(--color-primary-p-60,#00916d)}
        .bb-btn-save:disabled{background:var(--color-neutrals-n-100,#ccc);cursor:not-allowed;transform:none}
        .bb-key-meta{display:flex;justify-content:space-between;align-items:center;margin-top:6px;font-size:11px}
        .bb-key-counter{color:var(--color-neutrals-n-300,#888)}
        .bb-key-counter.exact{color:var(--color-primary-p-50,#00ab80);font-weight:600}
        .bb-key-error{color:#d32f2f;font-weight:500;font-size:11px;min-height:16px}

        @keyframes bb-fade{from{opacity:0}to{opacity:1}}
        @keyframes bb-pop{from{opacity:0;transform:scale(.95)}to{opacity:1;transform:scale(1)}}

        .bb-block { display: block; unicode-bidi: plaintext; }
        .bb-quote { display: block; border-inline-start: 3px solid var(--color-primary-p-50,#00ab80); padding: 2px 10px; margin: 2px 0; font-style: italic; opacity: 0.9; unicode-bidi: plaintext; }
        .bb-ul { margin: 4px 0; padding-inline-start: 22px; list-style: disc; unicode-bidi: plaintext; }
        .bb-ol { margin: 4px 0; padding-inline-start: 22px; list-style: decimal; unicode-bidi: plaintext; }
        .bb-li { margin: 2px 0; padding-inline-start: 2px; }
        .bb-hr { display: block; border-top: 1px solid var(--color-neutrals-n-100,#ccc); margin: 6px 0; }
        .bb-spacer { display: block; height: 0.4em; }

        .BAsWs0 .bb-block, .MRlMpm .bb-block, .dialog-item-content .bb-block, .aqFHpt .bb-block,
        .BAsWs0 .bb-quote, .MRlMpm .bb-quote, .dialog-item-content .bb-quote, .aqFHpt .bb-quote,
        .BAsWs0 .bb-ul, .MRlMpm .bb-ul, .dialog-item-content .bb-ul, .aqFHpt .bb-ul,
        .BAsWs0 .bb-ol, .MRlMpm .bb-ol, .dialog-item-content .bb-ol, .aqFHpt .bb-ol,
        .BAsWs0 .bb-li, .MRlMpm .bb-li, .dialog-item-content .bb-li, .aqFHpt .bb-li {
            display: inline !important; margin: 0 !important; padding: 0 !important; border: none !important;
        }
        .BAsWs0 .bb-spacer, .MRlMpm .bb-spacer, .dialog-item-content .bb-spacer, .aqFHpt .bb-spacer,
        .BAsWs0 .bb-hr, .MRlMpm .bb-hr, .dialog-item-content .bb-hr, .aqFHpt .bb-hr,
        .BAsWs0 .bb-copy-btn, .MRlMpm .bb-copy-btn, .dialog-item-content .bb-copy-btn, .aqFHpt .bb-copy-btn {
            display: none !important;
        }
        .bb-copy-btn:hover { opacity: 1 !important; }
        .BAsWs0 .bb-li::after, .MRlMpm .bb-li::after, .dialog-item-content .bb-li::after, .aqFHpt .bb-li::after {
            content: " \\00a0•\\00a0 ";
        }
        .BAsWs0 .bb-msg-container, .MRlMpm .bb-msg-container, .dialog-item-content .bb-msg-container, .aqFHpt .bb-msg-container {
            display: -webkit-box !important; -webkit-line-clamp: 2 !important; -webkit-box-orient: vertical !important; white-space: normal !important;
        }
    </style>`);

    // ─── 6. Context Menu ──────────────────────────────────────────────────────
    const popupMenu = document.createElement("div");
    popupMenu.id = "bale-bridge-menu";
    popupMenu.innerHTML = `
        <div class="bale-menu-item" id="bale-menu-enc">🔒 Send Encrypted</div>
        <div class="bale-menu-item" id="bale-menu-plain">⚠️ Send Unencrypted</div>`;
    document.body.appendChild(popupMenu);

    const showMenu = (x, y) => Object.assign(popupMenu.style, { display: "flex", left: Math.min(x, innerWidth - 210) + "px", top: Math.min(y, innerHeight - 120) + "px" });

    document.addEventListener("click", (e) => { if (!popupMenu.contains(e.target)) popupMenu.style.display = "none"; });
    document.getElementById("bale-menu-enc").onclick = () => { popupMenu.style.display = "none"; window._bbSend?.(true); };
    document.getElementById("bale-menu-plain").onclick = () => { popupMenu.style.display = "none"; window._bbSend?.(false); };

    // ─── 7. Settings Modal ────────────────────────────────────────────────────
    function openSettingsModal() {
        document.getElementById("bb-modal-overlay")?.remove();
        const s = getChatSettings();

        document.body.insertAdjacentHTML("beforeend", `
            <div id="bb-modal-overlay">
                <div id="bb-modal-card">
                    <h3 class="bb-modal-title">Shield Settings 🛡️</h3>
                    <p class="bb-modal-desc">Configure encryption for this chat. When enabled, a 32-character key is required.</p>
                    <label class="bb-toggle-lbl">
                        <input type="checkbox" id="bb-enable-enc" ${s.enabled ? "checked" : ""}
                            style="width:16px;height:16px;accent-color:var(--color-primary-p-50,#00ab80)">
                        <span>Enable Encryption Here</span>
                    </label>
                    <div id="bb-key-section" style="margin-top:16px;border-top:1px solid var(--color-neutrals-n-20,#f4f5f7);padding-top:16px">
                        <label style="font-size:12px;color:var(--color-neutrals-n-500,#151515);font-weight:600">
                            Encryption Key <span style="color:#d32f2f">*</span>
                        </label>
                        <div class="bb-key-row">
                            <input type="password" id="bb-custom-key" class="bb-input"
                                placeholder="Enter exactly 32 characters…"
                                maxlength="32"
                                value="${s.customKey || ""}">
                            <button class="bb-icon-btn" id="bb-toggle-vis" title="Show / hide key">👁</button>
                            <button class="bb-icon-btn" id="bb-copy-key" title="Copy key">📋</button>
                        </div>
                        <div class="bb-key-tools">
                            <button class="bb-tool-btn" id="bb-gen-key">⚡ Random Key</button>
                            <button class="bb-tool-btn" id="bb-start-hs" style="border-color:var(--color-primary-p-50,#00ab80);color:var(--color-primary-p-50,#00ab80);">🤝 Auto Bridge</button>
                        </div>
                        <div class="bb-key-meta">
                            <span class="bb-key-error" id="bb-key-error"></span>
                            <span class="bb-key-counter" id="bb-key-counter">0 / 32</span>
                        </div>
                    </div>
                    <div class="bb-actions">
                        <button class="bb-btn bb-btn-cancel" id="bb-btn-cancel">Cancel</button>
                        <button class="bb-btn bb-btn-save" id="bb-btn-save">Save</button>
                    </div>
                </div>
            </div>`);

        const overlay = document.getElementById("bb-modal-overlay");
        const keyInput = document.getElementById("bb-custom-key");
        const keySection = document.getElementById("bb-key-section");
        const counter = document.getElementById("bb-key-counter");
        const errorEl = document.getElementById("bb-key-error");
        const saveBtn = document.getElementById("bb-btn-save");
        const enableCb = document.getElementById("bb-enable-enc");
        const copyBtn = document.getElementById("bb-copy-key");
        const genBtn = document.getElementById("bb-gen-key");
        const visBtn = document.getElementById("bb-toggle-vis");
        const hsBtn = document.getElementById("bb-start-hs");

        const validate = () => {
            const len = keyInput.value.length;
            const enabled = enableCb.checked;
            counter.textContent = `${len} / 32`;
            counter.className = "bb-key-counter" + (len === 32 ? " exact" : "");
            keySection.style.display = enabled ? "" : "none";

            if (!enabled) {
                errorEl.textContent = ""; saveBtn.disabled = false; return;
            }
            if (len === 0) {
                errorEl.textContent = "Key required."; saveBtn.disabled = true;
            } else if (len !== 32) {
                errorEl.textContent = `Must be exactly 32 chars (${len}).`; saveBtn.disabled = true;
            } else {
                errorEl.textContent = ""; saveBtn.disabled = false;
            }
        };

        keyInput.addEventListener("input", validate);
        enableCb.addEventListener("change", validate);
        validate();

        visBtn.addEventListener("click", () => {
            const hidden = keyInput.type === "password";
            keyInput.type = hidden ? "text" : "password";
            visBtn.textContent = hidden ? "🙈" : "👁";
        });
        copyBtn.addEventListener("click", () => {
            if (!keyInput.value) return;
            navigator.clipboard.writeText(keyInput.value).then(() => {
                copyBtn.textContent = "✅"; copyBtn.classList.add("copied");
                setTimeout(() => { copyBtn.textContent = "📋"; copyBtn.classList.remove("copied"); }, 1500);
            });
        });
        genBtn.addEventListener("click", () => {
            keyInput.value = generateKey(); keyInput.type = "text";
            visBtn.textContent = "🙈"; validate();
        });
        hsBtn.addEventListener("click", () => { overlay.remove(); startHandshake(); });
        document.getElementById("bb-btn-cancel").onclick = () => overlay.remove();
        saveBtn.onclick = () => {
            if (saveBtn.disabled) return;
            saveChatSettings({ enabled: enableCb.checked, customKey: keyInput.value });
            overlay.remove();
            syncInputVisibility();
        };
    }

    // ─── 8. Secure Input & Shield Button ──────────────────────────────────────
    let isSending = false, lastHasText = false, isSyncing = false;

    const lockInput = (el) => Object.assign(el.style, { position: "absolute", opacity: "0", pointerEvents: "none", height: "0px", width: "0px", overflow: "hidden", zIndex: "-9999" });
    const unlockInput = (el) => {
        el.style.position = ""; el.style.opacity = "1"; el.style.pointerEvents = "auto";
        el.style.height = ""; el.style.width = "100%"; el.style.overflow = "auto"; el.style.zIndex = "";
    };

    function syncInputVisibility() {
        const real = getRealInput();
        const secure = document.getElementById("secure-input-overlay");
        const notice = document.getElementById("bb-no-key-notice");
        const btn = document.getElementById("bb-settings-btn");
        if (!real) return;

        if (!isEncryptionEnabled()) {
            unlockInput(real);
            if (secure) secure.style.display = "none";
            if (notice) notice.style.display = "none";
            if (btn) btn.style.color = "#5E6C84";
        } else if (getActiveKey()) {
            lockInput(real);
            if (secure) secure.style.display = "";
            if (notice) notice.style.display = "none";
            if (btn) btn.style.color = "var(--color-primary-p-50, #00ab80)";
        } else {
            lockInput(real);
            if (secure) secure.style.display = "none";
            if (notice) notice.style.display = "flex";
            if (btn) btn.style.color = "#f9a825";
        }
    }

    function ensureSecureInput() {
        const realInput = getRealInput();
        if (!realInput) return;
        const mobile = isMobileInput(realInput);
        const wrapper = realInput.parentElement;

        const emojiBtn = document.querySelector('[aria-label="emoji-icon"]') || document.querySelector(".MmBErq");
        if (emojiBtn && isEncryptionEnabled()) emojiBtn.style.display = "none";
        else if (emojiBtn) emojiBtn.style.display = "";

        if (emojiBtn && !document.getElementById("bb-settings-btn")) {
            const shieldBtn = document.createElement("div");
            shieldBtn.id = "bb-settings-btn";
            shieldBtn.className = emojiBtn.className;
            shieldBtn.setAttribute("role", "button");
            shieldBtn.style.cssText = "display:flex;align-items:center;justify-content:center;cursor:pointer;transition:color .2s";
            shieldBtn.innerHTML = `<div style="border-radius:50%;line-height:0;position:relative"><svg width="24" height="24" fill="currentColor" viewBox="0 0 24 24"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg></div>`;
            shieldBtn.onclick = openSettingsModal;
            emojiBtn.parentElement.insertBefore(shieldBtn, emojiBtn);
        }

        if (!document.getElementById("bb-no-key-notice")) {
            const notice = document.createElement("div");
            notice.id = "bb-no-key-notice";
            notice.innerHTML = `
                <div class="bb-notice-icon">⚠️</div>
                <div class="bb-notice-body">
                    <strong>Encryption key not set — sending is blocked.</strong>
                    Tap the 🔒 lock button to establish a secure session.
                    <br><button class="bb-notice-btn" id="bb-notice-set-key">🛡 Set Encryption Key</button>
                </div>`;
            wrapper.insertBefore(notice, realInput);
            notice.querySelector("#bb-notice-set-key").onclick = openSettingsModal;
        }

        const existingOverlay = document.getElementById("secure-input-overlay");
        if (existingOverlay) { window._bbSend = existingOverlay._triggerSend; syncInputVisibility(); return; }

        if (!realInput._hasStrictHijack) {
            realInput._hasStrictHijack = true;
            realInput.addEventListener("focus", () => {
                if (!isSyncing && isEncryptionEnabled()) {
                    realInput.blur(); document.getElementById("secure-input-overlay")?.focus();
                }
            });
            ["keydown", "keypress", "keyup", "paste", "drop"].forEach((evt) => realInput.addEventListener(evt, (e) => {
                if (!isSyncing && isEncryptionEnabled()) { e.preventDefault(); e.stopPropagation(); }
            }, true));
        }

        let secureInput;
        if (mobile) {
            secureInput = document.createElement("textarea");
            secureInput.dir = "auto";
            secureInput.placeholder = "🔒 پیام امن...";
            secureInput.rows = 1;
            secureInput.addEventListener("input", () => { secureInput.style.height = "auto"; secureInput.style.height = Math.min(secureInput.scrollHeight, 150) + "px"; });
        } else {
            secureInput = document.createElement("div");
            secureInput.contentEditable = "true";
            secureInput.dir = "auto";
            secureInput.dataset.placeholder = "🔒 پیام امن...";
            wrapper.style.overflow = "visible";
        }
        secureInput.id = "secure-input-overlay";
        secureInput.className = realInput.className;
        wrapper.insertBefore(secureInput, realInput);

        const getText = () => mobile ? secureInput.value.trim() : secureInput.innerText.trim();
        const setText = (v) => { if (mobile) secureInput.value = v; else secureInput.innerText = v; };

        const syncHasText = (hasText) => {
            if (hasText === lastHasText) return;
            lastHasText = hasText;
            isSyncing = true;
            if (mobile) {
                _textareaSetter?.call(realInput, hasText ? " " : "");
                realInput.dispatchEvent(new Event("input", { bubbles: true }));
            } else {
                const sel = window.getSelection();
                let marker = null;
                if (sel.rangeCount > 0 && secureInput.contains(sel.getRangeAt(0).commonAncestorContainer)) {
                    marker = document.createElement("span");
                    marker.id = "bb-caret-marker";
                    const range = sel.getRangeAt(0);
                    range.insertNode(marker);
                }

                realInput.focus();
                document.execCommand("selectAll", false, null);
                if (hasText) {
                    document.execCommand("insertText", false, " ");
                } else {
                    document.execCommand("delete", false, null);
                }
                realInput.dispatchEvent(new Event("input", { bubbles: true, cancelable: true }));
                secureInput.focus();

                if (marker) {
                    const newRange = document.createRange();
                    newRange.setStartBefore(marker);
                    newRange.collapse(true);
                    sel.removeAllRanges();
                    sel.addRange(newRange);
                    marker.remove();
                    secureInput.normalize();
                } else {
                    const newRange = document.createRange();
                    newRange.selectNodeContents(secureInput);
                    newRange.collapse(false);
                    sel.removeAllRanges();
                    sel.addRange(newRange);
                }
            }
            isSyncing = false;
        };

        secureInput.addEventListener("input", (e) => {
            if (e.isComposing) return;
            syncHasText(getText().length > 0);
        });
        secureInput.addEventListener("compositionend", () => {
            syncHasText(getText().length > 0);
        });

        const sendOneChunk = async (out) => {
            await _sendRaw(out);
        };

        const triggerSend = async (doEncrypt = true) => {
            if (isSending) return;
            const text = getText();
            if (!text) return;
            if (doEncrypt) {
                if (!getActiveKey()) { openSettingsModal(); return; }
                isSending = true;
                setText("🔒 Encrypting...");
                try {
                    const chunks = await encryptChunked(text);
                    if (!chunks) { setText(text); openSettingsModal(); return; }
                    for (const chunk of chunks) await sendOneChunk(chunk);
                    setText(""); lastHasText = false; secureInput.focus();
                } catch (e) {
                    console.error("[BB] Send failed:", e);
                    setText(text); alert("Send failed!");
                } finally { isSending = false; }
                return;
            }
            if (!confirm("⚠️ You are about to send this message WITHOUT encryption.\n\nAre you sure?")) return;
            isSending = true;
            setText("🌐 Sending...");
            try {
                await sendOneChunk(text);
                setText(""); lastHasText = false; secureInput.focus();
            } catch (e) {
                setText(text); alert("Send failed!");
            } finally { isSending = false; }
        };

        secureInput._triggerSend = triggerSend;
        window._bbSend = triggerSend;
        secureInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); e.stopPropagation(); triggerSend(true); }
        });
        syncInputVisibility();
    }

    // ─── 8b. Secure Edit / Caption Input ─────────────────────────────────────
    function ensureEditInput() {
        const real = document.querySelector('textarea[aria-label="File Description"]');
        if (!real || real._bbEditHooked) return;
        real._bbEditHooked = true;
        const secureEdit = document.createElement("textarea");
        secureEdit.id = "secure-edit-overlay";
        secureEdit.className = real.className;
        secureEdit.placeholder = "🔒 " + (real.placeholder || "ویرایش امن...");
        secureEdit.dir = real.dir || "auto";
        secureEdit.style.cssText = real.style.cssText;
        secureEdit.addEventListener("input", () => { secureEdit.style.height = "auto"; secureEdit.style.height = Math.min(secureEdit.scrollHeight, 150) + "px"; });

        real.parentElement.insertBefore(secureEdit, real);
        lockInput(real);
        secureEdit.focus();

        const existing = real.value.trim();
        _textareaSetter?.call(real, "");
        real.dispatchEvent(new Event("input", { bubbles: true }));
        if (existing.startsWith("@@")) decrypt(existing).then(p => { if (p !== existing) secureEdit.value = p; });
        else secureEdit.value = existing;

        const encryptAndForward = async (btn) => {
            if (secureEdit._isSending) return;
            const text = secureEdit.value.trim();
            if (!text) return;
            if (!getActiveKey()) { openSettingsModal(); return; }
            secureEdit._isSending = true;
            const prev = secureEdit.value;
            secureEdit.value = "🔒 Encrypting...";
            try {
                const out = await encrypt(text);
                if (!out) { secureEdit.value = prev; openSettingsModal(); return; }
                secureEdit.value = "";
                unlockInput(real);
                _textareaSetter?.call(real, out);
                real.dispatchEvent(new Event("input", { bubbles: true }));
                real.dispatchEvent(new Event("change", { bubbles: true }));
                await new Promise(r => setTimeout(r, 80));

                const btnProps = Object.keys(btn).find(k => k.startsWith('__reactProps$'));
                if (btnProps && btn[btnProps] && btn[btnProps].onClick) {
                    btn[btnProps].onClick({ preventDefault: () => {}, stopPropagation: () => {} });
                } else {
                    btn.click();
                }
            } catch (e) {
                secureEdit.value = prev; alert("Encryption failed!");
            } finally { secureEdit._isSending = false; }
        };

        const isConfirmBtn = (t) => t.closest('[data-testid="confirm-button"]') || (t.closest('button[aria-label="Send"]') && !t.closest('#chat_footer'));
        const editClickHandler = (e) => {
            const btn = isConfirmBtn(e.target);
            if (!btn || !secureEdit.value.trim()) return;
            if (secureEdit._isSending) { e.preventDefault(); e.stopPropagation(); return; }
            e.preventDefault(); e.stopPropagation(); encryptAndForward(btn);
        };
        document.addEventListener("click", editClickHandler, true);
        document.addEventListener("mousedown", editClickHandler, true);
        const editObserver = new MutationObserver(() => {
            if (!document.contains(secureEdit)) {
                document.removeEventListener("click", editClickHandler, true);
                document.removeEventListener("mousedown", editClickHandler, true);
                editObserver.disconnect();
            }
        });
        editObserver.observe(document.body, { childList: true, subtree: true });
        secureEdit.addEventListener("keydown", (e) => {
            if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault(); e.stopPropagation();
                const btn = document.querySelector('[data-testid="confirm-button"]') || document.querySelector('button[aria-label="Send"]:not(#chat_footer button)');
                if (btn) encryptAndForward(btn);
            }
        });
    }

    // ─── 9. Send Button Event Interception ────────────────────────────────────
    const getSecureText = () => {
        const si = document.getElementById("secure-input-overlay");
        return si ? (si.tagName === "TEXTAREA" ? si.value.trim() : si.innerText.trim()) : "";
    };
    const isSendBtn = (t) => !!(t.closest('[aria-label="send-button"]') || t.closest('.RaTWwR'));

    // Prevent Real Clicks & Trigger Secure Send
    const blockAndSend = (e) => {
        if (isSending) {
            e.preventDefault(); e.stopPropagation(); return;
        }
        if (!isSendBtn(e.target) || !isEncryptionEnabled() || !getSecureText()) return;

        e.preventDefault(); e.stopPropagation();
        if (e.type === 'mousedown' || e.type === 'touchstart') {
            window._bbSend?.(true);
        }
    };

    ['mousedown', 'click', 'pointerdown', 'touchstart'].forEach(evt => document.addEventListener(evt, blockAndSend, true));

    // Right Click
    document.addEventListener("contextmenu", (e) => {
        if (isSending || !isSendBtn(e.target) || !isEncryptionEnabled() || !getSecureText()) return;
        e.preventDefault(); e.stopPropagation(); showMenu(e.clientX, e.clientY);
    }, true);

    // Mobile Hold
    let touchTimer;
    document.addEventListener("touchstart", (e) => {
        if (isSending || !isSendBtn(e.target) || !isEncryptionEnabled() || !getSecureText()) return;
        touchTimer = setTimeout(() => {
            e.preventDefault(); showMenu(e.touches[0].clientX, e.touches[0].clientY);
        }, 500);
    }, { passive: false, capture: true });
    document.addEventListener("touchend", () => clearTimeout(touchTimer), true);
    document.addEventListener("touchmove", () => clearTimeout(touchTimer), true);

    // ─── 10. MutationObserver & SPA URL Tracker ───────────────────────────────
    let scanTO, lastUrl = location.href;
    new MutationObserver(() => {
        clearTimeout(scanTO);
        scanTO = setTimeout(() => {
            scanTree(document.body);
            ensureSecureInput();
            ensureEditInput();
            if (location.href !== lastUrl) {
                lastUrl = location.href;
                _settingsCache = null; _settingsCacheId = null;
                syncInputVisibility();
            }
        }, 100);
    }).observe(document.body, { childList: true, subtree: true, characterData: true });

})();
