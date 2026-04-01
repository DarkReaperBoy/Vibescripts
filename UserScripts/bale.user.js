// ==UserScript==
// @name         Bale Bridge Encryptor (Secure ECDH & Anti-XSS)
// @namespace    http://tampermonkey.net/
// @version      12.0
// @description  Hardened: XSS-safe rendering, constant-time ops, race-condition guards, memory management, input validation.
// @author       You
// @match        *://web.bale.ai/*
// @match        *://*.bale.ai/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

(function () {
    "use strict";

    // ─── 0. Constants & Frozen Configuration ──────────────────────────────────
    // Freeze all configuration to prevent prototype pollution or runtime tampering.
    const CONFIG = Object.freeze({
        KEY_LENGTH: 32,
        MAX_ENCRYPTED_LEN: 4000,
        HANDSHAKE_EXPIRY_SEC: 300,
        TOAST_DURATION: 5000,
        SCAN_DEBOUNCE_MS: 120,
        LONG_PRESS_MS: 400,
        SEND_DELAY_MS: 80,
        POST_SEND_DELAY_MS: 200,
        MAX_PROCESSED_HASHES: 50,
        KEY_CHARS: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_+=~",
        // Base85 alphabet — frozen to prevent mutation
        B85_ALPHABET: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~",
        HS_TYPE_REQUEST: 0x01,
        HS_TYPE_RESPONSE: 0x02,
        ENCRYPTED_PREFIX: "@@",
        HANDSHAKE_PREFIX: "!!",
    });

    // ─── 0a. WebSocket Draft Blocker ──────────────────────────────────────────
    // SECURITY: Use a captured reference so bypassing our override requires
    // access to the original symbol, not just reassigning .send.
    // We also guard against non-string/buffer types and avoid silent swallowing
    // of legitimate messages.
    const _origWsSend = WebSocket.prototype.send;
    const _draftBlockerRegex = /EditParameter.*drafts_|drafts_.*EditParameter/;

    Object.defineProperty(WebSocket.prototype, "send", {
        configurable: false, // Prevent re-override
        enumerable: true,
        writable: false,
        value: function (data) {
            try {
                let text = "";
                if (typeof data === "string") {
                    text = data;
                } else if (data instanceof ArrayBuffer) {
                    text = new TextDecoder().decode(data);
                } else if (ArrayBuffer.isView(data)) {
                    text = new TextDecoder().decode(data);
                }
                // Block draft sync messages that leak plaintext to server
                if (text && _draftBlockerRegex.test(text)) {
                    return undefined;
                }
            } catch {
                // If we can't decode, let it through — don't block legitimate binary frames
            }
            return _origWsSend.call(this, data);
        },
    });

    // ─── 1. Settings (Per-Chat) with Validation ──────────────────────────────
    /**
     * SECURITY: Chat ID extraction is sanitized to prevent path traversal
     * in localStorage keys. We whitelist alphanumeric + limited punctuation.
     */
    const SAFE_ID_RE = /^[a-zA-Z0-9_\-]+$/;

    const getChatId = () => {
        const p = new URLSearchParams(location.search);
        const raw =
            p.get("uid") ||
            p.get("groupId") ||
            p.get("channelId") ||
            location.pathname.split("/").pop() ||
            "global";
        // Sanitize: only allow safe characters to prevent localStorage key injection
        return SAFE_ID_RE.test(raw) ? raw : "global";
    };

    // Settings cache — invalidated on URL change
    let _settingsCacheId = null;
    let _settingsCache = null;

    const DEFAULT_SETTINGS = Object.freeze({ enabled: true, customKey: "" });

    const getChatSettings = () => {
        const id = getChatId();
        if (id === _settingsCacheId && _settingsCache !== null) {
            return _settingsCache;
        }
        try {
            const raw = localStorage.getItem("bale_bridge_settings_" + id);
            if (raw) {
                const parsed = JSON.parse(raw);
                // Validate shape — reject malformed data
                if (
                    typeof parsed === "object" &&
                    parsed !== null &&
                    typeof parsed.enabled === "boolean" &&
                    typeof parsed.customKey === "string" &&
                    parsed.customKey.length <= CONFIG.KEY_LENGTH
                ) {
                    _settingsCache = { enabled: parsed.enabled, customKey: parsed.customKey };
                    _settingsCacheId = id;
                    return _settingsCache;
                }
            }
        } catch {
            // Corrupted data — fall through to default
        }
        _settingsCache = { ...DEFAULT_SETTINGS };
        _settingsCacheId = id;
        return _settingsCache;
    };

    const saveChatSettings = (s) => {
        // Validate before saving
        if (typeof s.enabled !== "boolean" || typeof s.customKey !== "string") {
            throw new TypeError("Invalid settings shape");
        }
        if (s.customKey.length > 0 && s.customKey.length !== CONFIG.KEY_LENGTH) {
            throw new RangeError(`Key must be exactly ${CONFIG.KEY_LENGTH} characters`);
        }
        const id = getChatId();
        _settingsCache = { enabled: s.enabled, customKey: s.customKey };
        _settingsCacheId = id;
        localStorage.setItem("bale_bridge_settings_" + id, JSON.stringify(_settingsCache));
    };

    const getActiveKey = () => {
        const s = getChatSettings();
        if (!s.enabled) return null;
        return s.customKey && s.customKey.length === CONFIG.KEY_LENGTH ? s.customKey : null;
    };

    const isEncryptionEnabled = () => getChatSettings().enabled;

    const getSecurityFingerprint = () => {
        const k = getActiveKey();
        if (!k || k.length !== CONFIG.KEY_LENGTH) return "NONE";
        return k.substring(0, 5).toUpperCase();
    };

    // ─── 2. Crypto Engine (AES-GCM) ──────────────────────────────────────────
    /**
     * SECURITY FIX: The key cache uses a WeakRef-like approach via a bounded Map
     * to prevent unbounded memory growth. Keys are evicted when cache exceeds limit.
     *
     * SECURITY FIX: Key material is derived from the full 32-byte input, not
     * zero-padded (the original code zero-padded short keys, weakening security).
     */
    const KEY_CACHE_MAX = 16;
    const keyCache = new Map();

    async function getCryptoKey(keyStr) {
        if (keyCache.has(keyStr)) return keyCache.get(keyStr);

        // Enforce exact key length — no zero-padding of short keys
        const encoded = new TextEncoder().encode(keyStr);
        if (encoded.length !== CONFIG.KEY_LENGTH) {
            throw new RangeError("Key must encode to exactly 32 bytes");
        }

        const key = await crypto.subtle.importKey(
            "raw",
            encoded,
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
        );

        // Bounded cache: evict oldest entry if full
        if (keyCache.size >= KEY_CACHE_MAX) {
            const firstKey = keyCache.keys().next().value;
            keyCache.delete(firstKey);
        }
        keyCache.set(keyStr, key);
        return key;
    }

    /**
     * SECURITY FIX: Key generation uses rejection sampling to eliminate
     * modular bias. `byte % 76` introduces bias since 256 % 76 ≠ 0.
     * We reject bytes >= 76 * floor(256/76) = 76 * 3 = 228.
     */
    function generateKey() {
        const chars = CONFIG.KEY_CHARS;
        const charLen = chars.length; // 76
        const maxUnbiased = Math.floor(256 / charLen) * charLen; // 228
        const result = new Array(CONFIG.KEY_LENGTH);
        let filled = 0;

        while (filled < CONFIG.KEY_LENGTH) {
            const batch = crypto.getRandomValues(new Uint8Array(CONFIG.KEY_LENGTH * 2));
            for (let i = 0; i < batch.length && filled < CONFIG.KEY_LENGTH; i++) {
                if (batch[i] < maxUnbiased) {
                    result[filled++] = chars[batch[i] % charLen];
                }
            }
        }
        return result.join("");
    }

    // ─── Base85 Codec (with input validation) ────────────────────────────────
    const B85 = CONFIG.B85_ALPHABET;
    const B85D = new Uint8Array(128).fill(255); // 255 = invalid sentinel
    for (let i = 0; i < B85.length; i++) B85D[B85.charCodeAt(i)] = i;

    function b85enc(buf) {
        if (!(buf instanceof Uint8Array)) {
            throw new TypeError("b85enc expects Uint8Array");
        }
        const len = buf.length;
        const fullChunks = len >>> 2;
        const remainder = len & 3;
        const outLen = fullChunks * 5 + (remainder ? remainder + 1 : 0);
        const chars = new Array(outLen);
        let pos = 0;

        for (let i = 0; i < len; i += 4) {
            const rem = Math.min(len - i, 4);
            let acc = 0;
            for (let j = 0; j < 4; j++) {
                acc = (acc << 8) | (i + j < len ? buf[i + j] : 0);
            }
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
        if (typeof str !== "string") {
            throw new TypeError("b85dec expects string");
        }
        const slen = str.length;
        if (slen === 0) return new Uint8Array(0);

        const fullChunks = Math.floor(slen / 5);
        const remChars = slen % 5;
        // Validate: remainder of 1 is invalid in base85
        if (remChars === 1) {
            throw new RangeError("Invalid base85 string length");
        }
        const outEst = fullChunks * 4 + (remChars ? remChars - 1 : 0);
        const out = new Uint8Array(outEst);
        let wpos = 0;

        for (let i = 0; i < slen; i += 5) {
            const end = Math.min(i + 5, slen);
            const chunkLen = end - i;
            const pad = 5 - chunkLen;
            let acc = 0;
            for (let j = 0; j < 5; j++) {
                const ci = i + j < slen ? str.charCodeAt(i + j) : 126; // '~'
                // Validate character is within ASCII range and in alphabet
                if (ci >= 128 || B85D[ci] === 255) {
                    throw new RangeError(`Invalid base85 character at position ${i + j}`);
                }
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

    // ─── Compression (with graceful fallback) ────────────────────────────────
    async function compress(text) {
        if (typeof CompressionStream === "undefined") {
            return new TextEncoder().encode(text);
        }
        const cs = new CompressionStream("deflate");
        const writer = cs.writable.getWriter();
        const encoded = new TextEncoder().encode(text);
        await writer.write(encoded);
        await writer.close();
        return new Uint8Array(await new Response(cs.readable).arrayBuffer());
    }

    async function decompress(buf) {
        if (typeof DecompressionStream === "undefined") {
            return new TextDecoder().decode(buf);
        }
        try {
            const ds = new DecompressionStream("deflate");
            const writer = ds.writable.getWriter();
            await writer.write(buf);
            await writer.close();
            return new TextDecoder().decode(await new Response(ds.readable).arrayBuffer());
        } catch {
            // Fallback: data might not be compressed (backward compat)
            return new TextDecoder().decode(buf);
        }
    }

    // ─── Encrypt / Decrypt ───────────────────────────────────────────────────
    async function encrypt(text) {
        const k = getActiveKey();
        if (!k) return null;
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const compressed = await compress(text);
        const ct = new Uint8Array(
            await crypto.subtle.encrypt(
                { name: "AES-GCM", iv },
                await getCryptoKey(k),
                compressed
            )
        );
        const payload = new Uint8Array(12 + ct.length);
        payload.set(iv);
        payload.set(ct, 12);
        return CONFIG.ENCRYPTED_PREFIX + b85enc(payload);
    }

    async function decrypt(text) {
        if (!text.startsWith(CONFIG.ENCRYPTED_PREFIX)) return text;
        const k = getActiveKey();
        if (!k) return text;
        try {
            const buf = b85dec(text.slice(CONFIG.ENCRYPTED_PREFIX.length));
            if (buf.length < 13) return text; // IV(12) + at least 1 byte ciphertext
            const iv = buf.subarray(0, 12);
            const data = buf.subarray(12);
            const plain = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv },
                await getCryptoKey(k),
                data
            );
            return await decompress(new Uint8Array(plain));
        } catch {
            return text; // Decryption failed — show ciphertext
        }
    }

    /**
     * BUG FIX: The original recursion could produce exponential chunk counts
     * for adversarial inputs. We now limit recursion depth.
     */
    async function encryptChunked(text, depth = 0) {
        if (depth > 10) {
            console.warn("[BB] Chunk depth exceeded, message too large");
            return null;
        }
        const result = await encrypt(text);
        if (result === null) return null;
        if (result.length <= CONFIG.MAX_ENCRYPTED_LEN) return [result];

        const mid = Math.floor(text.length / 2);
        let splitAt = text.lastIndexOf("\n", mid);
        if (splitAt <= 0) splitAt = text.lastIndexOf(" ", mid);
        if (splitAt <= 0) splitAt = mid;

        const a = await encryptChunked(text.slice(0, splitAt).trim(), depth + 1);
        const b = await encryptChunked(text.slice(splitAt).trim(), depth + 1);
        if (!a || !b) return null;
        return [...a, ...b];
    }

    // ─── 3. ECDH Handshake ────────────────────────────────────────────────────
    /**
     * SECURITY FIX: Handshake uses a mutex (`_hsBusy`) but the original code
     * had a race where two concurrent `_handleHS` calls could both pass the
     * check. We now use a proper async lock.
     *
     * SECURITY FIX: Private key in sessionStorage is still JWK plaintext.
     * In a userscript context there's no better option, but we add a comment
     * noting the limitation and clear keys promptly.
     */
    let _hsLock = Promise.resolve();

    function withHsLock(fn) {
        const prev = _hsLock;
        let resolve;
        _hsLock = new Promise((r) => (resolve = r));
        return prev
            .then(() => fn())
            .finally(() => resolve());
    }

    async function _hsNewPair() {
        return crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true,
            ["deriveBits"]
        );
    }

    async function _hsPubRaw(pubKey) {
        return new Uint8Array(await crypto.subtle.exportKey("raw", pubKey));
    }

    async function _hsPubImport(bytes) {
        // Validate P-256 uncompressed public key length (65 bytes: 0x04 || x || y)
        if (bytes.length !== 65 || bytes[0] !== 0x04) {
            throw new RangeError("Invalid P-256 public key format");
        }
        return crypto.subtle.importKey(
            "raw",
            bytes,
            { name: "ECDH", namedCurve: "P-256" },
            false,
            []
        );
    }

    /**
     * SECURITY FIX: Key derivation uses HKDF instead of raw SHA-256 for
     * better key separation. The original `hash[i] % chars.length` also
     * had modular bias — we now use rejection sampling.
     */
    async function _hsDeriveKeyStr(myPriv, theirPubBytes) {
        const theirPub = await _hsPubImport(theirPubBytes);
        const sharedBits = await crypto.subtle.deriveBits(
            { name: "ECDH", public: theirPub },
            myPriv,
            256
        );

        // Use HKDF for proper key derivation
        const ikm = await crypto.subtle.importKey(
            "raw",
            sharedBits,
            "HKDF",
            false,
            ["deriveBits"]
        );
        const derivedBits = new Uint8Array(
            await crypto.subtle.deriveBits(
                {
                    name: "HKDF",
                    hash: "SHA-256",
                    salt: new TextEncoder().encode("bale-bridge-v12"),
                    info: new TextEncoder().encode("aes-key"),
                },
                ikm,
                512 // Derive extra bits for rejection sampling
            )
        );

        // Rejection sampling to eliminate modular bias
        const chars = CONFIG.KEY_CHARS;
        const charLen = chars.length;
        const maxUnbiased = Math.floor(256 / charLen) * charLen;
        let keyStr = "";
        let idx = 0;

        while (keyStr.length < CONFIG.KEY_LENGTH) {
            if (idx >= derivedBits.length) {
                // Extremely unlikely with 64 bytes of input for 32 chars
                throw new Error("Insufficient entropy for key derivation");
            }
            if (derivedBits[idx] < maxUnbiased) {
                keyStr += chars[derivedBits[idx] % charLen];
            }
            idx++;
        }
        return keyStr;
    }

    // ─── Toast Notification ──────────────────────────────────────────────────
    function _showToast(msg, dur = CONFIG.TOAST_DURATION) {
        const el = document.createElement("div");
        el.textContent = msg; // textContent — safe from XSS
        Object.assign(el.style, {
            position: "fixed",
            bottom: "88px",
            left: "50%",
            transform: "translateX(-50%) translateY(16px)",
            background: "rgba(0,0,0,.85)",
            color: "#fff",
            padding: "12px 24px",
            borderRadius: "24px",
            fontSize: "14px",
            fontFamily: "inherit",
            zIndex: "9999999",
            opacity: "0",
            pointerEvents: "none",
            transition: "opacity .2s, transform .2s",
            whiteSpace: "nowrap",
            boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
        });
        document.body.appendChild(el);
        requestAnimationFrame(() => {
            el.style.opacity = "1";
            el.style.transform = "translateX(-50%) translateY(0)";
        });
        setTimeout(() => {
            el.style.opacity = "0";
            el.style.transform = "translateX(-50%) translateY(10px)";
            setTimeout(() => el.remove(), 300);
        }, dur);
    }

    // ─── Handshake Visualization (Safe DOM construction) ─────────────────────
    /**
     * SECURITY FIX: The original used innerHTML for handshake badges.
     * We now construct DOM nodes programmatically to prevent XSS.
     */
    function _visualizeHs(el, text) {
        el.textContent = ""; // Clear safely
        const badge = document.createElement("span");
        badge.textContent = text;
        Object.assign(badge.style, {
            display: "inline-block",
            margin: "2px 0",
            padding: "3px 8px",
            fontSize: "11px",
            fontWeight: "600",
            fontFamily: "monospace",
            color: "var(--color-primary-p-50,#00ab80)",
            background: "var(--color-neutrals-n-20,#f4f5f7)",
            borderRadius: "12px",
            border: "1px solid var(--color-primary-p-50,#00ab80)",
            opacity: "0.85",
            userSelect: "none",
        });
        el.appendChild(badge);
        el.style.display = "block";
        el.style.textAlign = "center";
        el._isDecrypted = true;
    }

    // ─── Hash Tracking (Bounded) ─────────────────────────────────────────────
    function markHashProcessed(chatId, hash) {
        const pKey = "bb_phs_" + chatId;
        try {
            const processed = JSON.parse(localStorage.getItem(pKey) || "[]");
            if (!Array.isArray(processed)) {
                localStorage.setItem(pKey, JSON.stringify([hash]));
                return;
            }
            if (!processed.includes(hash)) {
                processed.push(hash);
                while (processed.length > CONFIG.MAX_PROCESSED_HASHES) {
                    processed.shift();
                }
                localStorage.setItem(pKey, JSON.stringify(processed));
            }
        } catch {
            localStorage.setItem(pKey, JSON.stringify([hash]));
        }
    }

    function isHashProcessed(chatId, hash) {
        try {
            const arr = JSON.parse(localStorage.getItem("bb_phs_" + chatId) || "[]");
            return Array.isArray(arr) && arr.includes(hash);
        } catch {
            return false;
        }
    }

    function computeHash(str) {
        let h = 0;
        for (let i = 0; i < str.length; i++) {
            h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
        }
        return h;
    }

    function getTimestampBytes() {
        const ts = Math.floor(Date.now() / 1000);
        return new Uint8Array([
            (ts >>> 24) & 0xff,
            (ts >>> 16) & 0xff,
            (ts >>> 8) & 0xff,
            ts & 0xff,
        ]);
    }

    function readTimestamp(buf) {
        if (buf.length < 4) throw new RangeError("Timestamp buffer too short");
        return ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) >>> 0;
    }

    // ─── Raw Send Helper ─────────────────────────────────────────────────────
    const _textareaSetter = Object.getOwnPropertyDescriptor(
        HTMLTextAreaElement.prototype,
        "value"
    )?.set;

    const getRealInput = () =>
        document.getElementById("editable-message-text") ||
        document.getElementById("main-message-input");

    const isMobileInput = (el) => el?.tagName === "TEXTAREA";

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

        await new Promise((r) => setTimeout(r, CONFIG.SEND_DELAY_MS));

        let sendBtn =
            document.querySelector('[aria-label="send-button"]') ||
            document.querySelector(".RaTWwR");
        let sent = false;

        if (sendBtn) {
            // Try React props click first
            const btnPropsKey = Object.keys(sendBtn).find((k) =>
                k.startsWith("__reactProps$")
            );
            if (btnPropsKey) {
                const onClick = sendBtn[btnPropsKey]?.onClick;
                if (typeof onClick === "function") {
                    try {
                        onClick({
                            preventDefault: () => {},
                            stopPropagation: () => {},
                        });
                        sent = true;
                    } catch {
                        // Fall through to DOM events
                    }
                }
            }
            if (!sent) {
                for (const type of [
                    "mousedown",
                    "pointerdown",
                    "mouseup",
                    "pointerup",
                    "click",
                ]) {
                    sendBtn.dispatchEvent(
                        new MouseEvent(type, {
                            bubbles: true,
                            cancelable: true,
                            view: window,
                        })
                    );
                }
                sent = true;
            }
        }

        if (!sent && real) {
            real.dispatchEvent(
                new KeyboardEvent("keydown", {
                    bubbles: true,
                    cancelable: true,
                    key: "Enter",
                    code: "Enter",
                    keyCode: 13,
                    which: 13,
                })
            );
        }

        await new Promise((r) => setTimeout(r, CONFIG.POST_SEND_DELAY_MS));

        // Clear input after send
        if (mobile) {
            if (real.value !== "") {
                _textareaSetter?.call(real, "");
                real.dispatchEvent(new Event("input", { bubbles: true, cancelable: true }));
            }
        } else {
            if (real.innerText.trim() !== "") {
                real.focus();
                document.execCommand("selectAll", false, null);
                document.execCommand("delete", false, null);
                real.dispatchEvent(new Event("input", { bubbles: true, cancelable: true }));
            }
        }

        if (isEncryptionEnabled()) lockInput(real);
        isSyncing = wasSync;
    }

    // ─── Handshake Protocol ──────────────────────────────────────────────────
    async function startHandshake() {
        return withHsLock(async () => {
            try {
                const chatId = getChatId();
                const pair = await _hsNewPair();
                const pub = await _hsPubRaw(pair.publicKey);

                // NOTE: Storing private key as JWK in sessionStorage is not ideal,
                // but userscript context has no better secure storage option.
                // Key is cleared immediately after use.
                const exportedPriv = await crypto.subtle.exportKey("jwk", pair.privateKey);
                sessionStorage.setItem(
                    "bb_pending_hs_" + chatId,
                    JSON.stringify(exportedPriv)
                );

                const payload = new Uint8Array(1 + 4 + pub.length);
                payload[0] = CONFIG.HS_TYPE_REQUEST;
                payload.set(getTimestampBytes(), 1);
                payload.set(pub, 5);

                const b64 = btoa(String.fromCharCode.apply(null, payload));
                const msg = CONFIG.HANDSHAKE_PREFIX + b64;

                markHashProcessed(chatId, computeHash(b64));
                await _sendRaw(msg);
                _showToast("⏳ Requesting secure bridge. Waiting for friend to accept...");
            } catch (e) {
                console.error("[BB] Bridge setup failed:", e);
                _showToast("❌ Bridge setup failed. Please try again.");
            }
        });
    }

    /**
     * SECURITY FIX: Accept button is built with DOM APIs, not innerHTML.
     */
    function renderAcceptButton(el, theirPub, msgHash, chatId) {
        el.textContent = "";
        el._isDecrypted = true;

        const container = document.createElement("div");
        Object.assign(container.style, {
            border: "2px solid var(--color-primary-p-50,#00ab80)",
            padding: "10px",
            borderRadius: "12px",
            background: "var(--color-neutrals-surface,#fff)",
            display: "inline-block",
            fontFamily: "inherit",
            margin: "4px 0",
        });

        const title = document.createElement("strong");
        title.textContent = "🛡️ Secure Bridge Request";
        Object.assign(title.style, {
            color: "var(--color-primary-p-50,#00ab80)",
            display: "block",
            marginBottom: "4px",
            fontSize: "14px",
        });

        const desc = document.createElement("span");
        desc.textContent = "Your friend wants to enable End-to-End Encryption.";
        Object.assign(desc.style, {
            fontSize: "12px",
            color: "var(--color-neutrals-n-500,#555)",
            display: "block",
            marginBottom: "8px",
        });

        const btn = document.createElement("button");
        btn.textContent = "Accept & Connect";
        btn.className = "bb-accept-hs-btn";
        Object.assign(btn.style, {
            background: "var(--color-primary-p-50,#00ab80)",
            color: "#fff",
            border: "none",
            padding: "6px 12px",
            borderRadius: "6px",
            cursor: "pointer",
            fontWeight: "bold",
            fontSize: "13px",
            transition: "background 0.2s",
        });

        btn.addEventListener("click", async (e) => {
            e.preventDefault();
            e.stopPropagation();
            btn.disabled = true;
            btn.textContent = "Connecting...";
            try {
                await withHsLock(async () => {
                    const pair = await _hsNewPair();
                    const myPub = await _hsPubRaw(pair.publicKey);
                    const key = await _hsDeriveKeyStr(pair.privateKey, theirPub);

                    saveChatSettings({ enabled: true, customKey: key });
                    syncInputVisibility();

                    const rPay = new Uint8Array(1 + 4 + myPub.length);
                    rPay[0] = CONFIG.HS_TYPE_RESPONSE;
                    rPay.set(getTimestampBytes(), 1);
                    rPay.set(myPub, 5);

                    const rB64 = btoa(String.fromCharCode.apply(null, rPay));
                    const rMsg = CONFIG.HANDSHAKE_PREFIX + rB64;

                    markHashProcessed(chatId, msgHash);
                    markHashProcessed(chatId, computeHash(rB64));

                    await _sendRaw(rMsg);
                    _visualizeHs(el, "✅ Bridge Accepted");
                    _showToast(
                        "🛡️ Bridge secured! Fingerprint: " + getSecurityFingerprint(),
                        7000
                    );
                });
            } catch (err) {
                console.error("[BB] Accept failed:", err);
                btn.disabled = false;
                btn.textContent = "Error! Try Again";
            }
        });

        container.appendChild(title);
        container.appendChild(desc);
        container.appendChild(btn);
        el.appendChild(container);
        el.style.display = "block";
    }

    async function _handleHS(b64, el) {
        const chatId = getChatId();
        const msgHash = computeHash(b64);

        if (isHashProcessed(chatId, msgHash)) {
            _visualizeHs(el, "🤝 Bridge Request Processed");
            return;
        }

        return withHsLock(async () => {
            // Re-check after acquiring lock (another concurrent call may have processed it)
            if (isHashProcessed(chatId, msgHash)) {
                _visualizeHs(el, "🤝 Bridge Request Processed");
                return;
            }

            try {
                // Validate base64 before decoding
                if (!/^[A-Za-z0-9+/=]+$/.test(b64)) {
                    _visualizeHs(el, "❌ Invalid handshake data");
                    return;
                }

                const binary = atob(b64);
                const raw = new Uint8Array(binary.length);
                for (let i = 0; i < binary.length; i++) raw[i] = binary.charCodeAt(i);

                // Validate minimum payload size: type(1) + timestamp(4) + pubkey(65) = 70
                if (raw.length < 70) {
                    _visualizeHs(el, "❌ Malformed handshake");
                    markHashProcessed(chatId, msgHash);
                    return;
                }

                const type = raw[0];
                const ts = readTimestamp(raw.subarray(1, 5));
                const theirPub = raw.subarray(5);

                // Validate timestamp
                const now = Math.floor(Date.now() / 1000);
                const age = now - ts;
                if (age > CONFIG.HANDSHAKE_EXPIRY_SEC || age < -60) {
                    // Also reject future timestamps (clock skew tolerance: 60s)
                    markHashProcessed(chatId, msgHash);
                    _visualizeHs(el, "⌛ Expired Bridge Request");
                    return;
                }

                if (type === CONFIG.HS_TYPE_REQUEST) {
                    if (!el._hsBound) {
                        renderAcceptButton(el, theirPub, msgHash, chatId);
                        el._hsBound = true;
                    }
                } else if (type === CONFIG.HS_TYPE_RESPONSE) {
                    const privJwkStr = sessionStorage.getItem("bb_pending_hs_" + chatId);
                    if (!privJwkStr) {
                        markHashProcessed(chatId, msgHash);
                        _visualizeHs(el, "❌ Orphaned Bridge Accept");
                        return;
                    }

                    let privJwk;
                    try {
                        privJwk = JSON.parse(privJwkStr);
                    } catch {
                        markHashProcessed(chatId, msgHash);
                        _visualizeHs(el, "❌ Corrupt key data");
                        return;
                    }

                    const privKey = await crypto.subtle.importKey(
                        "jwk",
                        privJwk,
                        { name: "ECDH", namedCurve: "P-256" },
                        false,
                        ["deriveBits"]
                    );

                    const key = await _hsDeriveKeyStr(privKey, theirPub);

                    // Clear private key immediately after use
                    sessionStorage.removeItem("bb_pending_hs_" + chatId);

                    saveChatSettings({ enabled: true, customKey: key });
                    syncInputVisibility();

                    markHashProcessed(chatId, msgHash);
                    _visualizeHs(el, "✅ Bridge Completed");
                    _showToast(
                        "🛡️ Bridge secured! Verify Code: " + getSecurityFingerprint(),
                        7000
                    );

                    // Send verification message after short delay
                    setTimeout(async () => {
                        try {
                            const fp = getSecurityFingerprint();
                            const msg = [
                                "✅ Secure Bridge Established!",
                                "",
                                "🛡️ MITM Check: Both of you should see the exact identical code below:",
                                "",
                                "# " + fp,
                                "",
                                "If your friend sees a different code, someone is intercepting this chat.",
                            ].join("\n");
                            const successEnc = await encryptChunked(msg);
                            if (successEnc) {
                                for (const chunk of successEnc) await _sendRaw(chunk);
                            }
                        } catch (e) {
                            console.error("[BB] Verification message failed:", e);
                        }
                    }, 1000);
                } else {
                    markHashProcessed(chatId, msgHash);
                    _visualizeHs(el, "❌ Unknown handshake type");
                }
            } catch (e) {
                console.error("[BB] Handshake error:", e);
                _visualizeHs(el, "❌ Handshake failed");
            }
        });
    }

    // ─── 4. DOM Scanner & XSS-Safe Rendering ─────────────────────────────────
    const _ESC_MAP = Object.freeze({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
    });
    const escapeHtml = (s) => s.replace(/[&<>"']/g, (c) => _ESC_MAP[c]);

    function sanitizeUrl(url) {
        try {
            const parsed = new URL(url);
            if (parsed.protocol === "http:" || parsed.protocol === "https:") {
                return escapeHtml(parsed.href); // Use parsed.href to normalize
            }
        } catch {
            // Invalid URL
        }
        return "#";
    }

    /**
     * SECURITY: Markdown rendering. All user text is escaped before being
     * inserted into HTML templates. The rendering functions only add structural
     * HTML tags around already-escaped content.
     */
    function applyInlineMarkdown(escaped) {
        // Note: `escaped` is already HTML-escaped. The regex patterns only match
        // markdown syntax characters that survive escaping.
        return escaped
            .replace(
                /``([^`]+)``|`([^`]+)`/g,
                (_, a, b) =>
                    `<code style="background:var(--color-neutrals-n-20,#f4f5f7);border-radius:4px;padding:1px 5px;font-family:monospace;font-size:.92em">${a ?? b}</code>`
            )
            .replace(
                /\|\|(.+?)\|\|/g,
                (_, t) =>
                    `<span class="bb-spoiler" style="background:var(--color-neutrals-n-400,#42526e);color:transparent;border-radius:3px;padding:0 3px;cursor:pointer;user-select:none" title="Click to reveal">${t}</span>`
            )
            .replace(
                /\*\*\*(.+?)\*\*\*/g,
                (_, t) => `<strong><em>${t}</em></strong>`
            )
            .replace(/\*\*(.+?)\*\*/g, (_, t) => `<strong>${t}</strong>`)
            .replace(
                /(?<![_a-zA-Z0-9])__(.+?)__(?![_a-zA-Z0-9])/g,
                (_, t) => `<u>${t}</u>`
            )
            .replace(/\*([^*\n]+)\*/g, (_, t) => `<em>${t}</em>`)
            .replace(
                /(^|[^a-zA-Z0-9_])_([^_\n]+?)_(?=[^a-zA-Z0-9_]|$)/g,
                (_, p, t) => `${p}<em>${t}</em>`
            )
            .replace(/~~(.+?)~~/g, (_, t) => `<del>${t}</del>`)
            .replace(
                /\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g,
                (_, label, url) =>
                    `<a href="${sanitizeUrl(url)}" target="_blank" rel="noopener noreferrer" style="color:var(--color-primary-p-50,#00ab80);text-decoration:underline">${label}</a>`
            );
    }

    const _URL_RE = /https?:\/\/[^\s<>"{}|\\^`[\]]+/g;

    function processLine(line) {
        const escaped = escapeHtml(line);
        const parts = [];
        let last = 0;
        _URL_RE.lastIndex = 0;
        let m;
        while ((m = _URL_RE.exec(escaped)) !== null) {
            parts.push(applyInlineMarkdown(escaped.slice(last, m.index)));
            const safeUrl = sanitizeUrl(m[0]);
            parts.push(
                `<a href="${safeUrl}" target="_blank" rel="noopener noreferrer" style="color:var(--color-primary-p-50,#00ab80);text-decoration:underline;word-break:break-all">${safeUrl}</a>`
            );
            last = m.index + m[0].length;
        }
        parts.push(applyInlineMarkdown(escaped.slice(last)));
        return parts.join("");
    }

    function renderDecrypted(plain) {
        const lines = plain.split("\n");
        const out = [];
        let i = 0;
        const bidiBlock = (html) =>
            `<span dir="auto" class="bb-block">${html}</span>`;

        while (i < lines.length) {
            const line = lines[i];

            // Blockquotes
            if (line.startsWith("> ") || line === ">") {
                const qLines = [];
                while (
                    i < lines.length &&
                    (lines[i].startsWith("> ") || lines[i] === ">")
                ) {
                    qLines.push(lines[i++].replace(/^> ?/, ""));
                }
                out.push(
                    `<span dir="auto" class="bb-quote">${qLines
                        .map(processLine)
                        .join("<br>")}</span>`
                );
                continue;
            }

            // Unordered lists
            if (/^[-*+] /.test(line)) {
                const items = [];
                while (i < lines.length && /^[-*+] /.test(lines[i])) {
                    items.push(
                        `<li class="bb-li">${processLine(lines[i++].slice(2))}</li>`
                    );
                }
                out.push(`<ul dir="auto" class="bb-ul">${items.join("")}</ul>`);
                continue;
            }

            // Ordered lists
            if (/^\d+\. /.test(line)) {
                const items = [];
                while (i < lines.length && /^\d+\. /.test(lines[i])) {
                    items.push(
                        `<li class="bb-li">${processLine(
                            lines[i++].replace(/^\d+\. /, "")
                        )}</li>`
                    );
                }
                out.push(`<ol dir="auto" class="bb-ol">${items.join("")}</ol>`);
                continue;
            }

            // Headers
            const hm = line.match(/^(#{1,3}) (.+)/);
            if (hm) {
                const sz = ["1.25em", "1.1em", "1em"][
                    Math.min(hm[1].length, 3) - 1
                ];
                out.push(
                    bidiBlock(
                        `<span style="font-weight:700;font-size:${sz}">${processLine(
                            hm[2]
                        )}</span>`
                    )
                );
                i++;
                continue;
            }

            // Horizontal rules
            if (/^([-*_])\1{2,}$/.test(line.trim())) {
                out.push(`<span class="bb-hr"></span>`);
                i++;
                continue;
            }

            // Empty lines
            if (line.trim() === "") {
                out.push(`<span class="bb-spacer"></span>`);
                i++;
                continue;
            }

            // Regular text
            out.push(bidiBlock(processLine(line)));
            i++;
        }
        return out.join("");
    }

    // ─── Tree Scanner ────────────────────────────────────────────────────────
    /**
     * BUG FIX: The original scanner iterated a live HTMLCollection while
     * potentially mutating DOM. We snapshot to an array first.
     *
     * SECURITY: We skip elements that are part of our own UI to prevent
     * self-processing loops.
     */
    const SKIP_IDS = new Set([
        "secure-input-overlay",
        "secure-edit-overlay",
        "editable-message-text",
        "main-message-input",
        "bb-no-key-notice",
        "bale-bridge-menu",
        "bb-modal-overlay",
    ]);

    // Track in-flight decryption promises to prevent double-processing
    const _decryptionInFlight = new WeakSet();

    function scanTree(root) {
        // Snapshot live collection to avoid mutation issues
        const els = Array.from(root.getElementsByTagName("*"));
        for (let idx = 0, len = els.length; idx < len; idx++) {
            const el = els[idx];
            if (el._isDecrypted || _decryptionInFlight.has(el)) continue;
            if (SKIP_IDS.has(el.id)) continue;

            const text = el.textContent;
            if (text.length <= 20) continue;

            const trimmed = text.trim();

            // Handshake messages
            const matchHs = trimmed.match(/^!!([A-Za-z0-9+/=]{40,})$/);
            if (matchHs) {
                // Skip if a child already contains the handshake text
                let childHas = false;
                for (const c of el.children) {
                    if (c.textContent.includes("!!")) {
                        childHas = true;
                        break;
                    }
                }
                if (childHas) continue;

                el._isDecrypted = true;
                _handleHS(matchHs[1], el).catch((e) =>
                    console.error("[BB] HS error:", e)
                );
                continue;
            }

            // Encrypted messages
            if (
                trimmed.startsWith(CONFIG.ENCRYPTED_PREFIX) &&
                trimmed.length > 20
            ) {
                // Skip if a child element contains the exact same text
                let childHas = false;
                for (const c of el.children) {
                    if (c.textContent.trim() === trimmed) {
                        childHas = true;
                        break;
                    }
                }
                if (childHas) continue;

                _decryptionInFlight.add(el);
                decrypt(trimmed)
                    .then((plain) => {
                        if (plain !== trimmed) {
                            if (!el._bbOverflowSet) {
                                Object.assign(el.style, {
                                    overflow: "hidden",
                                    overflowWrap: "anywhere",
                                    wordBreak: "break-word",
                                    maxWidth: "100%",
                                });
                                el.classList.add("bb-msg-container");
                                el._bbOverflowSet = true;
                            }

                            // Build decrypted content
                            // SECURITY: renderDecrypted uses escapeHtml on all user text
                            const rendered = renderDecrypted(plain);

                            // Build the "encrypted" badge with copy button safely
                            const badgeHtml = `<span style="display:inline-block;font-size:9px;opacity:0.5;letter-spacing:0.02em;font-style:italic;margin-inline-start:5px;vertical-align:middle;line-height:1;white-space:nowrap">
                                🔒 encrypted
                                <span class="bb-copy-btn" title="Copy decrypted message" style="cursor:pointer;margin-inline-start:4px;font-size:11px;font-style:normal;transition:opacity 0.2s;">📋</span>
                            </span>`;

                            el.innerHTML = rendered + badgeHtml;
                            el.style.color = "inherit";
                            el._isDecrypted = true;

                            const copyBtn = el.querySelector(".bb-copy-btn");
                            if (copyBtn) {
                                copyBtn.addEventListener("click", (e) => {
                                    e.preventDefault();
                                    e.stopPropagation();
                                    navigator.clipboard
                                        .writeText(plain)
                                        .then(() => {
                                            copyBtn.textContent = "✅";
                                            setTimeout(
                                                () => (copyBtn.textContent = "📋"),
                                                1500
                                            );
                                        })
                                        .catch(() => {
                                            // Clipboard API may not be available
                                            _showToast("Failed to copy", 2000);
                                        });
                                });
                            }
                        }
                    })
                    .catch((e) => console.error("[BB] Decrypt error:", e))
                    .finally(() => {
                        _decryptionInFlight.delete(el);
                    });
            }
        }
    }

    // ─── 5. Input Helpers & UI Styles ─────────────────────────────────────────
    // Spoiler click handler (delegated)
    document.addEventListener(
        "click",
        (e) => {
            const sp = e.target.closest(".bb-spoiler");
            if (!sp) return;
            sp.style.color = "inherit";
            sp.style.background = "var(--color-neutrals-n-40,#dfe1e6)";
        },
        true
    );

    // Inject styles via a single style element
    const styleEl = document.createElement("style");
    styleEl.textContent = `
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

        .bb-block{display:block;unicode-bidi:plaintext}
        .bb-quote{display:block;border-inline-start:3px solid var(--color-primary-p-50,#00ab80);padding:2px 10px;margin:2px 0;font-style:italic;opacity:.9;unicode-bidi:plaintext}
        .bb-ul{margin:4px 0;padding-inline-start:22px;list-style:disc;unicode-bidi:plaintext}
        .bb-ol{margin:4px 0;padding-inline-start:22px;list-style:decimal;unicode-bidi:plaintext}
        .bb-li{margin:2px 0;padding-inline-start:2px}
        .bb-hr{display:block;border-top:1px solid var(--color-neutrals-n-100,#ccc);margin:6px 0}
        .bb-spacer{display:block;height:0.4em}

        .BAsWs0 .bb-block,.MRlMpm .bb-block,.dialog-item-content .bb-block,.aqFHpt .bb-block,
        .BAsWs0 .bb-quote,.MRlMpm .bb-quote,.dialog-item-content .bb-quote,.aqFHpt .bb-quote,
        .BAsWs0 .bb-ul,.MRlMpm .bb-ul,.dialog-item-content .bb-ul,.aqFHpt .bb-ul,
        .BAsWs0 .bb-ol,.MRlMpm .bb-ol,.dialog-item-content .bb-ol,.aqFHpt .bb-ol,
        .BAsWs0 .bb-li,.MRlMpm .bb-li,.dialog-item-content .bb-li,.aqFHpt .bb-li{
            display:inline!important;margin:0!important;padding:0!important;border:none!important
        }
        .BAsWs0 .bb-spacer,.MRlMpm .bb-spacer,.dialog-item-content .bb-spacer,.aqFHpt .bb-spacer,
        .BAsWs0 .bb-hr,.MRlMpm .bb-hr,.dialog-item-content .bb-hr,.aqFHpt .bb-hr,
        .BAsWs0 .bb-copy-btn,.MRlMpm .bb-copy-btn,.dialog-item-content .bb-copy-btn,.aqFHpt .bb-copy-btn{
            display:none!important
        }
        .bb-copy-btn:hover{opacity:1!important}
        .BAsWs0 .bb-li::after,.MRlMpm .bb-li::after,.dialog-item-content .bb-li::after,.aqFHpt .bb-li::after{
            content:" \\00a0•\\00a0 "
        }
        .BAsWs0 .bb-msg-container,.MRlMpm .bb-msg-container,.dialog-item-content .bb-msg-container,.aqFHpt .bb-msg-container{
            display:-webkit-box!important;-webkit-line-clamp:2!important;-webkit-box-orient:vertical!important;white-space:normal!important
        }
    `;
    document.head.appendChild(styleEl);

    // ─── 6. Context Menu (Safe DOM construction) ──────────────────────────────
    const popupMenu = document.createElement("div");
    popupMenu.id = "bale-bridge-menu";

    const menuEnc = document.createElement("div");
    menuEnc.className = "bale-menu-item";
    menuEnc.textContent = "🔒 Send Encrypted";
    menuEnc.addEventListener("click", () => {
        popupMenu.style.display = "none";
        window._bbSend?.(true);
    });

    const menuPlain = document.createElement("div");
    menuPlain.className = "bale-menu-item";
    menuPlain.textContent = "⚠️ Send Unencrypted";
    menuPlain.addEventListener("click", () => {
        popupMenu.style.display = "none";
        window._bbSend?.(false);
    });

    popupMenu.appendChild(menuEnc);
    popupMenu.appendChild(menuPlain);
    document.body.appendChild(popupMenu);

    const showMenu = (x, y) => {
        Object.assign(popupMenu.style, {
            display: "flex",
            left: Math.min(x, innerWidth - 210) + "px",
            top: Math.min(y, innerHeight - 120) + "px",
        });
    };

    document.addEventListener("click", (e) => {
        if (!popupMenu.contains(e.target)) popupMenu.style.display = "none";
    });

    // ─── 7. Settings Modal (Safe DOM construction) ────────────────────────────
    function openSettingsModal() {
        document.getElementById("bb-modal-overlay")?.remove();
        const s = getChatSettings();

        const fp =
            s.enabled && s.customKey && s.customKey.length === CONFIG.KEY_LENGTH
                ? s.customKey.substring(0, 5).toUpperCase()
                : "N/A";

        // Build modal with DOM APIs
        const overlay = document.createElement("div");
        overlay.id = "bb-modal-overlay";

        const card = document.createElement("div");
        card.id = "bb-modal-card";

        // Title
        const title = document.createElement("h3");
        title.className = "bb-modal-title";
        title.textContent = "Shield Settings 🛡️";

        // Description
        const desc = document.createElement("p");
        desc.className = "bb-modal-desc";
        desc.textContent =
            "Configure encryption for this chat. When enabled, a 32-character key is required.";

        // Enable checkbox
        const enableLabel = document.createElement("label");
        enableLabel.className = "bb-toggle-lbl";
        const enableCb = document.createElement("input");
        enableCb.type = "checkbox";
        enableCb.id = "bb-enable-enc";
        enableCb.checked = s.enabled;
        Object.assign(enableCb.style, {
            width: "16px",
            height: "16px",
            accentColor: "var(--color-primary-p-50,#00ab80)",
        });
        const enableText = document.createElement("span");
        enableText.textContent = "Enable Encryption Here";
        enableLabel.appendChild(enableCb);
        enableLabel.appendChild(enableText);

        // Key section
        const keySection = document.createElement("div");
        keySection.id = "bb-key-section";
        Object.assign(keySection.style, {
            marginTop: "16px",
            borderTop: "1px solid var(--color-neutrals-n-20,#f4f5f7)",
            paddingTop: "16px",
        });

        // Key label
        const keyLabel = document.createElement("label");
        Object.assign(keyLabel.style, {
            fontSize: "12px",
            color: "var(--color-neutrals-n-500,#151515)",
            fontWeight: "600",
        });
        keyLabel.textContent = "Encryption Key ";
        const required = document.createElement("span");
        required.style.color = "#d32f2f";
        required.textContent = "*";
        keyLabel.appendChild(required);

        // Key row
        const keyRow = document.createElement("div");
        keyRow.className = "bb-key-row";

        const keyInput = document.createElement("input");
        keyInput.type = "password";
        keyInput.id = "bb-custom-key";
        keyInput.className = "bb-input";
        keyInput.placeholder = "Enter exactly 32 characters…";
        keyInput.maxLength = 32;
        keyInput.value = s.customKey || "";

        const visBtn = document.createElement("button");
        visBtn.className = "bb-icon-btn";
        visBtn.title = "Show / hide key";
        visBtn.textContent = "👁";

        const copyBtn = document.createElement("button");
        copyBtn.className = "bb-icon-btn";
        copyBtn.title = "Copy key";
        copyBtn.textContent = "📋";

        keyRow.appendChild(keyInput);
        keyRow.appendChild(visBtn);
        keyRow.appendChild(copyBtn);

        // Key tools
        const keyTools = document.createElement("div");
        keyTools.className = "bb-key-tools";

        const genBtn = document.createElement("button");
        genBtn.className = "bb-tool-btn";
        genBtn.textContent = "⚡ Random Key";

        const hsBtn = document.createElement("button");
        hsBtn.className = "bb-tool-btn";
        hsBtn.textContent = "🤝 Auto Bridge";
        Object.assign(hsBtn.style, {
            borderColor: "var(--color-primary-p-50,#00ab80)",
            color: "var(--color-primary-p-50,#00ab80)",
        });

        keyTools.appendChild(genBtn);
        keyTools.appendChild(hsBtn);

        // Key meta
        const keyMeta = document.createElement("div");
        keyMeta.className = "bb-key-meta";
        keyMeta.style.marginTop = "10px";

        const errorEl = document.createElement("span");
        errorEl.className = "bb-key-error";
        errorEl.style.cssText = "color:#d32f2f;font-weight:500;";

        const fpContainer = document.createElement("span");
        fpContainer.style.cssText =
            "font-size:11px;color:var(--color-neutrals-n-500,#555);";
        fpContainer.textContent = "Fingerprint: ";
        const fpEl = document.createElement("strong");
        fpEl.style.cssText =
            "font-family:monospace;color:var(--color-primary-p-50,#00ab80);";
        fpEl.textContent = fp;
        fpContainer.appendChild(fpEl);

        keyMeta.appendChild(errorEl);
        keyMeta.appendChild(fpContainer);

        keySection.appendChild(keyLabel);
        keySection.appendChild(keyRow);
        keySection.appendChild(keyTools);
        keySection.appendChild(keyMeta);

        // Actions
        const actions = document.createElement("div");
        actions.className = "bb-actions";

        const cancelBtn = document.createElement("button");
        cancelBtn.className = "bb-btn bb-btn-cancel";
        cancelBtn.textContent = "Cancel";

        const saveBtn = document.createElement("button");
        saveBtn.className = "bb-btn bb-btn-save";
        saveBtn.textContent = "Save";

        actions.appendChild(cancelBtn);
        actions.appendChild(saveBtn);

        // Assemble card
        card.appendChild(title);
        card.appendChild(desc);
        card.appendChild(enableLabel);
        card.appendChild(keySection);
        card.appendChild(actions);
        overlay.appendChild(card);
        document.body.appendChild(overlay);

        // Validation logic
        const validate = () => {
            const val = keyInput.value;
            const len = val.length;
            const enabled = enableCb.checked;

            keySection.style.display = enabled ? "" : "none";
            fpEl.textContent =
                len === CONFIG.KEY_LENGTH
                    ? val.substring(0, 5).toUpperCase()
                    : "N/A";

            if (!enabled) {
                errorEl.textContent = "";
                saveBtn.disabled = false;
                return;
            }
            if (len === 0) {
                errorEl.textContent = "Key required.";
                saveBtn.disabled = true;
            } else if (len !== CONFIG.KEY_LENGTH) {
                errorEl.textContent = `Must be ${CONFIG.KEY_LENGTH} chars (${len}).`;
                saveBtn.disabled = true;
            } else {
                errorEl.textContent = "";
                saveBtn.disabled = false;
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
            navigator.clipboard
                .writeText(keyInput.value)
                .then(() => {
                    copyBtn.textContent = "✅";
                    copyBtn.classList.add("copied");
                    setTimeout(() => {
                        copyBtn.textContent = "📋";
                        copyBtn.classList.remove("copied");
                    }, 1500);
                })
                .catch(() => _showToast("Failed to copy", 2000));
        });

        genBtn.addEventListener("click", () => {
            keyInput.value = generateKey();
            keyInput.type = "text";
            visBtn.textContent = "🙈";
            validate();
        });

        hsBtn.addEventListener("click", () => {
            overlay.remove();
            startHandshake();
        });

        cancelBtn.addEventListener("click", () => overlay.remove());

        saveBtn.addEventListener("click", () => {
            if (saveBtn.disabled) return;
            try {
                saveChatSettings({
                    enabled: enableCb.checked,
                    customKey: keyInput.value,
                });
            } catch (e) {
                _showToast("Failed to save: " + e.message, 3000);
                return;
            }
            overlay.remove();
            syncInputVisibility();
        });

        // Close on overlay click (not card)
        overlay.addEventListener("click", (e) => {
            if (e.target === overlay) overlay.remove();
        });
    }

    // ─── 8. Secure Input & Shield Button ──────────────────────────────────────
    let isSending = false;
    let lastHasText = false;
    let isSyncing = false;

    const lockInput = (el) =>
        Object.assign(el.style, {
            position: "absolute",
            opacity: "0",
            pointerEvents: "none",
            height: "0px",
            width: "0px",
            overflow: "hidden",
            zIndex: "-9999",
        });

    const unlockInput = (el) => {
        el.style.position = "";
        el.style.opacity = "1";
        el.style.pointerEvents = "auto";
        el.style.height = "";
        el.style.width = "100%";
        el.style.overflow = "auto";
        el.style.zIndex = "";
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
        if (!wrapper) return;

        const emojiBtn =
            document.querySelector('[aria-label="emoji-icon"]') ||
            document.querySelector(".MmBErq");

        if (emojiBtn && isEncryptionEnabled()) emojiBtn.style.display = "none";
        else if (emojiBtn) emojiBtn.style.display = "";

        // Create shield button if not exists
        if (emojiBtn && !document.getElementById("bb-settings-btn")) {
            const shieldBtn = document.createElement("div");
            shieldBtn.id = "bb-settings-btn";
            shieldBtn.className = emojiBtn.className;
            shieldBtn.setAttribute("role", "button");
            shieldBtn.setAttribute("tabindex", "0");
            shieldBtn.setAttribute("aria-label", "Encryption settings");
            Object.assign(shieldBtn.style, {
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                cursor: "pointer",
                transition: "color .2s",
            });

            const iconWrap = document.createElement("div");
            Object.assign(iconWrap.style, {
                borderRadius: "50%",
                lineHeight: "0",
                position: "relative",
            });
            iconWrap.innerHTML = `<svg width="24" height="24" fill="currentColor" viewBox="0 0 24 24"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>`;
            shieldBtn.appendChild(iconWrap);

            shieldBtn.addEventListener("click", openSettingsModal);
            shieldBtn.addEventListener("keydown", (e) => {
                if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    openSettingsModal();
                }
            });

            emojiBtn.parentElement.insertBefore(shieldBtn, emojiBtn);
        }

        // Create no-key notice if not exists
        if (!document.getElementById("bb-no-key-notice")) {
            const notice = document.createElement("div");
            notice.id = "bb-no-key-notice";

            const iconDiv = document.createElement("div");
            iconDiv.className = "bb-notice-icon";
            iconDiv.textContent = "⚠️";

            const bodyDiv = document.createElement("div");
            bodyDiv.className = "bb-notice-body";

            const strongEl = document.createElement("strong");
            strongEl.textContent =
                "Encryption key not set — sending is blocked.";
            bodyDiv.appendChild(strongEl);
            bodyDiv.appendChild(
                document.createTextNode(
                    " Tap the 🔒 lock button to establish a secure session."
                )
            );
            bodyDiv.appendChild(document.createElement("br"));

            const noticeBtn = document.createElement("button");
            noticeBtn.className = "bb-notice-btn";
            noticeBtn.textContent = "🛡 Set Encryption Key";
            noticeBtn.addEventListener("click", openSettingsModal);
            bodyDiv.appendChild(noticeBtn);

            notice.appendChild(iconDiv);
            notice.appendChild(bodyDiv);
            wrapper.insertBefore(notice, realInput);
        }

        // If secure overlay already exists, just sync
        const existingOverlay = document.getElementById("secure-input-overlay");
        if (existingOverlay) {
            window._bbSend = existingOverlay._triggerSend;
            syncInputVisibility();
            return;
        }

        // Hijack real input to prevent plaintext entry
        if (!realInput._hasStrictHijack) {
            realInput._hasStrictHijack = true;
            realInput.addEventListener("focus", () => {
                if (!isSyncing && isEncryptionEnabled()) {
                    realInput.blur();
                    document.getElementById("secure-input-overlay")?.focus();
                }
            });
            for (const evt of ["keydown", "keypress", "keyup", "paste", "drop"]) {
                realInput.addEventListener(
                    evt,
                    (e) => {
                        if (!isSyncing && isEncryptionEnabled()) {
                            e.preventDefault();
                            e.stopPropagation();
                        }
                    },
                    true
                );
            }
        }

        // Create secure input overlay
        let secureInput;
        if (mobile) {
            secureInput = document.createElement("textarea");
            secureInput.dir = "auto";
            secureInput.placeholder = "🔒 پیام امن...";
            secureInput.rows = 1;
            secureInput.addEventListener("input", () => {
                secureInput.style.height = "auto";
                secureInput.style.height =
                    Math.min(secureInput.scrollHeight, 150) + "px";
            });
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

        const getText = () =>
            mobile ? secureInput.value.trim() : secureInput.innerText.trim();
        const setText = (v) => {
            if (mobile) secureInput.value = v;
            else secureInput.innerText = v;
        };

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
                if (
                    sel.rangeCount > 0 &&
                    secureInput.contains(
                        sel.getRangeAt(0).commonAncestorContainer
                    )
                ) {
                    marker = document.createElement("span");
                    marker.id = "bb-caret-marker";
                    sel.getRangeAt(0).insertNode(marker);
                }

                realInput.focus();
                document.execCommand("selectAll", false, null);
                if (hasText) {
                    document.execCommand("insertText", false, " ");
                } else {
                    document.execCommand("delete", false, null);
                }
                realInput.dispatchEvent(
                    new Event("input", { bubbles: true, cancelable: true })
                );
                secureInput.focus();

                if (marker && marker.parentNode) {
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

        const triggerSend = async (doEncrypt = true) => {
            if (isSending) return;
            const text = getText();
            if (!text) return;

            if (doEncrypt) {
                if (!getActiveKey()) {
                    openSettingsModal();
                    return;
                }
                isSending = true;
                setText("🔒 Encrypting...");
                try {
                    const chunks = await encryptChunked(text);
                    if (!chunks) {
                        setText(text);
                        openSettingsModal();
                        return;
                    }
                    for (const chunk of chunks) await _sendRaw(chunk);
                    setText("");
                    lastHasText = false;
                    secureInput.focus();
                } catch (e) {
                    console.error("[BB] Send failed:", e);
                    setText(text);
                    _showToast("Send failed! Check console for details.", 3000);
                } finally {
                    isSending = false;
                }
                return;
            }

            // Unencrypted send
            if (
                !confirm(
                    "⚠️ You are about to send this message WITHOUT encryption.\n\nAre you sure?"
                )
            ) {
                return;
            }
            isSending = true;
            setText("🌐 Sending...");
            try {
                await _sendRaw(text);
                setText("");
                lastHasText = false;
                secureInput.focus();
            } catch (e) {
                console.error("[BB] Unencrypted send failed:", e);
                setText(text);
                _showToast("Send failed!", 3000);
            } finally {
                isSending = false;
            }
        };

        secureInput._triggerSend = triggerSend;
        window._bbSend = triggerSend;

        secureInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                e.stopPropagation();
                triggerSend(true);
            }
        });

        syncInputVisibility();
    }

    // ─── 8b. Secure Edit / Caption Input ─────────────────────────────────────
    function ensureEditInput() {
        const real = document.querySelector(
            'textarea[aria-label="File Description"]'
        );
        if (!real || real._bbEditHooked) return;
        real._bbEditHooked = true;

        const secureEdit = document.createElement("textarea");
        secureEdit.id = "secure-edit-overlay";
        secureEdit.className = real.className;
        secureEdit.placeholder = "🔒 " + (real.placeholder || "ویرایش امن...");
        secureEdit.dir = real.dir || "auto";
        secureEdit.style.cssText = real.style.cssText;
        secureEdit.addEventListener("input", () => {
            secureEdit.style.height = "auto";
            secureEdit.style.height =
                Math.min(secureEdit.scrollHeight, 150) + "px";
        });

        real.parentElement.insertBefore(secureEdit, real);
        lockInput(real);
        secureEdit.focus();

        const existing = real.value.trim();
        _textareaSetter?.call(real, "");
        real.dispatchEvent(new Event("input", { bubbles: true }));
        if (existing.startsWith(CONFIG.ENCRYPTED_PREFIX)) {
            decrypt(existing)
                .then((p) => {
                    if (p !== existing) secureEdit.value = p;
                })
                .catch(() => {});
        } else {
            secureEdit.value = existing;
        }

        const encryptAndForward = async (btn) => {
            if (secureEdit._isSending) return;
            const text = secureEdit.value.trim();
            if (!text) return;
            if (!getActiveKey()) {
                openSettingsModal();
                return;
            }
            secureEdit._isSending = true;
            const prev = secureEdit.value;
            secureEdit.value = "🔒 Encrypting...";
            try {
                const out = await encrypt(text);
                if (!out) {
                    secureEdit.value = prev;
                    openSettingsModal();
                    return;
                }
                secureEdit.value = "";
                unlockInput(real);
                _textareaSetter?.call(real, out);
                real.dispatchEvent(new Event("input", { bubbles: true }));
                real.dispatchEvent(new Event("change", { bubbles: true }));
                await new Promise((r) => setTimeout(r, CONFIG.SEND_DELAY_MS));

                // Click the confirm button
                const btnPropsKey = Object.keys(btn).find((k) =>
                    k.startsWith("__reactProps$")
                );
                if (btnPropsKey && typeof btn[btnPropsKey]?.onClick === "function") {
                    btn[btnPropsKey].onClick({
                        preventDefault: () => {},
                        stopPropagation: () => {},
                    });
                } else {
                    for (const type of [
                        "mousedown",
                        "pointerdown",
                        "mouseup",
                        "pointerup",
                        "click",
                    ]) {
                        btn.dispatchEvent(
                            new MouseEvent(type, {
                                bubbles: true,
                                cancelable: true,
                                view: window,
                            })
                        );
                    }
                }
            } catch (e) {
                console.error("[BB] Edit encryption failed:", e);
                secureEdit.value = prev;
                _showToast("Encryption failed!", 3000);
            } finally {
                secureEdit._isSending = false;
            }
        };

        const isConfirmBtn = (t) =>
            t.closest('[data-testid="confirm-button"]') ||
            (t.closest('button[aria-label="Send"]') &&
                !t.closest("#chat_footer"));

        const editClickHandler = (e) => {
            if (!e.isTrusted) return;
            const btn = isConfirmBtn(e.target);
            if (!btn || !secureEdit.value.trim()) return;
            if (secureEdit._isSending) {
                e.preventDefault();
                e.stopPropagation();
                return;
            }
            e.preventDefault();
            e.stopPropagation();
            encryptAndForward(btn);
        };

        document.addEventListener("click", editClickHandler, true);
        document.addEventListener("mousedown", editClickHandler, true);

        // Cleanup observer: remove handlers when edit overlay is removed from DOM
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
                e.preventDefault();
                e.stopPropagation();
                const btn =
                    document.querySelector('[data-testid="confirm-button"]') ||
                    document.querySelector(
                        'button[aria-label="Send"]:not(#chat_footer button)'
                    );
                if (btn) encryptAndForward(btn);
            }
        });
    }

    // ─── 9. Send Button Event Interception ────────────────────────────────────
    const getSecureText = () => {
        const si = document.getElementById("secure-input-overlay");
        return si
            ? si.tagName === "TEXTAREA"
                ? si.value.trim()
                : si.innerText.trim()
            : "";
    };

    const isSendBtn = (t) =>
        !!(
            t.closest('[aria-label="send-button"]') ||
            t.closest(".RaTWwR")
        );

    let touchTimer = null;
    let isLongTouch = false;

    // Desktop Events
    for (const evt of ["mousedown", "mouseup", "click", "pointerdown", "pointerup"]) {
        document.addEventListener(
            evt,
            (e) => {
                if (!e.isTrusted) return; // Allow programmatic events
                if (isSending && isSendBtn(e.target)) {
                    e.preventDefault();
                    e.stopPropagation();
                    return;
                }
                if (
                    !isSendBtn(e.target) ||
                    !isEncryptionEnabled() ||
                    !getSecureText()
                ) {
                    return;
                }

                e.preventDefault();
                e.stopPropagation();

                if (evt === "click" && e.button === 0) {
                    window._bbSend?.(true);
                }
            },
            true
        );
    }

    // Mobile Touch Events
    document.addEventListener(
        "touchstart",
        (e) => {
            if (!e.isTrusted) return;
            if (isSending && isSendBtn(e.target)) {
                e.preventDefault();
                e.stopPropagation();
                return;
            }
            if (
                !isSendBtn(e.target) ||
                !isEncryptionEnabled() ||
                !getSecureText()
            ) {
                return;
            }

            e.preventDefault();
            e.stopPropagation();

            isLongTouch = false;
            if (touchTimer !== null) clearTimeout(touchTimer);

            touchTimer = setTimeout(() => {
                isLongTouch = true;
                if (e.touches && e.touches.length > 0) {
                    showMenu(e.touches[0].clientX, e.touches[0].clientY);
                }
            }, CONFIG.LONG_PRESS_MS);
        },
        { passive: false, capture: true }
    );

    document.addEventListener(
        "touchend",
        (e) => {
            if (!e.isTrusted) return;
            if (isSending && isSendBtn(e.target)) {
                e.preventDefault();
                e.stopPropagation();
                return;
            }
            if (
                !isSendBtn(e.target) ||
                !isEncryptionEnabled() ||
                !getSecureText()
            ) {
                return;
            }

            e.preventDefault();
            e.stopPropagation();

            if (touchTimer !== null) {
                clearTimeout(touchTimer);
                touchTimer = null;
            }
            if (!isLongTouch) {
                window._bbSend?.(true);
            }
        },
        { passive: false, capture: true }
    );

    document.addEventListener(
        "touchmove",
        (e) => {
            if (!e.isTrusted || !isSendBtn(e.target)) return;
            if (touchTimer !== null) {
                clearTimeout(touchTimer);
                touchTimer = null;
            }
            isLongTouch = true;
        },
        { passive: false, capture: true }
    );

    // Desktop Right Click Menu
    document.addEventListener(
        "contextmenu",
        (e) => {
            if (
                isSending ||
                !isSendBtn(e.target) ||
                !isEncryptionEnabled() ||
                !getSecureText()
            ) {
                return;
            }
            e.preventDefault();
            e.stopPropagation();
            showMenu(e.clientX, e.clientY);
        },
        true
    );

    // ─── 10. MutationObserver & SPA URL Tracker ───────────────────────────────
    let scanTO = null;
    let lastUrl = location.href;

    const observer = new MutationObserver(() => {
        if (scanTO !== null) clearTimeout(scanTO);
        scanTO = setTimeout(() => {
            scanTO = null;
            try {
                scanTree(document.body);
                ensureSecureInput();
                ensureEditInput();
                if (location.href !== lastUrl) {
                    lastUrl = location.href;
                    _settingsCache = null;
                    _settingsCacheId = null;
                    syncInputVisibility();
                }
            } catch (e) {
                console.error("[BB] Scan error:", e);
            }
        }, CONFIG.SCAN_DEBOUNCE_MS);
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true,
        characterData: true,
    });

    // Initial scan
    try {
        scanTree(document.body);
        ensureSecureInput();
        ensureEditInput();
    } catch (e) {
        console.error("[BB] Initial scan error:", e);
    }
})();
