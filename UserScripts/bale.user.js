// ==UserScript==
// @name         Bale Bridge Encryptor
// @namespace    http://tampermonkey.net/
// @version      17.4
// @description  E2E encryption overlay for Bale Web with ECDH key exchange.
// @author       You
// @match        *://web.bale.ai/*
// @match        *://*.bale.ai/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

(function(){
"use strict";

const CFG = Object.freeze({
    KEY_LEN:32, MAX_ENC:4000, TOAST_MS:4500, LONG_PRESS:400,
    SEND_DLY:60, POST_DLY:100, MAX_DEPTH:10, KCACHE:16,
    CHARS:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_+=~",
    B85:"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~",
    PFX_E:"@@", PFX_E2:"@@+", PFX_H:"!!", HS_EXP:86400, HS_CLEANUP:86400000
});

const P = Object.freeze({
    ac:"#7c8af6",acDim:"#636fcc",acSoft:"rgba(124,138,246,.10)",
    bg:"#0d1117",card:"#161b22",srf:"#1c2128",
    bdr:"#30363d",bdrLt:"#3d444d",
    tx:"#e6edf3",txD:"#8b949e",txM:"#484f58",
    err:"#f85149",wrn:"#d29922",wrnBg:"rgba(210,153,34,.10)",
    glass:"rgba(22,27,34,.88)",glassBdr:"rgba(240,246,252,.06)"
});

const _W = typeof unsafeWindow !== "undefined" ? unsafeWindow : window;
const _C = crypto, _S = crypto.subtle;

function u8(ab){ const v = new Uint8Array(ab), c = new Uint8Array(v.length); c.set(v); return c; }

const _wsSend = _W.WebSocket.prototype.send;
const _draftRx = /EditParameter[\s\S]*drafts_|drafts_[\s\S]*EditParameter/;
_W.WebSocket.prototype.send = function(d){
    try{
        if(typeof d === "string"){
            if(_draftRx.test(d)){console.log("[BL] BLOCKED draft");return;}
            if(d!=="{}"&&!d.includes('"handShake"'))console.log("[BL] WS OUT:",d.length>300?d.slice(0,300)+"…":d);
        }
    }catch(_){}
    return _wsSend.apply(this, arguments);
};

const _safeId = /^[a-zA-Z0-9_\-]+$/;
const chatType = () => { const p = location.pathname; if(p.startsWith("/group")||p.startsWith("/supergroup")) return "group"; if(p.startsWith("/channel")) return "channel"; const bar=document.querySelector('[aria-label="ChatAppBar"]'); if(bar&&bar.querySelector('[aria-label="ThreeUser-icon"]')) return "group"; return "dm"; };
const isGroup = () => chatType() === "group";
const getChatId = () => { const r = new URLSearchParams(location.search).get("uid") || location.pathname.split("/").pop() || "global"; return _safeId.test(r) ? r : "global"; };

let _scId = null, _sc = null;
const getS = () => {
    const id = getChatId();
    if(id === _scId && _sc) return _sc;
    try{ const o = JSON.parse(localStorage.getItem("bale_bridge_settings_" + id)); if(o && typeof o.enabled === "boolean" && typeof o.customKey === "string" && o.customKey.length <= CFG.KEY_LEN){ _sc = {enabled:o.enabled, customKey:o.customKey}; _scId = id; return _sc; } }catch(_){}
    _sc = {enabled:true, customKey:""}; _scId = id; return _sc;
};
const setS = s => { const id = getChatId(); _sc = {enabled:!!s.enabled, customKey:String(s.customKey||"")}; _scId = id; localStorage.setItem("bale_bridge_settings_"+id, JSON.stringify(_sc)); };
const activeKey = () => { const s = getS(); return s.enabled && s.customKey?.length === CFG.KEY_LEN ? s.customKey : null; };
const encOn = () => getS().enabled;

function toB64(buf){ let b = ""; const a = buf instanceof Uint8Array ? buf : new Uint8Array(buf); for(let i=0;i<a.byteLength;i++) b += String.fromCharCode(a[i]); return btoa(b).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,""); }
function fromB64(s){ let c = s.replace(/[^A-Za-z0-9\-_]/g,"").replace(/-/g,"+").replace(/_/g,"/"); c += "=".repeat((4-(c.length%4))%4); const b = atob(c), a = new Uint8Array(b.length); for(let i=0;i<b.length;i++) a[i]=b.charCodeAt(i); return a; }
function fromStdB64(s){ const c = s.replace(/[^A-Za-z0-9+/=]/g,""), b = atob(c), a = new Uint8Array(b.length); for(let i=0;i<b.length;i++) a[i]=b.charCodeAt(i); return a; }
function fromLegacyB64(s){ let c = s.replace(/[^A-Za-z0-9\-_.+/=]/g,"").replace(/-/g,"+").replace(/_/g,"/").replace(/\./g,"=").replace(/=+$/,""); c += "=".repeat((4-(c.length%4))%4); const b = atob(c), a = new Uint8Array(b.length); for(let i=0;i<b.length;i++) a[i]=b.charCodeAt(i); return a; }
function decodeB64Smart(s){ try{const r=fromB64(s);if(r.length>0)return r;}catch(_){} try{const r=fromLegacyB64(s);if(r.length>0)return r;}catch(_){} try{const r=fromStdB64(s);if(r.length>0)return r;}catch(_){} return null; }

const _kc = new Map();
async function getKey(k){ let c = _kc.get(k); if(c) return c; c = await _S.importKey("raw", new TextEncoder().encode(k), {name:"AES-GCM"}, false, ["encrypt","decrypt"]); if(_kc.size >= CFG.KCACHE) _kc.delete(_kc.keys().next().value); _kc.set(k,c); return c; }
function genKey(){ const c=CFG.CHARS,cl=c.length,mx=(cl*Math.floor(256/cl))|0,r=[]; let f=0; while(f<CFG.KEY_LEN){const b=new Uint8Array(64);_C.getRandomValues(b);for(let i=0;i<64&&f<CFG.KEY_LEN;i++)if(b[i]<mx)r[f++]=c[b[i]%cl];} return r.join(""); }

const B85=CFG.B85,B85D=new Uint8Array(128).fill(255); for(let i=0;i<85;i++) B85D[B85.charCodeAt(i)]=i;
function b85d(s){ const sl=s.length; if(!sl) return new Uint8Array(0); const fl=(sl/5)|0,rm=sl%5,est=fl*4+(rm?rm-1:0),o=new Uint8Array(est); let w=0; for(let i=0;i<sl;i+=5){const e=i+5<sl?i+5:sl,pd=5-(e-i);let a=0;for(let j=0;j<5;j++){const c=i+j<sl?s.charCodeAt(i+j):126;a=a*85+B85D[c];}const b=4-pd;if(b>=1)o[w++]=(a>>>24)&255;if(b>=2)o[w++]=(a>>>16)&255;if(b>=3)o[w++]=(a>>>8)&255;if(b>=4)o[w++]=a&255;} return o.subarray(0,w); }

async function cmp(t){ if(typeof CompressionStream==="undefined") return new TextEncoder().encode(t); const c=new CompressionStream("deflate"),w=c.writable.getWriter(); w.write(new TextEncoder().encode(t)); w.close(); return new Uint8Array(await new Response(c.readable).arrayBuffer()); }
async function dcmp(b){ if(typeof DecompressionStream==="undefined") return new TextDecoder().decode(b); try{const d=new DecompressionStream("deflate"),w=d.writable.getWriter();w.write(b);w.close();return new TextDecoder().decode(await new Response(d.readable).arrayBuffer());}catch(_){return new TextDecoder().decode(b);} }

async function enc(t){ const k=activeKey(); if(!k) return null; const iv=new Uint8Array(12); _C.getRandomValues(iv); const ct=u8(await _S.encrypt({name:"AES-GCM",iv},await getKey(k),await cmp(t))); const p=new Uint8Array(12+ct.length); p.set(iv); p.set(ct,12); return CFG.PFX_E2+toB64(p); }
async function dec(t){ if(!t.startsWith(CFG.PFX_E)) return t; const k=activeKey(); if(!k) return t; try{ let b; if(t.startsWith(CFG.PFX_E2)) b=decodeB64Smart(t.slice(3)); else b=b85d(t.slice(2).replace(/[^\x21-\x7E]/g,"")); if(!b||b.length<13) return t; return await dcmp(u8(await _S.decrypt({name:"AES-GCM",iv:b.subarray(0,12)},await getKey(k),b.subarray(12)))); }catch(_){return t;} }
async function encChunk(t,d=0){ if(d>CFG.MAX_DEPTH) return null; const r=await enc(t); if(!r) return null; if(r.length<=CFG.MAX_ENC) return [r]; const m=t.length>>1; let s=t.lastIndexOf("\n",m); if(s<=0) s=t.lastIndexOf(" ",m); if(s<=0) s=m; const a=await encChunk(t.slice(0,s).trim(),d+1),b=await encChunk(t.slice(s).trim(),d+1); return a&&b?[...a,...b]:null; }

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
        const rq=indexedDB.open("bale_bridge_db",2);
        rq.onupgradeneeded=e=>{const d=e.target.result; if(e.oldVersion<2){for(const n of["identity","contacts","handshakes"])if(d.objectStoreNames.contains(n))d.deleteObjectStore(n);} for(const[n,k]of[["identity","id"],["contacts","id"],["handshakes","nonce"]])if(!d.objectStoreNames.contains(n))d.createObjectStore(n,{keyPath:k});};
        rq.onsuccess=e=>{_db=e.target.result;res(_db);}; rq.onerror=()=>{_useMem=true;rej(rq.error);};
    });
}
async function dbOp(s,o,v){
    try{ const d=await getDB(); if(!d) throw 0; return new Promise((res,rej)=>{ const tx=d.transaction(s,o==="get"||o==="getAll"?"readonly":"readwrite"),st=tx.objectStore(s); let rq; if(o==="get")rq=st.get(v);else if(o==="put")rq=st.put(safeClone(v));else if(o==="del")rq=st.delete(v);else rq=st.getAll(); rq.onsuccess=()=>{try{res(rq.result!=null&&typeof rq.result==="object"?safeClone(rq.result):rq.result);}catch(_){res(rq.result);}}; rq.onerror=()=>rej(rq.error); });
    }catch(_){ _useMem=true; if(o==="get") return _memDB[s][v]?safeClone(_memDB[s][v]):undefined; if(o==="put"){_memDB[s][v.id||v.nonce]=safeClone(v);return v;} if(o==="del"){delete _memDB[s][v];return;} return Object.values(_memDB[s]).map(safeClone); }
}

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

function renderHS(el,text,cc,fp="",trust="",onAction=null,btnText="Accept & Connect"){
    const c=cc==="ac"?P.ac:cc==="wrn"?P.wrn:cc==="err"?P.err:P.txM;
    const bg=cc==="ac"?P.acSoft:cc==="wrn"?P.wrnBg:cc==="err"?"rgba(248,81,73,0.1)":"rgba(255,255,255,0.05)";
    let h=`<div class="bb-hs-widget" style="border:1px solid ${c};background:${bg}"><span class="bb-hs-title" style="color:${c};margin-bottom:${fp?"6px":"0"}">${esc(text)}</span>`;
    if(fp){ h+=`<div class="bb-hs-fp" style="color:${P.ac}">Fingerprint: ${esc(fp)}</div>`; const tc=trust.includes("\u26a0\ufe0f")?P.err:P.txD; h+=`<div style="color:${tc};font-weight:${trust.includes("\u26a0\ufe0f")?"700":"500"};margin-bottom:${onAction?"8px":"0"}">${esc(trust)}</div>`; }
    if(onAction) h+=`<button class="bb-hs-btn" style="background:${c};color:${P.bg}">${esc(btnText)}</button>`;
    h+="</div>"; el.innerHTML=h;
    if(onAction){ const btn=el.querySelector(".bb-hs-btn"); if(btn) btn.onclick=e=>{e.preventDefault();e.stopPropagation();btn.disabled=true;btn.innerText="Processing...";onAction();}; }
}

function tsBuf(){ const ts=Math.floor(Date.now()/1000); return new Uint8Array([(ts>>>24)&255,(ts>>>16)&255,(ts>>>8)&255,ts&255]); }

async function startBridge(){
    const id=await getMyId(), eph=await _S.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
    const ephPub=u8(await _S.exportKey("raw",eph.publicKey)),ephPriv=u8(await _S.exportKey("pkcs8",eph.privateKey));
    const nonce=new Uint8Array(16); _C.getRandomValues(nonce);
    const payload=concatBytes(new Uint8Array([1,1]),nonce,tsBuf(),id.pubRaw,ephPub);
    const sig=await ecSign(id.priv,payload), msg=concatBytes(payload,sig);
    const hsRec={nonce:toHex(nonce),chatId:getChatId(),role:"initiator",stage:"invited",ephPrivHex:toHex(ephPriv),ephPubHex:toHex(ephPub),initIdPubHex:toHex(id.pubRaw),theirIdentityKeyHex:null,createdAt:Date.now(),payloadHashHex:toHex(await digest(payload)),chatType:chatType()};
    if(isGroup()) hsRec.groupKey=genKey();
    await dbOp("handshakes","put",hsRec);
    await sendRaw(CFG.PFX_H+" "+toB64(msg)); toast(isGroup()?"Group bridge invite sent!":"Bridge invite sent!"); syncVis();
}

async function acceptBridge(data,el){
    const id=await getMyId(), eph=await _S.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
    const ephPub=u8(await _S.exportKey("raw",eph.publicKey)),ephPriv=u8(await _S.exportKey("pkcs8",eph.privateKey));
    const {sessionKey,hmacKeyBytes}=await deriveSymmetric(ephPriv,data.theirEphPubRaw,data.nonce,data.theirIdPubRaw,id.pubRaw,data.theirEphPubRaw,ephPub);
    const payload=concatBytes(new Uint8Array([1,2]),data.nonce,tsBuf(),data.payloadHash,id.pubRaw,ephPub);
    const sig=await ecSign(id.priv,payload), msg=concatBytes(payload,sig);
    await dbOp("handshakes","put",{nonce:toHex(data.nonce),chatId:getChatId(),role:"responder",stage:"accepted",derivedKey:sessionKey,hmacKeyHex:toHex(hmacKeyBytes),theirIdentityKeyHex:toHex(data.theirIdPubRaw),createdAt:Date.now()});
    renderHS(el,"\ud83d\udd04 Bridge accepted \u2014 waiting for confirmation","wrn");
    await sendRaw(CFG.PFX_H+" "+toB64(msg));
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
    setS({enabled:true,customKey:activeSessionKey});
    await dbOp("contacts","put",{id:data.cid,chatId:getChatId(),pubHex:toHex(data.theirIdPubRaw),lastSeen:Date.now()});
    delete hs.ephPrivHex; hs.derivedKey=sessionKey; hs.stage="confirmed"; await dbOp("handshakes","put",hs);
    syncVis(); await sendRaw(CFG.PFX_H+" "+toB64(msg)); renderHS(el,useGroupKey?"\u2705 Group bridge \u2014 key delivered":"\u2705 Bridge established","ac");
    setTimeout(async()=>{ const tc=await encChunk("\u2705 Bridge Established! Fingerprints: "+id.fp+" \u2194 "+data.fp); if(tc) for(const c of tc) await sendRaw(c); },CFG.SEND_DLY+400);
}

async function processConfirm(data,hs,el){
    const hmacKey=await _S.importKey("raw",fromHex(hs.hmacKeyHex),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
    const expected=u8(await _S.sign("HMAC",hmacKey,concatBytes(new Uint8Array([0x63,0x6f,0x6e,0x66]),fromHex(hs.nonce))));
    if(toHex(data.hmac)!==toHex(expected)) throw new Error("HMAC Verification Failed");
    setS({enabled:true,customKey:hs.derivedKey});
    const fpInfo=await getTrustInfo(fromHex(hs.theirIdentityKeyHex),getChatId());
    await dbOp("contacts","put",{id:fpInfo.cid,chatId:getChatId(),pubHex:hs.theirIdentityKeyHex,lastSeen:Date.now()});
    delete hs.hmacKeyHex; hs.stage="confirmed"; await dbOp("handshakes","put",hs);
    syncVis(); renderHS(el,"\u2705 Bridge established","ac");
}

async function processGroupConfirm(data,hs,el){
    const hmacKey=await _S.importKey("raw",fromHex(hs.hmacKeyHex),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
    const expected=u8(await _S.sign("HMAC",hmacKey,concatBytes(new Uint8Array([0x63,0x6f,0x6e,0x66]),fromHex(hs.nonce))));
    if(toHex(data.hmac)!==toHex(expected)) throw new Error("HMAC Verification Failed");
    const pairwiseAes=await _S.importKey("raw",new TextEncoder().encode(hs.derivedKey),{name:"AES-GCM"},false,["decrypt"]);
    const gkIv=data.encBlob.slice(0,12),gkCt=data.encBlob.slice(12);
    const groupKey=new TextDecoder().decode(u8(await _S.decrypt({name:"AES-GCM",iv:gkIv},pairwiseAes,gkCt)));
    if(groupKey.length!==CFG.KEY_LEN) throw new Error("Invalid group key length");
    setS({enabled:true,customKey:groupKey});
    const fpInfo=await getTrustInfo(fromHex(hs.theirIdentityKeyHex),getChatId());
    await dbOp("contacts","put",{id:fpInfo.cid,chatId:getChatId(),pubHex:hs.theirIdentityKeyHex,lastSeen:Date.now()});
    delete hs.hmacKeyHex; hs.stage="confirmed"; hs.groupKey=groupKey; await dbOp("handshakes","put",hs);
    syncVis(); renderHS(el,"\u2705 Group bridge established","ac");
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

function toast(m,d=CFG.TOAST_MS){ const el=document.createElement("div"); el.textContent=m; Object.assign(el.style,{position:"fixed",bottom:"80px",left:"50%",transform:"translateX(-50%) translateY(12px)",background:P.glass,color:P.tx,padding:"10px 22px",borderRadius:"12px",fontSize:"13px",fontFamily:"inherit",zIndex:"9999999",opacity:"0",pointerEvents:"none",transition:"opacity .2s,transform .2s",whiteSpace:"nowrap",border:`1px solid ${P.glassBdr}`,backdropFilter:"blur(16px)",WebkitBackdropFilter:"blur(16px)"}); document.body.appendChild(el); requestAnimationFrame(()=>{el.style.opacity="1";el.style.transform="translateX(-50%) translateY(0)";}); setTimeout(()=>{el.style.opacity="0";el.style.transform="translateX(-50%) translateY(8px)";setTimeout(()=>el.remove(),250);},d); }

const _esc={"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"};
const esc=s=>s.replace(/[&<>"']/g,c=>_esc[c]);
function safeUrl(u){ try{const p=new URL(u);if(p.protocol==="http:"||p.protocol==="https:")return esc(p.href);}catch(_){} return "#"; }

const _mdRules=[[/``([^`]+)``|`([^`]+)`/g,(_,a,b)=>`<code class="bb-code">${a??b}</code>`],[/\|\|(.+?)\|\|/g,(_,t)=>`<span class="bb-spoiler" title="Click">${t}</span>`],[/\*\*\*(.+?)\*\*\*/g,(_,t)=>`<b><i>${t}</i></b>`],[/\*\*(.+?)\*\*/g,(_,t)=>`<b>${t}</b>`],[/(?<![_a-zA-Z0-9])__(.+?)__(?![_a-zA-Z0-9])/g,(_,t)=>`<u>${t}</u>`],[/\*([^*\n]+)\*/g,(_,t)=>`<i>${t}</i>`],[/(^|[^a-zA-Z0-9_])_([^_\n]+?)_(?=[^a-zA-Z0-9_]|$)/g,(_,p,t)=>`${p}<i>${t}</i>`],[/~~(.+?)~~/g,(_,t)=>`<del>${t}</del>`],[/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g,(_,l,u)=>`<a href="${safeUrl(u)}" target="_blank" rel="noopener noreferrer" class="bb-link">${l}</a>`]];
function inlMd(s){ for(const[rx,fn]of _mdRules) s=s.replace(rx,fn); return s; }
const _urlRx=/https?:\/\/[^\s<>"{}|\\^`[\]]+/g;
function procLine(raw){ const parts=[]; let last=0; _urlRx.lastIndex=0; let m; while((m=_urlRx.exec(raw))!==null){parts.push(inlMd(esc(raw.slice(last,m.index))));const su=safeUrl(m[0]);parts.push(`<a href="${su}" target="_blank" rel="noopener noreferrer" class="bb-link" style="word-break:break-all">${su}</a>`);last=m.index+m[0].length;} parts.push(inlMd(esc(raw.slice(last)))); return parts.join(""); }

function renderDec(plain){
    const lines=plain.split("\n"),out=[]; let i=0;
    const blk=h=>`<span dir="auto" class="bb-block">${h}</span>`;
    while(i<lines.length){
        const L=lines[i];
        if(/^```/.test(L)){
            const lang=L.slice(3).trim(); i++;
            const code=[];
            while(i<lines.length&&!/^```\s*$/.test(lines[i])) code.push(lines[i++]);
            if(i<lines.length) i++;
            const langTag=lang?`<span class="bb-cblk-lang">${esc(lang)}</span>`:"";
            out.push(`<div class="bb-cblk">${langTag}<pre class="bb-cblk-pre"><code>${esc(code.join("\n"))}</code></pre><span class="bb-cblk-copy" title="Copy">\ud83d\udccb</span></div>`);
            continue;
        }
        if(L.startsWith("> ")||L===">"){const q=[];while(i<lines.length&&(lines[i].startsWith("> ")||lines[i]===">"))q.push(lines[i++].replace(/^> ?/,""));out.push(`<span dir="auto" class="bb-quote">${q.map(procLine).join("<br>")}</span>`);continue;}
        if(/^[-*+] /.test(L)){const it=[];while(i<lines.length&&/^[-*+] /.test(lines[i]))it.push(`<li class="bb-li">${procLine(lines[i++].slice(2))}</li>`);out.push(`<ul dir="auto" class="bb-ul">${it.join("")}</ul>`);continue;}
        if(/^\d+\. /.test(L)){const it=[];while(i<lines.length&&/^\d+\. /.test(lines[i]))it.push(`<li class="bb-li">${procLine(lines[i++].replace(/^\d+\. /,""))}</li>`);out.push(`<ol dir="auto" class="bb-ol">${it.join("")}</ol>`);continue;}
        const hm=L.match(/^(#{1,3}) (.+)/); if(hm){const sz=["1.2em","1.1em","1em"][Math.min(hm[1].length,3)-1];out.push(blk(`<span style="font-weight:700;font-size:${sz}">${procLine(hm[2])}</span>`));i++;continue;}
        if(/^([-*_])\1{2,}$/.test(L.trim())){out.push(`<span class="bb-hr"></span>`);i++;continue;}
        if(!L.trim()){out.push(`<span class="bb-spacer"></span>`);i++;continue;}
        out.push(blk(procLine(L))); i++;
    }
    return out.join("");
}

document.addEventListener("click",e=>{
    const s=e.target.closest(".bb-spoiler"); if(s){s.style.color="inherit";s.style.background=P.bdr;}
    const cb=e.target.closest(".bb-cblk-copy"); if(cb){e.preventDefault();e.stopPropagation();const pre=cb.closest(".bb-cblk")?.querySelector("code");if(pre)navigator.clipboard.writeText(pre.textContent).then(()=>{cb.textContent="\u2705";setTimeout(()=>cb.textContent="\ud83d\udccb",1200);}).catch(()=>{});}
},true);

const getReal=()=>document.getElementById("editable-message-text")||document.getElementById("main-message-input");

async function sendRaw(text){
    const real=getReal(); if(!real) return;
    const ws=isSyncing; isSyncing=true; unlockI(real);
    try{real.focus();const _sel=_W.getSelection();if(_sel){_sel.selectAllChildren(real);_sel.deleteFromDocument();}document.execCommand("insertText",false,text)||(() =>{real.innerText=text;real.dispatchEvent(new Event("input",{bubbles:true}));})();}catch(_){try{real.innerText=text;real.dispatchEvent(new Event("input",{bubbles:true}));}catch(_){}}
    await new Promise(r=>setTimeout(r,CFG.SEND_DLY));
    const btn=document.querySelector('[aria-label="send-button"]')||document.querySelector(".RaTWwR");
    let sent=false;
    if(btn){try{const u=btn.wrappedJSObject||btn,rk=Object.keys(u).find(k=>k.startsWith("__reactProps$")||k.startsWith("__reactFiber$"));if(rk){let n=u[rk];while(n&&!n.onClick&&!n.memoizedProps?.onClick)n=n.return;const fn=n?.memoizedProps?.onClick||n?.onClick||u[rk]?.onClick;if(typeof fn==="function"){fn({preventDefault(){},stopPropagation(){}});sent=true;}}}catch(_){} if(!sent){btn.click();sent=true;}}
    if(!sent) real.dispatchEvent(new KeyboardEvent("keydown",{bubbles:true,key:"Enter",code:"Enter",keyCode:13}));
    await new Promise(r=>setTimeout(r,CFG.POST_DLY));
    try{real.focus();const _sel2=_W.getSelection();if(_sel2){_sel2.selectAllChildren(real);_sel2.deleteFromDocument();}real.dispatchEvent(new Event("input",{bubbles:true}));}catch(_){real.innerText="";real.dispatchEvent(new Event("input",{bubbles:true}));}
    if(encOn()) lockI(real); isSyncing=ws;
}

const SKIP=new Set(["secure-input-overlay","editable-message-text","bb-no-key-notice","bale-bridge-menu","bb-modal-overlay"]);
const _infly=new WeakSet();
function stripInvisibles(s){return s.replace(/[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF\u00AD\u034F\u061C\u180E\uFFF9-\uFFFB]/g,"");}

function scanContainer(root){
    for(const el of root.querySelectorAll("span, div, p")){
        if(el._isDecrypted||_infly.has(el)||SKIP.has(el.id)) continue;
        const tc=el.textContent; if(!tc||tc.length<=10) continue;
        const ct=stripInvisibles(tc);
        const hi=ct.indexOf(CFG.PFX_H);
        if(hi!==-1){let mc=false;for(const c of el.children)if(stripInvisibles(c.textContent||"").includes(CFG.PFX_H)){mc=true;break;}if(mc)continue;const raw=ct.slice(hi+CFG.PFX_H.length).trim().split(/\s+/)[0].replace(/[^A-Za-z0-9\-_]/g,"");if(raw.length>50){_infly.add(el);hsLock(()=>handleHandshake(raw,el).catch(()=>{})).finally(()=>_infly.delete(el));continue;}}
        if(ct.includes(CFG.PFX_E)){let mc=false;for(const c of el.children)if(stripInvisibles(c.textContent||"").includes(CFG.PFX_E)){mc=true;break;}if(mc)continue;const ei=ct.indexOf(CFG.PFX_E);if(ei!==-1){const raw=ct.slice(ei);_infly.add(el);dec(raw).then(plain=>{if(plain!==raw){if(!el._bbO){Object.assign(el.style,{overflow:"hidden",overflowWrap:"anywhere",wordBreak:"break-word",maxWidth:"100%"});el.classList.add("bb-msg-container");el._bbO=true;}el.innerHTML=renderDec(plain)+`<span class="bb-enc-badge">\ud83d\udd12 encrypted <span class="bb-copy-btn" title="Copy">\ud83d\udccb</span></span>`;el.style.color="inherit";el._isDecrypted=true;const cb=el.querySelector(".bb-copy-btn");if(cb)cb.onclick=ev=>{ev.preventDefault();ev.stopPropagation();navigator.clipboard.writeText(plain).then(()=>{cb.textContent="\u2705";setTimeout(()=>cb.textContent="\ud83d\udccb",1200);}).catch(()=>{});};}}).catch(()=>{}).finally(()=>_infly.delete(el));}}
    }
}

function scan(){ const sc=document.getElementById("message_list_scroller_id"); if(sc)scanContainer(sc); const dl=document.querySelectorAll(".dialog-item-content"); for(const d of dl)scanContainer(d); if(!sc&&!dl.length)scanContainer(document.body); }

const sty=document.createElement("style");
sty.textContent=`
#secure-input-overlay{width:100%;box-sizing:border-box;min-height:42px;max-height:150px;overflow-y:auto;background:${P.srf};border:1.5px solid ${P.ac};border-radius:14px;padding:10px 16px;font-family:inherit;font-size:inherit;outline:none;white-space:pre-wrap;word-break:break-word;margin-right:10px;resize:none;color:${P.tx};z-index:100;position:relative;transition:border-color .15s;display:block}
#secure-input-overlay:focus{border-color:${P.acDim}}
div#secure-input-overlay:empty::before{content:attr(data-placeholder);color:${P.txM};pointer-events:none;display:block}
textarea#secure-input-overlay:placeholder-shown{color:${P.txM}}
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
.bb-cblk{position:relative;background:${P.bg};border:1px solid ${P.bdr};border-radius:8px;margin:4px 0;overflow:hidden}
.bb-cblk-lang{display:block;padding:4px 12px;font-size:10px;font-weight:600;color:${P.txD};background:${P.srf};border-bottom:1px solid ${P.bdr};text-transform:uppercase;letter-spacing:.04em}
.bb-cblk-pre{margin:0;padding:10px 12px;overflow-x:auto;font-family:monospace;font-size:12.5px;line-height:1.5;color:${P.tx};white-space:pre;tab-size:4}
.bb-cblk-pre code{font-family:inherit;font-size:inherit;background:none;border:none;padding:0;color:inherit}
.bb-cblk-copy{position:absolute;top:4px;right:8px;cursor:pointer;font-size:12px;opacity:.4;transition:opacity .15s;z-index:1}
.bb-cblk-copy:hover{opacity:1}
.bb-spoiler{background:${P.txM};color:transparent;border-radius:3px;padding:0 3px;cursor:pointer;user-select:none;transition:color .15s,background .15s}
.bb-link{color:${P.ac};text-decoration:underline;text-decoration-color:rgba(124,138,246,.25);transition:text-decoration-color .15s}
.bb-link:hover{text-decoration-color:${P.ac}}
.bb-enc-badge{display:inline-block;font-size:9px;opacity:.4;letter-spacing:.02em;font-style:italic;margin-inline-start:5px;vertical-align:middle;line-height:1;white-space:nowrap}
.bb-copy-btn{cursor:pointer;margin-inline-start:3px;font-size:10px;font-style:normal;transition:opacity .15s;opacity:.65}
.bb-copy-btn:hover{opacity:1!important}
.BAsWs0 .bb-block,.MRlMpm .bb-block,.dialog-item-content .bb-block,.aqFHpt .bb-block,.YgUC8J .bb-block,.I2osyO .bb-block,
.BAsWs0 .bb-quote,.MRlMpm .bb-quote,.dialog-item-content .bb-quote,.aqFHpt .bb-quote,.YgUC8J .bb-quote,.I2osyO .bb-quote,
.BAsWs0 .bb-ul,.MRlMpm .bb-ul,.dialog-item-content .bb-ul,.aqFHpt .bb-ul,.YgUC8J .bb-ul,.I2osyO .bb-ul,
.BAsWs0 .bb-ol,.MRlMpm .bb-ol,.dialog-item-content .bb-ol,.aqFHpt .bb-ol,.YgUC8J .bb-ol,.I2osyO .bb-ol,
.BAsWs0 .bb-li,.MRlMpm .bb-li,.dialog-item-content .bb-li,.aqFHpt .bb-li,.YgUC8J .bb-li,.I2osyO .bb-li{display:inline!important;margin:0!important;padding:0!important;border:none!important;background:none!important}
.BAsWs0 .bb-spacer,.MRlMpm .bb-spacer,.dialog-item-content .bb-spacer,.aqFHpt .bb-spacer,.YgUC8J .bb-spacer,.I2osyO .bb-spacer,
.BAsWs0 .bb-hr,.MRlMpm .bb-hr,.dialog-item-content .bb-hr,.aqFHpt .bb-hr,.YgUC8J .bb-hr,.I2osyO .bb-hr,
.BAsWs0 .bb-copy-btn,.MRlMpm .bb-copy-btn,.dialog-item-content .bb-copy-btn,.aqFHpt .bb-copy-btn,.YgUC8J .bb-copy-btn,.I2osyO .bb-copy-btn{display:none!important}
.BAsWs0 .bb-cblk,.MRlMpm .bb-cblk,.dialog-item-content .bb-cblk,.aqFHpt .bb-cblk,.YgUC8J .bb-cblk,.I2osyO .bb-cblk{display:inline!important;background:none!important;border:none!important;margin:0!important;padding:0!important}
.BAsWs0 .bb-cblk-pre,.MRlMpm .bb-cblk-pre,.dialog-item-content .bb-cblk-pre,.aqFHpt .bb-cblk-pre,.YgUC8J .bb-cblk-pre,.I2osyO .bb-cblk-pre{display:inline!important;margin:0!important;padding:0!important;white-space:normal!important}
.BAsWs0 .bb-cblk-lang,.MRlMpm .bb-cblk-lang,.dialog-item-content .bb-cblk-lang,.aqFHpt .bb-cblk-lang,.YgUC8J .bb-cblk-lang,.I2osyO .bb-cblk-lang,
.BAsWs0 .bb-cblk-copy,.MRlMpm .bb-cblk-copy,.dialog-item-content .bb-cblk-copy,.aqFHpt .bb-cblk-copy,.YgUC8J .bb-cblk-copy,.I2osyO .bb-cblk-copy{display:none!important}
.BAsWs0 .bb-li::after,.MRlMpm .bb-li::after,.dialog-item-content .bb-li::after,.aqFHpt .bb-li::after,.YgUC8J .bb-li::after,.I2osyO .bb-li::after{content:" \\00a0\u2022\\00a0 "}
.BAsWs0 .bb-msg-container,.MRlMpm .bb-msg-container,.dialog-item-content .bb-msg-container,.aqFHpt .bb-msg-container,.YgUC8J .bb-msg-container,.I2osyO .bb-msg-container{display:-webkit-box!important;-webkit-line-clamp:2!important;-webkit-box-orient:vertical!important;white-space:normal!important}
.bb-hs-widget{border-radius:10px;padding:12px;margin:6px 0;font-family:inherit;font-size:13px;line-height:1.4;transition:border-color .15s}
.bb-hs-title{display:block;font-weight:700;margin-bottom:6px;font-size:14px;display:flex;align-items:center;gap:6px}
.bb-hs-fp{font-family:monospace;font-size:11.5px;margin-bottom:4px;font-weight:600}
.bb-hs-btn{display:inline-block;border:none;padding:7px 14px;border-radius:8px;cursor:pointer;font-weight:600;transition:opacity .15s,transform .1s;margin-top:8px;font-size:13px}
.bb-hs-btn:active{transform:scale(.97)}
.bb-hs-btn:hover{opacity:.85}
.bb-hs-btn:disabled{opacity:.6;cursor:not-allowed;transform:none}
`;
document.head.appendChild(sty);

const menu=document.createElement("div"); menu.id="bale-bridge-menu";
const m1=document.createElement("div"); m1.className="bale-menu-item"; m1.textContent="\ud83d\udd12 Send Encrypted"; m1.onclick=()=>{menu.style.display="none";window._bbSend?.(true);};
const m2=document.createElement("div"); m2.className="bale-menu-item"; m2.textContent="\u26a0\ufe0f Send Unencrypted"; m2.onclick=()=>{menu.style.display="none";window._bbSend?.(false);};
menu.appendChild(m1); menu.appendChild(m2); document.body.appendChild(menu);
const showMenu=(x,y)=>Object.assign(menu.style,{display:"flex",left:Math.min(x,innerWidth-210)+"px",top:Math.min(y,innerHeight-130)+"px"});
document.addEventListener("click",e=>{if(!menu.contains(e.target))menu.style.display="none";});

function openSettings(){
    document.getElementById("bb-modal-overlay")?.remove();
    const s=getS(), fv=s.enabled&&s.customKey?.length===CFG.KEY_LEN?s.customKey.substring(0,5).toUpperCase():"N/A";
    const ov=document.createElement("div"); ov.id="bb-modal-overlay";
    const cd=document.createElement("div"); cd.id="bb-modal-card";
    const t=document.createElement("h3"); t.className="bb-modal-title"; t.textContent="\ud83d\udee1\ufe0f Shield Settings";
    const d=document.createElement("p"); d.className="bb-modal-desc"; d.textContent="Configure encryption for this chat.";
    const elbl=document.createElement("label"); elbl.className="bb-toggle-lbl";
    const ecb=document.createElement("input"); ecb.type="checkbox"; ecb.checked=s.enabled;
    const etxt=document.createElement("span"); etxt.textContent="Enable Encryption"; elbl.appendChild(ecb); elbl.appendChild(etxt);
    const ksec=document.createElement("div"); ksec.className="bb-section-divider";
    const klbl=document.createElement("label"); Object.assign(klbl.style,{fontSize:"12px",color:P.txD,fontWeight:"600",display:"block",marginBottom:"2px"}); klbl.textContent="Encryption Key ";
    const req=document.createElement("span"); req.style.color=P.err; req.textContent="*"; klbl.appendChild(req);
    const krow=document.createElement("div"); krow.className="bb-key-row";
    const kinp=document.createElement("input"); kinp.type="password"; kinp.className="bb-input"; kinp.placeholder="32 characters\u2026"; kinp.maxLength=32; kinp.value=s.customKey||"";
    const vb=document.createElement("button"); vb.className="bb-icon-btn"; vb.title="Toggle"; vb.textContent="\ud83d\udc41";
    const cpb=document.createElement("button"); cpb.className="bb-icon-btn"; cpb.title="Copy"; cpb.textContent="\ud83d\udccb";
    krow.appendChild(kinp); krow.appendChild(vb); krow.appendChild(cpb);
    const kt=document.createElement("div"); kt.className="bb-key-tools";
    const gb=document.createElement("button"); gb.className="bb-tool-btn"; gb.textContent="\u26a1 Random Key"; kt.appendChild(gb);
    const km=document.createElement("div"); km.className="bb-key-meta"; km.style.marginTop="8px";
    const errEl=document.createElement("span"); errEl.className="bb-key-error";
    const fpW=document.createElement("span"); fpW.style.cssText=`font-size:11px;color:${P.txD}`; fpW.textContent="Fingerprint: ";
    const fpEl=document.createElement("strong"); fpEl.style.cssText=`font-family:monospace;color:${P.ac}`; fpEl.textContent=fv;
    fpW.appendChild(fpEl); km.appendChild(errEl); km.appendChild(fpW);
    ksec.appendChild(klbl); ksec.appendChild(krow); ksec.appendChild(kt); ksec.appendChild(km);
    const bridgeSec=document.createElement("div"); bridgeSec.className="bb-section-divider";
    const _ig=isGroup();
    const bTitle=document.createElement("div"); Object.assign(bTitle.style,{fontSize:"14px",fontWeight:"700",marginBottom:"4px"}); bTitle.textContent=_ig?"\ud83e\udd1d Group Key Exchange":"\ud83e\udd1d Automatic Key Exchange";
    const bDesc=document.createElement("div"); Object.assign(bDesc.style,{fontSize:"12px",color:P.txD,marginBottom:"10px"}); bDesc.textContent=_ig?"Start a group bridge \u2014 each member joins individually. You generate the key, others receive it securely.":"Establish encryption automatically with your contact.";
    const bBtn=document.createElement("button"); bBtn.className="bb-tool-btn"; bBtn.style.width="100%"; bBtn.style.marginTop="8px"; bBtn.textContent="Loading...";
    bridgeSec.appendChild(bTitle); bridgeSec.appendChild(bDesc); bridgeSec.appendChild(bBtn);
    const acts=document.createElement("div"); acts.className="bb-actions";
    const canB=document.createElement("button"); canB.className="bb-btn bb-btn-cancel"; canB.textContent="Cancel";
    const savB=document.createElement("button"); savB.className="bb-btn bb-btn-save"; savB.textContent="Save";
    acts.appendChild(canB); acts.appendChild(savB);
    cd.appendChild(t); cd.appendChild(d); cd.appendChild(elbl); cd.appendChild(ksec); cd.appendChild(bridgeSec); cd.appendChild(acts);
    ov.appendChild(cd); document.body.appendChild(ov);
    const validate=()=>{const v=kinp.value,l=v.length,on=ecb.checked;ksec.style.display=on?"":"none";bridgeSec.style.display=on?"":"none";fpEl.textContent=l===CFG.KEY_LEN?v.substring(0,5).toUpperCase():"N/A";if(!on){errEl.textContent="";savB.disabled=false;return;}if(!l){errEl.textContent="Key required.";savB.disabled=true;}else if(l!==CFG.KEY_LEN){errEl.textContent=`Need ${CFG.KEY_LEN} chars (${l}).`;savB.disabled=true;}else{errEl.textContent="";savB.disabled=false;}};
    const updateBridgeUI=async()=>{try{const hsList=await dbOp("handshakes","getAll"),ahs=hsList.find(h=>h.chatId===getChatId()&&h.stage!=="confirmed"&&Date.now()-h.createdAt<CFG.HS_EXP*1000);if(ahs){bBtn.textContent="\ud83d\udd04 Waiting for response... (Cancel)";bBtn.style.color=P.wrn;bBtn.style.borderColor=P.wrn;bBtn.onclick=async()=>{await dbOp("handshakes","del",ahs.nonce);updateBridgeUI();};}else{const ch=hsList.find(h=>h.chatId===getChatId()&&h.stage==="confirmed"&&(h.derivedKey===kinp.value||h.groupKey===kinp.value));if(ch&&kinp.value.length===CFG.KEY_LEN){bBtn.textContent=_ig?"\u2705 Group bridge active (Re-key)":"\u2705 Connected via Bridge (Re-key)";bBtn.style.color=P.ac;bBtn.style.borderColor=P.ac;}else{bBtn.textContent=_ig?"\ud83e\udd1d Start Group Bridge":"\ud83e\udd1d Start Bridge";bBtn.style.color=P.tx;bBtn.style.borderColor=P.bdr;}bBtn.onclick=async()=>{ov.remove();try{await startBridge();}catch(_){toast("Bridge error!");}};}}catch(_){bBtn.textContent="Bridge unavailable";bBtn.disabled=true;}};
    updateBridgeUI();
    kinp.oninput=()=>{validate();updateBridgeUI();}; ecb.onchange=validate; validate();
    vb.onclick=()=>{const h=kinp.type==="password";kinp.type=h?"text":"password";vb.textContent=h?"\ud83d\ude48":"\ud83d\udc41";};
    cpb.onclick=()=>{if(!kinp.value)return;navigator.clipboard.writeText(kinp.value).then(()=>{cpb.textContent="\u2705";cpb.classList.add("copied");setTimeout(()=>{cpb.textContent="\ud83d\udccb";cpb.classList.remove("copied");},1200);}).catch(()=>{});};
    gb.onclick=()=>{kinp.value=genKey();kinp.type="text";vb.textContent="\ud83d\ude48";validate();updateBridgeUI();};
    canB.onclick=()=>ov.remove();
    savB.onclick=()=>{if(savB.disabled)return;try{setS({enabled:ecb.checked,customKey:kinp.value});}catch(_){return;}ov.remove();syncVis();};
    ov.onclick=e=>{if(e.target===ov)ov.remove();};
}

let isSending=false,lastHasText=false,isSyncing=false;
const lockI=el=>Object.assign(el.style,{position:"absolute",opacity:"0",pointerEvents:"none",height:"0",width:"0",overflow:"hidden",zIndex:"-9999"});
const unlockI=el=>{el.style.position="";el.style.opacity="1";el.style.pointerEvents="auto";el.style.height="";el.style.width="100%";el.style.overflow="auto";el.style.zIndex="";};

function syncVis(){
    const real=getReal(),sec=document.getElementById("secure-input-overlay"),notice=document.getElementById("bb-no-key-notice"),btn=document.getElementById("bb-settings-btn");
    if(!real) return;
    if(!encOn()){unlockI(real);if(sec)sec.style.display="none";if(notice)notice.style.display="none";if(btn)btn.style.color=P.txD;}
    else if(activeKey()){lockI(real);if(sec)sec.style.display="";if(notice)notice.style.display="none";if(btn)btn.style.color=P.ac;}
    else{lockI(real);if(sec)sec.style.display="none";if(notice)notice.style.display="flex";if(btn)btn.style.color=P.wrn;}
}

function ensureInput(){
    const ri=getReal(); if(!ri) return;
    const wrap=ri.parentElement; if(!wrap) return;
    const emoji=document.querySelector('[aria-label="emoji-icon"]')||document.querySelector(".MmBErq");
    if(emoji&&encOn()) emoji.style.display="none"; else if(emoji) emoji.style.display="";
    if(emoji&&!document.getElementById("bb-settings-btn")){
        const sb=document.createElement("div"); sb.id="bb-settings-btn"; sb.className=emoji.className;
        sb.setAttribute("role","button"); sb.setAttribute("tabindex","0"); sb.setAttribute("aria-label","Encryption settings");
        Object.assign(sb.style,{display:"flex",alignItems:"center",justifyContent:"center",cursor:"pointer",transition:"color .15s"});
        const iw=document.createElement("div"); Object.assign(iw.style,{borderRadius:"50%",lineHeight:"0",position:"relative"});
        iw.innerHTML=`<svg width="24" height="24" fill="currentColor" viewBox="0 0 24 24"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>`;
        sb.appendChild(iw); sb.onclick=openSettings; sb.onkeydown=e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();openSettings();}};
        emoji.parentElement.insertBefore(sb,emoji);
    }
    if(!document.getElementById("bb-no-key-notice")){
        const n=document.createElement("div"); n.id="bb-no-key-notice";
        const ni=document.createElement("div"); ni.className="bb-notice-icon"; ni.textContent="\u26a0\ufe0f";
        const nb=document.createElement("div"); nb.className="bb-notice-body";
        const ns=document.createElement("strong"); ns.textContent="Encryption key not set.";
        nb.appendChild(ns); nb.appendChild(document.createTextNode(" Tap \ud83d\udd12 to set up.")); nb.appendChild(document.createElement("br"));
        const nbtn=document.createElement("button"); nbtn.className="bb-notice-btn"; nbtn.textContent="\ud83d\udee1 Set Key"; nbtn.onclick=openSettings; nb.appendChild(nbtn);
        n.appendChild(ni); n.appendChild(nb); wrap.insertBefore(n,ri);
    }
    const existing=document.getElementById("secure-input-overlay");
    if(existing){window._bbSend=existing._triggerSend;syncVis();return;}
    if(!ri._bbHij){
        ri._bbHij=true;
        ri.addEventListener("focus",()=>{if(!isSyncing&&encOn()){ri.blur();document.getElementById("secure-input-overlay")?.focus();}});
        for(const ev of["keydown","keypress","keyup","drop"]) ri.addEventListener(ev,e=>{if(!isSyncing&&encOn()){e.preventDefault();e.stopPropagation();}},true);
        ri.addEventListener("paste",e=>{
            if(isSyncing||!encOn()) return;
            const items=e.clipboardData?.items;
            if(items){for(const it of items){if(it.type.startsWith("image/")){return;}}}
            e.preventDefault(); e.stopPropagation();
        },true);
    }
    const isNarrow=window.innerWidth<600; let si;
    if(isNarrow){si=document.createElement("textarea");si.dir="auto";si.placeholder="\ud83d\udd12 \u067e\u06cc\u0627\u0645 \u0627\u0645\u0646...";si.rows=1;si.addEventListener("input",()=>{si.style.height="auto";si.style.height=Math.min(si.scrollHeight,150)+"px";});}
    else{si=document.createElement("div");si.contentEditable="true";si.dir="auto";si.dataset.placeholder="\ud83d\udd12 \u067e\u06cc\u0627\u0645 \u0627\u0645\u0646...";wrap.style.overflow="visible";}
    si.id="secure-input-overlay"; wrap.insertBefore(si,ri);
    const siTA=si.tagName==="TEXTAREA";
    const getT=()=>siTA?si.value.trim():si.innerText.trim();
    const setT=v=>{if(siTA)si.value=v;else si.innerText=v;};
    const syncH=has=>{if(has===lastHasText)return;lastHasText=has;isSyncing=true;ri.innerText=has?" ":"";ri.dispatchEvent(new Event("input",{bubbles:true}));isSyncing=false;};
    si.addEventListener("input",e=>{if(!e.isComposing)syncH(getT().length>0);});
    si.addEventListener("compositionend",()=>syncH(getT().length>0));
    si.addEventListener("paste",e=>{
        const items=e.clipboardData?.items;
        if(items){for(const it of items){if(it.type.startsWith("image/")){
            e.preventDefault(); e.stopPropagation();
            const file=it.getAsFile(); if(!file) return;
            const fi=document.querySelector("#chat_footer input[type='file']");
            if(fi){const dt=new DataTransfer();dt.items.add(file);fi.files=dt.files;fi.dispatchEvent(new Event("change",{bubbles:true}));}
            return;
        }}}
        if(!siTA){
            e.preventDefault();
            const text=e.clipboardData?.getData("text/plain");
            if(text) document.execCommand("insertText",false,text);
        }
    },true);
    si.addEventListener("keydown",e=>{
        if(e.key==="Tab"&&!siTA){
            e.preventDefault();
            document.execCommand("insertText",false,"\t");
        }
    });
    const triggerSend=async(doEnc=true)=>{
        if(isSending)return; const text=getT(); if(!text)return;
        if(doEnc){if(!activeKey()){openSettings();return;}isSending=true;setT("\ud83d\udd12 \u2026");try{const ch=await encChunk(text);if(!ch){setT(text);openSettings();return;}for(const c of ch)await sendRaw(c);setT("");lastHasText=false;si.focus();}catch(_){setT(text);toast("Send failed!");}finally{isSending=false;}return;}
        if(!confirm("\u26a0\ufe0f Send WITHOUT encryption?"))return;
        isSending=true;setT("\ud83c\udf10 \u2026");try{await sendRaw(text);setT("");lastHasText=false;si.focus();}catch(_){setT(text);toast("Send failed!");}finally{isSending=false;}
    };
    si._triggerSend=triggerSend; window._bbSend=triggerSend;
    si.addEventListener("keydown",e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();e.stopPropagation();triggerSend(true);}});
    syncVis();
}

const secTxt=()=>{const s=document.getElementById("secure-input-overlay");return s?s.tagName==="TEXTAREA"?s.value.trim():s.innerText.trim():"";};
const isSnB=t=>!!(t.closest('[aria-label="send-button"]')||t.closest(".RaTWwR"));

let tTmr=null,isLng=false;
for(const ev of["mousedown","mouseup","click","pointerdown","pointerup"]) document.addEventListener(ev,e=>{if(!e.isTrusted||!isSnB(e.target)||!encOn()||!secTxt())return;if(isSending){e.preventDefault();e.stopPropagation();return;}e.preventDefault();e.stopPropagation();if(ev==="click"&&e.button===0)window._bbSend?.(true);},true);
document.addEventListener("touchstart",e=>{if(!e.isTrusted||!isSnB(e.target)||!encOn()||!secTxt())return;if(isSending){e.preventDefault();e.stopPropagation();return;}e.preventDefault();e.stopPropagation();isLng=false;if(tTmr!==null)clearTimeout(tTmr);tTmr=setTimeout(()=>{isLng=true;if(e.touches?.length)showMenu(e.touches[0].clientX,e.touches[0].clientY);},CFG.LONG_PRESS);},{passive:false,capture:true});
document.addEventListener("touchend",e=>{if(!e.isTrusted||!isSnB(e.target)||!encOn()||!secTxt())return;if(isSending){e.preventDefault();e.stopPropagation();return;}e.preventDefault();e.stopPropagation();if(tTmr!==null){clearTimeout(tTmr);tTmr=null;}if(!isLng)window._bbSend?.(true);},{passive:false,capture:true});
document.addEventListener("touchmove",e=>{if(!e.isTrusted||!isSnB(e.target))return;if(tTmr!==null){clearTimeout(tTmr);tTmr=null;}isLng=true;},{passive:false,capture:true});
document.addEventListener("contextmenu",e=>{if(isSending||!isSnB(e.target)||!encOn()||!secTxt())return;e.preventDefault();e.stopPropagation();showMenu(e.clientX,e.clientY);},true);

let _dirty=false,_raf=0,lastUrl=location.href;
function ensureEdit(){
    const real=document.querySelector('textarea[aria-label="File Description"]');
    if(!real||real._bbE||!encOn()) return; real._bbE=true;
    const se=document.createElement("textarea"); se.className=real.className;
    se.placeholder="\ud83d\udd12 "+(real.placeholder||"Encrypted description..."); se.dir=real.dir||"auto";
    Object.assign(se.style,{width:"100%",boxSizing:"border-box",background:P.srf,border:"1.5px solid "+P.ac,borderRadius:"8px",padding:"6px 10px",color:P.tx,fontFamily:"inherit",fontSize:"inherit",resize:"none",outline:"none"});
    se.addEventListener("input",()=>{se.style.height="auto";se.style.height=Math.min(se.scrollHeight,120)+"px";});
    real.parentElement.insertBefore(se,real); lockI(real); se.focus();
    const ex=real.value?real.value.trim():"";
    if(ex.startsWith(CFG.PFX_E)) dec(ex).then(p=>{if(p!==ex)se.value=p;}).catch(()=>{}); else se.value=ex;
    const encAndSend=async(btn)=>{
        if(se._busy) return; const text=se.value.trim();
        if(!text){unlockI(real);real.value="";real.dispatchEvent(new Event("input",{bubbles:true}));btn.click();return;}
        if(!activeKey()){openSettings();return;}
        se._busy=true; const prev=se.value; se.value="\ud83d\udd12 \u2026";
        try{
            const out=await enc(text); if(!out){se.value=prev;openSettings();return;}
            se.value=""; unlockI(real); real.value=out;
            real.dispatchEvent(new Event("input",{bubbles:true})); real.dispatchEvent(new Event("change",{bubbles:true}));
            await new Promise(r=>setTimeout(r,CFG.SEND_DLY));
            btn.click();
        }catch(_){se.value=prev;toast("Encrypt failed!");}finally{se._busy=false;}
    };
    const confirmSel='[data-testid="confirm-button"]';
    const eh=e=>{if(!e.isTrusted) return; const btn=e.target.closest(confirmSel); if(!btn||se._busy) return; if(!se.value.trim()){unlockI(real);return;} e.preventDefault();e.stopPropagation();encAndSend(btn);};
    document.addEventListener("click",eh,true); document.addEventListener("mousedown",e=>{if(e.isTrusted&&e.target.closest(confirmSel)&&se.value.trim()){e.preventDefault();e.stopPropagation();}},true);
    const obs=new MutationObserver(()=>{if(!document.contains(se)){document.removeEventListener("click",eh,true);obs.disconnect();}});
    obs.observe(document.body,{childList:true,subtree:true});
    se.addEventListener("keydown",e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();e.stopPropagation();const btn=document.querySelector(confirmSel);if(btn)encAndSend(btn);}});
}

function tick(){_raf=0;_dirty=false;try{scan();ensureInput();ensureEdit();if(location.href!==lastUrl){lastUrl=location.href;_sc=null;_scId=null;syncVis();}}catch(_){}}
new MutationObserver(()=>{if(!_dirty){_dirty=true;if(_raf)cancelAnimationFrame(_raf);_raf=requestAnimationFrame(tick);}}).observe(document.body,{childList:true,subtree:true,characterData:true});

function cleanupHs(){dbOp("handshakes","getAll").then(hs=>{const now=Date.now();hs.forEach(h=>{if(h.stage!=="confirmed"&&now-h.createdAt>CFG.HS_CLEANUP)dbOp("handshakes","del",h.nonce);});}).catch(()=>{});}

try{scan();ensureInput();ensureEdit();setTimeout(cleanupHs,2000);setInterval(cleanupHs,CFG.HS_CLEANUP);}catch(_){}
})();
