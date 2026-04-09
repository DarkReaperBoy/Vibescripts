// ==UserScript==
// @name         Rubika Bridge — E2E Encryption + Connectivity Fix
// @namespace    http://tampermonkey.net/
// @version      10.2.0
// @description  E2E encryption, ad blocker, connectivity fix (DC racing, active sync, keepalive). Desktop + Mobile.
// @author       You
// @match        *://web.rubika.ir/*
// @match        *://m.rubika.ir/*
// @grant        none
// @run-at       document-start
// ==/UserScript==

// ── CONNECTIVITY FIX (document-start) ──
(function(){
"use strict";
const _W=typeof unsafeWindow!=="undefined"?unsafeWindow:window,OrigWS=_W.WebSocket;
let _rk={api:[],sock:[]},_ri={api:0,sock:0},_bad=new Set();
function bestS(){for(let i=0;i<_rk.sock.length;i++){const u=_rk.sock[(_ri.sock+i)%_rk.sock.length];if(!_bad.has(u))return u;}return _rk.sock[0]||null;}
function rotS(b){if(b){_bad.add(b);setTimeout(()=>_bad.delete(b),30000);}if(_rk.sock.length>1)_ri.sock=(_ri.sock+1)%_rk.sock.length;}
function bestA(){return _rk.api[_ri.api]||null;}
function rotA(){if(_rk.api.length>1)_ri.api=(_ri.api+1)%_rk.api.length;}
async function raceDCs(){try{const r=await fetch("https://getdcmess.iranlms.ir/",{signal:AbortSignal.timeout(12000)});const d=(await r.json()).data;let a=[],s=[];if(d.API)a=Object.values(d.API).filter(Boolean);if(d.socket)s=Object.values(d.socket).filter(Boolean);else if(d.Socket)s=Object.values(d.Socket).filter(Boolean);a=[...new Set(a.map(u=>u.endsWith("/")?u:u+"/"))];s=[...new Set(s)];if(a.length){const rs=await Promise.allSettled(a.map(async u=>{const t=performance.now();await fetch(u,{method:"POST",headers:{"Content-Type":"text/plain"},body:"{}",signal:AbortSignal.timeout(10000)});return{u,ms:performance.now()-t};}));_rk.api=rs.filter(x=>x.status==="fulfilled").map(x=>x.value).sort((a,b)=>a.ms-b.ms).map(x=>x.u);const seen=new Set(_rk.api);a.forEach(u=>{if(!seen.has(u))_rk.api.push(u);});}
if(s.length)_rk.sock=await new Promise(res=>{const r=[],st={},ws=[];let n=s.length;const to=setTimeout(fin,10000);function fin(){clearTimeout(to);ws.forEach(w=>{try{w.close();}catch(_){}});const ok=r.sort((a,b)=>a.ms-b.ms).map(x=>x.u);const seen=new Set(ok);s.forEach(u=>{if(!seen.has(u))ok.push(u);});res(ok);}s.forEach(u=>{try{st[u]=performance.now();const w=new OrigWS(u);ws.push(w);w.onopen=()=>{r.push({u,ms:performance.now()-st[u]});if(--n<=0)fin();};w.onerror=()=>{if(--n<=0)fin();};}catch(_){if(--n<=0)fin();}});if(n<=0)fin();});
}catch(e){console.log("[RB] DC fail:",e.message);}}
raceDCs();setTimeout(()=>{if(!_rk.api.length)raceDCs();},15000);
let aSock=null,lastM=Date.now(),rtt=[],pS=0,piT=null,poT=null,_decAuth=null,_sState=0,_sBusy=false,_sMiss=0;
function aPoT(){if(rtt.length<3)return 8000;const s=[...rtt].sort((a,b)=>a-b);return Math.max(4000,Math.min(10000,s[Math.floor(s.length*.9)]*2.5));}
function aPiT(){if(rtt.length<3)return 8000;return Math.max(6000,Math.min(15000,(rtt.reduce((a,b)=>a+b,0)/rtt.length)*6));}
function clrP(){clearInterval(piT);clearTimeout(poT);piT=poT=null;}
function PW(url,pr){const bs=bestS();if(bs&&url&&url.includes("iranlms.ir")&&!url.includes("getdcmess"))url=bs;const ws=pr!==undefined?new OrigWS(url,pr):new OrigWS(url);if(!url||!url.includes("iranlms.ir"))return ws;aSock=ws;lastM=Date.now();const os=ws.send.bind(ws);ws.send=function(d){try{if(typeof d==="string"&&d.includes("EditParameter")&&d.includes("drafts_"))return;}catch(_){}return os(d);};
function sP(){clrP();piT=setInterval(()=>{if(ws.readyState===1){pS=performance.now();try{os("{}");}catch(_){}clearTimeout(poT);poT=setTimeout(()=>{try{ws.close(4000,"pt");}catch(_){}},aPoT());}},aPiT());}
ws.addEventListener("open",()=>{lastM=Date.now();sP();});ws.addEventListener("message",()=>{lastM=Date.now();clearTimeout(poT);poT=null;if(pS>0){rtt.push(performance.now()-pS);if(rtt.length>10)rtt.shift();pS=0;}});ws.addEventListener("close",()=>{clrP();rotS(url);aSock=null;});return ws;}
PW.CONNECTING=OrigWS.CONNECTING;PW.OPEN=OrigWS.OPEN;PW.CLOSING=OrigWS.CLOSING;PW.CLOSED=OrigWS.CLOSED;PW.prototype=OrigWS.prototype;_W.WebSocket=PW;
// Draft blocker — must run before Angular creates WebSocket instances
const _origProtoSend=OrigWS.prototype.send;
OrigWS.prototype.send=function(d){try{if(typeof d==="string"&&d.includes("EditParameter")&&d.includes("drafts_"))return;}catch(_){}return _origProtoSend.apply(this,arguments);};

// ── Notifications via WebSocket decryption ──
let _authKey=null, _passKey=null, _myGuid=null, _lastActivity=Date.now();
// Track user activity — any interaction resets the timer
["mousedown","mousemove","keydown","touchstart","scroll","wheel"].forEach(e=>{
    _W.addEventListener(e,()=>{_lastActivity=Date.now();},{passive:true,capture:true});
});
function derivePassphrase(auth){
    if(auth.length!==32)return auth;
    const c0=auth.slice(0,8),c1=auth.slice(8,16),c2=auth.slice(16,24),c3=auth.slice(24,32);
    let r=c2+c0+c3+c1,out="";
    for(let i=0;i<r.length;i++){const c=r.charCodeAt(i);
        if(c>=48&&c<=57)out+=String.fromCharCode((c-48+5)%10+48);
        else if(c>=97&&c<=122)out+=String.fromCharCode((c-97+9)%26+97);
        else out+=r[i];}
    return out;
}
async function aesCbcDecrypt(b64data,key){
    try{
        let raw=atob(b64data);const data=new Uint8Array(raw.length);for(let i=0;i<raw.length;i++)data[i]=raw.charCodeAt(i);
        const iv=new Uint8Array(16); // zero IV
        const keyBuf=new TextEncoder().encode(key);
        const ck=await crypto.subtle.importKey("raw",keyBuf,{name:"AES-CBC"},false,["decrypt"]);
        const dec=new Uint8Array(await crypto.subtle.decrypt({name:"AES-CBC",iv},ck,data));
        // Remove PKCS7 padding
        const pad=dec[dec.length-1];if(pad>0&&pad<=16){const unpd=dec.slice(0,dec.length-pad);return new TextDecoder().decode(unpd);}
        return new TextDecoder().decode(dec);
    }catch(_){return null;}
}
let _notifAC=null;
// Pre-warm AudioContext on first user interaction so it's ready for notifications
["click","keydown","touchstart"].forEach(e=>{_W.addEventListener(e,function _acWarm(){
    try{if(!_notifAC){_notifAC=new(window.AudioContext||window.webkitAudioContext)();_notifAC.resume();}}catch(_){}
    _W.removeEventListener(e,_acWarm);},{once:true,capture:true});});
function playNotifSound(){
    try{
        if(!_notifAC)_notifAC=new(window.AudioContext||window.webkitAudioContext)();
        _notifAC.resume().then(()=>{
            const ac=_notifAC;
            // Three-tone chime — louder, longer
            [[880,.0,.12],[1047,.1,.22],[1319,.2,.35]].forEach(([freq,start,end])=>{
                const o=ac.createOscillator(),g=ac.createGain();
                o.type="sine";o.frequency.value=freq;
                g.gain.setValueAtTime(0,ac.currentTime+start);
                g.gain.linearRampToValueAtTime(0.35,ac.currentTime+start+0.03);
                g.gain.linearRampToValueAtTime(0,ac.currentTime+end);
                o.connect(g);g.connect(ac.destination);
                o.start(ac.currentTime+start);o.stop(ac.currentTime+end+0.01);
            });
        }).catch(()=>{});
    }catch(_){}
}
function showMsgNotification(chatName,text,authorName){
    if(!("Notification" in _W))return;
    if(Notification.permission==="default"){Notification.requestPermission();return;}
    if(Notification.permission!=="granted")return;
    let title=authorName&&authorName!==chatName?authorName+" in "+chatName:chatName;
    let body=text||"New message";
    if(body.length>120)body=body.slice(0,120)+"\u2026";
    console.log("[RB] Notification:",title,"—",body,"| Permission:",Notification.permission);
    playNotifSound();
    try{
        const n=new Notification(title,{body,icon:"https://web.rubika.ir/assets/img/iphone_home120.png",tag:"rb-"+chatName});
        n.onclick=()=>{_W.focus();n.close();};
        setTimeout(()=>n.close(),8000);
    }catch(_){}
}
// ── Notification message handler (reusable) ──
let _wsMsgCount=0;
function _handleWsMsg(e){
    try{
        if(!e.data||typeof e.data!=="string")return;
        const msg=JSON.parse(e.data);
        if(!msg.data_enc)return;
        _wsMsgCount++;
        if(!_passKey){if(_wsMsgCount<=3)console.log("[RB] WS msg #%d but no auth yet",_wsMsgCount);return;}
        aesCbcDecrypt(msg.data_enc,_passKey).then(plain=>{
            if(!plain)return;
            try{
                const d=JSON.parse(plain);
                // Log first few messages to diagnose format
                if(_wsMsgCount<=5)console.log("[RB] WS #%d keys:",_wsMsgCount,Object.keys(d).join(","),"| sample:",JSON.stringify(d).slice(0,300));
                // Extract messages from ALL possible field names
                // WS push uses: message_updates, chat_updates, message, chat, show_notifications
                // May also be nested under d.data
                const src=d.data||d;
                const msgs=src.message_updates||src.message||[];
                const chats=src.chat_updates||src.chat||[];
                const notifs=src.show_notifications||[];
                if(!msgs.length&&!chats.length&&!notifs.length)return;
                // Process message updates
                for(const m of msgs){
                    const mm=m.message||m;
                    const authorGuid=mm.author_object_guid||mm.author_guid||"";
                    if(_myGuid&&authorGuid===_myGuid)continue;
                    const text=mm.text||"";
                    const authorName=mm.author_name||mm.author_title||"";
                    const chatGuid=mm.object_guid||m.object_guid||"";
                    let chatName=authorName||"New message";
                    if(document.hasFocus()&&Date.now()-_lastActivity<15000)continue;
                    try{
                        const items=document.querySelectorAll("ul.chatlist > li[rb-chat-item]");
                        for(const li of items){
                            const pt=li.querySelector(".peer-title");
                            if(pt&&li.innerHTML.includes(chatGuid)){chatName=pt.textContent.trim();break;}
                        }
                    }catch(_){}
                    if(text||authorName){
                        if(text.startsWith("@@")&&_W._rbDecrypt){
                            _W._rbDecrypt(text).then(dec=>{
                                showMsgNotification(chatName,dec!==text?"\ud83d\udd12 "+dec:"\ud83d\udd12 Encrypted message",authorName);
                            }).catch(()=>showMsgNotification(chatName,"\ud83d\udd12 Encrypted message",authorName));
                        } else { showMsgNotification(chatName,text,authorName); }
                    }
                }
                // Process show_notifications (Rubika's own notification triggers)
                for(const n of notifs){
                    const text=n.text||n.message_text||"";
                    const title=n.title||n.chat_title||n.sender_name||"Rubika";
                    if(document.hasFocus()&&Date.now()-_lastActivity<15000)continue;
                    const authorGuid=n.author_object_guid||n.sender_guid||"";
                    if(_myGuid&&authorGuid===_myGuid)continue;
                    if(text||title){
                        if(text.startsWith("@@")&&_W._rbDecrypt){
                            _W._rbDecrypt(text).then(dec=>{
                                showMsgNotification(title,dec!==text?"\ud83d\udd12 "+dec:"\ud83d\udd12 Encrypted message");
                            }).catch(()=>showMsgNotification(title,"\ud83d\udd12 Encrypted message"));
                        } else { showMsgNotification(title,text); }
                    }
                }
            }catch(ex){console.log("[RB] WS parse error:",ex.message);}
        }).catch(ex=>{if(_wsMsgCount<=5)console.log("[RB] WS decrypt fail:",ex.message);});
    }catch(_){}
}

// Capture auth from handshake, intercept incoming messages
(function(){
    const origAddEL=OrigWS.prototype.addEventListener;
    const _omsgHandlers=new WeakMap();

    // Wrap addEventListener to intercept 'message' events
    OrigWS.prototype.addEventListener=function(type,fn,...rest){
        if(type==="message"){
            const wrapped=function(e){ _handleWsMsg(e); return fn.call(this,e); };
            _omsgHandlers.set(fn,wrapped);
            return origAddEL.call(this,type,wrapped,...rest);
        }
        return origAddEL.call(this,type,fn,...rest);
    };

    // Also intercept onmessage property — RxJS WebSocketSubject uses this instead of addEventListener
    const _origOnMsgDesc=Object.getOwnPropertyDescriptor(OrigWS.prototype,'onmessage');
    if(_origOnMsgDesc&&_origOnMsgDesc.set){
        Object.defineProperty(OrigWS.prototype,'onmessage',{configurable:true,enumerable:true,
            get:_origOnMsgDesc.get,
            set:function(fn){
                if(!fn)return _origOnMsgDesc.set.call(this,fn);
                const ws=this;
                _origOnMsgDesc.set.call(this,function(e){ _handleWsMsg(e); return fn.call(ws,e); });
            }
        });
    }

    // Capture auth from WS send (handshake)
    OrigWS.prototype.send=function(d){
        try{
            if(typeof d==="string"){
                const p=JSON.parse(d);
                if(p.method==="handShake"&&p.auth&&typeof p.auth==="string"&&p.auth.length>=20){
                    _authKey=p.auth;_passKey=derivePassphrase(p.auth);_decAuth=null;_sState=0;_sMiss=0;
                    console.log("[RB] Auth captured from WS handshake (%d chars)",p.auth.length);
                }
                if(d.includes("EditParameter")&&d.includes("drafts_"))return;
            }
        }catch(_){}
        return _origProtoSend.apply(this,arguments);
    };

    // Try to get myGuid and auth from localStorage
    function _scanLocalStorage(){
        try{for(let i=0;i<localStorage.length;i++){
            const k=localStorage.key(i),v=localStorage.getItem(k);
            if(!v)continue;
            try{const obj=JSON.parse(v);
                if(obj&&typeof obj==="object"){
                    if(!_myGuid&&obj.user_guid)_myGuid=obj.user_guid;
                    // Auth stored as JSON field
                    if(!_authKey&&typeof obj.auth==="string"&&obj.auth.length>=20&&/^[a-z0-9]+$/.test(obj.auth)){
                        _authKey=obj.auth;_passKey=derivePassphrase(obj.auth);_decAuth=null;_sState=0;
                        console.log("[RB] Auth from localStorage (key: %s)",k);
                    }
                }
            }catch(_){}
            // Regex scan for auth in stringified values
            if(!_authKey){
                const m=v.match(/"auth"\s*:\s*"([a-z]{20,32})"/);
                if(m){_authKey=m[1];_passKey=derivePassphrase(m[1]);_decAuth=null;_sState=0;
                    console.log("[RB] Auth from localStorage regex (key: %s)",k);}
            }
        }}catch(_){}
    }
    _scanLocalStorage();
    // Retry periodically in case localStorage is populated after page load
    const _lsTimer=setInterval(()=>{if(_authKey){clearInterval(_lsTimer);return;}_scanLocalStorage();},3000);
    setTimeout(()=>clearInterval(_lsTimer),60000); // stop after 1 min

    // Ask notification permission
    if("Notification" in _W&&Notification.permission==="default"){
        document.addEventListener("click",function ask(){Notification.requestPermission();document.removeEventListener("click",ask);},{once:true});
    }
})();

const oO=XMLHttpRequest.prototype.open,oX=XMLHttpRequest.prototype.send;
// Adaptive XHR timeout: scales with connection speed. Fast=15s, slow=45s
function adaptiveXhrTimeout(){if(rtt.length<3)return 20000;const avg=rtt.reduce((a,b)=>a+b,0)/rtt.length;return Math.max(15000,Math.min(45000,avg*15));}
XMLHttpRequest.prototype.open=function(m,u,...r){this._ru=u;const b=bestA();if(b&&typeof u==="string"&&u.includes("iranlms.ir")&&!u.includes("getdcmess")&&!u.includes("GetFile")&&!u.includes("getfile")&&m==="POST"){try{const o=new URL(u),n=new URL(b);if(o.hostname!==n.hostname)u=n.origin+o.pathname+o.search;}catch(_){}this.timeout=adaptiveXhrTimeout();}return oO.call(this,m,u,...r);};
XMLHttpRequest.prototype.send=function(...a){
// Capture auth from XHR API requests (fallback if WS capture fails)
if(!_authKey&&a[0]&&typeof a[0]==="string"&&this._ru&&this._ru.includes("iranlms.ir")){
try{const b=JSON.parse(a[0]);if(b.auth&&typeof b.auth==="string"&&b.auth.length>=20){
// b.auth is decode_auth — _dAuth is its own inverse, so _dAuth(decode_auth) = raw_auth
const raw=_dAuth(b.auth);_authKey=raw;_passKey=derivePassphrase(raw);_decAuth=b.auth;_sState=0;_sMiss=0;
console.log("[RB] Auth captured from XHR request");
}}catch(_){}}
this.addEventListener("error",()=>{if(this._ru&&this._ru.includes("iranlms.ir"))rotA();},{once:true});this.addEventListener("timeout",()=>{if(this._ru&&this._ru.includes("iranlms.ir"))rotA();},{once:true});return oX.apply(this,a);};
document.addEventListener("visibilitychange",()=>{if(!document.hidden){if(!aSock||aSock.readyState!==1)_W.dispatchEvent(new Event("online"));else if(Date.now()-lastM>60000){try{aSock.close(4000,"stale");}catch(_){}}}});
_W.addEventListener("online",()=>{setTimeout(()=>{if(!aSock||aSock.readyState!==1)_W.dispatchEvent(new Event("online"));},1000);});
if(navigator.connection)navigator.connection.addEventListener("change",()=>{if(navigator.onLine&&(!aSock||aSock.readyState!==1))_W.dispatchEvent(new Event("online"));});
setInterval(()=>{if(!aSock||aSock.readyState!==1)return;if(Date.now()-lastM>aPiT()*2){pS=performance.now();try{aSock.send("{}");}catch(_){}clearTimeout(poT);poT=setTimeout(()=>{try{aSock.close(4000,"hc");}catch(_){}},aPoT());}},10000);

// ── Active Sync Engine ──
// Provides backup message sync via API polling when WebSocket misses updates.
// Detects sync gaps, injects missed updates, and forces WS reconnect as fallback.
function _dAuth(a){let r='';for(let i=0;i<a.length;i++){const c=a.charCodeAt(i);if(c>=97&&c<=122)r+=String.fromCharCode(((32-(c-97))%26)+97);else if(c>=65&&c<=90)r+=String.fromCharCode(((29-(c-65))%26)+65);else if(c>=48&&c<=57)r+=String.fromCharCode(((13-(c-48))%10)+48);else r+=a[i];}return r;}
async function _aEnc(s,k){const iv=new Uint8Array(16),ck=await crypto.subtle.importKey("raw",new TextEncoder().encode(k),{name:"AES-CBC"},false,["encrypt"]),enc=new Uint8Array(await crypto.subtle.encrypt({name:"AES-CBC",iv},ck,new TextEncoder().encode(s)));let b='';for(let i=0;i<enc.length;i++)b+=String.fromCharCode(enc[i]);return btoa(b);}
async function _rApi(m,inp){
if(!_authKey||!_passKey)return null;if(!_decAuth)_decAuth=_dAuth(_authKey);
const u=bestA()||_rk.api[0];if(!u)return null;
try{const _pkg=location.hostname.includes("m.rubika")?"m.rubika.ir":"web.rubika.ir";
const de=await _aEnc(JSON.stringify({client:{app_name:"Main",app_version:"2.5.4",platform:"PWA",package:_pkg,lang_code:"fa"},method:m,input:inp}),_passKey);
const r=await fetch(u,{method:"POST",headers:{"Content-Type":"text/plain"},body:JSON.stringify({api_version:"6",auth:_decAuth,data_enc:de}),signal:AbortSignal.timeout(12000)});
const j=await r.json();if(!j.data_enc)return null;const p=await aesCbcDecrypt(j.data_enc,_passKey);return p?JSON.parse(p):null;
}catch(_){rotA();return null;}}

// Poll getChatsUpdates — detect missed messages, inject or reconnect
async function _doSync(){
if(_sBusy||!_authKey)return;_sBusy=true;
try{if(!_sState)_sState=Math.floor(Date.now()/1000)-30;
const r=await _rApi("getChatsUpdates",{state:_sState});
if(!r||r.status!=="OK"){
// Handle "OldState" — server says our state is too stale, reset and force full reconnect
if(r&&(r.status_det==="OldState"||r.status==="OldState"||(r.data&&r.data.status==="OldState"))){
_sState=Math.floor(Date.now()/1000)-30;
if(aSock&&aSock.readyState===1){try{aSock.close(4000,"old");}catch(_){}}
else{_W.dispatchEvent(new Event("online"));}}
return;}
const d=r.data||{};if(d.new_state&&d.new_state>_sState)_sState=d.new_state;
// Also handle OldState inside data
if(d.status==="OldState"){_sState=Math.floor(Date.now()/1000)-30;
if(aSock&&aSock.readyState===1){try{aSock.close(4000,"old");}catch(_){}}return;}
const chats=d.chats||[];
if(chats.length>0){_sMiss++;
// Always inject chat updates — force sync regardless of WS state
if(aSock&&aSock.readyState===1){
try{const ed=await _aEnc(JSON.stringify({chat_updates:chats,message_updates:chats.filter(c=>c.last_message).map(c=>({message:c.last_message,object_guid:c.object_guid}))}),_passKey);
aSock.dispatchEvent(new MessageEvent("message",{data:JSON.stringify({data_enc:ed})}));}catch(_){}}
// Force WS reconnect after 3+ consecutive missed syncs
if(_sMiss>=3){_sMiss=0;
if(aSock&&aSock.readyState===1){try{aSock.close(4000,"sync");}catch(_){}}
else{_W.dispatchEvent(new Event("online"));}}
}else{_sMiss=0;}
// Always sync current chat messages too
await _chatSync();
}finally{_sBusy=false;}}

// Per-chat sync — fetch messages for current open chat
async function _chatSync(){
if(!_authKey)return;const h=location.hash;if(!h.startsWith("#c="))return;const g=h.slice(3);if(!g)return;
try{const r=await _rApi("getMessagesUpdates",{object_guid:g,state:Math.floor(Date.now()/1000)-120});
if(!r||r.status!=="OK")return;const d=r.data||{};
const msgs=d.updated_messages||d.messages||[];
if(msgs.length>0&&aSock&&aSock.readyState===1){
try{const ed=await _aEnc(JSON.stringify({message_updates:msgs.map(m=>({message:m,object_guid:g}))}),_passKey);
aSock.dispatchEvent(new MessageEvent("message",{data:JSON.stringify({data_enc:ed})}));}catch(_){}
}}catch(_){}}

// Fixed 5s sync scheduler
(function(){let st=null;
function sched(){clearTimeout(st);
st=setTimeout(()=>{_doSync().then(sched);},2000);}
const wi=setInterval(()=>{if(_authKey){clearInterval(wi);console.log("[RB] Sync engine started");_doSync().then(sched);}},2000);
// Immediate sync on tab focus
document.addEventListener("visibilitychange",()=>{if(!document.hidden&&_authKey){clearTimeout(st);_doSync().then(()=>{_chatSync();sched();});}});
// Sync current chat on navigation
_W.addEventListener("hashchange",()=>{if(_authKey)setTimeout(_chatSync,1500);});
})();

// Reconnection watchdog — force reconnect if WS dead >10s
setInterval(()=>{if(_authKey&&(!aSock||aSock.readyState>1)&&Date.now()-lastM>10000)_W.dispatchEvent(new Event("online"));},8000);
// Re-race DCs every 5 minutes to adapt to network changes
setInterval(raceDCs,300000);
})();

// ── Ad Blocker ──
// CSS: hide ads early, before they render
const _adCSS=document.createElement("style");_adCSS.textContent=`
[class*="ads-"],[class*="-ads"],[class*="_ads"],[class*="ads_"],
[class*="advert"],[class*="banner-ad"],[class*="ad-banner"],
[class*="promo"],[class*="sponsor"],[class*="campaign"],
[id*="ads-"],[id*="-ads"],[id*="ad-banner"],[id*="promo"],
[class*="tabligh"],[class*="tebligh"],
rb-chat-ads-container,.user-caption-ads,
.ads-container,.ad-wrapper,.ad-slot,.ad-placeholder,
.rb-ad,.rb-ads,.rb-banner,.rb-promo,
.advertisement,.sponsored-content,.promoted,
iframe[src*="yektanet"],iframe[src*="tapsell"],iframe[src*="adro"],
iframe[src*="divar"],iframe[src*="ads"],
[data-ad],[data-ads],[data-ad-slot],[data-campaign],
div[style*="z-index"][style*="position: fixed"]:not(#bb-modal-overlay):not(#bale-bridge-menu):not(.bubble):has(a[target="_blank"][href*="rubika.ir/app"]),
div[style*="z-index"][style*="position: fixed"]:not(#bb-modal-overlay):not(#bale-bridge-menu):not(.bubble):has(img[src*="banner"]),
div[style*="z-index"][style*="position: fixed"]:not(#bb-modal-overlay):not(#bale-bridge-menu):not(.bubble):has(img[src*="promo"])
{display:none!important;width:0!important;height:0!important;overflow:hidden!important;pointer-events:none!important;}
`;
(document.head||document.documentElement).appendChild(_adCSS);

// DOM cleaner: remove ad iframes and scripts injected after load
document.addEventListener("DOMContentLoaded",()=>{
const _adDomains=["yektanet","tapsell","adro.ir","google-analytics","googletagmanager","doubleclick","googlesyndication","adservice"];
const _adObs=new MutationObserver(muts=>{for(const m of muts){for(const n of m.addedNodes){if(n.nodeType!==1)continue;
// Kill ad iframes
if(n.tagName==="IFRAME"){const s=n.src||"";if(_adDomains.some(d=>s.includes(d))){n.remove();continue;}}
// Kill ad scripts
if(n.tagName==="SCRIPT"){const s=n.src||n.textContent||"";if(_adDomains.some(d=>s.includes(d))){n.remove();continue;}}
// Kill elements with ad classes
const cl=n.className||"";const id=n.id||"";
if(/\b(ads?[-_]|[-_]ads?|advert|banner.?ad|promo|sponsor|tabligh|tebligh)\b/i.test(cl+id)){n.remove();}
}}});
_adObs.observe(document.body,{childList:true,subtree:true});
});

// ── E2E ENCRYPTION (deferred to DOM ready) ──
function _rbInitEnc(){
!function(){"use strict";

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
const _C = crypto, _S = crypto.subtle;

function u8(ab){ const v=new Uint8Array(ab),c=new Uint8Array(v.length);c.set(v);return c; }
function toB64(buf){ let b="";const a=buf instanceof Uint8Array?buf:new Uint8Array(buf);for(let i=0;i<a.byteLength;i++)b+=String.fromCharCode(a[i]);return btoa(b).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,""); }
function fromB64(s){ let c=s.replace(/[^A-Za-z0-9\-_]/g,"").replace(/-/g,"+").replace(/_/g,"/");c+="=".repeat((4-(c.length%4))%4);const b=atob(c),a=new Uint8Array(b.length);for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a; }
function fromLegacyB64(s){ let c=s.replace(/[^A-Za-z0-9\-_.+/=]/g,"").replace(/-/g,"+").replace(/_/g,"/").replace(/\./g,"=").replace(/=+$/,"");c+="=".repeat((4-(c.length%4))%4);const b=atob(c),a=new Uint8Array(b.length);for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a; }
function decodeB64Smart(s){ try{const r=fromB64(s);if(r.length>0)return r;}catch(_){} try{const r=fromLegacyB64(s);if(r.length>0)return r;}catch(_){} return null; }

// ── Crypto helpers ──
async function digest(d){ return u8(await _S.digest("SHA-256",d)); }
function toHex(b){ return Array.from(b).map(x=>x.toString(16).padStart(2,"0")).join(""); }
function fromHex(h){ if(!h)return new Uint8Array(0);const a=new Uint8Array(h.length/2);for(let i=0;i<h.length;i+=2)a[i/2]=parseInt(h.substring(i,i+2),16);return a; }
function concatBytes(...a){ let t=a.reduce((s,x)=>s+x.length,0),r=new Uint8Array(t),o=0;for(const x of a){r.set(x,o);o+=x.length;}return r; }
async function getFpStr(pub){ return toHex(await digest(pub)).slice(0,8).toUpperCase(); }
async function ecSign(priv,buf){ return u8(await _S.sign({name:"ECDSA",hash:"SHA-256"},priv,buf)); }
async function ecVerify(pubRaw,sig,buf){ try{const p=await _S.importKey("raw",pubRaw,{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);return await _S.verify({name:"ECDSA",hash:"SHA-256"},p,sig,buf);}catch(_){return false;} }
async function deriveSymmetric(myPrivBuf,theirPubRaw,nonce,initIdPub,respIdPub,initEphPub,respEphPub){
    const myPriv=await _S.importKey("pkcs8",myPrivBuf,{name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
    const theirPub=await _S.importKey("raw",theirPubRaw,{name:"ECDH",namedCurve:"P-256"},true,[]);
    const shared=await _S.deriveBits({name:"ECDH",public:theirPub},myPriv,256);
    const hkdfKey=await _S.importKey("raw",shared,{name:"HKDF"},false,["deriveBits"]);
    const info=concatBytes(initEphPub,respEphPub,nonce,initIdPub,respIdPub);
    const salt=u8(await _S.digest("SHA-256",concatBytes(nonce,initIdPub,respIdPub)));
    const material=u8(await _S.deriveBits({name:"HKDF",hash:"SHA-256",salt,info},hkdfKey,96*8));
    const keyMat=material.slice(0,64),hmacMat=material.slice(64,96);
    const c=CFG.CHARS,cl=c.length,mx=(cl*Math.floor(256/cl))|0,r=[];let f=0;
    for(let i=0;i<keyMat.length&&f<CFG.KEY_LEN;i++)if(keyMat[i]<mx)r[f++]=c[keyMat[i]%cl];
    if(f<CFG.KEY_LEN)throw new Error("Key Exhaustion");
    return{sessionKey:r.join(""),hmacKeyBytes:hmacMat};
}
function genKey(){ const c=CFG.CHARS,cl=c.length,mx=(cl*Math.floor(256/cl))|0,r=[];let f=0;while(f<CFG.KEY_LEN){const b=new Uint8Array(64);_C.getRandomValues(b);for(let i=0;i<64&&f<CFG.KEY_LEN;i++)if(b[i]<mx)r[f++]=c[b[i]%cl];}return r.join(""); }

// ── IndexedDB ──
function safeClone(obj){if(obj==null||typeof obj!=="object")return obj;try{return structuredClone(obj);}catch(_){}try{return JSON.parse(JSON.stringify(obj));}catch(_){}return obj;}
let _db,_memDB={identity:{},contacts:{},handshakes:{}},_useMem=false;
async function getDB(){
    if(_useMem)return null;if(_db)return _db;
    return new Promise((res,rej)=>{const rq=indexedDB.open("rubika_bridge_db",2);
    rq.onupgradeneeded=e=>{const d=e.target.result;if(e.oldVersion<2){for(const n of["identity","contacts","handshakes"])if(d.objectStoreNames.contains(n))d.deleteObjectStore(n);}for(const[n,k]of[["identity","id"],["contacts","id"],["handshakes","nonce"]])if(!d.objectStoreNames.contains(n))d.createObjectStore(n,{keyPath:k});};
    rq.onsuccess=e=>{_db=e.target.result;res(_db);};rq.onerror=()=>{_useMem=true;rej(rq.error);};});
}
async function dbOp(s,o,v){
    try{const d=await getDB();if(!d)throw 0;return new Promise((res,rej)=>{const tx=d.transaction(s,o==="get"||o==="getAll"?"readonly":"readwrite"),st=tx.objectStore(s);let rq;if(o==="get")rq=st.get(v);else if(o==="put")rq=st.put(safeClone(v));else if(o==="del")rq=st.delete(v);else rq=st.getAll();rq.onsuccess=()=>{try{res(rq.result!=null&&typeof rq.result==="object"?safeClone(rq.result):rq.result);}catch(_){res(rq.result);}};rq.onerror=()=>rej(rq.error);});
    }catch(_){_useMem=true;if(o==="get")return _memDB[s][v]?safeClone(_memDB[s][v]):undefined;if(o==="put"){_memDB[s][v.id||v.nonce]=safeClone(v);return v;}if(o==="del"){delete _memDB[s][v];return;}return Object.values(_memDB[s]).map(safeClone);}
}

// ── Identity & Trust ──
async function getMyId(){
    let rec=await dbOp("identity","get","self");
    if(rec&&rec.pubHex&&rec.privHex){try{const pubBuf=fromHex(rec.pubHex),privBuf=fromHex(rec.privHex);const pub=await _S.importKey("raw",pubBuf,{name:"ECDSA",namedCurve:"P-256"},true,["verify"]);const priv=await _S.importKey("pkcs8",privBuf,{name:"ECDSA",namedCurve:"P-256"},true,["sign"]);return{pub,priv,pubRaw:pubBuf,fp:await getFpStr(pubBuf)};}catch(_){}}
    const kp=await _S.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
    const pubRaw=u8(await _S.exportKey("raw",kp.publicKey)),privPkcs8=u8(await _S.exportKey("pkcs8",kp.privateKey));
    await dbOp("identity","put",{id:"self",pubHex:toHex(pubRaw),privHex:toHex(privPkcs8),createdAt:Date.now()});
    return{pub:kp.publicKey,priv:kp.privateKey,pubRaw,fp:await getFpStr(pubRaw)};
}
async function getTrustInfo(idPubRaw,chatId){
    const h=toHex(await digest(idPubRaw)),cid=h.slice(0,16),fp=h.slice(0,8).toUpperCase(),all=await dbOp("contacts","getAll");
    const ex=all.find(c=>c.id===cid);if(ex)return{state:"known",fp,cid};
    const oc=all.find(c=>c.chatId===chatId);if(oc)return{state:"changed",fp,cid,oldFp:oc.id.slice(0,8).toUpperCase()};
    return{state:"new",fp,cid};
}
let _hsLock=Promise.resolve();
function hsLock(fn){let unlock;const prev=_hsLock;_hsLock=new Promise(r=>unlock=r);return prev.then(()=>fn()).finally(()=>unlock());}
function formatError(e){if(!e)return"Unknown Error";return(e.name?e.name+": ":"")+(e.message||String(e));}
function tsBuf(){const ts=Math.floor(Date.now()/1000);return new Uint8Array([(ts>>>24)&255,(ts>>>16)&255,(ts>>>8)&255,ts&255]);}
const chatType=()=>{const h=location.hash;if(h.includes("g0"))return"group";if(h.includes("c0"))return"channel";return"dm";};
const isGroup=()=>chatType()==="group";
function stripInvisibles(s){return s.replace(/[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF\u00AD\u034F\u061C\u180E\uFFF9-\uFFFB]/g,"");}

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

function getKey() {
    let s = getSettings();
    return s.enabled && s.customKey && s.customKey.length === 32 ? s.customKey : null;
}

function isEnabled() {
    return getSettings().enabled;
}

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
    if (!text.startsWith("@@")) return text;
    let keys = getAllStoredKeys();
    if (!keys.length) return text;
    for (let k of keys) {
        try {
            let data;
            if (text.startsWith("@@+")) data = fromB64(text.slice(3));
            else data = base85decode(text.slice(2).replace(/[^\x21-\x7E]/g,""));
            if (!data || data.length < 13) continue;
            let iv = data.subarray(0, 12);
            let ct = data.subarray(12);
            let aesKey = await deriveKey(k);
            let dec = await crypto.subtle.decrypt({ name: ALGO, iv }, aesKey, ct);
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
    let data = await compress(text);
    let aesKey = await deriveKey(k);
    let enc = new Uint8Array(await crypto.subtle.encrypt({ name: ALGO, iv }, aesKey, data));
    let combined = new Uint8Array(12 + enc.length);
    combined.set(iv);
    combined.set(enc, 12);
    return "@@+" + toB64(combined);
}

async function decrypt(text) {
    if (!text.startsWith("@@")) return text;
    let k = getKey();
    if (!k) return text;
    try {
        let data;
        if (text.startsWith("@@+")) data = fromB64(text.slice(3));
        else data = base85decode(text.slice(2).replace(/[^\x21-\x7E]/g,""));
        if (!data || data.length < 13) return text;
        let iv = data.subarray(0, 12);
        let ct = data.subarray(12);
        let aesKey = await deriveKey(k);
        let dec = await crypto.subtle.decrypt({ name: ALGO, iv }, aesKey, ct);
        return await decompress(new Uint8Array(dec));
    } catch { return text; }
}

async function splitEncrypt(text) {
    let result = await encrypt(text);
    if (!result) return null;
    if (result.length <= 2000) return [result];
    let mid = Math.floor(text.length / 2);
    let splitAt = text.lastIndexOf("\n", mid);
    if (splitAt <= 0) splitAt = text.lastIndexOf(" ", mid);
    if (splitAt <= 0) splitAt = mid;
    let a = await splitEncrypt(text.slice(0, splitAt).trim());
    let b = await splitEncrypt(text.slice(splitAt).trim());
    return a && b ? [...a, ...b] : null;
}

// ── ECDH Bridge ──
function renderHS(el,text,cc,fp,trust,onAction,btnText){
    btnText=btnText||"Accept & Connect";
    const c=cc==="ac"?"#00ab80":cc==="wrn"?"#d29922":cc==="err"?"#d32f2f":"#555";
    const bg=cc==="ac"?"rgba(0,171,128,.1)":cc==="wrn"?"rgba(210,153,34,.1)":cc==="err"?"rgba(248,81,73,.1)":"rgba(0,0,0,.06)";
    let h='<div class="bb-hs-widget" style="border:1.5px solid '+c+';background:'+bg+';border-radius:10px;padding:12px;margin:6px 0;font-size:13px;line-height:1.4"><span style="display:block;font-weight:700;font-size:14px;color:'+c+'">'+escapeHtml(text)+'</span>';
    if(fp){h+='<div style="font-family:monospace;font-size:11.5px;margin:4px 0;font-weight:600;color:#00ab80">Fingerprint: '+escapeHtml(fp)+'</div>';h+='<div style="color:'+(trust&&trust.includes("\u26a0")?"#d32f2f":"#555")+';font-weight:500;margin-bottom:'+(onAction?"8px":"0")+'">'+escapeHtml(trust||"")+'</div>';}
    if(onAction)h+='<button class="bb-hs-btn" style="display:inline-block;border:none;padding:7px 14px;border-radius:8px;cursor:pointer;font-weight:600;font-size:13px;background:'+c+';color:#fff">'+escapeHtml(btnText)+'</button>';
    h+='</div>';
    // Instead of replacing innerHTML (Angular overwrites it), hide the rb-copyable
    // and inject widget as a sibling that Angular can't touch
    el.style.display="none";
    el._hsProcessed=true;
    // Remove any previous widget sibling
    let prev=el.parentElement&&el.parentElement.querySelector(".bb-hs-widget");
    if(prev)prev.remove();
    // Insert widget after the hidden rb-copyable
    let widget=document.createElement("div");
    widget.innerHTML=h;
    widget=widget.firstChild;
    el.parentElement.insertBefore(widget,el.nextSibling);
    if(onAction){const btn=widget.querySelector(".bb-hs-btn");if(btn)btn.onclick=e=>{e.preventDefault();e.stopPropagation();btn.disabled=true;btn.innerText="Processing...";onAction();};}
}
function toast(m,d){d=d||CFG.TOAST_MS;const el=document.createElement("div");el.textContent=m;Object.assign(el.style,{position:"fixed",bottom:"80px",left:"50%",transform:"translateX(-50%)",background:"rgba(0,0,0,.85)",color:"#fff",padding:"10px 22px",borderRadius:"12px",fontSize:"13px",zIndex:"9999999",opacity:"0",pointerEvents:"none",transition:"opacity .2s",whiteSpace:"nowrap"});document.body.appendChild(el);requestAnimationFrame(()=>{el.style.opacity="1";});setTimeout(()=>{el.style.opacity="0";setTimeout(()=>el.remove(),250);},d);}

async function sendViaBridge(text){
    // Use the exposed injectAndSend which properly handles isBypass flag
    if(window._bbInjectAndSend){
        await window._bbInjectAndSend(text);
    } else {
        // Fallback if injectUI hasn't run yet — inject directly
        let ta=findTextarea();if(!ta)return;
        ta.focus();
        document.execCommand("selectAll",false,null);
        document.execCommand("insertText",false,text);
        ta.dispatchEvent(new Event("input",{bubbles:true}));
        await delay(200);
        let btn=findSendButton();
        if(btn){btn.click();}
        await delay(300);
        ta.focus();document.execCommand("selectAll",false,null);
        document.execCommand("insertText",false,"");
        ta.dispatchEvent(new Event("input",{bubbles:true}));
    }
}

async function startBridge(){
    const id=await getMyId(),eph=await _S.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
    const ephPub=u8(await _S.exportKey("raw",eph.publicKey)),ephPriv=u8(await _S.exportKey("pkcs8",eph.privateKey));
    const nonce=new Uint8Array(16);_C.getRandomValues(nonce);
    const payload=concatBytes(new Uint8Array([1,1]),nonce,tsBuf(),id.pubRaw,ephPub);
    const sig=await ecSign(id.priv,payload),msg=concatBytes(payload,sig);
    const hsRec={nonce:toHex(nonce),chatId:getChatId(),role:"initiator",stage:"invited",ephPrivHex:toHex(ephPriv),ephPubHex:toHex(ephPub),initIdPubHex:toHex(id.pubRaw),theirIdentityKeyHex:null,createdAt:Date.now(),payloadHashHex:toHex(await digest(payload)),chatType:chatType()};
    if(isGroup())hsRec.groupKey=genKey();
    await dbOp("handshakes","put",hsRec);
    const hsB64=toB64(msg);
    const hsSnippet=hsB64.slice(0,16);
    await sendViaBridge(CFG.PFX_H+" "+hsB64);toast(isGroup()?"Group bridge invite sent!":"Bridge invite sent!");refreshUI();
    // Poll for the !! node and render widget directly
    let pollCount=0;
    const pollForHS=setInterval(()=>{
        if(++pollCount>50){clearInterval(pollForHS);return;} // 10 seconds
        const nodes=document.querySelectorAll("div[rb-copyable]");
        for(const n of nodes){
            const raw=n.textContent;
            if(raw&&raw.includes("!!")&&raw.includes(hsSnippet)){
                renderHS(n,"\ud83d\udd04 Bridge invite sent","txM");
                clearInterval(pollForHS);
                return;
            }
        }
    },200);
}
async function acceptBridge(data,el){
    const id=await getMyId(),eph=await _S.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
    const ephPub=u8(await _S.exportKey("raw",eph.publicKey)),ephPriv=u8(await _S.exportKey("pkcs8",eph.privateKey));
    const{sessionKey,hmacKeyBytes}=await deriveSymmetric(ephPriv,data.theirEphPubRaw,data.nonce,data.theirIdPubRaw,id.pubRaw,data.theirEphPubRaw,ephPub);
    const payload=concatBytes(new Uint8Array([1,2]),data.nonce,tsBuf(),data.payloadHash,id.pubRaw,ephPub);
    const sig=await ecSign(id.priv,payload),msg=concatBytes(payload,sig);
    await dbOp("handshakes","put",{nonce:toHex(data.nonce),chatId:getChatId(),role:"responder",stage:"accepted",derivedKey:sessionKey,hmacKeyHex:toHex(hmacKeyBytes),theirIdentityKeyHex:toHex(data.theirIdPubRaw),createdAt:Date.now()});
    renderHS(el,"\ud83d\udd04 Bridge accepted — waiting for confirmation","wrn");
    await sendViaBridge(CFG.PFX_H+" "+toB64(msg));
}
async function processAccept(data,hs,el){
    const id=await getMyId();
    const hsNonce=fromHex(hs.nonce),hsInitPub=fromHex(hs.initIdPubHex),hsEphPub=fromHex(hs.ephPubHex),myPriv=fromHex(hs.ephPrivHex);
    const{sessionKey,hmacKeyBytes}=await deriveSymmetric(myPriv,data.theirEphPubRaw,hsNonce,hsInitPub,data.theirIdPubRaw,hsEphPub,data.theirEphPubRaw);
    const hmacKey=await _S.importKey("raw",hmacKeyBytes,{name:"HMAC",hash:"SHA-256"},false,["sign"]);
    const hmacVal=u8(await _S.sign("HMAC",hmacKey,concatBytes(new Uint8Array([0x63,0x6f,0x6e,0x66]),hsNonce)));
    const useGK=hs.chatType==="group"&&hs.groupKey;
    const activeKey=useGK?hs.groupKey:sessionKey;
    let payload,encBlob;
    if(useGK){const pw=await _S.importKey("raw",new TextEncoder().encode(sessionKey),{name:"AES-GCM"},false,["encrypt"]);const iv=new Uint8Array(12);_C.getRandomValues(iv);const ct=u8(await _S.encrypt({name:"AES-GCM",iv},pw,new TextEncoder().encode(hs.groupKey)));encBlob=concatBytes(iv,ct);payload=concatBytes(new Uint8Array([1,4]),hsNonce,tsBuf(),hmacVal,encBlob);}
    else{payload=concatBytes(new Uint8Array([1,3]),hsNonce,tsBuf(),hmacVal);}
    const sig=await ecSign(id.priv,payload),msg=concatBytes(payload,sig);
    await dbOp("contacts","put",{id:data.cid,chatId:getChatId(),pubHex:toHex(data.theirIdPubRaw),lastSeen:Date.now()});
    delete hs.ephPrivHex;hs.derivedKey=sessionKey;hs.stage="confirmed";await dbOp("handshakes","put",hs);
    // Send confirmation FIRST, then apply key — so we don't encrypt before other side has the key
    await sendViaBridge(CFG.PFX_H+" "+toB64(msg));
    saveSettings({enabled:true,customKey:activeKey});
    refreshUI();renderHS(el,useGK?"\u2705 Group bridge — key delivered":"\u2705 Bridge established","ac");
}
async function processConfirm(data,hs,el){
    const hmacKey=await _S.importKey("raw",fromHex(hs.hmacKeyHex),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
    const expected=u8(await _S.sign("HMAC",hmacKey,concatBytes(new Uint8Array([0x63,0x6f,0x6e,0x66]),fromHex(hs.nonce))));
    if(toHex(data.hmac)!==toHex(expected))throw new Error("HMAC Verification Failed");
    saveSettings({enabled:true,customKey:hs.derivedKey});
    const fp=await getTrustInfo(fromHex(hs.theirIdentityKeyHex),getChatId());
    await dbOp("contacts","put",{id:fp.cid,chatId:getChatId(),pubHex:hs.theirIdentityKeyHex,lastSeen:Date.now()});
    delete hs.hmacKeyHex;hs.stage="confirmed";await dbOp("handshakes","put",hs);
    refreshUI();renderHS(el,"\u2705 Bridge established","ac");
}
async function processGroupConfirm(data,hs,el){
    const hmacKey=await _S.importKey("raw",fromHex(hs.hmacKeyHex),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
    const expected=u8(await _S.sign("HMAC",hmacKey,concatBytes(new Uint8Array([0x63,0x6f,0x6e,0x66]),fromHex(hs.nonce))));
    if(toHex(data.hmac)!==toHex(expected))throw new Error("HMAC Verification Failed");
    const pw=await _S.importKey("raw",new TextEncoder().encode(hs.derivedKey),{name:"AES-GCM"},false,["decrypt"]);
    const gkIv=data.encBlob.slice(0,12),gkCt=data.encBlob.slice(12);
    const groupKey=new TextDecoder().decode(u8(await _S.decrypt({name:"AES-GCM",iv:gkIv},pw,gkCt)));
    if(groupKey.length!==CFG.KEY_LEN)throw new Error("Invalid group key length");
    saveSettings({enabled:true,customKey:groupKey});
    const fp=await getTrustInfo(fromHex(hs.theirIdentityKeyHex),getChatId());
    await dbOp("contacts","put",{id:fp.cid,chatId:getChatId(),pubHex:hs.theirIdentityKeyHex,lastSeen:Date.now()});
    delete hs.hmacKeyHex;hs.stage="confirmed";hs.groupKey=groupKey;await dbOp("handshakes","put",hs);
    refreshUI();renderHS(el,"\u2705 Group bridge established","ac");
}
async function handleHandshake(b64,el){
    if(el._hsProcessed)return;
    try{
        const bytes=decodeB64Smart(b64);if(!bytes||bytes.length<118)return;
        const ver=bytes[0],type=bytes[1];if(ver!==1)return;
        const nonce=bytes.slice(2,18),hexNonce=toHex(nonce);
        const myId=await getMyId(),hs=await dbOp("handshakes","get",hexNonce);
        if(type===1){
            if(bytes.length!==216)return;
            const payload=bytes.slice(0,152),sig=bytes.slice(152,216),idPub=bytes.slice(22,87),ephPub=bytes.slice(87,152);
            if(!await ecVerify(idPub,sig,payload))return;
            if(toHex(idPub)===toHex(myId.pubRaw))return renderHS(el,"\ud83d\udd04 Bridge invite sent","txM");
            if(hs){if(hs.stage==="accepted")return renderHS(el,"\ud83d\udd04 Waiting for confirmation","wrn");if(hs.stage==="confirmed")return renderHS(el,"\u2705 Bridge established","ac");return renderHS(el,"\ud83e\udd1d Processed","txM");}
            const trust=await getTrustInfo(idPub,getChatId()),hsList=await dbOp("handshakes","getAll");
            const out=hsList.find(h=>h.chatId===getChatId()&&h.role==="initiator"&&h.stage==="invited");
            if(out){if(myId.fp<trust.fp)return renderHS(el,"\ud83e\udd1d Collision avoided","txM");else if(myId.fp>trust.fp)await dbOp("handshakes","del",out.nonce);else return;}
            const tStr=trust.state==="new"?"\ud83c\udd95 New contact":trust.state==="known"?"\u2705 Known contact":"\u26a0\ufe0f IDENTITY CHANGED — old: "+trust.oldFp+", new: "+trust.fp;
            renderHS(el,isGroup()?"\ud83d\udee1\ufe0f Group Bridge Request":"\ud83d\udee1\ufe0f Secure Bridge Request","ac",trust.fp,tStr,async()=>{
                try{await acceptBridge({nonce,theirIdPubRaw:idPub,theirEphPubRaw:ephPub,payloadHash:await digest(payload)},el);}catch(e){renderHS(el,"\u274c "+formatError(e),"err");}
            },isGroup()?"Join Group Bridge":"Accept & Connect");
        }else if(type===2){
            if(bytes.length!==248)return;
            const payload=bytes.slice(0,184),sig=bytes.slice(184,248),invHash=bytes.slice(22,54),idPub=bytes.slice(54,119),ephPub=bytes.slice(119,184);
            if(!await ecVerify(idPub,sig,payload))return;
            if(toHex(idPub)===toHex(myId.pubRaw))return renderHS(el,"\ud83d\udd04 Bridge accept sent","txM");
            if(!hs||hs.role!=="initiator"||hs.stage!=="invited"){if(hs&&hs.stage==="confirmed")return renderHS(el,"\u2705 Bridge established","ac");return renderHS(el,"\ud83e\udd1d Processed","txM");}
            if(toHex(invHash)!==toHex(fromHex(hs.payloadHashHex)))return;
            const trust=await getTrustInfo(idPub,getChatId());
            const doAccept=async()=>{try{await processAccept({nonce,theirIdPubRaw:idPub,theirEphPubRaw:ephPub,fp:trust.fp,cid:trust.cid},hs,el);}catch(e){renderHS(el,"\u274c "+formatError(e),"err");}};
            if(trust.state==="changed")renderHS(el,"\u26a0\ufe0f Identity Changed!","err",trust.fp,"Old: "+trust.oldFp+", New: "+trust.fp,doAccept,"Acknowledge & Connect");
            else{renderHS(el,"\u2705 Bridge completing...","ac");await doAccept();}
        }else if(type===3){
            if(bytes.length!==118)return;
            const hmac=bytes.slice(22,54),sig=bytes.slice(54,118);
            if(hs&&hs.role==="responder"&&hs.stage==="accepted"){
                if(!await ecVerify(fromHex(hs.theirIdentityKeyHex),sig,bytes.slice(0,54)))return;
                try{await processConfirm({hmac},hs,el);}catch(e){renderHS(el,"\u274c "+formatError(e),"err");}
            }else{if(hs&&hs.stage==="confirmed")return renderHS(el,"\u2705 Bridge established","ac");renderHS(el,"\ud83e\udd1d Processed","txM");}
        }else if(type===4){
            if(bytes.length<178)return;
            const hmac=bytes.slice(22,54),encBlob=bytes.slice(54,bytes.length-64);
            const payload=bytes.slice(0,bytes.length-64),sig=bytes.slice(bytes.length-64);
            if(hs&&hs.role==="responder"&&hs.stage==="accepted"){
                if(!await ecVerify(fromHex(hs.theirIdentityKeyHex),sig,payload))return;
                try{await processGroupConfirm({hmac,encBlob},hs,el);}catch(e){renderHS(el,"\u274c "+formatError(e),"err");}
            }else{if(hs&&hs.stage==="confirmed")return renderHS(el,"\u2705 Group bridge established","ac");renderHS(el,"\ud83e\udd1d Processed","txM");}
        }
    }catch(e){renderHS(el,"\u274c "+formatError(e),"err");}
}

function escapeHtml(s) { return s.replace(/[&<>"]/g, c => HTML_ESC[c]); }

function renderInline(s) {
    return s
        .replace(/``([^`]+)``|`([^`]+)`/g, (_, a, b) =>
            `<code style="background:#1b2028;color:#e6edf3;border-radius:4px;padding:1px 5px;font-family:monospace;font-size:.9em">${a ?? b}</code>`)
        .replace(/\|\|(.+?)\|\|/g, (_, t) =>
            `<span class="bb-spoiler" style="background:#42526e;color:transparent;border-radius:3px;padding:0 3px;cursor:pointer;user-select:none" title="Click to reveal">${t}</span>`)
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
        // Fenced code blocks
        if (/^```/.test(line)) {
            let lang = line.slice(3).trim();
            i++;
            let code = [];
            while (i < lines.length && !/^```\s*$/.test(lines[i])) code.push(lines[i++]);
            if (i < lines.length) i++;
            let langTag = lang ? `<div style="padding:4px 10px;font-size:10px;font-weight:600;color:#8b949e;background:#161b22;border-bottom:1px solid #30363d;text-transform:uppercase;letter-spacing:.04em">${escapeHtml(lang)}</div>` : "";
            result.push(`<div style="position:relative;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:8px;margin:4px 0;overflow:hidden">${langTag}<pre style="margin:0;padding:10px 12px;overflow-x:auto;font-family:monospace;font-size:12.5px;line-height:1.5;white-space:pre;tab-size:4;color:#e6edf3"><code>${escapeHtml(code.join("\n"))}</code></pre><span class="bb-cblk-copy" title="Copy" style="position:absolute;top:4px;right:8px;cursor:pointer;font-size:12px;opacity:.6;color:#8b949e">\ud83d\udccb</span></div>`);
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
        // Markdown tables: | col | col |
        if (/^\|(.+\|)+\s*$/.test(line) && i + 1 < lines.length && /^\|[\s:-]+\|/.test(lines[i+1])) {
            let headerCells = line.split("|").filter(c => c.trim()).map(c => `<th style="padding:4px 10px;text-align:left;font-weight:600;border-bottom:2px solid rgba(0,0,0,.15)">${renderWithUrls(c.trim())}</th>`);
            i += 2; // skip header + separator
            let rows = [];
            while (i < lines.length && /^\|(.+\|)+\s*$/.test(lines[i])) {
                let cells = lines[i].split("|").filter(c => c.trim()).map(c => `<td style="padding:4px 10px;border-bottom:1px solid rgba(0,0,0,.08)">${renderWithUrls(c.trim())}</td>`);
                rows.push(`<tr>${cells.join("")}</tr>`);
                i++;
            }
            result.push(`<table style="border-collapse:collapse;margin:4px 0;font-size:inherit;width:100%;max-width:100%;overflow-x:auto;display:block"><thead><tr>${headerCells.join("")}</tr></thead><tbody>${rows.join("")}</tbody></table>`);
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
    let counter = document.getElementById("bb-key-counter");
    let error = document.getElementById("bb-key-error");
    let saveBtn = document.getElementById("bb-btn-save");
    let enableChk = document.getElementById("bb-enable-enc");
    let copyBtn = document.getElementById("bb-copy-key");
    let genBtn = document.getElementById("bb-gen-key");
    let visBtn = document.getElementById("bb-toggle-vis");

    let _ig = isGroup();
    if(_ig) document.getElementById("bb-bridge-desc").textContent = "Start a group bridge — each member joins individually.";

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
            if(ahs){bridgeBtn.textContent="\ud83d\udd04 Waiting for response... (Cancel)";bridgeBtn.style.color="#d29922";bridgeBtn.onclick=async()=>{await dbOp("handshakes","del",ahs.nonce);updateBridgeUI();};}
            else{const ch=hsList.find(h=>h.chatId===getChatId()&&h.stage==="confirmed"&&(h.derivedKey===keyInput.value||h.groupKey===keyInput.value));
            if(ch&&keyInput.value.length===CFG.KEY_LEN){bridgeBtn.textContent=_ig?"\u2705 Group bridge active (Re-key)":"\u2705 Connected via Bridge (Re-key)";bridgeBtn.style.color="#00ab80";}
            else{bridgeBtn.textContent=_ig?"\ud83e\udd1d Start Group Bridge":"\ud83e\udd1d Start Bridge";bridgeBtn.style.color="inherit";}
            bridgeBtn.onclick=async()=>{overlay.remove();try{await startBridge();}catch(_){toast("Bridge error!");}};}
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
    overlay.onclick = e => { if(e.target===overlay) overlay.remove(); };
    saveBtn.onclick = () => {
        if (saveBtn.disabled) return;
        saveSettings({ enabled: enableChk.checked, customKey: keyInput.value });
        overlay.remove();
        refreshUI();
    };
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

    // Manage blocker overlay — sits on top of native input, makes it untouchable
    let blocker = document.getElementById("rb-input-blocker");
    if (!blocker && hideTarget) {
        blocker = document.createElement("div");
        blocker.id = "rb-input-blocker";
        // Make the native input's container position:relative so blocker positions correctly
        if (hideTarget.parentElement) hideTarget.parentElement.style.position = "relative";
        hideTarget.parentElement.insertBefore(blocker, hideTarget);
        blocker.addEventListener("click", () => {
            let ov = document.getElementById("secure-input-overlay");
            if (ov) ov.focus();
        });
        blocker.addEventListener("mousedown", e => { e.preventDefault(); e.stopPropagation(); });
        blocker.addEventListener("touchstart", e => { e.preventDefault(); e.stopPropagation(); }, {passive:false});
    }

    // Kill native input completely when encryption is on
    let composer = textarea ? textarea.querySelector(".composer_rich_textarea") || textarea : null;
    function lockNative() {
        if (hideTarget) hideTarget.classList.add("rb-locked-input");
        if (composer) { composer.contentEditable = "false"; composer.tabIndex = -1; }
        if (textarea) { textarea.tabIndex = -1; }
        if (inputWrapper) { inputWrapper.tabIndex = -1; }
    }
    function unlockNative() {
        if (hideTarget) hideTarget.classList.remove("rb-locked-input");
        if (composer) { composer.contentEditable = "true"; composer.removeAttribute("tabindex"); }
        if (textarea) { textarea.removeAttribute("tabindex"); }
        if (inputWrapper) { inputWrapper.removeAttribute("tabindex"); }
    }

    if (on) {
        if (hasKey) {
            lockNative();
            if (overlay) overlay.style.display = "";
            if (notice) notice.style.display = "none";
            if (blocker) blocker.style.display = "block";
        } else {
            lockNative();
            if (overlay) overlay.style.display = "none";
            if (notice) notice.style.display = "flex";
            if (blocker) blocker.style.display = "block";
        }
    } else {
        unlockNative();
        if (overlay) overlay.style.display = "none";
        if (notice) notice.style.display = "none";
        if (blocker) blocker.style.display = "none";
    }
}

let isSending = false;
let hasContent = false;
let isBypass = false;

function overlayHasContent() {
    let el = document.getElementById("secure-input-overlay");
    return !!el && !!(el.value||el.innerText||"").trim();
}

function isSendTarget(el) {
    return !!el.closest(".btn-send-container") || !!el.closest(".btn-send") ||
           (el.classList && (el.classList.contains("btn-send") || el.classList.contains("btn-send-container")));
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

// Draft blocker moved to connectivity fix (document-start) for correct timing

document.head.insertAdjacentHTML("beforeend", `<style>
button.toggle-emoticons { display: none !important; }

/* Outgoing bubble — Telegram-style soft green/gray */
.bubble.is-out .bubble-content {
    background-color: #eeffde !important;
}
html.night .bubble.is-out .bubble-content {
    background-color: #2b5278 !important;
}
.bubble.is-out .bubble-tail use {
    fill: #eeffde !important;
}
html.night .bubble.is-out .bubble-tail use {
    fill: #2b5278 !important;
}

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

/* Solid blocker overlay — covers native input completely */
#rb-input-blocker {
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    z-index: 99;
    background: var(--surface-color, #fff);
    cursor: text;
    user-select: none;
    -webkit-user-select: none;
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
#secure-input-overlay::placeholder {
    color: #888;
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
    if (cb) { e.preventDefault(); e.stopPropagation(); let code = cb.parentElement?.querySelector("code"); if(code) navigator.clipboard.writeText(code.textContent).then(()=>{cb.textContent="\u2705";setTimeout(()=>cb.textContent="\ud83d\udccb",1200);}).catch(()=>{}); }
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

// ── Auto-decrypt main messages ──
const _hsInfly = new WeakSet();
function decryptMessages() {
    let nodes = document.body.querySelectorAll("div[rb-copyable]");
    for (let node of nodes) {
        if (node._isDecrypting || _hsInfly.has(node)) continue;
        // If node was processed as handshake, keep it hidden (Angular may unhide)
        if (node._hsProcessed) {
            if (node.style.display !== "none") node.style.display = "none";
            continue;
        }
        let text = node.textContent.trim();
        let ct = stripInvisibles(text);

        // Detect handshake !! prefix
        let hi = ct.indexOf(CFG.PFX_H);
        if (hi !== -1 && !node._hsProcessed) {
            let raw = ct.slice(hi + CFG.PFX_H.length).trim().split(/\s+/)[0].replace(/[^A-Za-z0-9\-_]/g,"");
            if (raw.length > 50) {
                _hsInfly.add(node);
                hsLock(() => handleHandshake(raw, node).catch(e => {
                    console.error("[RB] Handshake error:", e);
                    node.innerHTML = '<div style="border:1.5px solid #d32f2f;background:rgba(248,81,73,.1);border-radius:10px;padding:12px;margin:6px 0"><span style="font-weight:700;color:#d32f2f">\u274c Bridge error: ' + (e.message||e) + '</span></div>';
                    node._hsProcessed = true;
                })).finally(() => _hsInfly.delete(node));
                continue;
            }
        }

        if (node._isDecrypted) {
            if (!ct.startsWith("@@") || node.querySelector(".bb-copy-btn")) continue;
            node._isDecrypted = false;
            node.removeAttribute("data-orig-text");
        }

        if (!ct.startsWith("@@") || ct.length <= 20) continue;

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

    // Block ALL input on every native input element when encryption is on
    // textarea = .composer_rich_textarea, inputWrapper = .input-message-input
    // Also block on .input-message-container which wraps both
    let allInputEls = [textarea, inputWrapper].filter(Boolean);
    for (let el of allInputEls) {
        if (!el || el._hasStrictHijack) continue;
        el._hasStrictHijack = true;
        el.addEventListener("focus", e => {
            if (!isBypass && isEnabled()) {
                e.preventDefault();
                try { el.blur(); } catch(_) {}
                document.getElementById("secure-input-overlay")?.focus();
            }
        }, true);
        for (const evt of ["keydown","keypress","keyup","input","beforeinput","paste","drop","compositionstart","compositionend","click"]) {
            el.addEventListener(evt, e => {
                if (!isBypass && isEnabled()) {
                    e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation();
                    if (evt === "click" || evt === "keydown") {
                        document.getElementById("secure-input-overlay")?.focus();
                    }
                }
            }, true);
        }
    }

    // Global keyboard redirect: any typing anywhere goes to secure overlay
    if (!document._rbGlobalKeyGuard) {
        document._rbGlobalKeyGuard = true;
        document.addEventListener("keydown", e => {
            if (isBypass || !isEnabled()) return;
            let ov = document.getElementById("secure-input-overlay");
            if (!ov || document.activeElement === ov) return;
            // If user is typing a printable character and not in our overlay, redirect
            if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
                e.preventDefault(); e.stopPropagation();
                ov.focus();
                // Insert the character they typed
                let start = ov.selectionStart, end = ov.selectionEnd;
                ov.value = ov.value.slice(0, start) + e.key + ov.value.slice(end);
                ov.selectionStart = ov.selectionEnd = start + 1;
                ov.dispatchEvent(new Event("input", {bubbles:true}));
            }
        }, true);
    }

    let secureInput = document.createElement("textarea");
    secureInput.id = "secure-input-overlay";
    secureInput.dir = "auto";
    secureInput.placeholder = "\ud83d\udd12 \u067e\u06cc\u0627\u0645 \u0627\u0645\u0646...";
    secureInput.rows = 1;
    secureInput.style.cssText += ";resize:none;";
    // Auto-grow height
    secureInput.addEventListener("input", () => {
        secureInput.style.height = "auto";
        secureInput.style.height = Math.min(secureInput.scrollHeight, 150) + "px";
    });

    let insertParent = inputWrapper?.parentElement || textarea.parentElement;
    let insertBefore = inputWrapper || textarea;
    insertParent.insertBefore(secureInput, insertBefore);

    ["keydown", "keypress", "keyup", "paste", "drop"].forEach(evt => {
        secureInput.addEventListener(evt, e => { e.stopPropagation(); });
    });

    function getOverlayText() { return secureInput.value.trim(); }
    function setOverlayText(t) { secureInput.value = t; secureInput.style.height = "auto"; secureInput.style.height = Math.min(secureInput.scrollHeight, 150) + "px"; }

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
        let blocker = document.getElementById("rb-input-blocker");
        if (blocker) blocker.style.display = "none";
        hideTarget.classList.remove("rb-locked-input");
        // Temporarily restore native input for injection
        let composer = textarea.querySelector(".composer_rich_textarea") || textarea;
        composer.contentEditable = "true";
        if (textarea.tabIndex === -1) textarea.removeAttribute("tabindex");
        if (inputWrapper && inputWrapper.tabIndex === -1) inputWrapper.removeAttribute("tabindex");
        hideTarget.style.cssText = "position:absolute!important;top:0!important;left:0!important;opacity:0!important;pointer-events:none!important;z-index:-1!important";

        textarea.focus();
        document.execCommand("selectAll", false, null);
        document.execCommand("insertText", false, msgText);
        textarea.dispatchEvent(new Event("input", { bubbles: true }));

        let enterEvt = { bubbles: true, cancelable: true, key: "Enter", keyCode: 13, which: 13 };
        textarea.dispatchEvent(new KeyboardEvent("keydown", enterEvt));
        textarea.dispatchEvent(new KeyboardEvent("keyup", enterEvt));

        let sendBtn = null;
        for (let attempt = 0; attempt < 10; attempt++) {
            await delay(20);
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

        await delay(100);

        textarea.focus();
        document.execCommand("selectAll", false, null);
        document.execCommand("insertText", false, "");
        textarea.dispatchEvent(new Event("input", { bubbles: true }));

        hideTarget.style.cssText = "";
        hideTarget.classList.add("rb-locked-input");
        // Relock native input completely
        composer.contentEditable = "false";
        composer.tabIndex = -1;
        if (textarea) textarea.tabIndex = -1;
        if (inputWrapper) inputWrapper.tabIndex = -1;
        if (blocker) blocker.style.display = "block";
        isBypass = false;
    }

    // Direct API send — bypasses DOM injection entirely, near-instant
    async function apiSendMessage(msgText) {
        const chatId = getChatId();
        if (!chatId || chatId === "global") throw new Error("No chat open");
        if (typeof _rApi !== "function" || !_authKey) throw new Error("API not ready");
        const r = await _rApi("sendMessage", {
            object_guid: chatId,
            text: msgText,
            rnd: Math.floor(Math.random() * 999999) + 1
        });
        if (!r || r.status !== "OK") throw new Error("API send failed: " + (r ? r.status_det || r.status : "null"));
        return true;
    }

    async function triggerSend(encrypted = true) {
        if (isSending) return;
        let text = getOverlayText();
        if (!text) return;

        // Try direct API first (instant), fallback to DOM injection (slow)
        async function sendChunks(chunks) {
            for (let chunk of chunks) {
                try {
                    await apiSendMessage(chunk);
                } catch(apiErr) {
                    console.log("[RB] API send failed, falling back to DOM:", apiErr.message);
                    await injectAndSend(chunk);
                }
            }
            return true;
        }

        if (encrypted) {
            if (!getKey()) { openSettings(); return; }
            isSending = true;
            isBypass = true;
            setOverlayText("\ud83d\udd12 Sending...");
            try {
                let chunks = await splitEncrypt(text);
                if (!chunks) { setOverlayText(text); openSettings(); return; }
                let ok = await sendChunks(chunks);
                if (ok) {
                    setOverlayText("");
                    hasContent = false;
                    syncHasContent(false);
                    secureInput.focus();
                } else {
                    setOverlayText(text);
                    toast("Send failed. Tap send to retry.");
                }
            } catch (err) {
                console.error("[RB] Encrypted send error:", err);
                setOverlayText(text);
                toast("Send failed. Tap send to retry.");
            } finally {
                isSending = false;
                isBypass = false;
            }
        } else {
            let confirm_ = confirm("\u26a0\ufe0f You are about to send this message WITHOUT encryption.\n\nThis may expose sensitive information. Are you sure?");
            if (!confirm_) return;
            isSending = true;
            isBypass = true;
            setOverlayText("\ud83c\udf10 Sending...");
            try {
                let ok = await sendChunks([text]);
                if (ok) {
                    setOverlayText("");
                    hasContent = false;
                    syncHasContent(false);
                    secureInput.focus();
                } else {
                    setOverlayText(text);
                    toast("Send failed. Tap send to retry.");
                }
            } catch (err) {
                console.error("[RB] Plain send error:", err);
                setOverlayText(text);
                toast("Send failed. Tap send to retry.");
            } finally {
                isSending = false;
                isBypass = false;
            }
        }
    }

    secureInput._triggerSend = triggerSend;
    window._bbSendMessage = triggerSend;
    window._bbInjectAndSend = injectAndSend;
    window._rbDecrypt = tryDecryptWithAllKeys;

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
                if (ov) setSendButtonState((ov.value||ov.innerText||"").trim().length > 0);
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

// Notifications now handled via WebSocket decryption in connectivity fix

// Handshake cleanup
function cleanupHs(){dbOp("handshakes","getAll").then(hs=>{const now=Date.now();hs.forEach(h=>{if(h.stage!=="confirmed"&&now-h.createdAt>CFG.HS_CLEANUP)dbOp("handshakes","del",h.nonce);});}).catch(()=>{});}
setTimeout(cleanupHs,2000);setInterval(cleanupHs,CFG.HS_CLEANUP);

}();
} // end _rbInitEnc
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",()=>setTimeout(_rbInitEnc,100));
else setTimeout(_rbInitEnc,100);
 
