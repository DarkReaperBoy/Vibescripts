// ==UserScript==
// @name         GLWiz Premium Web Player
// @namespace    http://tampermonkey.net/
// @version      5.0
// @description  The ultimate glwiz premium viewing experience. Features a sleek responsive UI, advanced native player with quality/speed controls, PiP, screenshot, seamless layouts, and Live DVR caching.
// @author       You
// @match        *://www.glwiz.com/
// @match        *://www.glwiz.com/Pages/Player/Player.aspx*
// @run-at       document-start
// @grant        none
// ==/UserScript==

(function () {
    'use strict';

    /* Redirect to Player Page */
    if (location.pathname === '/' || location.pathname === '') {
        location.replace('/Pages/Player/Player.aspx');
        return;
    }

    /* Block Original Assets & Prevent Flash */
    const hideStyles = document.createElement('style');
    hideStyles.textContent = `
        html, body { background: #09090b !important; }
        body > *:not(#GZ) { position: fixed !important; top: -9999px !important; opacity: 0 !important; pointer-events: none !important; z-index: -1 !important; }
    `;
    document.documentElement.appendChild(hideStyles);
    const observer = new MutationObserver(muts => {
        for (const m of muts) for (const n of m.addedNodes) if (n.tagName === 'IMG' && (!n.closest || !n.closest('#GZ'))) { n.removeAttribute('src'); n.remove(); }
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });

    document.addEventListener('DOMContentLoaded', () => {
        /* App State & Persistence */
        const LS_KEY = 'gz_pro_data';
        const defData = { favs:[], hidden:[], cfg: { player: 'native', layout: 'compact', fit: 'contain', theme: '#e05555', useCdn: false, pipHide: false } };
        let localData = { ...defData };
        try { const d = localStorage.getItem(LS_KEY); if(d) { const p = JSON.parse(d); localData = { ...defData, ...p, cfg: {...defData.cfg, ...(p.cfg||{})} }; } } catch(e){}

        const S = {
            chs:[], genres: {}, cur: null, cat: 'all', q: '',
            favs: new Set(localData.favs), hidden: new Set(localData.hidden), cfg: localData.cfg
        };
        const save = () => localStorage.setItem(LS_KEY, JSON.stringify({ favs:[...S.favs], hidden:[...S.hidden], cfg: S.cfg }));

        let hlsNative = null, artInst = null;

        /* Core UI Styles */
        document.head.insertAdjacentHTML('beforeend', `<style>
        :root { --a: ${S.cfg.theme}; --bg: #09090b; --surf: #18181b; --surf-hov: #27272a; --border: rgba(255,255,255,0.08); --text: #f4f4f5; --sub: #a1a1aa; }
        * { box-sizing: border-box; font-family: system-ui, -apple-system, sans-serif; }
        html, body { margin:0; padding:0!important; overflow:hidden!important; height:100%!important; background:var(--bg)!important; color:var(--text); }
        ::-webkit-scrollbar { width:6px; } ::-webkit-scrollbar-thumb { background:var(--surf-hov); border-radius:3px; }

        #GZ { position:fixed; inset:0; z-index:9999999; display:flex; flex-direction:column; background:var(--bg); height:100dvh; max-width:100vw; overflow:hidden; }
        .gz-v { display:none; flex:1; flex-direction:column; min-height:0; position:relative; }
        .gz-v.on { display:flex; }
        @keyframes fadeUp { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }
        @keyframes fadeIn { from { opacity:0; } to { opacity:1; } }

        /* Top Bar */
        .gz-bar { display:flex; align-items:center; padding:0 16px; height:60px; background:rgba(24,24,27,0.8); backdrop-filter:blur(12px); border-bottom:1px solid var(--border); gap:16px; flex-shrink:0; z-index:50; }
        .gz-btn-icon { background:transparent; border:none; color:var(--sub); cursor:pointer; padding:8px; display:flex; align-items:center; justify-content:center; border-radius:8px; transition:0.2s; }
        .gz-btn-icon:hover { background:var(--surf-hov); color:var(--text); }
        .gz-btn-icon svg { width:22px; height:22px; fill:currentColor; }
        .gz-logo { font-size:20px; font-weight:700; margin:0; letter-spacing:0.5px; flex-shrink:0; display:flex; align-items:center; gap:6px; }
        .gz-logo b { color:var(--a); }
        .gz-sr-wrap { flex:1; display:flex; justify-content:flex-end; }
        .gz-sr { display:flex; align-items:center; gap:8px; background:var(--surf); border:1px solid var(--border); border-radius:20px; height:40px; padding:0 16px; width:100%; max-width:360px; transition:0.2s; }
        .gz-sr:focus-within { border-color:var(--a); box-shadow:0 0 0 3px rgba(224,85,85,0.15); }
        .gz-sr svg { width:18px; height:18px; color:var(--sub); flex-shrink:0; }
        .gz-si { flex:1; background:none; border:none; outline:none; font-size:14px; color:var(--text); width:100%; }

        /* Navigation Drawer */
        .gz-main { display:flex; flex:1; overflow:hidden; position:relative; }
        .gz-drawer { width:240px; background:var(--surf); border-right:1px solid var(--border); display:flex; flex-direction:column; overflow-y:auto; flex-shrink:0; transition:transform 0.3s cubic-bezier(0.4,0,0.2,1); z-index:40; }
        .gz-dr-backdrop { display:none; position:absolute; inset:0; background:rgba(0,0,0,0.5); backdrop-filter:blur(2px); z-index:39; opacity:0; transition:0.3s; }
        .gz-dr-item { display:flex; align-items:center; gap:14px; padding:12px 20px; color:var(--sub); cursor:pointer; transition:0.2s; font-size:14px; font-weight:500; border-left:3px solid transparent; user-select:none; }
        .gz-dr-item svg { width:20px; height:20px; fill:currentColor; flex-shrink:0; }
        .gz-dr-item:hover { background:var(--surf-hov); color:var(--text); }
        .gz-dr-item.active { background:rgba(224,85,85,0.08); color:var(--a); border-left-color:var(--a); font-weight:600; }
        .gz-dr-div { height:1px; background:var(--border); margin:8px 0; }
        .gz-dr-title { padding:12px 20px 4px; font-size:11px; text-transform:uppercase; color:var(--sub); font-weight:700; letter-spacing:1px; }

        /* Dynamic Grid Layout */
        .gz-grid-wrap { flex:1; overflow-y:auto; padding:20px; scroll-behavior:smooth; }
        .gz-grid { display:grid; gap:12px; align-content:start; grid-template-columns:repeat(auto-fill, minmax(140px, 1fr)); }
        .gz-grid.list { grid-template-columns:1fr; gap:8px; }

        /* Channel Card */
        .gz-card { background:var(--surf); border:1px solid var(--border); border-radius:12px; overflow:hidden; cursor:pointer; display:flex; flex-direction:column; transition:0.2s; animation:fadeUp 0.3s ease-out both; position:relative; }
        .gz-card:hover { transform:translateY(-4px); border-color:var(--a); box-shadow:0 12px 24px rgba(0,0,0,0.4); }
        .gz-grid.list .gz-card { flex-direction:row; align-items:center; }
        .gz-cthumb { width:100%; aspect-ratio:16/9; position:relative; background:linear-gradient(135deg, #0f0f12, #1a1a1e); border-bottom:1px solid var(--border); overflow:hidden; display:flex; align-items:center; justify-content:center; }
        .gz-grid.list .gz-cthumb { width:120px; border-bottom:none; border-right:1px solid var(--border); }
        .gz-cthumb img { position:absolute; inset:0; width:100%; height:100%; object-fit:contain; padding:12%; transform:scale(1.05); transition:0.3s; }
        .gz-card:hover .gz-cthumb img { transform:scale(1.15); }
        .gz-cbody { padding:14px; flex:1; display:flex; flex-direction:column; justify-content:center; min-width:0; }
        .gz-cname { font-size:14px; font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .gz-cnum { font-size:12px; color:var(--sub); margin-top:6px; font-weight:500; display:flex; justify-content:space-between; align-items:center; }
        .gz-badge-fav { color:#f59e0b; font-size:14px; }

        /* Overlays & Modals */
        .gz-ctx { position:absolute; background:rgba(24,24,27,0.95); backdrop-filter:blur(12px); border:1px solid var(--border); border-radius:10px; padding:6px; min-width:180px; display:none; flex-direction:column; gap:2px; z-index:9999; box-shadow:0 10px 30px rgba(0,0,0,0.6); animation:fadeIn 0.15s; }
        .gz-ctx.on { display:flex; }
        .gz-ctx-btn { background:none; border:none; color:var(--text); padding:10px 14px; text-align:left; font-size:13px; font-weight:500; cursor:pointer; border-radius:6px; transition:0.2s; display:flex; align-items:center; gap:10px; }
        .gz-ctx-btn:hover { background:var(--surf-hov); }
        .gz-ctx-btn svg { width:16px; height:16px; fill:currentColor; opacity:0.8; }

        .gz-modal-wrap { position:fixed; inset:0; background:rgba(0,0,0,0.7); backdrop-filter:blur(6px); display:none; align-items:center; justify-content:center; z-index:99999; }
        .gz-modal-wrap.on { display:flex; animation:fadeIn 0.2s; }
        .gz-modal { background:var(--surf); border:1px solid var(--border); width:90%; max-width:440px; border-radius:16px; overflow:hidden; box-shadow:0 20px 40px rgba(0,0,0,0.6); animation:fadeUp 0.3s ease-out; }
        .gz-m-head { padding:16px 24px; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; font-weight:600; font-size:16px; background:rgba(255,255,255,0.02); }
        .gz-m-body { padding:24px; display:flex; flex-direction:column; gap:20px; max-height:70vh; overflow-y:auto; }
        .gz-m-row { display:flex; justify-content:space-between; align-items:center; gap:16px; }
        .gz-m-label { font-size:14px; color:var(--text); font-weight:500; display:flex; flex-direction:column; gap:4px; }
        .gz-m-hint { font-size:11px; color:var(--sub); font-weight:400; }
        .gz-m-select { background:var(--bg); color:var(--text); border:1px solid var(--border); padding:8px 12px; border-radius:8px; outline:none; font-size:13px; cursor:pointer; flex-shrink:0; }
        .gz-m-switch { position:relative; width:44px; height:24px; background:var(--bg); border-radius:12px; border:1px solid var(--border); cursor:pointer; transition:0.3s; flex-shrink:0; }
        .gz-m-switch::after { content:''; position:absolute; top:2px; left:2px; width:18px; height:18px; background:var(--sub); border-radius:50%; transition:0.3s; }
        .gz-m-switch.on { background:var(--a); border-color:var(--a); }
        .gz-m-switch.on::after { transform:translateX(20px); background:#fff; }
        .gz-btn-theme { width:26px; height:26px; border-radius:50%; border:2px solid transparent; cursor:pointer; display:inline-block; margin-left:8px; transition:0.2s; }
        .gz-btn-theme.active { border-color:#fff; transform:scale(1.15); box-shadow:0 0 10px currentColor; }
        .gz-m-btn-danger { background:rgba(224,85,85,0.1); color:#e05555; border:1px solid rgba(224,85,85,0.3); padding:10px 16px; border-radius:8px; cursor:pointer; font-size:13px; font-weight:600; width:100%; transition:0.2s; }
        .gz-m-btn-danger:hover { background:#e05555; color:#fff; }

        /* High-Visibility Native Player */
        #gz-stage-native, #gz-stage-art { flex:1; position:relative; background:#000; overflow:hidden; display:none; }
        #gz-stage-native.on, #gz-stage-art.on { display:block; }
        #gz-vid { width:100%; height:100%; object-fit:var(--fit, contain); background:#000; display:block; }
        .gz-p-ov { position:absolute; inset:0; display:flex; flex-direction:column; justify-content:space-between; opacity:1; transition:opacity 0.4s; pointer-events:none; }
        .gz-p-ov::before { content:''; position:absolute; top:0; left:0; right:0; height:140px; background:linear-gradient(rgba(0,0,0,0.9), transparent); z-index:-1; }
        .gz-p-ov::after { content:''; position:absolute; bottom:0; left:0; right:0; height:240px; background:linear-gradient(transparent, rgba(0,0,0,0.95) 40%, #000 100%); z-index:-1; }
        .gz-p-ov.idle { opacity:0; }
        .gz-ptop, .gz-p-btm { pointer-events:auto; z-index:2; padding:20px; }
        .gz-ptop { display:flex; align-items:center; gap:16px; }
        .gz-p-back { background:rgba(255,255,255,0.1); backdrop-filter:blur(8px); border:1px solid rgba(255,255,255,0.1); color:#fff; cursor:pointer; padding:10px; border-radius:50%; transition:0.2s; display:flex; align-items:center; justify-content:center; }
        .gz-p-back:hover { background:var(--a); box-shadow:0 0 12px var(--a); }
        .gz-p-back svg { width:24px; height:24px; fill:currentColor; }
        .gz-ptitle { font-size:20px; font-weight:600; text-shadow:0 2px 6px rgba(0,0,0,0.9); color:#fff; }

        .gz-p-center { position:absolute; top:50%; left:50%; transform:translate(-50%,-50%); text-align:center; pointer-events:none; z-index:10; }
        .gz-spin { width:48px; height:48px; border:4px solid rgba(255,255,255,0.1); border-top-color:var(--a); border-radius:50%; animation:gz-sp 0.8s linear infinite; margin:0 auto; }
        @keyframes gz-sp { to { transform:rotate(360deg); } }
        .gz-fb { position:absolute; top:50%; left:50%; background:rgba(0,0,0,0.7); color:#fff; font-size:24px; padding:16px; border-radius:50%; pointer-events:none; opacity:0; transition:0.2s; z-index:50; backdrop-filter:blur(8px); transform:translate(-50%,-50%) scale(0.8); display:flex; align-items:center; justify-content:center; box-shadow: 0 4px 12px rgba(0,0,0,0.6); }
        .gz-fb svg { width:32px; height:32px; fill:currentColor; }
        .gz-fb.show { opacity:1; transform:translate(-50%,-50%) scale(1); }
        .gz-fb.txt { font-size:16px; font-weight:600; border-radius:24px; padding:12px 24px; }

        .gz-timeline-wrap { width:100%; height:28px; display:flex; align-items:center; cursor:pointer; position:relative; margin-bottom:8px; touch-action:none; }
        .gz-t-track { width:100%; height:6px; background:rgba(255,255,255,0.35); border:1px solid rgba(0,0,0,0.5); border-radius:4px; position:relative; transition:0.2s; box-shadow:0 2px 4px rgba(0,0,0,0.6); }
        .gz-timeline-wrap:hover .gz-t-track, .gz-timeline-wrap.dragging .gz-t-track { height:8px; background:rgba(255,255,255,0.5); }
        .gz-t-fill { position:absolute; left:0; top:0; height:100%; background:var(--a); border-radius:3px; pointer-events:none; box-shadow:0 0 8px rgba(0,0,0,0.5); }
        .gz-t-thumb { position:absolute; top:50%; margin-top:-8px; margin-left:-8px; width:16px; height:16px; background:#fff; border-radius:50%; transform:scale(0); transition:transform 0.2s; pointer-events:none; box-shadow:0 2px 6px rgba(0,0,0,0.8); }
        .gz-timeline-wrap:hover .gz-t-thumb, .gz-timeline-wrap.dragging .gz-t-thumb { transform:scale(1); }

        .gz-ctrl-row { display:flex; align-items:center; gap:20px; flex-wrap:nowrap; position:relative; }
        .gz-cb { background:transparent; border:none; color:#fff; cursor:pointer; display:flex; align-items:center; justify-content:center; padding:0; transition:0.2s; flex-shrink:0; opacity:1; filter:drop-shadow(0 2px 4px rgba(0,0,0,0.8)); }
        .gz-cb:hover { color:var(--a); }
        .gz-cb svg { width:28px; height:28px; fill:currentColor; }
        .gz-vol-wrap { display:flex; align-items:center; gap:12px; }
        .gz-vol-s { -webkit-appearance:none; width:80px; height:6px; border-radius:4px; background:linear-gradient(to right, var(--a) var(--v), rgba(255,255,255,0.35) var(--v)); border:1px solid rgba(0,0,0,0.5); cursor:pointer; outline:none; box-shadow:0 2px 4px rgba(0,0,0,0.6); }
        .gz-vol-s::-webkit-slider-thumb { -webkit-appearance:none; width:14px; height:14px; background:#fff; border-radius:50%; box-shadow:0 1px 5px rgba(0,0,0,0.8); }
        .gz-live-badge { font-size:12px; font-weight:800; padding:5px 8px; border-radius:6px; border:1px solid rgba(255,255,255,0.15); background:rgba(20,20,24,0.85); color:#fff; letter-spacing:1px; cursor:pointer; transition:0.2s; flex-shrink:0; box-shadow:0 2px 6px rgba(0,0,0,0.8); }
        .gz-live-badge.active { background:var(--a); border-color:transparent; box-shadow:0 0 10px rgba(224,85,85,0.6); }
        .gz-time-disp { font-size:14px; font-variant-numeric:tabular-nums; color:#fff; flex-shrink:0; font-weight:700; background:rgba(30,30,35,0.9); padding:5px 10px; border-radius:6px; border:1px solid rgba(255,255,255,0.2); box-shadow:0 4px 10px rgba(0,0,0,0.8); letter-spacing:0.5px; }
        .gz-spacer { flex:1; }

        /* Player In-Video Settings Modal */
        .gz-p-set-panel { position:absolute; bottom:50px; right:0; background:rgba(20,20,24,0.95); backdrop-filter:blur(12px); border:1px solid rgba(255,255,255,0.15); border-radius:12px; padding:12px; width:220px; display:none; flex-direction:column; gap:8px; z-index:50; box-shadow:0 8px 32px rgba(0,0,0,0.8); pointer-events:auto; }
        .gz-p-set-panel.on { display:flex; animation:fadeIn 0.2s; }
        .gz-p-set-row { display:flex; justify-content:space-between; align-items:center; font-size:13px; color:#fff; font-weight:500; }
        .gz-p-set-row select { background:rgba(255,255,255,0.1); color:#fff; border:1px solid rgba(255,255,255,0.1); padding:4px 8px; border-radius:6px; outline:none; cursor:pointer; font-weight:500; }
        .gz-p-set-row select option { background:#222; }
        .gz-p-set-btn { background:none; border:none; color:#fff; text-align:left; font-size:13px; padding:8px; border-radius:6px; cursor:pointer; transition:0.2s; font-weight:500; }
        .gz-p-set-btn:hover { background:rgba(255,255,255,0.1); color:var(--a); }

        @media (max-width: 768px) {
            .gz-drawer { position:absolute; left:0; top:0; bottom:0; transform:translateX(-100%); width:260px; }
            .gz-drawer.open { transform:translateX(0); }
            .gz-dr-backdrop.open { display:block; opacity:1; }
            .gz-vol-wrap { display:none !important; } .gz-ptop, .gz-p-btm { padding:12px; } .gz-ctrl-row { gap:14px; }
            .gz-cb svg { width:24px; height:24px; }
            .gz-p-set-panel { right:-10px; }
        }
        </style>`);

        /* App SVG Icons */
        const ic = {
            menu: `<path d="M3 18h18v-2H3v2zm0-5h18v-2H3v2zm0-7v2h18V6H3z"/>`,
            all: `<path d="M4 6H2v14c0 1.1.9 2 2 2h14v-2H4V6zm16-4H8c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H8V4h12v12zM10 9h8v2h-8zm0 3h4v2h-4zm0-6h8v2h-8z"/>`,
            fav: `<path d="M12 17.27L18.18 21l-1.64-7.03L22 9.24l-7.19-.61L12 2 9.19 8.63 2 9.24l5.46 4.73L5.82 21z"/>`,
            hide: `<path d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"/>`,
            set: `<path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.06-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.56-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.73 8.87c-.11.2-.06.47.12.61l2.03 1.58c-.04.3-.06.62-.06.94s.02.64.06.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .43-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.49-.12-.61l-2.03-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/>`,
            play: `<path d="M8 5v14l11-7z"/>`, pause: `<path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/>`,
            back: `<path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"/>`,
            cat: `<path d="M4 8h4V4H4v4zm6 12h4v-4h-4v4zm-6 0h4v-4H4v4zm0-6h4v-4H4v4zm6 0h4v-4h-4v4zm6-10v4h4V4h-4zm-6 4h4V4h-4v4zm6 6h4v-4h-4v4zm0 6h4v-4h-4v4z"/>`,
            srch: `<path d="M15.5 14h-.79l-.28-.27A6.47 6.47 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/>`,
            clr: `<path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>`,
            fs: `<path d="M7 14H5v5h5v-2H7v-3zm-2-4h2V7h3V5H5v5zm12 7h-3v2h5v-5h-2v3zM14 5v2h3v3h2V5h-5z"/>`,
            vol: `<path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02zM14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77z"/>`,
            mute: `<path d="M16.5 12c0-1.77-1.02-3.29-2.5-4.03v2.21l2.45 2.45c.03-.2.05-.41.05-.63zm2.5 0c0 .94-.2 1.82-.54 2.64l1.51 1.51C20.63 14.91 21 13.5 21 12c0-4.28-2.99-7.86-7-8.77v2.06c2.89.86 5 3.54 5 6.71zM4.27 3L3 4.27 7.73 9H3v6h4l5 5v-6.73l4.25 4.25c-.67.52-1.42.93-2.25 1.18v2.06c1.38-.31 2.63-.95 3.69-1.81L19.73 21 21 19.73l-9-9L4.27 3zM12 4L9.91 6.09 12 8.18V4z"/>`
        };

        /* Scaffold Layout Structure */
        document.body.insertAdjacentHTML('beforeend', `
        <div id="GZ">
            <div class="gz-v on" id="gz-bv">
                <div class="gz-bar">
                    <button class="gz-btn-icon" id="gz-btn-menu"><svg viewBox="0 0 24 24">${ic.menu}</svg></button>
                    <h1 class="gz-logo"><b>GL</b>Wiz Pro</h1>
                    <div class="gz-sr-wrap">
                        <div class="gz-sr">
                            <svg viewBox="0 0 24 24">${ic.srch}</svg>
                            <input class="gz-si" id="gz-si" type="search" placeholder="Search Channels..." autocomplete="off">
                            <svg id="gz-s-clr" class="gz-btn-icon" viewBox="0 0 24 24" style="width:18px;height:18px;padding:0;display:none">${ic.clr}</svg>
                        </div>
                    </div>
                </div>

                <div class="gz-main">
                    <div class="gz-dr-backdrop" id="gz-backdrop"></div>
                    <div class="gz-drawer" id="gz-drawer">
                        <div class="gz-dr-menu" id="gz-dr-main"></div>
                        <div class="gz-dr-div"></div>
                        <div class="gz-dr-title">Categories</div>
                        <div class="gz-dr-menu" id="gz-dr-cats"></div>
                        <div class="gz-dr-div"></div>
                        <div class="gz-dr-menu" id="gz-dr-btm">
                            <div class="gz-dr-item" data-cat="hidden"><svg viewBox="0 0 24 24">${ic.hide}</svg>Hidden</div>
                            <div class="gz-dr-item" id="gz-btn-set"><svg viewBox="0 0 24 24">${ic.set}</svg>Settings</div>
                        </div>
                    </div>
                    <div class="gz-grid-wrap"><div class="gz-grid ${S.cfg.layout}" id="gz-grid"></div></div>
                </div>
            </div>

            <div class="gz-v" id="gz-pv">
                <!-- Native Player Canvas -->
                <div id="gz-stage-native">
                    <video id="gz-vid" playsinline crossOrigin="anonymous" style="--fit:${S.cfg.fit}"></video>
                    <div class="gz-p-center" id="gz-load-ct"><div class="gz-spin" id="gz-spinner"></div><div class="gz-p-msg" id="gz-msg" style="display:none;color:#fff;margin-top:10px;font-weight:500;"></div></div>
                    <div class="gz-fb" id="gz-fb"></div>
                    <div class="gz-fb txt" id="gz-fb-txt"></div>
                    <div class="gz-p-ov" id="gz-ov">
                        <div class="gz-ptop">
                            <button class="gz-p-back" id="gz-back-n" title="Exit Player (Esc)"><svg viewBox="0 0 24 24">${ic.back}</svg></button>
                            <span class="gz-ptitle" id="gz-ptitle-n"></span>
                        </div>
                        <div class="gz-p-btm">
                            <div class="gz-timeline-wrap" id="gz-t-wrap"><div class="gz-t-track"><div class="gz-t-fill" id="gz-t-fill"></div></div><div class="gz-t-thumb" id="gz-t-thumb"></div></div>
                            <div class="gz-ctrl-row">
                                <button class="gz-cb" id="gz-play" title="Play/Pause (Space)"></button>
                                <div class="gz-vol-wrap">
                                    <button class="gz-cb" id="gz-mute" title="Mute (M)"></button>
                                    <input type="range" class="gz-vol-s" id="gz-vol" min="0" max="1" step="0.05" value="1" style="--v:100%">
                                </div>
                                <div class="gz-live-badge active" id="gz-live-btn" title="Go to Live">LIVE</div>
                                <div class="gz-time-disp" id="gz-time">LIVE</div>
                                <div class="gz-spacer"></div>

                                <!-- Floating Setup Menu -->
                                <div class="gz-p-set-panel" id="gz-p-set-panel">
                                    <div class="gz-p-set-row" id="gz-p-row-qual" style="display:none"><span>Quality</span> <select id="gz-p-qual"><option value="-1">Auto</option></select></div>
                                    <div class="gz-p-set-row"><span>Speed</span> <select id="gz-p-speed"><option value="0.5">0.5x</option><option value="1" selected>Normal</option><option value="1.25">1.25x</option><option value="1.5">1.5x</option><option value="2">2x</option></select></div>
                                    <div class="gz-p-set-row"><span>Video Fit</span> <select id="gz-p-fit"><option value="contain">Contain</option><option value="cover">Cover</option></select></div>
                                    <div style="height:1px;background:rgba(255,255,255,0.1);margin:4px 0"></div>
                                    <button class="gz-p-set-btn" id="gz-p-btn-pip">Picture in Picture (P)</button>
                                    <button class="gz-p-set-btn" id="gz-p-btn-shot">Take Screenshot (S)</button>
                                </div>

                                <button class="gz-cb" id="gz-p-set-tog" title="Settings"><svg viewBox="0 0 24 24">${ic.set}</svg></button>
                                <button class="gz-cb" id="gz-fs" title="Fullscreen (F)"><svg viewBox="0 0 24 24">${ic.fs}</svg></button>
                            </div>
                        </div>
                    </div>
                </div>
                <!-- Artplayer Container -->
                <div id="gz-stage-art"></div>
            </div>

            <!-- Context Flyout -->
            <div class="gz-ctx" id="gz-ctx">
                <button class="gz-ctx-btn" id="gz-ctx-play"><svg viewBox="0 0 24 24">${ic.play}</svg>Play Channel</button>
                <button class="gz-ctx-btn" id="gz-ctx-fav"><svg viewBox="0 0 24 24">${ic.fav}</svg><span id="gz-ctx-fav-t">Add to Favorites</span></button>
                <button class="gz-ctx-btn" id="gz-ctx-hide" style="color:#e05555"><svg viewBox="0 0 24 24">${ic.hide}</svg><span id="gz-ctx-hide-t">Hide Channel</span></button>
            </div>

            <!-- Global Preferences Modal -->
            <div class="gz-modal-wrap" id="gz-modal">
                <div class="gz-modal" onclick="event.stopPropagation()">
                    <div class="gz-m-head">Preferences <button class="gz-btn-icon" id="gz-m-close" style="width:32px;height:32px"><svg viewBox="0 0 24 24">${ic.clr}</svg></button></div>
                    <div class="gz-m-body">
                        <div class="gz-m-row">
                            <span class="gz-m-label">Theme Color</span>
                            <div>
                                <span class="gz-btn-theme" data-c="#e05555" style="background:#e05555"></span>
                                <span class="gz-btn-theme" data-c="#3b82f6" style="background:#3b82f6"></span>
                                <span class="gz-btn-theme" data-c="#10b981" style="background:#10b981"></span>
                                <span class="gz-btn-theme" data-c="#8b5cf6" style="background:#8b5cf6"></span>
                            </div>
                        </div>
                        <div class="gz-m-row">
                            <span class="gz-m-label">Grid Layout</span>
                            <select class="gz-m-select" id="gz-cfg-layout">
                                <option value="compact">Compact Grid</option>
                                <option value="list">List View</option>
                            </select>
                        </div>
                        <div class="gz-dr-div"></div>
                        <div class="gz-m-row">
                            <span class="gz-m-label">Auto PiP on Hide<span class="gz-m-hint">Minimizes to PiP when leaving player</span></span>
                            <div class="gz-m-switch" id="gz-cfg-pip"></div>
                        </div>
                        <div class="gz-m-row">
                            <span class="gz-m-label">Enable External CDN Engines<span class="gz-m-hint">Allows ArtPlayer & fallback Hls.js</span></span>
                            <div class="gz-m-switch" id="gz-cfg-cdn"></div>
                        </div>
                        <div class="gz-m-row" id="gz-row-engine" style="display:none">
                            <span class="gz-m-label">Player Engine</span>
                            <select class="gz-m-select" id="gz-cfg-engine">
                                <option value="native">Native (Recommended)</option>
                                <option value="art">ArtPlayer</option>
                            </select>
                        </div>
                        <div class="gz-dr-div"></div>
                        <button class="gz-m-btn-danger" id="gz-btn-clear">Reset Data & Favorites</button>
                    </div>
                </div>
            </div>
        </div>`);

        const $ = id => document.getElementById(id);
        const esc = s => String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}['m']));

        /* Dependency Inj & Management */
        async function getHls() {
            if (window.Hls) return true;
            try { const iw = $('frmPlayer').contentWindow; if (iw && iw.Hls) { window.Hls = iw.Hls; return true; } } catch(_) {}
            if (!S.cfg.useCdn) return false;
            return new Promise(res => { const s = document.createElement('script'); s.src = 'https://cdn.jsdelivr.net/npm/hls.js@1.5.0/dist/hls.min.js'; s.onload = ()=>res(true); s.onerror = ()=>res(false); document.head.appendChild(s); });
        }
        async function getArt() {
            if (window.Artplayer) return true;
            if (!S.cfg.useCdn) return false;
            return new Promise(res => { const s = document.createElement('script'); s.src = 'https://cdn.jsdelivr.net/npm/artplayer@5.1.7/dist/artplayer.js'; s.onload = ()=>res(true); s.onerror = ()=>res(false); document.head.appendChild(s); });
        }

        /* Remote API Communication */
        function loadChannels() {
            let iframe = $('frmPlayer'); if (!iframe) { iframe = document.createElement('iframe'); iframe.id = 'frmPlayer'; iframe.style.display='none'; document.body.appendChild(iframe); }
            try { if (!iframe.contentWindow.location.href.includes('p2.html')) iframe.src = '/Pages/Player/p2.html?t=' + Date.now(); } catch(_) {}
            return new Promise((resolve, reject) => {
                let n = 0; const p = () => {
                    if (++n > 250) return reject();
                    try {
                        const iw = iframe.contentWindow;
                        if (iw && iw.location.href.includes('p2.html') && iw.dtDataAllArray && iw.dtDataAllArray.length > 0) {
                            const genMap = {};
                            if (iw.arGenre && iw.arGenreName) iw.arGenre.forEach((id, idx) => { genMap[id] = iw.arGenreName[idx]; });
                            else if (iw.dtGenreArray) Array.from(iw.dtGenreArray).forEach(g => { genMap[g.id ?? g.i] = g.name ?? g.n ?? g.un; });
                            const fb = { 5:'⭐ Favs', 401:'All', 1:'Persian', 19:'Series/Films', 2:'IRIB', 10:'Music', 4:'Kids', 64:'TV Audio' };
                            resolve({ chs: Array.from(iw.dtDataAllArray), genres: Object.keys(genMap).length ? genMap : fb });
                        } else setTimeout(p, 200);
                    } catch(_) { setTimeout(p, 200); }
                }; p();
            });
        }
        function norm(r) {
            return {
                id: String(r.id ?? r.i ?? 0), name: (r.name || r.un || r.n || '').trim(), num: r.VisibleNumber ?? r.v ?? '',
                url: r.streamurl || r.s || '', gid: String(r.genreID ?? r.g ?? 0), cn: r.cn || '',
                logo: r.logo || r.l || `https://hd200.glwiz.com/menu/epg/imagesNew/cim_${r.id??r.i??0}.png`,
            };
        }

        /* Interface Interactions */
        const dr = $('gz-drawer'), bd = $('gz-backdrop');
        const toggleMenu = () => { const o = dr.classList.toggle('open'); bd.classList.toggle('open', o); };
        $('gz-btn-menu').onclick = toggleMenu; bd.onclick = toggleMenu;

        function buildSidebar() {
            const main = $('gz-dr-main'), cats = $('gz-dr-cats'); main.innerHTML = ''; cats.innerHTML = '';
            const mk = (cat, lbl, ico, parent) => {
                const d = document.createElement('div'); d.className = 'gz-dr-item' + (S.cat === cat ? ' active' : '');
                d.dataset.cat = cat; d.innerHTML = `<svg viewBox="0 0 24 24">${ico}</svg>${lbl}`;
                d.onclick = () => { S.cat = cat; buildSidebar(); renderGrid(); if(window.innerWidth<=768) toggleMenu(); $('gz-si').value = ''; $('gz-s-clr').style.display='none'; S.q = ''; };
                parent.appendChild(d);
            };
            mk('all', 'All Channels', ic.all, main); mk('fav', 'Favorites', ic.fav, main);
            const activeGids = new Set(S.chs.map(c => c.gid));
            Object.entries(S.genres).forEach(([g, l]) => { if (activeGids.has(String(g)) && g !== '401') mk(g, l, ic.cat, cats); });
            document.querySelectorAll('#gz-dr-btm .gz-dr-item[data-cat]').forEach(d => {
                d.classList.toggle('active', S.cat === d.dataset.cat);
                d.onclick = () => { S.cat = d.dataset.cat; buildSidebar(); renderGrid(); if(window.innerWidth<=768) toggleMenu(); $('gz-si').value=''; S.q=''; };
            });
        }

        function renderGrid() {
            let list = S.chs.filter(c => c.name && c.url.length > 5);
            if (S.cat === 'fav') list = list.filter(c => S.favs.has(c.id));
            else if (S.cat === 'hidden') list = list.filter(c => S.hidden.has(c.id));
            else if (S.cat !== 'all') list = list.filter(c => c.gid === S.cat && !S.hidden.has(c.id));
            else list = list.filter(c => !S.hidden.has(c.id));

            const seen = new Set();
            list = list.filter(c => { const k = c.name.toLowerCase()+'|'+c.url.split('?')[0]; if(seen.has(k)) return false; seen.add(k); return true; });
            if (S.q) list = list.filter(c => c.name.toLowerCase().includes(S.q));

            const grid = $('gz-grid'); grid.innerHTML = ''; grid.className = `gz-grid ${S.cfg.layout}`;
            if (!list.length) return grid.innerHTML = `<div style="grid-column:1/-1;text-align:center;padding:100px 20px;color:var(--sub)">Nothing found.</div>`;

            const frag = document.createDocumentFragment();
            list.forEach((ch, idx) => {
                const d = document.createElement('div'); d.className = 'gz-card'; d.style.animationDelay = `${Math.min(idx * 0.015, 0.2)}s`;
                d.innerHTML = `
                    <div class="gz-cthumb"><img src="${esc(ch.logo)}" loading="lazy" onerror="this.style.display='none'"></div>
                    <div class="gz-cbody">
                        <div class="gz-cname" title="${esc(ch.name)}">${esc(ch.name)}</div>
                        <div class="gz-cnum">CH ${esc(ch.num || ch.id)} ${S.favs.has(ch.id) ? `<span class="gz-badge-fav">★</span>` : ''}</div>
                    </div>`;
                d.onclick = () => play(ch); d.oncontextmenu = e => showCtx(e, ch); frag.appendChild(d);
            });
            grid.appendChild(frag);
        }

        /* Context Sub-menu */
        const ctx = $('gz-ctx'); let ctxCh = null;
        function showCtx(e, ch) {
            e.preventDefault(); ctxCh = ch;
            $('gz-ctx-fav-t').textContent = S.favs.has(ch.id) ? 'Remove Favorite' : 'Add Favorite';
            $('gz-ctx-hide-t').textContent = S.hidden.has(ch.id) ? 'Unhide Channel' : 'Hide Channel';
            ctx.classList.add('on');
            let x = e.clientX, y = e.clientY;
            if (x + 190 > window.innerWidth) x -= 190; if (y + 130 > window.innerHeight) y -= 130;
            ctx.style.left = x + 'px'; ctx.style.top = y + 'px';
        }
        document.addEventListener('click', () => ctx.classList.remove('on'));
        $('gz-ctx-play').onclick = () => play(ctxCh);
        $('gz-ctx-fav').onclick = () => { S.favs.has(ctxCh.id) ? S.favs.delete(ctxCh.id) : S.favs.add(ctxCh.id); save(); renderGrid(); };
        $('gz-ctx-hide').onclick = () => { S.hidden.has(ctxCh.id) ? S.hidden.delete(ctxCh.id) : S.hidden.add(ctxCh.id); save(); renderGrid(); };

        /* Preferences Form Config */
        const mod = $('gz-modal');
        const syncSetUI = () => {
            $('gz-cfg-layout').value = S.cfg.layout;
            $('gz-p-fit').value = S.cfg.fit;
            $('gz-cfg-engine').value = S.cfg.player;
            document.querySelectorAll('.gz-btn-theme').forEach(b => b.classList.toggle('active', b.dataset.c === S.cfg.theme));
            $('gz-cfg-cdn').classList.toggle('on', S.cfg.useCdn); $('gz-cfg-pip').classList.toggle('on', S.cfg.pipHide);
            $('gz-row-engine').style.display = S.cfg.useCdn ? 'flex' : 'none';
        };
        $('gz-btn-set').onclick = () => { syncSetUI(); mod.classList.add('on'); if(window.innerWidth<=768) toggleMenu(); };
        $('gz-m-close').onclick = () => mod.classList.remove('on'); mod.onclick = () => mod.classList.remove('on');

        $('gz-cfg-layout').onchange = e => { S.cfg.layout = e.target.value; save(); renderGrid(); };
        $('gz-cfg-engine').onchange = e => { S.cfg.player = e.target.value; save(); };
        $('gz-cfg-cdn').onclick = () => { S.cfg.useCdn = !S.cfg.useCdn; if(!S.cfg.useCdn) S.cfg.player='native'; save(); syncSetUI(); };
        $('gz-cfg-pip').onclick = () => { S.cfg.pipHide = !S.cfg.pipHide; save(); syncSetUI(); };
        document.querySelectorAll('.gz-btn-theme').forEach(b => {
            b.onclick = () => { S.cfg.theme = b.dataset.c; document.documentElement.style.setProperty('--a', S.cfg.theme); save(); syncSetUI(); };
        });
        $('gz-btn-clear').onclick = () => { if(confirm('Erase all data?')) { S.favs.clear(); S.hidden.clear(); save(); mod.classList.remove('on'); renderGrid(); } };

        /* Inline Media Settings Panel */
        let isSetOpen = false;
        $('gz-p-set-tog').onclick = (e) => { e.stopPropagation(); const p = $('gz-p-set-panel'); p.classList.toggle('on'); isSetOpen = p.classList.contains('on'); };
        $('gz-p-fit').onchange = e => { S.cfg.fit = e.target.value; $('gz-vid').style.setProperty('--fit', S.cfg.fit); save(); };
        $('gz-p-speed').onchange = e => { if($('gz-vid')) $('gz-vid').playbackRate = parseFloat(e.target.value); };
        $('gz-p-qual').onchange = e => { if(hlsNative) hlsNative.currentLevel = parseInt(e.target.value); };

        /* Search Subroutine */
        let searchTo;
        $('gz-si').oninput = e => { const v = e.target.value; $('gz-s-clr').style.display = v.length ? 'block' : 'none'; clearTimeout(searchTo); searchTo = setTimeout(() => { S.q = v.toLowerCase(); renderGrid(); }, 150); };
        $('gz-s-clr').onclick = () => { $('gz-si').value = ''; $('gz-s-clr').style.display = 'none'; S.q = ''; renderGrid(); };

        /* Extract Raw Stream URI */
        async function resolveStream(ch) {
            const seg = ch.url.split('?')[0].replace(/\.(m3u8|ts|mp4)$/i, '').split('/').pop();
            const qs = new URLSearchParams({ action:'getStreamURL', ClusterName:ch.cn, gid:'', RecType:'4', itemName: seg.split('_')[0], IsExternalRadio:'0', ScreenMode:'0', ref:Date.now() });
            const r = await fetch(`/Pages/Player/Ajax.aspx?${qs}`, { credentials:'include', headers:{'X-hello-data':'you-are-allow'} });
            if (!r.ok) throw new Error();
            const j = await r.json(); let url = decodeURIComponent(typeof j === 'string' ? j : j.resp);
            if (!url || /^https?:\/\/[^./]+:\d+\//i.test(url)) throw new Error();
            return url;
        }

        /* Base Player Ops */
        function stopAll() {
            if (document.pictureInPictureElement) document.exitPictureInPicture().catch(()=>{});
            if (hlsNative) { hlsNative.destroy(); hlsNative = null; }
            if (artInst) { artInst.destroy(true); artInst = null; }
            const vid = $('gz-vid'); vid.pause(); vid.removeAttribute('src'); vid.load();
            $('gz-stage-native').classList.remove('on'); $('gz-stage-art').classList.remove('on');
            $('gz-load-ct').style.display = 'none'; $('gz-fb').classList.remove('show'); $('gz-fb-txt').classList.remove('show');
            $('gz-p-set-panel').classList.remove('on'); isSetOpen = false;
        }

        $('gz-back-n').onclick = async () => {
            const vid = $('gz-vid');
            if (S.cfg.pipHide && document.pictureInPictureEnabled && !document.pictureInPictureElement && !vid.paused) {
                try {
                    await vid.requestPictureInPicture();
                    $('gz-pv').classList.remove('on'); $('gz-bv').classList.add('on'); renderGrid();
                    return;
                } catch(e) { console.error('Auto PiP fallback error', e); }
            }
            if (document.fullscreenElement) document.exitFullscreen().catch(()=>{});
            stopAll();
            $('gz-pv').classList.remove('on'); $('gz-bv').classList.add('on'); renderGrid();
        };

        async function play(ch) {
            S.cur = ch; $('gz-bv').classList.remove('on'); $('gz-pv').classList.add('on'); stopAll();
            try {
                const streamUrl = await resolveStream(ch);
                if (S.cfg.player === 'art' && S.cfg.useCdn) playArt(ch, streamUrl);
                else playNative(ch, streamUrl);
            } catch (e) {
                $('gz-stage-native').classList.add('on');
                $('gz-load-ct').style.display = 'block'; $('gz-spinner').style.display = 'none'; $('gz-msg').textContent = 'Stream unavailable.'; $('gz-msg').style.display = 'block';
            }
        }

        /* Native Player Execution Context */
        const vid = $('gz-vid'), stageN = $('gz-stage-native'), ovN = $('gz-ov');
        let tStart = 0, tEnd = 0, clickC = 0, clickT = null;

        function fbt(ico) { const fb = $('gz-fb'); fb.innerHTML = `<svg viewBox="0 0 24 24">${ico}</svg>`; fb.classList.add('show'); setTimeout(()=>fb.classList.remove('show'), 600); }
        function fbx(txt) { const fb = $('gz-fb-txt'); fb.textContent = txt; fb.classList.add('show'); setTimeout(()=>fb.classList.remove('show'), 800); }
        function fmtT(s) { if(isNaN(s)||s<=0)return"0:00"; s=Math.floor(s); const m=Math.floor(s/60),sc=s%60; return (m>0?m+':':'0:')+(sc<10?'0':'')+sc; }

        $('gz-play').onclick = () => { vid.paused ? vid.play() : vid.pause(); fbt(vid.paused ? ic.pause : ic.play); };
        vid.addEventListener('play', () => $('gz-play').innerHTML = `<svg viewBox="0 0 24 24">${ic.pause}</svg>`);
        vid.addEventListener('pause', () => $('gz-play').innerHTML = `<svg viewBox="0 0 24 24">${ic.play}</svg>`);

        stageN.addEventListener('click', (e) => {
            if(!e.target.closest('#gz-p-set-panel') && !e.target.closest('#gz-p-set-tog')) { $('gz-p-set-panel').classList.remove('on'); isSetOpen = false; }
        });

        stageN.addEventListener('pointerup', e => {
            if (e.target.closest('.gz-p-btm') || e.target.closest('.gz-ptop') || e.target.closest('#gz-p-set-panel')) return;
            clickC++;
            if (clickC===1) clickT = setTimeout(()=>{ clickC=0; $('gz-play').click(); ovN.classList.remove('idle'); }, 250);
            else if (clickC===2) {
                clearTimeout(clickT); clickC=0;
                const L = e.clientX < window.innerWidth/2;
                if(vid.seekable.length) {
                    vid.currentTime = Math.max(tStart, Math.min(vid.currentTime+(L?-10:10), tEnd));
                    fbx(L?'-10s':'+10s');
                }
            }
        });

        let ovTo; stageN.addEventListener('mousemove', () => {
            ovN.classList.remove('idle');
            clearTimeout(ovTo);
            ovTo = setTimeout(() => { if(!vid.paused && !isSetOpen) ovN.classList.add('idle'); }, 3000);
        });

        /* Timeline Interactions & Bulletproof Touch Handling */
        let isDragging = false, dragPos = 0, lastTouch = 0;
        const tWrap = $('gz-t-wrap');
        const setTimeUI = (p) => { $('gz-t-fill').style.width = p*100+'%'; $('gz-t-thumb').style.left = p*100+'%'; };

        const calcDragPos = (e) => {
            const r = tWrap.getBoundingClientRect();
            let cx = e.clientX;
            if (e.touches && e.touches.length > 0) cx = e.touches[0].clientX;
            else if (e.changedTouches && e.changedTouches.length > 0) cx = e.changedTouches[0].clientX;
            return Math.max(0, Math.min(1, (cx - r.left) / r.width));
        };

        const startDrag = (e) => {
            if (e.type === 'touchstart') { lastTouch = Date.now(); }
            else if (e.type === 'mousedown' && Date.now() - lastTouch < 500) { return; /* Block mobile phantom click! */ }

            isDragging = true;
            tWrap.classList.add('dragging');
            dragPos = calcDragPos(e);
            setTimeUI(dragPos);
        };

        tWrap.addEventListener('mousedown', startDrag);
        tWrap.addEventListener('touchstart', startDrag, {passive: true});

        window.addEventListener('mousemove', e => {
            if(isDragging) { dragPos = calcDragPos(e); setTimeUI(dragPos); }
        });
        tWrap.addEventListener('touchmove', e => {
            if(isDragging) {
                if(e.cancelable) e.preventDefault();
                dragPos = calcDragPos(e);
                setTimeUI(dragPos);
            }
        }, {passive: false});

        const commitDrag = (e) => {
            if (e && e.type === 'mouseup' && Date.now() - lastTouch < 500) return; /* Block mobile phantom release! */
            if(isDragging) {
                isDragging = false; tWrap.classList.remove('dragging');
                if(vid.seekable.length) {
                    vid.currentTime = tStart + dragPos * (tEnd - tStart);
                }
            }
        };

        window.addEventListener('mouseup', commitDrag);
        window.addEventListener('touchend', commitDrag);

        vid.addEventListener('timeupdate', () => {
            if(!vid.seekable.length) return;
            const rawStart = vid.seekable.start(0);
            tEnd = vid.seekable.end(vid.seekable.length-1);

            /* Volatile Edge Trimmer:
               Hides the first ~15-20 seconds of the rolling playlist server buffer
               so users don't drag into a segment that is actively being deleted. */
            tStart = rawStart + Math.min(20, (tEnd - rawStart) * 0.5);

            if (!isDragging) {
                let p = Math.max(0, Math.min(1, (vid.currentTime-tStart)/(tEnd-tStart)||0));
                setTimeUI(p);
            }
            const d = tEnd - vid.currentTime;
            if (d < 6) { $('gz-live-btn').classList.add('active'); $('gz-time').textContent='LIVE'; } else { $('gz-live-btn').classList.remove('active'); $('gz-time').textContent='-'+fmtT(d); }
        });
        $('gz-live-btn').onclick = () => { if (vid.seekable.length) vid.currentTime = tEnd; };

        const syncVol = () => { $('gz-vol').value = vid.volume; $('gz-vol').style.setProperty('--v', vid.volume*100+'%'); $('gz-mute').innerHTML = `<svg viewBox="0 0 24 24">${vid.muted||vid.volume===0 ? ic.mute : ic.vol}</svg>`; };
        $('gz-vol').oninput = e => { vid.muted=false; vid.volume = e.target.value; syncVol(); };
        $('gz-mute').onclick = () => { vid.muted = !vid.muted; syncVol(); }; vid.addEventListener('volumechange', syncVol);

        $('gz-fs').onclick = () => { if(!document.fullscreenElement) stageN.requestFullscreen().catch(()=>{}); else document.exitFullscreen(); };

        const togglePip = async () => {
            try {
                if (document.pictureInPictureElement) {
                    await document.exitPictureInPicture();
                } else if (document.pictureInPictureEnabled) {
                    await vid.requestPictureInPicture();
                } else if (vid.webkitSupportsPresentationMode) {
                    vid.webkitSetPresentationMode(vid.webkitPresentationMode === "picture-in-picture" ? "inline" : "picture-in-picture");
                }
            } catch(e) { console.error('PiP Error:', e); fbx('PiP Not Supported/Failed'); }
        };

        $('gz-p-btn-pip').onclick = (e) => { e.stopPropagation(); $('gz-p-set-panel').classList.remove('on'); isSetOpen = false; togglePip(); };
        vid.addEventListener('leavepictureinpicture', () => {
            if (!vid.paused && !$('gz-pv').classList.contains('on')) { $('gz-bv').classList.remove('on'); $('gz-pv').classList.add('on'); }
        });

        $('gz-p-btn-shot').onclick = () => {
            try {
                const cvs = document.createElement('canvas'); cvs.width = vid.videoWidth; cvs.height = vid.videoHeight;
                cvs.getContext('2d').drawImage(vid, 0, 0);
                const a = document.createElement('a'); a.href = cvs.toDataURL('image/png'); a.download = `GLWiz_${Date.now()}.png`; a.click(); fbx('📸 Saved');
            } catch(e) { fbx('❌ Error taking screenshot'); }
        };

        /* Universal Keyboard Binding Router */
        document.addEventListener('keydown', e => {
            if (document.activeElement.tagName === 'INPUT' || !$('gz-pv').classList.contains('on') || $('gz-stage-art').classList.contains('on')) return;
            switch(e.key.toLowerCase()) {
                case 'escape':
                    e.preventDefault();
                    if(document.fullscreenElement) document.exitFullscreen().catch(()=>{});
                    else $('gz-back-n').click();
                    break;
                case ' ': case 'k': e.preventDefault(); $('gz-play').click(); break;
                case 'f': e.preventDefault(); $('gz-fs').click(); break;
                case 'm': e.preventDefault(); $('gz-mute').click(); break;
                case 's': e.preventDefault(); $('gz-p-btn-shot').click(); break;
                case 'p': e.preventDefault(); togglePip(); break;
                case 'arrowup': e.preventDefault(); vid.muted=false; vid.volume=Math.min(1,vid.volume+0.1); syncVol(); fbx(`Vol ${Math.round(vid.volume*100)}%`); break;
                case 'arrowdown': e.preventDefault(); vid.muted=false; vid.volume=Math.max(0,vid.volume-0.1); syncVol(); fbx(`Vol ${Math.round(vid.volume*100)}%`); break;
                case 'arrowright': e.preventDefault(); if(vid.seekable.length) { vid.currentTime=Math.min(vid.currentTime+10, tEnd); fbx('+10s'); } break;
                case 'arrowleft': e.preventDefault(); if(vid.seekable.length) { vid.currentTime=Math.max(vid.currentTime-10, tStart); fbx('-10s'); } break;
            }
        });

        async function playNative(ch, url) {
            stageN.classList.add('on'); $('gz-ptitle-n').textContent = esc(ch.name);
            $('gz-load-ct').style.display='block'; $('gz-spinner').style.display='block'; $('gz-msg').style.display='none';
            $('gz-p-speed').value = "1"; vid.playbackRate = 1;

            const hasHls = await getHls();
            if (hasHls && window.Hls.isSupported()) {
                /* Initialize Hls with immense back buffer limit and completely disable HLS.js auto-live-jump */
                hlsNative = new window.Hls({
                    liveDurationInfinity: true,
                    backBufferLength: 9000,
                    liveMaxLatencyDurationCount: 999999,
                });
                hlsNative.loadSource(url); hlsNative.attachMedia(vid);
                hlsNative.on(window.Hls.Events.MANIFEST_PARSED, () => {
                    vid.play();
                    $('gz-load-ct').style.display='none';
                    /* Extract Stream Qualities */
                    const qRow = $('gz-p-row-qual'), qSel = $('gz-p-qual');
                    qSel.innerHTML = '<option value="-1">Auto</option>';
                    if (hlsNative.levels && hlsNative.levels.length > 1) {
                        hlsNative.levels.forEach((l, i) => {
                            const qLbl = l.height ? `${l.height}p` : `${Math.round(l.bitrate / 1000)}kbps`;
                            qSel.innerHTML += `<option value="${i}">${qLbl}</option>`;
                        });
                        qRow.style.display = 'flex'; qSel.value = hlsNative.currentLevel;
                    } else { qRow.style.display = 'none'; }
                });
                hlsNative.on(window.Hls.Events.ERROR, (_, d) => { if(d.fatal) { $('gz-msg').textContent='Error. Retrying...'; $('gz-msg').style.display='block'; setTimeout(()=>playNative(ch, url), 2000); }});
            } else if (vid.canPlayType('application/vnd.apple.mpegurl')) {
                vid.src = url; vid.play(); $('gz-load-ct').style.display='none'; $('gz-p-row-qual').style.display='none';
            } else {
                $('gz-msg').textContent = 'HLS format unsupported by browser.'; $('gz-msg').style.display='block'; $('gz-spinner').style.display='none';
            }
        }

        /* External Artplayer Implementation (Optional) */
        async function playArt(ch, url) {
            $('gz-stage-art').classList.add('on');
            await getHls(); const loaded = await getArt();
            if(!loaded) { alert('Failed to resolve ArtPlayer plugin. Attempting native fallback.'); return playNative(ch, url); }

            artInst = new window.Artplayer({
                container: '#gz-stage-art', url: url, title: ch.name, poster: ch.logo, volume: 1, isLive: true, muted: false, autoplay: true, pip: true, autoSize: true, autoMini: true, screenshot: true, setting: true, playbackRate: true, aspectRatio: true, fullscreen: true, fullscreenWeb: true, miniProgressBar: true, theme: S.cfg.theme, type: 'm3u8', crossOrigin: 'anonymous', playsInline: true,
                customType: {
                    m3u8: function (video, streamUri, art) {
                        if (window.Hls && window.Hls.isSupported()) {
                            if (art.hls) art.hls.destroy();
                            const hls = new window.Hls({ liveDurationInfinity: true, backBufferLength: 9000, liveMaxLatencyDurationCount: 999999 });
                            hls.loadSource(streamUri); hls.attachMedia(video); art.hls = hls;
                            art.on('destroy', () => hls.destroy());
                            hls.on(window.Hls.Events.ERROR, (_, d) => { if(d.fatal && d.type === window.Hls.ErrorTypes.NETWORK_ERROR) hls.startLoad(); });
                        } else if (video.canPlayType('application/vnd.apple.mpegurl')) video.src = streamUri;
                    }
                },
                controls:[{ position:'left', html:`<div style="display:flex;align-items:center;cursor:pointer;padding:0 10px;color:#fff;gap:6px" title="Exit Player (Esc)"><svg style="width:24px;height:24px;fill:currentColor" viewBox="0 0 24 24">${ic.back}</svg></div>`, click: function() { stopAll(); $('gz-pv').classList.remove('on'); $('gz-bv').classList.add('on'); renderGrid(); } }]
            });
        }

        /* Initial Entry & Pre-fetching */
        let initPoll = 0; const boot = () => {
            if ((window.oDevice && window.oDevice.Settings) || initPoll > 25) {
                loadChannels().then(d => { S.chs = d.chs.map(norm); S.genres = d.genres; buildSidebar(); renderGrid(); }).catch(() => { $('gz-grid').innerHTML = '<div style="grid-column:1/-1;text-align:center;padding:50px;color:var(--sub)">Failed to establish network pipeline. Check logs.</div>'; });
            } else { initPoll++; setTimeout(boot, 200); }
        }; boot();
    });
})();
