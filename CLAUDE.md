# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A collection of browser userscripts (Violentmonkey/Tampermonkey) for Persian web services. No build system, no tests, no dependencies — each `.user.js` file is a standalone, self-contained script. Licensed AGPL-3.0.

## Userscripts

All scripts live in `UserScripts/`:

- **bale.user.js** — E2E encryption overlay for [Bale Web](https://web.bale.ai). AES-GCM encryption with ECDH key exchange, per-chat keys, draft blocking, base85/base64 encoding, compression, chunked message splitting, and a full settings UI. The most complex script.
- **rubika.user.js** — E2E encryption overlay for [Rubika Web](https://web.rubika.ir). Similar crypto approach to Bale (AES-GCM, per-chat keys, draft blocking) but adapted for Rubika's DOM and routing (`#c=` hash-based chat IDs).
- **glwiz.user.js** — Premium web player replacement for [GLWiz](https://glwiz.com) IPTV. Replaces the entire page with a custom UI: HLS streaming, channel grid, favorites, DVR caching, PiP, screenshot, quality/speed controls.

## Architecture Patterns

- Scripts use the Tampermonkey/Violentmonkey `==UserScript==` metadata block header for matching URLs and configuration.
- Encryption scripts (Bale, Rubika) share the same core design: per-chat settings in `localStorage`, AES-GCM with 12-byte IV, WebCrypto API (`crypto.subtle`), base64url and base85 encoding, deflate compression, `@@` / `@@+` message prefixes to identify encrypted content, and WebSocket `send` patching to block drafts.
- All scripts are single IIFEs with no external imports — crypto, UI, and DOM manipulation are all inline.
- Settings are persisted to `localStorage` with per-chat key prefixes (`bale_bridge_settings_`, `rubika_bridge_settings_`).

## Development Notes

- Scripts are installed by pasting into Violentmonkey's editor or loading the raw GitHub URL. There is no build/bundle step.
- The `@match` patterns in each script's metadata block control which sites the script runs on.
- When editing encryption scripts, the `@@` prefix marks encrypted messages and `@@+` marks the v2 base64url format (vs older base85 `@@`). Both must be handled for backwards compatibility.
