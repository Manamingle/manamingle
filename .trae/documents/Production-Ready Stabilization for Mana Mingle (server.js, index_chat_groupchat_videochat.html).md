## Goals
- Harden backend and sockets for production security and reliability
- Make all buttons and flows work end-to-end (chat, group chat, video chat)
- Make coin system server‑authoritative and consistent across pages
- Ensure online user count is accurate everywhere
- Ensure liquid glass UI renders consistently with graceful fallbacks

## Server Hardening (server.js)
- Set `app.set('trust proxy', 1)` to fix real IP detection behind proxy/CDN
- Tighten Helmet CSP: remove `'unsafe-inline'`, use nonces/hashes; correct `mediaSrc` and enable stricter cross‑origin policies
- Strengthen CORS: keep allowlist for `manamingle.site`, verify credentials only if needed
- Enforce schema validation for REST and Socket payloads; reject invalid/oversized inputs early
- Unify and raise rate limits for sensitive endpoints and socket events; add progressive penalties and temporary bans for abuse
- Replace static admin shared secret with per‑admin accounts + hashed passwords + short‑lived JWT + MFA
- Persist moderation state (bans/reports) to durable storage; load on startup and include in `admin-state`
- Add log rotation/retention and structured error codes

## Coin System (server + UI)
- Make server the source of truth for balances; stop trusting client `coin-update`
- Implement coin award rules server‑side (interval credit, actions, transfers), atomic operations, and non‑negative checks
- Persist balances to durable storage and load on connect; include in peer payloads and `existing-peers`
- Normalize UI bindings:
  - `index.html`: continue showing `appState.manaCoins`, but update via server events
  - `groupchat.html`: keep `coin-transfer`/`coin-update`; validate on server
  - `videochat.html`: `updateCoinDisplay` driven by authoritative server balance
- Add fraud/abuse protections: rate limits, max per interval, audit trail

## Online Count
- Keep source of truth `state.users.size`; already emitted on connect/disconnect (`server.js:1006`, `server.js:1628`)
- Ensure consistent listeners and renderers:
  - `index.html` navbar pill updates (`index.html:2914–2933`)
  - `videochat.html` header badge updates (`videochat.html:1499–1504`)
  - Add visible count to `chat.html` (currently logs only); bind to on‑page element
- Include in admin dashboard via `admin-state.stats.onlineUsers` (`server.js:1677`)

## UI Fixes & Buttons
- `chat.html`:
  - Either implement file upload (with validation and server endpoint) or hide `#attachBtn` until ready
  - Verify report modal actions and socket payloads; align with server schema
  - Add visible online count badge and bind to `online_count`
- `groupchat.html`:
  - Remove or re‑wire legacy `.media-preview` block; add handler for `#removePreviewBtn` if retained
  - Ensure media send flows correctly integrate with coin payment and server validation
- `videochat.html`:
  - Add missing permission modal elements (`#permissionModal`, `#allowPermission`, `#denyPermission`) referenced by handlers, or guard for null and use a consistent UX
  - Verify all core controls (`start`, `skip`, `send`, `report`, `block`) operate and reflect server responses

## Liquid Glass Styling
- Audit `backdrop-filter` usages and add `-webkit-backdrop-filter` for Safari; add non‑glass graceful fallbacks for browsers without support
- Centralize CSS variables for blur strength, translucency, borders, and gradients to ensure consistency
- Verify components across pages: cards, buttons, overlays, modals, chat bubbles render uniformly

## Verification & Tests
- Add integration tests for socket events (coins, presence, messaging) and REST moderation endpoints
- Add UI smoke tests: button click flows and modal confirmations
- Manual QA checklist:
  - Coin award/timer, transfer, and balance persistence
  - Online count accuracy on index/chat/video pages
  - Permission modal flow in video chat
  - Report/ban/resolve actions reflected in admin dashboard
  - Liquid glass visual consistency on Chrome/Safari/Firefox

## Deployment Readiness
- Document environment variables and secrets handling; avoid hard‑coded keys
- Build/minify static assets; enable compression and cache‑control
- Ensure TLS termination and HSTS; confirm reverse proxy headers
- Prepare log rotation and monitoring/alerts

## Next Steps (Implementation Order)
1) Server hardening (trust proxy, validation, rate limits, admin auth, persistence)
2) Coin system authority + persistence, emit authoritative updates
3) Online count UI binding in chat.html
4) Fix button gaps (chat attach, groupchat media preview, videochat permission modal)
5) Liquid glass consistency and fallbacks
6) Tests, QA, and deployment checks