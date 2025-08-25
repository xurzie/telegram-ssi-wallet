# Telegram SSI Wallet (Starter)

A minimal starter that implements a **Telegram WebApp wallet** which can **store credentials (JWT or JSON-LD)** and, in the ideal flow, **authenticate against a Verifier (Week #2)** using Polygon ID js-sdk.
> ✅ Out of the box: WebApp UI + Express server + SQLite storage + Telegram bot with "Open Wallet" button + Credential import/list.
> 🔜 Plug in Polygon ID js-sdk (`@0xpolygonid/js-sdk`) in `sdk/polygonid.js` to generate real proofs for your verifier. A mock mode is included to let you wire the flow first.

---

## Quick start

1. **Install deps**

```bash
npm i
```

2. **Configure `.env`**

Copy `.env.example` to `.env` and fill:
- `TELEGRAM_BOT_TOKEN`
- `WEBAPP_URL` (e.g. `http://localhost:5173/webapp/`)
- keep `ENABLE_MOCKS=1` while wiring UI; switch to `0` after integrating js-sdk.

3. **Initialize DB**

```bash
npm run initdb
```

4. **Start server**

```bash
npm run start
```

5. **Run bot** (in another terminal)

```bash
npm run bot
```

Open Telegram, talk to your bot, press **Open Wallet** → it loads the WebApp hosted by your server.

---

## What’s included

- **server/** Express backend
  - `index.js` – API routes, static hosting for WebApp
  - `db.js` – SQLite wrapper via better-sqlite3
  - `initdb.js` – one-time DB schema init
  - `bot.js` – Telegram bot that shows a WebApp button
- **webapp/** – Minimal HTML/JS UI (no build toolchain)
  - Import credential (paste JWT or JSON-LD)
  - List stored credentials
  - Start **Verifier auth** by pasting `request_uri` (from your Week #2 verifier QR)

- **sdk/polygonid.js** – Integration point for Polygon ID js-sdk.
  - Contains **mock** implementation by default.
  - Replace with real `@0xpolygonid/js-sdk` logic when ready.

---

## API

- `POST /api/session` – Upserts a user by Telegram user id, returns a wallet DID (placeholder until js-sdk plugged in).
- `GET /api/credentials` – List user credentials.
- `POST /api/credentials/import` – Body `{ credential }` (JWT string or JSON-LD object). Stores the credential and parsed header/payload for quick view.
- `POST /api/auth` – Body `{ requestUri }`. With mocks: returns a dummy response. With js-sdk: generates real auth response and (optionally) POSTs to callback from the request.

---

## Plugging Polygon ID js-sdk

1. Install the SDK:

```bash
npm i @0xpolygonid/js-sdk
```

2. Open `sdk/polygonid.js` and set `USE_MOCKS=false`. Implement:
   - **Identity creation/loading** for each Telegram user
   - **Credential storage** (reuse `credentials` table or your own)
   - **Auth flow**: parse `request_uri` from the QR, call e.g.
     `authHandler.handleAuthorizationRequest(userDID, msgBytes)` and return the JWT response.
   - If request contains `callbackUrl` (aka `serviceUrl`), POST the response there.

> Tip: see the js-sdk test you were given for a working reference:
> `tests/handlers/auth.test.ts`

---

## Verifier (Week #2)

- Open your verifier page and **copy the `request_uri`** behind the QR.
- In the wallet WebApp, paste it into the **Authenticate** field and submit.
- With js-sdk integrated, you’ll return a valid **Auth Response JWT** and pass checks.

---

## Security notes (dev starter)

- This is a barebones dev template. Don’t ship to prod as‑is.
- Add key management, encrypt storage, CSRF protection, strict CORS, proper session handling.
- Never commit your bot token or real secrets.
# telegram-ssi-wallet
