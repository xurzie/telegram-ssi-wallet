/* eslint-disable no-console */
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
dotenv.config();

const { ensureUser, getUserByTgId } = require('./users');
const { importCredentialAny, listCredentials } = require('./wallet'); // << поменял
const { authRequest } = require('../sdk/polygonid');
const { ensureDidForUser } = require('../sdk/identity');
const { getDb } = require('./db');

const app = express();
app.use(bodyParser.json({ limit: '1mb' }));

const PORT = process.env.PORT || 5173;
const HOST = process.env.HOST || '0.0.0.0';

// статика
app.use('/webapp', express.static(path.join(__dirname, '..', 'webapp')));
app.get('/', (_req, res) =>
    res.sendFile(path.join(__dirname, '..', 'webapp', 'index.html'))
);

app.get('/healthz', (_req, res) => res.json({ ok: true }));

// ===== helpers =====
const DEBUG_IMPORT = process.env.DEBUG_IMPORT === '1';
const dlog = (...a) => { if (DEBUG_IMPORT) console.log('[import-link]', ...a); };

function looksLikeJwt(s) {
    return typeof s === 'string' && s.split('.').length >= 3;
}

// достаём оффер и возвращаем {offerUrl, msg}
async function fetchOffer(link) {
    let requestUri = (link || '').trim();
    dlog('incoming link:', requestUri);
    if (!requestUri) throw new Error('empty link');

    // wallet-staging/prod: вытаскиваем request_uri из #hash
    if (/^https:\/\/wallet(-staging)?\.privado\.id/i.test(requestUri)) {
        const hash = requestUri.split('#')[1] || '';
        const params = new URLSearchParams(hash);
        const ru = params.get('request_uri') || params.get('requestUri') || '';
        if (!ru) throw new Error('wallet-staging link has no request_uri');
        requestUri = decodeURIComponent(ru);
    }
    // iden3comm://?request_uri=...
    else if (requestUri.toLowerCase().startsWith('iden3comm://')) {
        const q = requestUri.slice('iden3comm://'.length);
        const s = q.startsWith('?') ? q.slice(1) : q;
        const params = new URLSearchParams(s);
        requestUri =
            params.get('request_uri') ||
            params.get('requestUri') ||
            params.get('requestUrl') ||
            params.get('uri') || '';
        if (!requestUri) throw new Error('invalid iden3comm link: no request_uri');
        requestUri = decodeURIComponent(requestUri);
    } else if (!/^https?:\/\//i.test(requestUri)) {
        throw new Error('request_uri is not http(s): ' + requestUri);
    }

    dlog('request_uri:', requestUri);
    const r0 = await fetch(requestUri);
    if (!r0.ok) throw new Error(`request_uri HTTP ${r0.status}`);
    let msgText = await r0.text();
    let msg;
    try { msg = JSON.parse(msgText); }
    catch { throw new Error('request_uri did not return JSON'); }

    dlog('message keys:', Object.keys(msg));
    const body = msg.body || msg;

    let offerUrl =
        body.url || body.uri || body.offerUrl || body.issueUrl || body.callbackUrl ||
        msg.url  || msg.uri  || msg.offerUrl;

    if (!offerUrl && Array.isArray(msg.attachments) && msg.attachments[0]) {
        offerUrl = msg.attachments[0]?.data?.url || msg.attachments[0]?.data?.uri;
    }
    if (!offerUrl) throw new Error('offer url not found in message');

    dlog('offerUrl:', offerUrl);
    return { offerUrl, msg };
}

// шлём JWZ в /v2/agent, возвращаем credential JSON-LD
async function requestIssuanceWithJwz(offerUrl, jwz, threadHint) {
    if (!jwz || !jwz.length) throw new Error('jwz required');

    // самый совместимый вариант — прислать JWZ как raw body
    const headersList = [
        { 'content-type': 'text/plain' },
        { 'content-type': 'application/jwz' },       // на всякий — вдруг кто-то так ждёт
        { 'content-type': 'application/octet-stream' }
    ];

    for (const headers of headersList) {
        try {
            dlog('POST JWZ ->', offerUrl, 'ct:', headers['content-type']);
            const r = await fetch(offerUrl, { method: 'POST', headers, body: jwz });
            const t = await r.text();

            // иногда выдаёт пусто на 200 — пробуем следующую CT
            if (!t) { dlog('POST JWZ empty body'); continue; }

            let j;
            try { j = JSON.parse(t); } catch { /* not json */ }

            // ищем credential в стандартных местах ответа "issuance-response"
            const vc = j?.body?.credential || j?.credential;
            if (vc && typeof vc === 'object' && vc['@context']) return vc;

            // некоторые сборки возвращают массив credentials
            const vc2 = Array.isArray(j?.credentials) && j.credentials[0];
            if (vc2 && vc2['@context']) return vc2;

            dlog('POST JWZ unknown body 200b:', t.slice(0, 200));
        } catch (e) {
            dlog('POST JWZ failed:', e.message);
        }
    }

    // вдруг сервер ожидает GET с параметрами (редко)
    try {
        const u = new URL(offerUrl);
        if (threadHint) u.searchParams.set('thid', String(threadHint));
        dlog('GET (fallback) ->', u.toString());
        const r = await fetch(u.toString(), { headers: { accept: 'application/json' }});
        const t = await r.text();
        let j; try { j = JSON.parse(t); } catch {}
        const vc = j?.body?.credential || j?.credential;
        if (vc && vc['@context']) return vc;
        dlog('GET fallback no token, body200b:', t.slice(0, 200));
    } catch (e) {
        dlog('GET fallback failed:', e.message);
    }

    throw new Error('issuer did not return credential');
}

// ===== API =====

// сессия: создаём/ищем юзера и гарантируем DID
app.post('/api/session', async (req, res) => {
    try {
        const { tgUserId } = req.body || {};
        if (!tgUserId) return res.status(400).json({ error: 'tgUserId required' });

        let user = ensureUser(String(tgUserId));
        try {
            user = await ensureDidForUser(user);
        } catch (e) {
            console.error('ensureDidForUser error:', e);
            return res.status(500).json({ error: 'internal' });
        }
        res.json({ ok: true, user });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message || 'internal' });
    }
});

/**
 * Импорт по оффер-ссылке (iden3comm / wallet-staging / прямой qr-store)
 * ТРЕБУЕТ jwz — его надо получить предварительно из QR авторизации Issuer’а.
 * См. /api/auth (ты это уже юзал для Verifier — работает и тут).
 */
app.post('/api/credentials/import-link', async (req, res) => {
    try {
        const { tgUserId, link, jwz } = req.body || {};
        if (!tgUserId || !link) return res.status(400).json({ error: 'tgUserId and link required' });
        if (!jwz || !looksLikeJwt(jwz)) {
            return res.status(400).json({ error: 'jwz required (authorization response JWT from issuer auth QR)' });
        }

        const db = getDb();
        const user = db.prepare('SELECT id,did FROM users WHERE tg_id=?').get(String(tgUserId));
        if (!user) return res.status(404).json({ error: 'user not found' });

        const { offerUrl, msg } = await fetchOffer(link);

        // thid из оффера может пригодиться серверу, передаём как подсказку в GET-фоллбэке
        const thid = msg?.thid || msg?.id;

        // делаем корректный вызов: JWZ -> /v2/agent, получаем VC JSON-LD
        const vc = await requestIssuanceWithJwz(offerUrl, jwz, thid);

        // сохраняем (и JWT, и JSON-LD поддерживаются)
        const rec = importCredentialAny(user.id, vc);
        res.json({ ok: true, mode: 'issuance-response', credential: rec });
    } catch (e) {
        console.error('import-link error:', e);
        res.status(500).json({ error: e.message || 'internal' });
    }
});

// список
app.get('/api/credentials', (req, res) => {
    try {
        const tgUserId = req.query.tgUserId;
        if (!tgUserId) return res.status(400).json({ error: 'tgUserId required' });
        const user = getUserByTgId(String(tgUserId));
        if (!user) return res.status(404).json({ error: 'user not found' });
        const rows = listCredentials(user.id);
        res.json({ items: rows });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message || 'internal' });
    }
});

app.post('/api/session', async (req, res) => {
    try {
        const { tgUserId } = req.body || {};
        if (!tgUserId) return res.status(400).json({ error: 'tgUserId required' });

        const tg = String(tgUserId);

        const u0 = ensureUser(tg);   // создаём запись, если нет

        // гарантия DID (ничего не возвращаем/не присваиваем)
        try { await ensureDidForUser(u0); } catch (e) {
            console.error('ensureDidForUser error:', e);
        }

        // перечитать свежее состояние из БД
        const db = getDb();
        const user = db
            .prepare('SELECT id,tg_id,did,seed_hex,created_at FROM users WHERE tg_id=?')
            .get(tg);

        if (!user) return res.status(404).json({ error: 'user not found' });
        res.json({ ok: true, user });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message || 'internal' });
    }
});



app.listen(PORT, HOST, () => {
    console.log(`Wallet server on http://${HOST}:${PORT}`);
});
