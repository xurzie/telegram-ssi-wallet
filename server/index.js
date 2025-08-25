/* eslint-disable no-console */
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
dotenv.config();
const fetch = global.fetch || require('node-fetch');

const { ensureUser, getUserByTgId } = require('./users');
const { importCredentialAny, listCredentials } = require('./wallet');
const { ensureDidForUser } = require('../sdk/identity'); // не трогаем
// auth сейчас не нужен для DID/импорта, чтобы не падал — можно временно заглушить в sdk/polygonid.js
const { authRequest } = require('../sdk/polygonid');

const app = express();
app.use(bodyParser.json({ limit: '1mb' }));

const PORT = process.env.PORT || 5173;
const HOST = process.env.HOST || '0.0.0.0';

/* ---------- статика ---------- */
app.use('/webapp', express.static(path.join(__dirname, '..', 'webapp')));
app.get('/', (_req, res) =>
    res.sendFile(path.join(__dirname, '..', 'webapp', 'index.html'))
);

app.get('/healthz', (_req, res) => res.json({ ok: true }));

/* ---------- API ---------- */

/** Сессия: гарантируем запись юзера и наличие DID. ВСЕГДА возвращаем объект { ... , did } */
app.post('/api/session', async (req, res) => {
    try {
        const { tgUserId } = req.body || {};
        if (!tgUserId) return res.status(400).json({ error: 'tgUserId required' });

        // создать/найти пользователя
        let user = ensureUser(String(tgUserId));

        // обеспечить DID (если уже есть — вернётся как есть)
        try {
            user = await ensureDidForUser(user);
        } catch (e) {
            console.error('ensureDidForUser error:', e);
            return res.status(500).json({ error: 'internal' });
        }

        // на всякий пожарный: вернуть именно объект
        if (typeof user !== 'object' || !user.did) {
            // если кто-то внутри вернул строку, достанем полную запись
            const { getDb } = require('./db');
            const db = getDb();
            const row = db.prepare('SELECT * FROM users WHERE tg_id=?').get(String(tgUserId));
            if (row) user = row;
            else user = { tg_id: String(tgUserId), did: String(user || '') };
        }

        res.json({ ok: true, user });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message || 'internal' });
    }
});

/** Импорт существующего креденшела вручную (JWT или JSON-LD) */
app.post('/api/credentials/import', (req, res) => {
    try {
        const { tgUserId, jwt, credential } = req.body || {};
        if (!tgUserId) return res.status(400).json({ error: 'tgUserId required' });

        const user = getUserByTgId(String(tgUserId));
        if (!user) return res.status(404).json({ error: 'user not found' });

        const data = credential || jwt;
        if (!data) return res.status(400).json({ error: 'credential required' });

        const rec = importCredentialAny(user.id, data);
        res.json({ ok: true, credential: rec });
    } catch (e) {
        console.error(e);
        res.status(400).json({ error: e.message || 'invalid credential' });
    }
});

/** Импорт креденшела по ссылке (iden3comm request_uri) */
app.post('/api/credentials/import-link', async (req, res) => {
    try {
        const { tgUserId, link } = req.body || {};
        if (!tgUserId || !link) return res.status(400).json({ error: 'tgUserId and link required' });

        let user = getUserByTgId(String(tgUserId));
        if (!user) return res.status(404).json({ error: 'user not found' });

        // ensure DID exists (client might skip /api/session)
        if (!user.did || user.did.startsWith('did:example')) {
            try {
                const did = await ensureDidForUser(user);
                user = { ...user, did };
            } catch (err) {
                console.error('ensureDidForUser error:', err);
                return res.status(500).json({ error: 'internal' });
            }
        }

        // извлечь request_uri из iden3comm:// или wallet-staging ссылки
        let requestUri;
        try {
            if (link.startsWith('iden3comm://')) {
                const u = new URL(link.replace('iden3comm://', 'http://'));
                requestUri = u.searchParams.get('request_uri');
            } else {
                const u = new URL(link);
                requestUri = u.searchParams.get('request_uri');
                if (!requestUri && u.hash) {
                    requestUri = new URLSearchParams(u.hash.substring(1)).get('request_uri');
                }
            }
        } catch (_) {}
        if (!requestUri) return res.status(400).json({ error: 'request_uri not found in link' });

        // запрос оффера
        const offerRes = await fetch(requestUri);
        if (!offerRes.ok) throw new Error(`offer HTTP ${offerRes.status}`);
        const offer = await offerRes.json();
        const credUrl = offer?.body?.url;
        const credId = offer?.body?.credentials?.[0]?.id;
        if (!credUrl || !credId) throw new Error('invalid offer');

        // запрос самого креденшела
        const credRes = await fetch(credUrl, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ credentialId: credId, did: user.did })
        });
        if (!credRes.ok) throw new Error(`credential HTTP ${credRes.status}`);
        const raw = await credRes.text();

        let credential;
        try {
            const j = JSON.parse(raw);
            credential = j.credential || j.credentialJWT || j.jwt || j.token || j;
        } catch (_) {
            credential = raw.trim();
        }
        const rec = importCredentialAny(user.id, credential);
        res.json({ ok: true, credential: rec });
    } catch (e) {
        console.error(e);
        res.status(400).json({ error: e.message || 'import-link failed' });
    }
});

/** Список кредов */
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

/** (НЕобязательное) Auth для верифаеров.
 * Если сейчас валится — временно верни мок внутри sdk/polygonid.js,
 * чтобы UI не ломался. На импорт и DID это не влияет. */
app.post('/api/auth', async (req, res) => {
    try {
        const { tgUserId, requestUri } = req.body || {};
        if (!tgUserId || !requestUri) return res.status(400).json({ error: 'tgUserId and requestUri required' });

        const user = getUserByTgId(String(tgUserId));
        if (!user) return res.status(404).json({ error: 'user not found' });

        const out = await authRequest(user, requestUri);
        res.json(out);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message || 'auth failed' });
    }
});

app.listen(PORT, HOST, () => {
    console.log(`Wallet server on http://${HOST}:${PORT}`);
});
