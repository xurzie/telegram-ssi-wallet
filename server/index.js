/* eslint-disable no-console */
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
dotenv.config();
const fetch = global.fetch || require('node-fetch');

const { ensureUser, getUserByTgId } = require('./users');
const { importCredential, importCredentialAny, listCredentials } = require('./wallet');
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

/** Импорт креденшела по ссылке (iden3comm request_uri / i_m) */
app.post('/api/credentials/import-link', async (req, res) => {
    try {
        const { tgUserId, link } = req.body || {};
        if (!tgUserId || !link) return res.status(400).json({ error: 'tgUserId and link required' });

        const user = getUserByTgId(String(tgUserId));
        if (!user) return res.status(404).json({ error: 'user not found' });

        // 1) достаём request_uri либо i_m (base64) из iden3comm:// или universal link #fragment
        //    Правила из официальной доки Universal Links (request_uri или i_m в #fragment) :contentReference[oaicite:4]{index=4}
        let requestUri;
        let inlineMsgBase64;
        try {
            if (link.startsWith('iden3comm://')) {
                const u = new URL(link.replace('iden3comm://', 'http://'));
                requestUri = u.searchParams.get('request_uri');
                inlineMsgBase64 = u.searchParams.get('i_m');
            } else {
                const u = new URL(link);
                requestUri = u.searchParams.get('request_uri');
                if (!requestUri && u.hash) {
                    const sp = new URLSearchParams(u.hash.substring(1));
                    requestUri = sp.get('request_uri');
                    inlineMsgBase64 = sp.get('i_m');
                }
            }
        } catch (_) { /* ignore parse errors */ }

        // Если пришёл короткий inline-message (i_m) — это сам оффер/реквест внутри base64
        let offer;
        if (inlineMsgBase64) {
            try {
                const raw = Buffer.from(decodeURIComponent(inlineMsgBase64), 'base64').toString('utf8');
                offer = JSON.parse(raw);
            } catch (e) {
                return res.status(400).json({ error: 'invalid i_m payload' });
            }
        }

        // 2) иначе тянем оффер по request_uri
        if (!offer) {
            if (!requestUri) return res.status(400).json({ error: 'request_uri not found in link' });
            const offerRes = await fetch(requestUri);
            if (!offerRes.ok) throw new Error(`offer HTTP ${offerRes.status}`);
            offer = await offerRes.json();
        }

        if (process.env.DEBUG_IMPORT) console.log('offer', JSON.stringify(offer));

        // 3) извлекаем URL/ID самого креденшела из оффера разных форматов
        //    (встречается в body.url или внутри body.credentials[0].url/id и т.п.)
        let credUrl = offer?.body?.url || offer?.url;
        let credId  = offer?.body?.credentialId || offer?.credentialId || offer?.body?.credentials?.[0]?.id;
        if (!credUrl) credUrl = offer?.body?.credentials?.[0]?.url;

        if (!credUrl || !credId) throw new Error('invalid offer: credential url/id not found');

        // 4) забираем сам credential (JWT или JSON)
        const credRes = await fetch(credUrl, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ credentialId: credId, did: user.did })
        });
        if (!credRes.ok) throw new Error(`credential HTTP ${credRes.status}`);
        const raw = await credRes.text();

        // 5) пробуем вытащить jwt из разных обёрток
        let jwtOrJson = raw.trim();
        try {
            const j = JSON.parse(raw);
            jwtOrJson = j.credentialJWT || j.jwt || j.token || j; // j может быть уже JSON-LD VC
        } catch (_) {}

        const rec = importCredentialAny(user.id, jwtOrJson);
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

/** Auth: принимает requestUri ИЛИ полную ссылку (iden3comm/universal) и возвращает Auth Response JWT */
app.post('/api/auth', async (req, res) => {
    try {
        const { tgUserId, requestUri } = req.body || {};
        if (!tgUserId || !requestUri) return res.status(400).json({ error: 'tgUserId and requestUri required' });

        const user = getUserByTgId(String(tgUserId));
        if (!user) return res.status(404).json({ error: 'user not found' });

        let link = String(requestUri);
        // Позволяем сюда же кидать целиком iden3comm:// или https://wallet.privado.id/#...
        // — выдираем оттуда request_uri или i_m (как выше)
        let extracted = link;
        try {
            let reqUri, i_m;
            if (link.startsWith('iden3comm://')) {
                const u = new URL(link.replace('iden3comm://', 'http://'));
                reqUri = u.searchParams.get('request_uri');
                i_m = u.searchParams.get('i_m');
            } else {
                const u = new URL(link);
                reqUri = u.searchParams.get('request_uri');
                if (!reqUri && u.hash) {
                    const sp = new URLSearchParams(u.hash.substring(1));
                    reqUri = sp.get('request_uri');
                    i_m = sp.get('i_m');
                }
            }
            if (i_m) {
                // inline auth request
                extracted = Buffer.from(decodeURIComponent(i_m), 'base64').toString('utf8');
            } else if (reqUri) {
                extracted = reqUri;
            }
        } catch (_) {}

        const out = await authRequest(user, extracted);
        res.json(out);
    } catch (e) {
        console.error(e);
        res.status(400).json({ error: e.message || 'auth failed' });
    }
});


app.listen(PORT, HOST, () => {
    console.log(`Wallet server on http://${HOST}:${PORT}`);
});
