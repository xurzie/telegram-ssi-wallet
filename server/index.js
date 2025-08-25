/* eslint-disable no-console */
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
dotenv.config();

const { ensureUser, getUserByTgId } = require('./users');
const { importCredential, listCredentials } = require('./wallet');
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

/** Импорт JWT-креденшела вручную (то, что у тебя уже есть из direct issue) */
app.post('/api/credentials/import', (req, res) => {
    try {
        const { tgUserId, jwt } = req.body || {};
        if (!tgUserId || !jwt) return res.status(400).json({ error: 'tgUserId and jwt required' });

        const user = getUserByTgId(String(tgUserId));
        if (!user) return res.status(404).json({ error: 'user not found' });

        const rec = importCredential(user.id, jwt);
        res.json({ ok: true, credential: rec });
    } catch (e) {
        console.error(e);
        res.status(400).json({ error: e.message || 'invalid credential' });
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
