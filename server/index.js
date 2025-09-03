/* eslint-disable no-console */
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
dotenv.config();

const fetch = global.fetch || require('node-fetch');

const { ensureUser, getUserByTgId } = require('./users');
const { importCredentialAny, listCredentials } = require('./wallet');
const { ensureDidForUser } = require('../sdk/identity');
const { handleAuthRequest } = require('../sdk/polygonid');


/* ---------- Issuer config (.env) ---------- */
const ISSUER_BASE_URL = (process.env.ISSUER_BASE_URL || '').trim(); // https://issuer-node-core-api-testing.privado.id
const ISSUER_BASIC_USER = (process.env.ISSUER_BASIC_USER || '').trim();
const ISSUER_BASIC_PASS = (process.env.ISSUER_BASIC_PASS || '').trim();
const ISSUER_DID = (process.env.ISSUER_DID || '').trim();

function basicAuthHeader(u, p) {
    if (!u || !p) return null;
    const token = Buffer.from(`${u}:${p}`).toString('base64');
    return `Basic ${token}`;
}
const AUTH_HDR = basicAuthHeader(ISSUER_BASIC_USER, ISSUER_BASIC_PASS);

/* ---------- helpers ---------- */

function getParamFromUrl(u, names) {
    try {
        const url = new URL(u);
        for (const n of names) {
            const v = url.searchParams.get(n);
            if (v) return v;
        }
        if (url.hash) {
            const sp = new URLSearchParams(url.hash.slice(1));
            for (const n of names) {
                const v = sp.get(n);
                if (v) return v;
            }
        }
    } catch {}
    return null;
}

function parseIden3Link(link) {
    let requestUri = null;
    let inlineMsgBase64 = null;

    if (!link) return { requestUri, inlineMsgBase64, directUrl: null };

    try {
        if (link.startsWith('iden3comm://')) {
            const u = new URL(link.replace('iden3comm://', 'http://dummy-host/'));
            requestUri =
                u.searchParams.get('request_uri') ||
                u.searchParams.get('request_url') ||
                u.searchParams.get('requestUri') ||
                null;
            inlineMsgBase64 = u.searchParams.get('i_m') || null;
        } else {
            requestUri = getParamFromUrl(link, ['request_uri', 'request_url', 'requestUri']) || null;
            inlineMsgBase64 = getParamFromUrl(link, ['i_m']) || null;

            if (!requestUri && !inlineMsgBase64 && /^https?:\/\//i.test(link)) {
                return { requestUri: null, inlineMsgBase64: null, directUrl: link };
            }
        }
    } catch {}

    return { requestUri, inlineMsgBase64, directUrl: null };
}

async function fetchText(url, init = {}) {
    const r = await fetch(url, init);
    const body = await r.text().catch(() => '');
    if (!r.ok) {
        const err = new Error('fetch failed');
        err.status = r.status;
        err.body = body;
        throw err;
    }
    return body;
}

async function fetchJson(url, init = {}) {
    const body = await fetchText(url, init);
    try {
        return JSON.parse(body);
    } catch {
        const err = new Error('invalid json');
        err.status = 200;
        err.body = body;
        throw err;
    }
}

function rootFromUrl(u) {
    try {
        const x = new URL(u);
        return `${x.protocol}//${x.host}`;
    } catch { return null; }
}


async function fetchCredentialByIssuerAndId(baseUrl, issuerDid, credentialId, didForPost, withAuth) {
    if (!baseUrl) throw new Error('issuer base url not set');
    if (!issuerDid) throw new Error('issuer did not provided');
    if (!credentialId) throw new Error('credential id not provided');

    const base = baseUrl.replace(/\/+$/, '');
    const encDid = encodeURIComponent(issuerDid);
    const encId  = encodeURIComponent(credentialId);

    const headers = {
        ...(withAuth || (AUTH_HDR ? { Authorization: AUTH_HDR } : {})),
        Accept: 'application/json',
    };

    const urls = [
        // v2 (DID in path)
        `${base}/v2/credentials/${encDid}/${encId}`,
        `${base}/v2/credentials/${encDid}/${encId}?repr=jwt`,
        // v2 (DID in query)
        `${base}/v2/credentials/${encId}?issuer=${encDid}`,
        `${base}/v2/credentials/${encId}?issuer=${encDid}&repr=jwt`,
        // v2 ("claims" instead "credentials")
        `${base}/v2/claims/${encId}?issuer=${encDid}`,
        // v1 (DID in path)
        `${base}/v1/${encDid}/claims/${encId}`,
        `${base}/v1/${encDid}/claims/${encId}?repr=jwt`,
        // v1 (DID in query)
        `${base}/v1/claims/${encId}?issuer=${encDid}`,
        `${base}/v1/claims/${encId}?issuer=${encDid}&repr=jwt`,
        // v1 (alt)
        `${base}/v1/credentials/${encId}?issuer=${encDid}`,
    ];

    let lastErr;
    for (const url of urls) {
        // GET
        try {
            const body = await fetchText(url, { method: 'GET', headers });
            try { return JSON.parse(body); } catch { return body.trim(); }
        } catch (e) {
            lastErr = e;
            console.warn('issuer attempt failed:', 'GET', url, e.status, (e.body||'').slice(0,160));
            if (e.status && [400,401,403,404,405].includes(e.status)) {
                try {
                    const body = await fetchText(url, {
                        method: 'POST',
                        headers: { 'content-type':'application/json', ...headers },
                        body: JSON.stringify({ credentialId, did: didForPost || undefined, issuer: issuerDid }),
                    });
                    try { return JSON.parse(body); } catch { return body.trim(); }
                } catch (e2) {
                    lastErr = e2;
                    console.warn('issuer POST fallback failed:', url, e2.status, (e2.body||'').slice(0,160));
                }
            }
        }
    }

    const err = new Error('issuer fetch failed');
    err.status = lastErr?.status;
    err.body = lastErr?.body;
    err.hint = 'Tried v2/v1 with DID in path and query, GET+POST';
    throw err;
}

/* ---------- express ---------- */
const app = express();
app.use(bodyParser.json({ limit: '1mb' }));

const PORT = process.env.PORT || 5173;
const HOST = process.env.HOST || '0.0.0.0';

/* ---------- static ---------- */
app.use('/webapp', express.static(path.join(__dirname, '..', 'webapp')));
app.get('/', (_req, res) =>
    res.sendFile(path.join(__dirname, '..', 'webapp', 'index.html'))
);
app.get('/healthz', (_req, res) => res.json({ ok: true }));

/* ---------- API ---------- */

/** Session */
app.post('/api/session', async (req, res) => {
    try {
        const { tgUserId } = req.body || {};
        if (!tgUserId) return res.status(400).json({ error: 'tgUserId required' });

        let user = ensureUser(String(tgUserId));
        try { user = await ensureDidForUser(user); }
        catch (e) { console.error('ensureDidForUser error:', e); return res.status(500).json({ error: 'internal' }); }

        if (typeof user !== 'object' || !user.did) {
            const { getDb } = require('./db');
            const db = getDb();
            const row = db.prepare('SELECT * FROM users WHERE tg_id=?').get(String(tgUserId));
            user = row || { tg_id: String(tgUserId), did: String(user || '') };
        }
        res.json({ ok: true, user });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message || 'internal' });
    }
});

/** Import (JWT or JSON-LD) */
app.post('/api/credentials/import', (req, res) => {
    try {
        const { tgUserId, jwt, credential } = req.body || {};
        if (!tgUserId) return res.status(400).json({ error: 'tgUserId required' });
        const user = getUserByTgId(String(tgUserId));
        if (!user) return res.status(404).json({ error: 'user not found' });

        let data = credential || jwt;
        if (!data) return res.status(400).json({ error: 'credential required' });
        if (typeof data === 'string' && data.trim().startsWith('{')) {
            try { data = JSON.parse(data); } catch {}
        }

        const rec = importCredentialAny(user.id, data);
        res.json({ ok: true, credential: rec });
    } catch (e) {
        console.error(e);
        res.status(400).json({ error: e.message || 'invalid credential' });
    }
});

/**
 * Import from link
 */
app.post('/api/credentials/import-link', async (req, res) => {
    try {
        const { tgUserId, link, issuerDid, credentialId, basic } = req.body || {};
        if (!tgUserId) return res.status(400).json({ error: 'tgUserId required' });
        const user = getUserByTgId(String(tgUserId));
        if (!user) return res.status(404).json({ error: 'user not found' });

        const withAuth = (basic && basicAuthHeader(basic.user, basic.pass))
            ? { Authorization: basicAuthHeader(basic.user, basic.pass) }
            : (AUTH_HDR ? { Authorization: AUTH_HDR } : undefined);

        if (!link && credentialId) {
            const usedDid = issuerDid || ISSUER_DID;
            if (!usedDid) return res.status(400).json({ error: 'issuerDid missing and ISSUER_DID not set' });
            try {
                const vc = await fetchCredentialByIssuerAndId(ISSUER_BASE_URL, usedDid, credentialId, user.did, withAuth);
                const saved = importCredentialAny(user.id, vc);
                return res.json({ ok: true, credential: saved });
            } catch (e) {
                console.error('issuer direct fetch error:', e);
                return res.status(502).json({ error: 'issuer fetch failed', status: e.status, body: e.body, hint: e.hint });
            }
        }

        if (!link) return res.status(400).json({ error: 'provide "link" OR ("issuerDid" & "credentialId")' });

        const { requestUri, inlineMsgBase64, directUrl } = parseIden3Link(link);

        if (directUrl) {
            try {
                const vc = await fetchJson(directUrl, { headers: withAuth });
                const saved = importCredentialAny(user.id, vc);
                return res.json({ ok: true, credential: saved });
            } catch (e) {
                console.error('direct VC url error:', e);
                return res.status(502).json({ error: 'issuer fetch failed', status: e.status, body: e.body });
            }
        }

        let offer;
        if (inlineMsgBase64) {
            try {
                const raw = Buffer.from(decodeURIComponent(inlineMsgBase64), 'base64').toString('utf8');
                offer = JSON.parse(raw);
            } catch {
                return res.status(400).json({ error: 'invalid i_m payload' });
            }
        }

        if (!offer) {
            if (!requestUri) return res.status(400).json({ error: 'request_uri not found in link' });
            console.log('fetch offer from', requestUri);
            try {
                offer = await fetchJson(requestUri);
            } catch (e) {
                console.error('offer fetch error:', e);
                return res.status(502).json({ error: 'offer fetch failed', status: e.status, body: e.body });
            }
        }

        {
            const typ = (offer?.typ || offer?.type || '').toString();
            const isAuthReq =
                typ.includes('authorization/1.0/request') ||
                offer?.type === 'https://iden3-communication.io/authorization/1.0/request';

            if (isAuthReq) {
                return res.status(400).json({
                    error: 'link is an authorization request (not a credential offer)',
                    hint: 'Use /api/auth for this QR. To import a credential, paste a credentials/1.0/offer link.',
                    sample: 'iden3comm://?i_m=... (base64 of {"type":"https://iden3-communication.io/credentials/1.0/offer",...})'
                });
            }
        }

        let credUrl =
            offer?.body?.url ||
            offer?.url ||
            offer?.body?.credentials?.[0]?.url ||
            null;

        let credId =
            offer?.body?.credentialId ||
            offer?.credentialId ||
            offer?.body?.credentials?.[0]?.id ||
            offer?.body?.id ||
            null;

        if (!credId && requestUri) {
            const idFromReqUri = getParamFromUrl(requestUri, ['id']);
            if (idFromReqUri) credId = idFromReqUri;
        }
        let usedIssuerDid =
            offer?.body?.issuer ||
            (requestUri && getParamFromUrl(requestUri, ['issuer'])) ||
            issuerDid ||
            ISSUER_DID ||
            null;

        if (!credUrl) {
            if (!credId) return res.status(400).json({ error: 'invalid offer: credential id not found' });
            if (!usedIssuerDid) return res.status(400).json({ error: 'issuer did not found (set ISSUER_DID?)' });
            try {
                const vc = await fetchCredentialByIssuerAndId(ISSUER_BASE_URL || (requestUri && rootFromUrl(requestUri)), usedIssuerDid, credId, user.did, withAuth);
                const saved = importCredentialAny(user.id, vc);
                return res.json({ ok: true, credential: saved });
            } catch (e) {
                console.error('issuer fallback fetch error:', e);
                return res.status(502).json({ error: 'issuer fetch failed', status: e.status, body: e.body, hint: e.hint });
            }
        }

        try {
            let vc;
            try {
                vc = await fetchJson(credUrl, { headers: withAuth });
            } catch (eGet) {
                if (eGet.status && [400,404,405].includes(eGet.status)) {
                    vc = await fetchJson(credUrl, {
                        method: 'POST',
                        headers: { 'content-type': 'application/json', ...(withAuth || {}) },
                        body: JSON.stringify({ credentialId: credId, did: user.did }),
                    });
                } else {
                    throw eGet;
                }
            }
            const saved = importCredentialAny(user.id, vc);
            return res.json({ ok: true, credential: saved });
        } catch (e) {
            console.error('credUrl fetch error:', e);
            return res.status(502).json({ error: 'issuer fetch failed', status: e.status, body: e.body });
        }
    } catch (e) {
        console.error(e);
        res.status(400).json({ error: e.message || 'import-link failed' });
    }
});

/** VC list */
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

/** Auth  */
app.post('/api/auth', async (req, res) => {
    try {
        const { tgUserId, requestUri } = req.body || {};
        if (!tgUserId || !requestUri) return res.status(400).json({ error: 'tgUserId and requestUri required' });

        const user = getUserByTgId(String(tgUserId));
        if (!user) return res.status(404).json({ error: 'user not found' });

        let extracted = String(requestUri);
        try {
            let reqUri, i_m;
            if (extracted.startsWith('iden3comm://')) {
                const u = new URL(extracted.replace('iden3comm://', 'http://'));
                reqUri = u.searchParams.get('request_uri');
                i_m = u.searchParams.get('i_m');
            } else {
                const u = new URL(extracted);
                reqUri = u.searchParams.get('request_uri');
                if (!reqUri && u.hash) {
                    const sp = new URLSearchParams(u.hash.substring(1));
                    reqUri = sp.get('request_uri');
                    i_m = sp.get('i_m');
                }
            }
            if (i_m) {
                extracted = Buffer.from(decodeURIComponent(i_m), 'base64').toString('utf8'); // inline JSON
            } else if (reqUri) {
                extracted = reqUri;
            }
        } catch (_) {}

        const { token, authRequest } = await handleAuthRequest(user, extracted);

        const callbackUrl = authRequest?.body?.callbackUrl || null;
        let callbackStatus = null;
        let callbackBody = null;
        const imported = [];

        if (callbackUrl) {
            const tries = [];
            const baseHdr = { accept: 'application/json' };

            const withBasic = AUTH_HDR ? { ...baseHdr, authorization: AUTH_HDR } : baseHdr;
            const noBasic = baseHdr;

            for (const hdr of [withBasic, noBasic]) {
                for (const ct of [
                    'application/iden3comm-plain-json',
                    'text/plain',
                    'application/json'
                ]) {
                    tries.push({ headers: { ...hdr, 'content-type': ct }, label: `${ct} ${hdr.authorization ? 'with' : 'no'} Basic` });
                }
            }

            let lastErr = null;
            for (const t of tries) {
                try {
                    const r = await fetch(callbackUrl, { method: 'POST', headers: t.headers, body: token });
                    const bodyTxt = await r.text().catch(() => '');
                    console.log('callback try:', t.label, '→', r.status, (bodyTxt || '').slice(0, 200));
                    callbackStatus = r.status;
                    callbackBody = bodyTxt.slice(0, 8192);
                    if (r.ok) break; 
                    lastErr = new Error(`callback ${r.status}`);
                } catch (e) {
                    lastErr = e;
                    console.warn('callback error:', t.label, e.message);
                }
            }
            if (!callbackStatus) {
                callbackStatus = 0;
                callbackBody = String(lastErr?.message || 'callback failed');
            }

            const tryImportOffer = async (offerLike) => {
                try {
                    let msg = null;
                    if (!offerLike) return;
                    // if JSON
                    if (offerLike.trim().startsWith('{')) {
                        msg = JSON.parse(offerLike);
                    } else {
                        const { inlineMsgBase64, requestUri: ru } = parseIden3Link(offerLike);
                        if (inlineMsgBase64) {
                            const raw = Buffer.from(decodeURIComponent(inlineMsgBase64), 'base64').toString('utf8');
                            msg = JSON.parse(raw);
                        } else if (ru) {
                            msg = await fetchJson(ru);
                        }
                    }

                    const typ = (msg?.type || msg?.typ || '').toString();
                    const isOffer = typ.includes('/credentials/1.0/offer');
                    if (!isOffer) return;

                    const credUrl = msg?.body?.url || msg?.url;
                    const creds = msg?.body?.credentials || msg?.credentials || [];
                    if (!credUrl || !Array.isArray(creds) || creds.length === 0) return;

                    for (const c of creds) {
                        const credId = c?.id || c?.credentialId;
                        if (!credId) continue;
                        const r = await fetch(credUrl, {
                            method: 'POST',
                            headers: { 'content-type': 'application/json', ...(AUTH_HDR ? { Authorization: AUTH_HDR } : {}) },
                            body: JSON.stringify({ credentialId: credId, did: user.did })
                        });
                        if (!r.ok) continue;
                        const raw = await r.text();
                        let jwtOrJson = raw.trim();
                        try {
                            const j = JSON.parse(raw);
                            jwtOrJson = j.credentialJWT || j.jwt || j.token || j;
                        } catch {}
                        try {
                            imported.push(importCredentialAny(user.id, jwtOrJson));
                        } catch (e) {
                            console.error('import credential failed:', e);
                        }
                    }
                } catch (_) { /* ignore */ }
            };

            await tryImportOffer(callbackBody);
        }

        res.json({
            ok: true,
            mode: imported.length ? 'auth+import' : 'auth',
            token,
            callbackStatus,
            callbackBody,
            importedCount: imported.length
        });
    } catch (e) {
        console.error(e);
        res.status(400).json({ error: e.message || 'auth failed' });
    }
});

/* ---- run ---- */
app.listen(PORT, HOST, () => {
    console.log(`Wallet server on http://${HOST}:${PORT}`);
});
