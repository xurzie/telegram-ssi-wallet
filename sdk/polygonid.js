// sdk/polygonid.js
// Реальная авторизация через @0xpolygonid/js-sdk + импорт кредов из БД.

const USE_MOCKS = (process.env.ENABLE_MOCKS || '1') !== '0';

// сеть/резолвер
const NETWORK_ID = process.env.NETWORK_ID || 'amoy';
const CHAIN_RPC = process.env.CHAIN_RPC || 'https://rpc-amoy.polygon.technology';
// адрес state-контракта в твоей сети (замени при необходимости)
const STATE_CONTRACT = process.env.STATE_CONTRACT || '0x134B1BE34911E39A8397ec6289782989729807a4';

// пути к циркUITам AuthV2
const AUTH_WASM = process.env.AUTH_WASM;
const AUTH_ZKEY = process.env.AUTH_ZKEY;

const { getDb } = require('../server/db');

// ================= Helpers =================

function normalizeRequestUri(requestUri) {
    // iden3comm://?request_uri=... → обычный URL
    if (requestUri.startsWith('iden3comm://')) {
        const u = new URL(requestUri.replace('iden3comm://', 'https://'));
        const inner = u.searchParams.get('request_uri');
        if (inner) return inner;
    }
    return requestUri;
}

async function loadAuthMessageString(requestUri) {
    const url = normalizeRequestUri(requestUri);

    // Если это http(s) → тянем JSON iden3comm
    if (/^https?:\/\//i.test(url)) {
        // Node 18+ имеет global fetch; если нет — поставь cross-fetch и раскомментируй:
        // const fetch = require('cross-fetch');
        const r = await fetch(url);
        if (!r.ok) throw new Error(`request_uri fetch failed: ${r.status}`);
        return await r.text(); // как строка
    }

    // Иначе считаем, что нам дали уже “сырой” JSON (или JWT-строку)
    return url;
}

function extractCallbackMeta(jsonStr) {
    try {
        const o = JSON.parse(jsonStr);
        // разные верифаеры используют разные ключи
        const callbackUrl = o?.callbackUrl || o?.serviceUrl || o?.replyUrl || null;
        const sessionId = o?.sessionId || o?.thid || null;
        return { callbackUrl, sessionId };
    } catch {
        return null;
    }
}

async function postCallback(url, body) {
    try {
        const r = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        return r.ok;
    } catch {
        return false;
    }
}

function getUserCredJWTs(userId) {
    const db = getDb();
    return db.prepare('SELECT jwt FROM credentials WHERE user_id = ?').all(userId);
}

function saveUserDID(userId, did) {
    const db = getDb();
    db.prepare('UPDATE users SET did = ? WHERE id = ?').run(did, userId);
}

// ================= Main =================

async function authRequest(user, requestUri) {
    if (USE_MOCKS) {
        // Mock-ответ (чтобы провязать флоу end-to-end)
        const now = Math.floor(Date.now() / 1000);
        const header = { alg: 'none', typ: 'JWT' };
        const payload = {
            iss: user.did,
            sub: 'verifier',
            iat: now,
            exp: now + 600,
            msg: 'MOCK_AUTH_RESPONSE_NOT_VALID_FOR_REAL_VERIFIER'
        };
        const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
        return { ok: true, mode: 'mock', token: `${b64u(header)}.${b64u(payload)}.` };
    }

    // 0) Загружаем сообщение авторизации (iden3comm JSON)
    const msgStr = await loadAuthMessageString(requestUri);
    const msgBytes = Buffer.from(msgStr, 'utf8');

    // 1) Инициализация js-sdk
    const {
        initInMemoryDataStorage,
        IdentityWallet,
        CredentialWallet,
        KMS, KmsKeyType,
        BjjProvider,
        EthStateResolver,
        DefaultDIDResolver,
        CredentialStatusResolverRegistry,
        AuthHandler,
    } = require('@0xpolygonid/js-sdk');

    if (!AUTH_WASM || !AUTH_ZKEY) {
        throw new Error('AUTH_WASM/AUTH_ZKEY не заданы в .env (пути к authV2.wasm и authV2.zkey).');
    }

    const dataStorage = await initInMemoryDataStorage();

    const kms = new KMS();
    // BabyJubJub ключ из seed (users.seed_hex)
    const seed = Buffer.from(user.seed_hex, 'hex');
    const keyId = await kms.createKeyFromSeed(KmsKeyType.BabyJubJub, seed);
    const bjj = new BjjProvider(kms, keyId);

    const identityWallet = new IdentityWallet({ methods: { bjj }, storage: dataStorage });
    const credentialWallet = new CredentialWallet({ storage: dataStorage });

    // Резолвер состояния и DID
    const ethResolver = new EthStateResolver({ url: CHAIN_RPC, contractAddress: STATE_CONTRACT });
    const didResolver = new DefaultDIDResolver({ resolvers: { polygonid: ethResolver } });
    const statusRegistry = new CredentialStatusResolverRegistry();

    const authHandler = new AuthHandler(
        identityWallet,
        credentialWallet,
        didResolver,
        statusRegistry,
        {
            // пути к циркUITам для AuthV2
            authV2: {
                key: keyId,
                wasm: AUTH_WASM,
                zkey: AUTH_ZKEY,
            },
        }
    );

    // 2) Гарантируем корректный DID
    let did = user.did;
    if (!did || !did.startsWith('did:polygonid')) {
        const newDidObj = await identityWallet.createDID({
            method: 'polygonid',
            blockchain: 'polygon',
            networkId: NETWORK_ID,
            keyProvider: bjj,
        });
        did = typeof newDidObj === 'string'
            ? newDidObj
            : (newDidObj.string?.() || newDidObj.id || String(newDidObj));
        saveUserDID(user.id, did);
    }

    // 3) Импортим креды из БД — если твой запрос будет их проверять
    const credRows = getUserCredJWTs(user.id);
    for (const { jwt } of credRows) {
        try { await credentialWallet.import(jwt); } catch {}
    }

    // 4) Генерируем ответ на AuthorizationRequest
    const responseJwt = await authHandler.handleAuthorizationRequest(did, msgBytes);

    // 5) Если у запроса есть callback — отправим туда ответ (часто это ожидается)
    const meta = extractCallbackMeta(msgStr);
    if (meta?.callbackUrl) {
        await postCallback(meta.callbackUrl, { token: responseJwt, sessionId: meta.sessionId });
    }

    return { ok: true, mode: 'real', token: responseJwt };
}

module.exports = { authRequest };
