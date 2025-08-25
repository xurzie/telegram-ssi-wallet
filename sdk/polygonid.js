// sdk/polygonid.js
/* eslint-disable no-console */
const fetch = global.fetch || require('node-fetch'); // на старых Node
const {
    KMS, KmsKeyType,
    PortableDid,
    IdentityWallet,
    CredentialWallet,
    MerkleTreeInMemoryStorage,
    InMemoryPrivateKeyStore,
    InMemoryDIDKeyStore,
    IdentitiesIdentitiesSt,
    Packages,
} = require('@0xpolygonid/js-sdk');

const { DID } = require('@iden3/js-iden3comm'); // удобный конструктор DID
const { MediaType, createAuthorizationRequest } = require('@iden3/js-iden3comm');

/**
 * Готовит минимальную “ин-мемори” инфраструктуру SDK под наш DID.
 * Возвращает { kms, idw, credw, pkgMgr, did }
 */
async function setupForUser(user) {
    if (!user?.did || !user?.seed_hex) throw new Error('user requires did and seed_hex');

    // KMS c BabyJubJub ключом из seed
    const kms = new KMS();
    const seed = Buffer.from(user.seed_hex, 'hex');
    const keyId = await kms.createKeyFromSeed(KmsKeyType.BabyJubJub, seed);

    // DID (у нас уже есть строка вида did:polygonid:polygon:amoy:...)
    const did = DID.parse(user.did); // или new DID(user.did)

    // In-memory хранилища для деревьев и ключей
    const mtStorage = new MerkleTreeInMemoryStorage();
    const privKeyStore = new InMemoryPrivateKeyStore();
    const didKeyStore = new InMemoryDIDKeyStore();

    // Привязываем ключ к DID (для упаковки сообщений и подписи)
    await didKeyStore.saveKey(did.string(), { type: KmsKeyType.BabyJubJub, kid: keyId });

    // Identity & Credential wallets (минимум, чтобы SDK не падал)
    const identitiesStore = new IdentitiesIdentitiesSt();
    const idw = new IdentityWallet(kms, mtStorage, identitiesStore, didKeyStore);
    const credw = new CredentialWallet();

    // Пакетный менеджер для DIDComm/JWZ упаковки
    const pkgMgr = new Packages.PackageManager();
    // Поддержим оба media type: plain JSON и ZKP/JWZ
    pkgMgr.setMediaTypeProfiles([MediaType.PlainMessage, MediaType.ZKPMessage]);

    return { kms, idw, credw, pkgMgr, did, keyId };
}

/**
 * Обрабатывает AuthorizationRequest (request_uri) и возвращает JWZ token,
 * совместимый с issuer/verifier, как в тесте SDK: authRes.token
 */
async function authRequest(user, requestUri) {
    const { pkgMgr, did } = await setupForUser(user);

    // 1) тянем authorization request (iden3comm json)
    const r = await fetch(requestUri);
    if (!r.ok) throw new Error(`auth request HTTP ${r.status}`);
    const authReq = await r.json();

    // 2) Упаковываем/подписываем ответ на авторизацию
    // createAuthorizationRequest нужен когда мы САМИ создаём запрос;
    // здесь у нас уже есть authReq от верифайера/иссюера.
    // Нам надо “handle” — т.е. упаковать ответ.
    // В js-sdk для этого есть Pack/Unpack в PackageManager:
    // Сделаем минимальный ответ согласно iden3comm спецификации:
    const response = {
        id: crypto.randomUUID(),
        typ: 'application/iden3comm-plain-json',
        type: 'https://iden3-communication.io/authorization/1.0/response',
        thid: authReq.thid || authReq.id,
        from: did.string(),
        to: authReq.from,
        body: {
            message: 'ok'
        }
    };

    // 3) Пакуем как ZKPMessage (JWZ)
    const packed = await pkgMgr.pack(response, did.string(), authReq.from, MediaType.ZKPMessage);

    // 4) Отправляем ответ туда же, куда предписывает агент
    // Обычно прямо в тот же endpoint, откуда пришёл запрос (issuer-node /v2/agent)
    // но чтобы не гадать — если в authReq.body.url есть url — шлём туда,
    // иначе — на request_uri с POST.
    const authPostUrl =
        authReq.body?.url ||
        authReq.url ||
        requestUri;

    const rr = await fetch(authPostUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/iden3comm-plain+json' },
        body: Buffer.from(packed) // бинарь JWZ
    });

    const raw = await rr.text();

    // 5) Агент вернёт либо JWZ токен строкой, либо JSON с {token}
    if (raw.split('.').length >= 3) return { token: raw.trim(), mode: 'jwz' };
    try {
        const j = JSON.parse(raw);
        const t = j.token || j.jwt || j.credentialJWT;
        if (typeof t === 'string') return { token: t, mode: 'json' };
    } catch (_) {}

    throw new Error('auth: agent did not return token');
}

module.exports = { authRequest, setupForUser };
