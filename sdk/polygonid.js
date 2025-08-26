// sdk/polygonid.js
// Подключаем Polygon ID js-sdk и настраиваем кошелёк/примитивы для Auth
const path = require('path');
const fs = require('fs');

// В Node 22 fetch уже глобальный; для Node<18 можно раскомментировать:
// global.fetch = global.fetch || require('node-fetch');

const {
    // ключи/подписи
    KMS,
    KmsKeyType,
    BjjProvider,
    InMemoryPrivateKeyStore,

    // идентичность/сторедж
    IdentityWallet,
    CredentialWallet,
    InMemoryDataSource,
    InMemoryMerkleTreeStorage,

    // пакеры и менеджер пакетов iden3comm
    PackageManager,
    JWSPacker,
    ZKPPacker,
    PlainPacker,

    // прувер и загрузка ключей для циркутов
    ProofService,
    FSKeyLoader,
    CircuitStorage,

    // обработчик auth
    AuthHandler,
    Resolver
} = require('@0xpolygonid/js-sdk');

const USE_MOCKS = false; // в README у тебя про это—оставляю совместимость

// --- Вспомогательная проверка: каталоги циркутов ---
function assertCircuitsDir(dir) {
    const must = [
        // минимальный набор для AuthV2 (параметры верификации/доказательства)
        path.join(dir, 'authV2', 'circuit_final.zkey'),
        path.join(dir, 'authV2', 'verification_key.json'),
        path.join(dir, 'authV2', 'wasm', 'circuit.wasm'),
    ];
    for (const p of must) {
        if (!fs.existsSync(p)) {
            throw new Error(
                `Circuits are not found. Expected: ${p}\n` +
                `Set CIRCUITS_DIR .env to folder with PolygonID circuits (authV2).`
            );
        }
    }
}

function circuitsFromEnv() {
    const dir = process.env.CIRCUITS_DIR || path.resolve(process.cwd(), 'circuits');
    assertCircuitsDir(dir);
    return dir;
}

// --- Глобально одноразовая инициализация того, что не зависит от пользователя ---
let globalOnce = null;
function initGlobalsOnce() {
    if (globalOnce) return globalOnce;

    // Пакетный менеджер для iden3comm (JWZ/JWS, ZKP, plain)
    const pkgMgr = new PackageManager();

    // Сторедж циркутов (читаем с диска)
    const circuitsDir = circuitsFromEnv();
    const keyLoader = new FSKeyLoader(circuitsDir);
    const circuitStorage = new CircuitStorage(keyLoader);

    // ZKP-пакер должен знать где брать proving/verification params
    const zkpPacker = new ZKPPacker({
        provingParams: { dir: circuitsDir },
        verificationParams: { dir: circuitsDir },
    });

    // Регистрируем пакеры
    pkgMgr.registerPackers([
        new JWSPacker(),
        zkpPacker,
        new PlainPacker(),
    ]);

    // Привязываем прувер
    const proofService = new ProofService({
        circuitStorage,
        // можно передать custom prover, если надо; по умолчанию нативный groth16
    });

    const resolver = new Resolver(); // базовый резолвер DID/issuer, по необходимости донастроишь

    globalOnce = { pkgMgr, proofService, circuitStorage, resolver, circuitsDir };
    return globalOnce;
}

// --- Инициализация кошелька/ключей ПОД ПОЛЬЗОВАТЕЛЯ ---
async function setupForUser(user) {
    if (!user || !user.did) {
        throw new Error('setupForUser: user.did is required');
    }
    if (!user.seed_hex) {
        throw new Error('setupForUser: user.seed_hex is required to derive BJJ key');
    }

    const { pkgMgr, proofService } = initGlobalsOnce();

    // KeyStore в памяти + провайдер для BabyJubJub
    const keyStore = new InMemoryPrivateKeyStore();
    const bjjProvider = new BjjProvider(KmsKeyType.BabyJubJub, keyStore);

    // KMS и регистрация провайдера под конкретным типом ключа
    const kms = new KMS();
    kms.registerKeyProvider(KmsKeyType.BabyJubJub, bjjProvider);

    // Создаём/импортируем ключ из seed (детерминированный keyId)
    const seed = Buffer.from(user.seed_hex, 'hex');
    const keyId = await kms.createKeyFromSeed(KmsKeyType.BabyJubJub, seed);

    // Памятные стореджи js-sdk (identity / credentials / merkle trees / states)
    const dataStorage = {
        identity: new InMemoryDataSource(),
        credential: new InMemoryDataSource(),
        mt: new InMemoryMerkleTreeStorage(),
        states: new InMemoryDataSource(),
    };

    const credWallet = new CredentialWallet(dataStorage.credential);
    const idWallet = new IdentityWallet(kms, dataStorage, credWallet);

    // Привязываем обработчик auth
    const authHandler = new AuthHandler({
        wallet: idWallet,
        credentialWallet: credWallet,
        packageManager: pkgMgr,
        proofService,
        // mediaType/packerOptions можно переопределить при вызове
    });

    return {
        did: user.did,
        keyId,
        kms,
        idWallet,
        credWallet,
        authHandler,
        pkgMgr,
        proofService,
    };
}

// --- Утилита: подтянуть байты iden3comm запроса по request_uri / iden3comm:// ---
async function fetchAuthRequestBytes(requestUriOrIden3commUrl) {
    let url = requestUriOrIden3commUrl;

    // Поддержка QR формата вида iden3comm://?request_uri=...
    if (String(url).startsWith('iden3comm://')) {
        const u = new URL(url.replace('iden3comm://', 'http://dummy-host/'));
        const req = u.searchParams.get('request_uri');
        if (!req) throw new Error('request uri not found');
        url = req;
    }

    // request_uri — это либо data:payload, либо https-URL на JSON
    if (String(url).startsWith('data:')) {
        const base64 = url.split(',')[1] || '';
        return Buffer.from(base64, 'base64');
    }

    const resp = await fetch(url, { method: 'GET' });
    if (!resp.ok) {
        throw new Error(`failed to fetch request uri: ${resp.status}`);
    }
    const buf = Buffer.from(await resp.arrayBuffer());
    return new Uint8Array(buf);
}

// --- Публичная точка: обработать auth-запрос и вернуть JWT ответа ---
async function handleAuthRequest(user, requestUri, opts = {}) {
    const { authHandler } = await setupForUser(user);

    const raw = await fetchAuthRequestBytes(requestUri);

    // по умолчанию полагаемся на auto-detect mediaType внутри пакеров
    const { token, authRequest, authResponse } =
        await authHandler.handleAuthorizationRequest(user.did, raw, opts);

    return { token, authRequest, authResponse };
}

// Совместимость с тем, как у тебя дергается из server/
module.exports = {
    USE_MOCKS,
    setupForUser,
    handleAuthRequest,
};
