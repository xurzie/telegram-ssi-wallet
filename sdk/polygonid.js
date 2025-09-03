// sdk/polygonid.js

const path = require('path');
const fs = require('fs');

const USE_MOCKS = false;

/* ---------- Circuits check (supports two layouts) ---------- */
function assertCircuitsDir(dir) {
    const vA = {
        wasm: path.join(dir, 'authV2', 'circuit.wasm'),
        zkey: path.join(dir, 'authV2', 'circuit_final.zkey'),
        vk:   path.join(dir, 'authV2', 'verification_key.json'),
    };
    const vB = {
        wasm: path.join(dir, 'authV2', 'wasm', 'circuit.wasm'),
        zkey: path.join(dir, 'authV2', 'circuit_final.zkey'),
        vk:   path.join(dir, 'authV2', 'verification_key.json'),
    };
    const okA = fs.existsSync(vA.wasm) && fs.existsSync(vA.zkey) && fs.existsSync(vA.vk);
    const okB = fs.existsSync(vB.wasm) && fs.existsSync(vB.zkey) && fs.existsSync(vB.vk);
    if (!okA && !okB) {
        throw new Error(
            `PolygonID circuits for authV2 not found.\n` +
            `Tried:\n - ${vA.wasm}\n   ${vA.zkey}\n   ${vA.vk}\n` +
            ` - ${vB.wasm}\n   ${vB.zkey}\n   ${vB.vk}\n` +
            `Download https://circuits.privado.id/latest.zip and set CIRCUITS_DIR to its root.`
        );
    }
}
function circuitsFromEnv() {
    const dir = process.env.CIRCUITS_DIR || path.resolve(process.cwd(), 'circuits');
    assertCircuitsDir(dir);
    return dir;
}

/* ---------- Dynamic SDK loader (ESM-friendly) ---------- */
let __sdkCache = null;
async function loadSdk() {
    if (__sdkCache) return __sdkCache;

    let mod = await import('@0xpolygonid/js-sdk').catch(() => null);
    mod = mod && mod.default && Object.keys(mod).length === 1 ? mod.default : mod;
    if (!mod) throw new Error('Cannot load @0xpolygonid/js-sdk. Is it installed?');

    const S = {
        KMS: mod.KMS,
        KmsKeyType: mod.KmsKeyType,
        BjjProvider: mod.BjjProvider,
        InMemoryPrivateKeyStore: mod.InMemoryPrivateKeyStore,
        IdentityWallet: mod.IdentityWallet,
        CredentialWallet: mod.CredentialWallet,
        InMemoryDataSource: mod.InMemoryDataSource,
        InMemoryMerkleTreeStorage: mod.InMemoryMerkleTreeStorage,
        PackageManager: mod.PackageManager,
        JWSPacker: mod.JWSPacker,
        ZKPPacker: mod.ZKPPacker,
        PlainPacker: mod.PlainPacker,
        ProofService: mod.ProofService,
        FSCircuitStorage: mod.FSCircuitStorage,
        FSKeyLoader: mod.FSKeyLoader,
        CircuitStorage: mod.CircuitStorage,
        NodeFileSystem: mod.NodeFileSystem || mod.NodeFileSystemKeyLoader,
        AuthHandler: mod.AuthHandler,
    };

    const required = [
        'KMS','KmsKeyType','BjjProvider','InMemoryPrivateKeyStore',
        'IdentityWallet','CredentialWallet','InMemoryDataSource','InMemoryMerkleTreeStorage',
        'PackageManager','JWSPacker','ZKPPacker','PlainPacker','ProofService','AuthHandler'
    ];
    for (const k of required) if (!S[k]) throw new Error(`@0xpolygonid/js-sdk: missing export ${k}`);

    __sdkCache = S;
    return S;
}

function makePackerManager(S, circuitsDir) {
    const packers = [
        new S.JWSPacker(),
        new S.ZKPPacker({
            provingParams: { dir: circuitsDir },
            verificationParams: { dir: circuitsDir },
        }),
        new S.PlainPacker(),
    ];

    return {
        async unpack(bytes) {
            for (const p of packers) {
                try {
                    const msg = await p.unpack(bytes);
                    if (msg) return msg;
                } catch (_) { /* not this packer */ }
            }
            throw new Error('Unable to unpack iden3 message with known packers');
        },

        async pack(message, mediaType, ctx) {
            for (const p of packers) {
                const mt = typeof p.getMediaType === 'function' ? p.getMediaType() : p.mediaType;
                if (mt === mediaType || (Array.isArray(mt) && mt.includes(mediaType))) {
                    return p.pack(message, ctx);
                }
            }
            return packers[0].pack(message, ctx);
        },
    };
}

/* ---------- Globals (one-time) ---------- */
let globalOnce = null;
async function initGlobalsOnce() {
    if (globalOnce) return globalOnce;

    const S = await loadSdk();
    const circuitsDir = circuitsFromEnv();

    let circuitStorage = null;
    if (typeof S.FSCircuitStorage === 'function') {
        circuitStorage = new S.FSCircuitStorage({ dirname: circuitsDir });
    } else if (typeof S.FSKeyLoader === 'function' && typeof S.CircuitStorage === 'function') {
        const keyLoader = new S.FSKeyLoader(circuitsDir);
        circuitStorage = new S.CircuitStorage(keyLoader);
    } else {
        throw new Error('No circuit storage class (FSCircuitStorage or FSKeyLoader+CircuitStorage) in this js-sdk version.');
    }

    const proofService = new S.ProofService({ circuitStorage });

    let packerMgr;
    if (typeof S.PackageManager === 'function') {
        const pm = new S.PackageManager();
        if (typeof pm.registerPacker === 'function') {
            pm.registerPacker(new S.JWSPacker());
            pm.registerPacker(new S.ZKPPacker({
                provingParams: { dir: circuitsDir },
                verificationParams: { dir: circuitsDir },
            }));
            pm.registerPacker(new S.PlainPacker());
            packerMgr = pm;
        } else if (typeof pm.registerPackers === 'function') {
            pm.registerPackers([
                new S.JWSPacker(),
                new S.ZKPPacker({
                    provingParams: { dir: circuitsDir },
                    verificationParams: { dir: circuitsDir },
                }),
                new S.PlainPacker(),
            ]);
            packerMgr = pm;
        }
    }
    if (!packerMgr) {
        packerMgr = makePackerManager(S, circuitsDir);
    }

    globalOnce = { S, packerMgr, proofService, circuitStorage, circuitsDir };
    return globalOnce;
}

/* ---------- Per-user setup ---------- */
async function setupForUser(user) {
    if (!user || !user.did) throw new Error('setupForUser: user.did is required');
    if (!user.seed_hex) throw new Error('setupForUser: user.seed_hex is required');

    const { S, packerMgr, proofService } = await initGlobalsOnce();

    const keyStore = new S.InMemoryPrivateKeyStore();
    const bjjProvider = new S.BjjProvider(S.KmsKeyType.BabyJubJub, keyStore);

    const kms = new S.KMS();
    kms.registerKeyProvider(S.KmsKeyType.BabyJubJub, bjjProvider);

    const seed = Buffer.from(user.seed_hex, 'hex');
    const keyId = await kms.createKeyFromSeed(S.KmsKeyType.BabyJubJub, seed);

    function makeNullStateStorage() {
        return {
            getRpcProvider: () => null,
            setRpcProvider: (_p) => {},
            async getLatestStateById(_did) { return null; },
            async getStateByIdAndState(_did, _state) { return null; },
            async getStatesByDid(_did) { return []; },
            async save(_stateModel) { /* noop */ },
            async deleteAll() { /* noop */ },
        };
    }

    const dataStorage = {
        identity: new S.InMemoryDataSource(),
        credential: new S.InMemoryDataSource(),
        mt: new S.InMemoryMerkleTreeStorage(),
        states: makeNullStateStorage(),
    };

    const credWallet = new S.CredentialWallet(dataStorage.credential);
    const idWallet = new S.IdentityWallet(kms, dataStorage, credWallet);

    const authHandler = new S.AuthHandler({
        wallet: idWallet,
        credentialWallet: credWallet,

        packerMgr,
        packerManager: packerMgr,
        packageManager: packerMgr,

        proofService,
    });

    for (const k of ['_packerMgr','packerMgr','packerManager','packageManager','_packageManager']) {
        authHandler[k] = packerMgr;
    }

    return { did: user.did, keyId, kms, idWallet, credWallet, authHandler, packerMgr, proofService };
}

/* ---------- Helpers ---------- */
function parseIden3Link(maybeLink) {
    let requestUri, inlineMsgBase64;
    const s = String(maybeLink || '');
    try {
        if (s.startsWith('iden3comm://')) {
            const u = new URL(s.replace('iden3comm://', 'http://dummy-host/'));
            requestUri = u.searchParams.get('request_uri') || u.searchParams.get('request_url') || u.searchParams.get('requestUri') || undefined;
            inlineMsgBase64 = u.searchParams.get('i_m') || undefined;
        } else {
            const u = new URL(s);
            requestUri = u.searchParams.get('request_uri') || u.searchParams.get('request_url') || u.searchParams.get('requestUri') || undefined;
            if (!requestUri && u.hash) {
                const sp = new URLSearchParams(u.hash.substring(1));
                requestUri = sp.get('request_uri') || sp.get('request_url') || sp.get('requestUri') || undefined;
                inlineMsgBase64 = sp.get('i_m') || undefined;
            }
        }
    } catch {}
    return { requestUri, inlineMsgBase64 };
}

async function fetchAuthRequestBytes(request) {
    const s = String(request || '');
    const { requestUri, inlineMsgBase64 } = parseIden3Link(s);

    if (inlineMsgBase64) {
        const raw = Buffer.from(decodeURIComponent(inlineMsgBase64), 'base64');
        return new Uint8Array(raw);
    }
    if (requestUri) return fetchAuthRequestBytes(requestUri);

    if (s.startsWith('data:')) return new Uint8Array(Buffer.from((s.split(',')[1] || ''), 'base64'));
    if (/^https?:\/\//i.test(s)) {
        const r = await fetch(s, { method: 'GET' });
        if (!r.ok) throw new Error(`failed to fetch request uri: HTTP ${r.status}`);
        const buf = Buffer.from(await r.arrayBuffer());
        return new Uint8Array(buf);
    }
    if (s.trim().startsWith('{')) return new Uint8Array(Buffer.from(s, 'utf8'));
    if (s && typeof request !== 'string') return new Uint8Array(request);

    throw new Error('unsupported auth request input');
}

function asDidObject(did) {
    const s = String(did || '');
    return {
        string: () => s,
        toString: () => s,
        toJSON: () => s,
    };
}

/* ---------- Public API ---------- */
async function handleAuthRequest(user, requestUriOrMsg, opts = {}) {
    const { authHandler } = await setupForUser(user);
    const raw = await fetchAuthRequestBytes(requestUriOrMsg);

    const didObj = asDidObject(user.did);
    const options = {
        mediaType: 'application/iden3comm-plain-json',
        ...opts,
    };

    const { token, authRequest: authReqMsg, authResponse } =
        await authHandler.handleAuthorizationRequest(didObj, raw, options);

    return { token, authRequest: authReqMsg, authResponse };
}

function authRequest(user, requestUriOrMsg, opts = {}) {
    return handleAuthRequest(user, requestUriOrMsg, opts);
}

module.exports = {
    USE_MOCKS,
    setupForUser,
    handleAuthRequest,
    authRequest,
};
