// sdk/identity.js
const {
    InMemoryDataSource,
    IdentityStorage,
    CredentialStorage,
    InMemoryMerkleTreeStorage,
    EthStateStorage,
    defaultEthConnectionConfig,
    InMemoryPrivateKeyStore,
    KMS, KmsKeyType,
    BjjProvider,
    CredentialWallet,
    IdentityWallet,
    // Тип ревокации берём из sdk — пригодится, но можно не передавать
    CredentialStatusType,
} = require('@0xpolygonid/js-sdk');

const { DidMethod, Blockchain, NetworkId } = require('@iden3/js-iden3-core');
const { getDb } = require('../server/db');

function buildDataStorage() {
    // Полноценный state storage (иначе у твоей версии IdentityWallet сваливается на getRpcProvider/nonce)
    const ethCfg = { ...defaultEthConnectionConfig };
    ethCfg.url = process.env.RPC_URL || 'https://rpc-amoy.polygon.technology';
    ethCfg.contractAddress =
        process.env.STATE_CONTRACT_ADDRESS ||
        '0x1a4cC30f2aA0377b0c3bc9848766D90cb4404124';
    // chainId в defaultEthConnectionConfig для Amoy уже корректный (80002)

    return {
        credential: new CredentialStorage(new InMemoryDataSource()),
        identity: new IdentityStorage(
            new InMemoryDataSource(), // identities
            new InMemoryDataSource()  // profiles
        ),
        mt: new InMemoryMerkleTreeStorage(40),
        states: new EthStateStorage(ethCfg),
    };
}

// NB: Без кэша! Каждый вызов — «чистые» стораджи, чтобы не ловить конфликт метаданных меркл-дерева
function newWallets() {
    const dataStorage = buildDataStorage();

    const keyStore = new InMemoryPrivateKeyStore();
    const bjjProvider = new BjjProvider(KmsKeyType.BabyJubJub, keyStore);
    const kms = new KMS();
    kms.registerKeyProvider(KmsKeyType.BabyJubJub, bjjProvider);

    const credWallet = new CredentialWallet(dataStorage);
    const idWallet = new IdentityWallet(kms, dataStorage, credWallet);

    return { idWallet };
}

async function ensureDidForUser(user) {
    // уже есть реальный DID — ничего не делаем
    if (user.did && !user.did.startsWith('did:example')) return user.did;

    const { idWallet } = newWallets();
    const seed = Buffer.from(user.seed_hex, 'hex');

    try {
        // Полный вызов с явными enum’ами (из @iden3/js-iden3-core)
        const opts = {
            method: DidMethod.PolygonId,
            blockchain: Blockchain.Polygon,
            networkId: NetworkId.Amoy,
            seed,
        };
        // ревокацию можно не указывать — оставляю как коммент на будущее
        if (process.env.RHS_URL) {
            opts.revocationOpts = {
                type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
                id: process.env.RHS_URL,
            };
        }

        const { did } = await idWallet.createIdentity(opts);

        const didStr = did.string ? did.string() : (did.toString?.() || String(did));
        const db = getDb();
        db.prepare('UPDATE users SET did = ? WHERE id = ?').run(didStr, user.id);
        console.log('Created DID for tg', user.tg_id, '=>', didStr);
        return didStr;
    } catch (err) {
        // Если во время первой попытки успели записать мету меркл-дерева
        // и теперь ловим «Present merkle tree meta …» — создадим identity с НОВЫМ seed.
        const msg = String(err && err.message || err);
        if (msg.includes('Present merkle tree meta information')) {
            console.warn('Merkle meta already present, regenerating with fresh seed for', user.tg_id);
            const crypto = require('crypto');
            const freshSeed = crypto.randomBytes(32);

            const { idWallet: idWallet2 } = newWallets();
            const { did } = await idWallet2.createIdentity({
                method: DidMethod.PolygonId,
                blockchain: Blockchain.Polygon,
                networkId: NetworkId.Amoy,
                seed: freshSeed,
            });

            const didStr = did.string ? did.string() : (did.toString?.() || String(did));
            const db = getDb();
            // сохраняем DID, а seed можно не менять — он используется только для детерминированности
            db.prepare('UPDATE users SET did = ? WHERE id = ?').run(didStr, user.id);
            console.log('Created DID (fresh) for tg', user.tg_id, '=>', didStr);
            return didStr;
        }
        console.error('ensureDidForUser hard error:', err);
        throw err;
    }
}

module.exports = { ensureDidForUser };
