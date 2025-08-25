// server/wallet.js
const { getDb } = require('./db');

function looksLikeJwt(s) {
    return typeof s === 'string' && s.split('.').length === 3;
}

function b64urlToJson(str) {
    // поддержка и base64url, и "ручного" варианта
    try {
        const txt = Buffer.from(str, 'base64url').toString('utf8');
        return JSON.parse(txt);
    } catch {
        const pad = '==='.slice((str.length + 3) % 4);
        const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + pad;
        const txt = Buffer.from(b64, 'base64').toString('utf8');
        return JSON.parse(txt);
    }
}

function parseJwtUnsafe(jwt) {
    const parts = String(jwt).split('.');
    if (parts.length !== 3) throw new Error('not a JWT');
    const header = b64urlToJson(parts[0]);
    const payload = b64urlToJson(parts[1]);
    return { header, payload };
}

// Нормализация полей для записи в БД
function normalizeRecordFromJwt(userId, jwt) {
    const { header, payload } = parseJwtUnsafe(jwt);

    const issuer =
        payload.iss ?? payload.issuer ?? null;

    const subject =
        payload.sub ??
        payload.vc?.credentialSubject?.id ??
        null;

    const type =
        (Array.isArray(payload.vc?.type)
            ? payload.vc.type.join(',')
            : (payload.vc?.type || payload.type || null));

    const issuanceDate =
        payload.vc?.issuanceDate ??
        payload.nbf ??
        payload.iat ??
        null;

    const expirationDate =
        payload.vc?.expirationDate ??
        payload.exp ??
        null;

    return {
        user_id: userId,
        jwt,
        header_json: JSON.stringify(header),
        payload_json: JSON.stringify(payload),
        issuer,
        subject,
        type,
        issuance_date: String(issuanceDate ?? ''),
        expiration_date: String(expirationDate ?? '')
    };
}

function normalizeRecordFromJsonLd(userId, vc) {
    // vc — объект JSON-LD Verifiable Credential
    const issuer =
        (typeof vc.issuer === 'string' ? vc.issuer : vc.issuer?.id) ?? null;

    const subject =
        vc.credentialSubject?.id ?? null;

    const type =
        (Array.isArray(vc.type)
            ? vc.type.filter(t => t !== 'VerifiableCredential').join(',')
            : (vc.type || null));

    const issuanceDate =
        vc.issuanceDate ?? null;

    const expirationDate =
        vc.expirationDate ?? null;

    return {
        user_id: userId,
        jwt: null, // для JSON-LD JWT отсутствует
        header_json: '{}',
        payload_json: JSON.stringify(vc),
        issuer,
        subject,
        type,
        issuance_date: String(issuanceDate ?? ''),
        expiration_date: String(expirationDate ?? '')
    };
}

function insertCredentialRow(rec) {
    const db = getDb();
    const stmt = db.prepare(`
    INSERT INTO credentials
      (user_id, jwt, header_json, payload_json, issuer, subject, type, issuance_date, expiration_date)
    VALUES
      (?,       ?,   ?,           ?,            ?,      ?,       ?,    ?,             ?)
  `);
    const info = stmt.run(
        rec.user_id,
        rec.jwt,
        rec.header_json,
        rec.payload_json,
        rec.issuer,
        rec.subject,
        rec.type,
        rec.issuance_date,
        rec.expiration_date
    );
    return db.prepare('SELECT * FROM credentials WHERE id = ?').get(info.lastInsertRowid);
}

/**
 * Универсальный импорт:
 * - Если пришла строка вида "xxx.yyy.zzz" — считаем JWT и парсим.
 * - Если пришла строка JSON — парсим объект.
 * - Если это объект с @context и type — считаем JSON-LD VC и сохраняем.
 */
function importCredentialAny(userId, input) {
    if (typeof input === 'string') {
        if (looksLikeJwt(input)) {
            const rec = normalizeRecordFromJwt(userId, input);
            return insertCredentialRow(rec);
        }
        // пробуем как JSON
        let obj;
        try { obj = JSON.parse(input); }
        catch { throw new Error('invalid credential json'); }
        return importCredentialAny(userId, obj);
    }

    if (input && typeof input === 'object' && input['@context'] && input.type) {
        const rec = normalizeRecordFromJsonLd(userId, input);
        return insertCredentialRow(rec);
    }

    throw new Error('unsupported credential format');
}

// Оставляем старые имена для обратной совместимости:
// importCredential(userId, jwt) — только JWT
function importCredential(userId, jwt) {
    const rec = normalizeRecordFromJwt(userId, jwt);
    return insertCredentialRow(rec);
}

function listCredentials(userId) {
    const db = getDb();
    return db
        .prepare('SELECT * FROM credentials WHERE user_id = ? ORDER BY id DESC')
        .all(userId);
}

module.exports = {
    importCredentialAny,         // новый универсальный
    importCredential,            // совместимость со старым кодом (JWT)
    listCredentials
};
