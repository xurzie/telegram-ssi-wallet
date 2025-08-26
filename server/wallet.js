// server/wallet.js
'use strict';

const { getDb } = require('./db');

/** Примитивная проверка на формат JWT */
function looksLikeJwt(s) {
    return typeof s === 'string' && s.split('.').length === 3;
}

/** base64url → JSON (с подстраховкой под «ручной» base64) */
function b64urlToJson(str) {
    // сначала пробуем строго base64url
    try {
        const txt = Buffer.from(str, 'base64url').toString('utf8');
        return JSON.parse(txt);
    } catch {
        // затем приводим к обычному base64
        const pad = '==='.slice((str.length + 3) % 4);
        const b64 = String(str).replace(/-/g, '+').replace(/_/g, '/') + pad;
        const txt = Buffer.from(b64, 'base64').toString('utf8');
        return JSON.parse(txt);
    }
}

/** Небезопасный (но быстрый) парсинг JWT без проверки подписи */
function parseJwtUnsafe(jwt) {
    const parts = String(jwt).split('.');
    if (parts.length !== 3) throw new Error('not a JWT');
    const header = b64urlToJson(parts[0]);
    const payload = b64urlToJson(parts[1]);
    return { header, payload };
}

/** Нормализуем запись из JWT (JWT-VC и/или VC внутри payload.vc) */
function normalizeRecordFromJwt(userId, jwt) {
    const { header, payload } = parseJwtUnsafe(jwt);

    // issuer
    const issuer =
        payload.iss ??
        payload.issuer ??
        payload.vc?.issuer?.id ??
        payload.vc?.issuer ??
        null;

    // subject
    const subject =
        payload.sub ??
        payload.vc?.credentialSubject?.id ??
        payload.credentialSubject?.id ??
        null;

    // type
    let type = null;
    if (Array.isArray(payload.vc?.type)) type = payload.vc.type.join(',');
    else if (Array.isArray(payload.type)) type = payload.type.join(',');
    else type = payload.vc?.type || payload.type || null;

    // dates (оставляем строками; если числа — это unix сек.)
    const issuanceDate =
        payload.vc?.issuanceDate ??
        payload.issuanceDate ??
        payload.nbf ??
        payload.iat ??
        null;

    const expirationDate =
        payload.vc?.expirationDate ??
        payload.expirationDate ??
        payload.exp ??
        null;

    return {
        user_id: userId,
        jwt,
        header_json: JSON.stringify(header || {}),
        payload_json: JSON.stringify(payload || {}),
        issuer,
        subject,
        type,
        issuance_date: String(issuanceDate ?? ''),
        expiration_date: String(expirationDate ?? '')
    };
}

/** Нормализуем запись из JSON-LD VC (не JWT) */
function normalizeRecordFromJsonLd(userId, vc) {
    // issuer
    const issuer =
        (typeof vc.issuer === 'string' ? vc.issuer : vc.issuer?.id) ?? null;

    // subject
    const subject = vc.credentialSubject?.id ?? null;

    // type
    let type = null;
    if (Array.isArray(vc.type)) {
        type = vc.type.filter(t => t !== 'VerifiableCredential').join(',');
    } else {
        type = vc.type || null;
    }

    // dates
    const issuanceDate = vc.issuanceDate ?? null;
    const expirationDate = vc.expirationDate ?? null;

    return {
        user_id: userId,
        jwt: null, // у JSON-LD нет JWT
        header_json: '{}',
        payload_json: JSON.stringify(vc || {}),
        issuer,
        subject,
        type,
        issuance_date: String(issuanceDate ?? ''),
        expiration_date: String(expirationDate ?? '')
    };
}

/** Вставляем запись в БД и возвращаем её */
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

/** Старый API: импорт только JWT */
function importCredential(userId, jwt) {
    const rec = normalizeRecordFromJwt(userId, jwt);
    return insertCredentialRow(rec);
}

/**
 * Универсальный импорт VC:
 *  - строка JWT (xxx.yyy.zzz)
 *  - строка JSON (W3C VC JSON-LD)
 *  - объект JSON (W3C VC JSON-LD)
 */
function importCredentialAny(userId, input) {
    // строка?
    if (typeof input === 'string') {
        if (looksLikeJwt(input)) {
            const rec = normalizeRecordFromJwt(userId, input);
            return insertCredentialRow(rec);
        }
        // пробуем как JSON
        let obj;
        try {
            obj = JSON.parse(input);
        } catch {
            throw new Error('invalid credential json');
        }
        return importCredentialAny(userId, obj);
    }

    // объект JSON-LD VC
    if (input && typeof input === 'object' && (input['@context'] || input.type)) {
        const rec = normalizeRecordFromJsonLd(userId, input);
        return insertCredentialRow(rec);
    }

    throw new Error('unsupported credential format');
}

/** Список сохранённых VC пользователя */
function listCredentials(userId) {
    const db = getDb();
    return db
        .prepare('SELECT * FROM credentials WHERE user_id = ? ORDER BY id DESC')
        .all(userId);
}

module.exports = {
    importCredentialAny,
    importCredential,
    listCredentials
};
