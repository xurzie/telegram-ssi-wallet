// server/wallet.js
'use strict';

const { getDb } = require('./db');

function looksLikeJwt(s) {
    return typeof s === 'string' && s.split('.').length === 3;
}

function b64urlToJson(str) {
    try {
        const txt = Buffer.from(str, 'base64url').toString('utf8');
        return JSON.parse(txt);
    } catch (_) {
        const clean = String(str).replace(/-/g, '+').replace(/_/g, '/');
        const padLen = (4 - (clean.length % 4)) % 4;
        const padded = clean + '='.repeat(padLen);
        const txt = Buffer.from(padded, 'base64').toString('utf8');
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

function extractJwtFromObject(obj) {
    if (!obj || typeof obj !== 'object') return null;
    const candidate =
        obj.credentialJWT ||
        obj.jwt ||
        obj.token ||
        (typeof obj.credential === 'string' && obj.credential) ||
        (obj.proof && typeof obj.proof.jwt === 'string' && obj.proof.jwt) ||
        null;

    return (candidate && looksLikeJwt(candidate)) ? candidate : null;
}

function normalizeVcType(type) {
    if (!type) return null;
    if (Array.isArray(type)) {
        return type
            .filter(t => t && t !== 'VerifiableCredential')
            .join(',');
    }
    return (type === 'VerifiableCredential') ? null : String(type);
}

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
    const type = normalizeVcType(
        payload.vc?.type ?? payload.type ?? null
    );

    // dates
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
        issuance_date: issuanceDate != null ? String(issuanceDate) : '',
        expiration_date: expirationDate != null ? String(expirationDate) : '',
    };
}

function normalizeRecordFromJsonLd(userId, vc) {
    // issuer
    const issuer =
        (typeof vc.issuer === 'string' ? vc.issuer : vc.issuer?.id) ?? null;

    // subject
    const subject = vc.credentialSubject?.id ?? null;

    // type
    const type = normalizeVcType(vc.type);

    // dates
    const issuanceDate = vc.issuanceDate ?? vc.validFrom ?? null;
    const expirationDate = vc.expirationDate ?? null;

    return {
        user_id: userId,
        jwt: null,
        header_json: '{}',
        payload_json: JSON.stringify(vc || {}),
        issuer,
        subject,
        type,
        issuance_date: issuanceDate != null ? String(issuanceDate) : '',
        expiration_date: expirationDate != null ? String(expirationDate) : '',
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

function importCredential(userId, jwt) {
    const rec = normalizeRecordFromJwt(userId, jwt);
    return insertCredentialRow(rec);
}

function importCredentialAny(userId, input) {
    if (typeof input === 'string') {
        if (looksLikeJwt(input)) {
            const rec = normalizeRecordFromJwt(userId, input);
            return insertCredentialRow(rec);
        }
        let obj;
        try {
            obj = JSON.parse(input);
        } catch {
            throw new Error('invalid credential json');
        }
        return importCredentialAny(userId, obj);
    }

    const wrappedJwt = extractJwtFromObject(input);
    if (wrappedJwt) {
        const rec = normalizeRecordFromJwt(userId, wrappedJwt);
        return insertCredentialRow(rec);
    }

    if (input && typeof input === 'object' && (input['@context'] || input.type || input.credentialSubject)) {
        const rec = normalizeRecordFromJsonLd(userId, input);
        return insertCredentialRow(rec);
    }

    throw new Error('unsupported credential format');
}

function listCredentials(userId) {
    const db = getDb();
    return db
        .prepare('SELECT * FROM credentials WHERE user_id = ? ORDER BY id DESC')
        .all(userId);
}

module.exports = {
    importCredentialAny,
    importCredential,
    listCredentials,
};
