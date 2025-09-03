// server/_vc_utils.js
'use strict';

function base64urlToJSON(str) {
    try {
        const normalized = String(str)
            .replace(/-/g, '+')
            .replace(/_/g, '/')
            .padEnd(Math.ceil(str.length / 4) * 4, '=');
        const buf = Buffer.from(normalized, 'base64');
        return JSON.parse(buf.toString('utf8'));
    } catch {
        return null;
    }
}

function tryParseJwt(jwt) {
    const parts = String(jwt || '').split('.');
    if (parts.length !== 3) return null;
    const header = base64urlToJSON(parts[0]);
    const payload = base64urlToJSON(parts[1]);
    if (!header || !payload) return null;
    return { header, payload };
}

function normalizeVcSummary(payload, header = {}) {
    const vc = payload?.vc || payload;

    // issuer
    const issuer =
        payload?.iss ||
        vc?.issuer?.id ||
        vc?.issuer ||
        payload?.issuer?.id ||
        payload?.issuer ||
        null;

    // subject
    const subject =
        payload?.sub ||
        vc?.credentialSubject?.id ||
        payload?.credentialSubject?.id ||
        null;

    // type
    let type = null;
    if (Array.isArray(payload?.type)) type = payload.type.join(',');
    else if (typeof payload?.type === 'string') type = payload.type;
    else if (Array.isArray(vc?.type)) type = vc.type.join(',');

    // dates
    const issuanceDate =
        payload?.nbf ? new Date(payload.nbf * 1000).toISOString()
            : payload?.iat ? new Date(payload.iat * 1000).toISOString()
                : vc?.issuanceDate || payload?.issuanceDate || null;

    const expirationDate =
        payload?.exp ? new Date(payload.exp * 1000).toISOString()
            : vc?.expirationDate || payload?.expirationDate || null;

    return { issuer, subject, type, issuanceDate, expirationDate, header };
}

module.exports = { tryParseJwt, normalizeVcSummary };
