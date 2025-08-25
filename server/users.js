const crypto = require('crypto');
const { getDb } = require('./db');

function getUserByTgId(tgId) {
  const db = getDb();
  return db.prepare('SELECT * FROM users WHERE tg_id = ?').get(String(tgId));
}

function ensureUser(tgId) {
  tgId = String(tgId);
  const db = getDb();
  const found = getUserByTgId(tgId);
  if (found) return found;
  // Dev placeholder DID & seed; replace with Polygon ID DID via js-sdk later
  const seed = crypto.randomBytes(32);
  const seedHex = seed.toString('hex');
  const did = `did:example:tg-${tgId}`;
  const stmt = db.prepare('INSERT INTO users (tg_id, did, seed_hex) VALUES (?, ?, ?)');
  const info = stmt.run(tgId, did, seedHex);
  return db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
}

module.exports = { getUserByTgId, ensureUser };
