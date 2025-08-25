const { getDb } = require('./db');

const db = getDb();
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tg_id TEXT UNIQUE NOT NULL,
  did TEXT NOT NULL,
  seed_hex TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  jwt TEXT NOT NULL,
  header_json TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  issuer TEXT,
  subject TEXT,
  type TEXT,
  issuance_date TEXT,
  expiration_date TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

console.log('DB initialized.');
