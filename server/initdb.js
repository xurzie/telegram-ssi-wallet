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
  jwt TEXT,
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

// If the table already existed with a NOT NULL constraint on `jwt`,
// migrate it to allow storing credentials without a JWT (e.g. JSON-LD VCs).
const columns = db.prepare('PRAGMA table_info(credentials)').all();
const jwtCol = columns.find((c) => c.name === 'jwt');
if (jwtCol && jwtCol.notnull === 1) {
    db.transaction(() => {
        db.exec(`
      ALTER TABLE credentials RENAME TO credentials_old;
      CREATE TABLE credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        jwt TEXT,
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
      INSERT INTO credentials (id,user_id,jwt,header_json,payload_json,issuer,subject,type,issuance_date,expiration_date,created_at)
        SELECT id,user_id,jwt,header_json,payload_json,issuer,subject,type,issuance_date,expiration_date,created_at FROM credentials_old;
      DROP TABLE credentials_old;
    `);
    })();
    console.log('Migrated credentials table to allow nullable jwt');
}


console.log('DB initialized.');
