const Database = require('better-sqlite3');
const dotenv = require('dotenv');
dotenv.config();
const DB_PATH = process.env.DB_PATH || './wallet.db';

let db;
function getDb() {
  if (!db) {
    db = new Database(DB_PATH);
    db.pragma('journal_mode = wal');
  }
  return db;
}

module.exports = { getDb };
