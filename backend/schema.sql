-- SQLite bootstrap schema, applied by main.init_db() on first launch.
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS policies(user_id TEXT PRIMARY KEY REFERENCES users(id),per_tx REAL NOT NULL,daily REAL NOT NULL,monthly REAL NOT NULL,currency TEXT NOT NULL,mode TEXT NOT NULL,merchants TEXT NOT NULL,approval_threshold REAL NOT NULL,approval_new INTEGER NOT NULL,version INTEGER NOT NULL DEFAULT 1,active INTEGER NOT NULL DEFAULT 1,updated TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS proposals(id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),request_key TEXT NOT NULL,product_id TEXT NOT NULL,agent TEXT NOT NULL,merchant_id TEXT NOT NULL,merchant TEXT NOT NULL,product TEXT NOT NULL,amount REAL NOT NULL,currency TEXT NOT NULL,status TEXT NOT NULL,decision TEXT NOT NULL,reason TEXT NOT NULL,fingerprint TEXT NOT NULL,created REAL NOT NULL,UNIQUE(user_id,request_key));
CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY,proposal_id TEXT UNIQUE REFERENCES proposals(id),user_id TEXT REFERENCES users(id),status TEXT NOT NULL,decision_at REAL,fingerprint TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS transactions(id TEXT PRIMARY KEY,user_id TEXT REFERENCES users(id),proposal_id TEXT UNIQUE REFERENCES proposals(id),amount REAL NOT NULL,currency TEXT NOT NULL,payment_status TEXT NOT NULL,policy_status TEXT NOT NULL,paypal_order TEXT,paypal_capture TEXT,created REAL NOT NULL,updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS audits(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT REFERENCES users(id),entity_id TEXT,event TEXT,reason TEXT,metadata TEXT,created REAL NOT NULL);
CREATE INDEX IF NOT EXISTS proposal_user_time ON proposals(user_id,created);
CREATE INDEX IF NOT EXISTS transaction_user_time ON transactions(user_id,created);
CREATE INDEX IF NOT EXISTS audit_user_time ON audits(user_id,created);
