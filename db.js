const path = require('path');
const fs = require('fs');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');

// DATA_DIR can point to a persistent disk on a hosted server (e.g. Render: /var/data).
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

// One-time restore: if an admin uploaded a backup (POST /api/admin/restore), it waits here
// until the next start — unpacked BEFORE the database is opened, so nothing is overwritten
// while in use.
const RESTORE_FILE = path.join(DATA_DIR, 'restore-pending.tar.gz');
if (fs.existsSync(RESTORE_FILE)) {
  try {
    // Leftover WAL/SHM files of the previous (empty) database must not be replayed onto the restored one.
    for (const f of ['app.db-wal', 'app.db-shm']) { try { fs.unlinkSync(path.join(DATA_DIR, f)); } catch (e) { /* none */ } }
    require('child_process').execFileSync('tar', ['-xzf', RESTORE_FILE, '-C', DATA_DIR]);
    console.log('მონაცემები აღდგენილია ბექაფიდან.');
  } catch (e) {
    console.error('ბექაფის აღდგენა ვერ მოხერხდა:', e.message);
  }
  fs.unlinkSync(RESTORE_FILE);
}

const RECORDINGS_DIR = path.join(DATA_DIR, 'recordings');
const PHOTOS_DIR = path.join(DATA_DIR, 'photos');
fs.mkdirSync(RECORDINGS_DIR, { recursive: true });
fs.mkdirSync(PHOTOS_DIR, { recursive: true });

const db = new DatabaseSync(path.join(DATA_DIR, 'app.db'));
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');

// node:sqlite has no built-in db.transaction() helper (unlike better-sqlite3) —
// run fn() inside a manual BEGIN/COMMIT, rolling back on any error.
function transaction(fn) {
  db.exec('BEGIN');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','manager','employee')),
  branch_id INTEGER REFERENCES branches(id) ON DELETE SET NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS branches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS criteria_templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS criteria_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  template_id INTEGER NOT NULL REFERENCES criteria_templates(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  max_score INTEGER NOT NULL DEFAULT 10,
  order_index INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS recordings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL CHECK(type IN ('observation','manual')),
  employee_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  branch_id INTEGER REFERENCES branches(id) ON DELETE SET NULL,
  note TEXT,
  file_path TEXT NOT NULL,
  original_filename TEXT,
  mime_type TEXT,
  duration_seconds REAL,
  uploaded_by INTEGER NOT NULL REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','evaluated','error')),
  error_message TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS evaluations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  recording_id INTEGER NOT NULL REFERENCES recordings(id) ON DELETE CASCADE,
  template_ids TEXT NOT NULL,
  transcript TEXT,
  overall_score REAL,
  max_score REAL,
  summary TEXT,
  raw_response TEXT,
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS evaluation_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  evaluation_id INTEGER NOT NULL REFERENCES evaluations(id) ON DELETE CASCADE,
  criterion_text TEXT NOT NULL,
  score REAL NOT NULL,
  max_score REAL NOT NULL,
  comment TEXT
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS recording_photos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  recording_id INTEGER NOT NULL REFERENCES recordings(id) ON DELETE CASCADE,
  file_path TEXT NOT NULL,
  original_filename TEXT,
  mime_type TEXT,
  uploaded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS role_permissions (
  role TEXT NOT NULL,
  page_id TEXT NOT NULL,
  can_view INTEGER NOT NULL DEFAULT 0,
  can_edit INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (role, page_id)
);
`);

// One-time seed: default admin account if no users exist yet
const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
if (userCount === 0) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare(
    `INSERT INTO users (username, password_hash, full_name, role, active) VALUES (?, ?, ?, 'admin', 1)`
  ).run('admin', hash, 'ადმინისტრატორი');
  console.log('==============================================');
  console.log('შეიქმნა საწყისი ადმინის ანგარიში:');
  console.log('  მომხმარებელი: admin');
  console.log('  პაროლი:       admin123');
  console.log('პირველივე შესვლისას შეცვალეთ პაროლი!');
  console.log('==============================================');
}

// One-time seed: internal system account used as "uploaded_by" for recordings that
// arrive via the external API import endpoint (POST /api/import/recording), rather
// than through a real logged-in user. Kept inactive (active=0) so it can never be
// used to log in, even if someone guessed its username.
let importUserId = (db.prepare("SELECT id FROM users WHERE username = 'api-import'").get() || {}).id;
if (!importUserId) {
  const hash = bcrypt.hashSync(require('crypto').randomBytes(24).toString('hex'), 10);
  importUserId = db.prepare(
    `INSERT INTO users (username, password_hash, full_name, role, active) VALUES ('api-import', ?, ?, 'admin', 0)`
  ).run(hash, 'API იმპორტი (სისტემური)').lastInsertRowid;
}

// Persistent JWT secret (survives restarts)
const secretPath = path.join(DATA_DIR, 'jwt-secret.txt');
if (!fs.existsSync(secretPath)) {
  fs.writeFileSync(secretPath, require('crypto').randomBytes(48).toString('hex'));
}
const JWT_SECRET = fs.readFileSync(secretPath, 'utf8').trim();

// ---------- Role permissions (per-role view/edit access to fixed platform pages) ----------
// admin always has full access everywhere (hardcoded, non-configurable, so an admin can
// never lock themselves out of managing permissions). Only 'manager' and 'employee' rows
// are stored/configurable.

const PAGES = [
  { id: 'recordings', label: 'ჩანაწერები', hasEdit: true },
  { id: 'analytics', label: 'ანალიტიკა', hasEdit: false },
  { id: 'observe', label: 'დაკვირვების ჩაწერა', hasEdit: true },
  { id: 'manual-upload', label: 'ზარის ხელით ატვირთვა', hasEdit: true },
  { id: 'criteria', label: 'შეფასების კრიტერიუმები', hasEdit: true },
  { id: 'users', label: 'თანამშრომლები და როლები', hasEdit: true },
  { id: 'branches', label: 'ფილიალები', hasEdit: true },
  { id: 'settings', label: 'პარამეტრები', hasEdit: true },
];

// Matches the platform's previous hardcoded role rules exactly, so nothing changes
// for existing installs until an admin explicitly edits the matrix.
const DEFAULT_PERMISSIONS = {
  manager: {
    recordings: { view: true, edit: true },
    analytics: { view: true, edit: false },
    observe: { view: true, edit: true },
    'manual-upload': { view: true, edit: true },
    criteria: { view: true, edit: true },
    users: { view: false, edit: false },
    branches: { view: false, edit: false },
    settings: { view: false, edit: false },
  },
  employee: {
    recordings: { view: true, edit: false },
    analytics: { view: false, edit: false },
    observe: { view: true, edit: true },
    'manual-upload': { view: false, edit: false },
    criteria: { view: false, edit: false },
    users: { view: false, edit: false },
    branches: { view: false, edit: false },
    settings: { view: false, edit: false },
  },
};

const permCount = db.prepare('SELECT COUNT(*) AS c FROM role_permissions').get().c;
if (permCount === 0) {
  const insertPerm = db.prepare(
    'INSERT INTO role_permissions (role, page_id, can_view, can_edit) VALUES (?, ?, ?, ?)'
  );
  transaction(() => {
    for (const role of ['manager', 'employee']) {
      for (const page of PAGES) {
        const d = (DEFAULT_PERMISSIONS[role] && DEFAULT_PERMISSIONS[role][page.id]) || { view: false, edit: false };
        insertPerm.run(role, page.id, d.view ? 1 : 0, d.edit ? 1 : 0);
      }
    }
  });
}

function getPermMatrix() {
  const rows = db.prepare('SELECT role, page_id, can_view, can_edit FROM role_permissions').all();
  const matrix = { manager: {}, employee: {} };
  for (const r of rows) {
    if (!matrix[r.role]) continue;
    matrix[r.role][r.page_id] = { view: !!r.can_view, edit: !!r.can_edit };
  }
  return matrix;
}

function setPermMatrix(newMatrix) {
  const pageIds = PAGES.map((p) => p.id);
  const upsert = db.prepare(
    `INSERT INTO role_permissions (role, page_id, can_view, can_edit) VALUES (?, ?, ?, ?)
     ON CONFLICT(role, page_id) DO UPDATE SET can_view = excluded.can_view, can_edit = excluded.can_edit`
  );
  transaction(() => {
    for (const role of ['manager', 'employee']) {
      const roleData = (newMatrix && newMatrix[role]) || {};
      for (const pageId of pageIds) {
        const entry = roleData[pageId] || { view: false, edit: false };
        upsert.run(role, pageId, entry.view ? 1 : 0, entry.edit ? 1 : 0);
      }
    }
  });
}

function effectivePerms(role) {
  if (role === 'admin') {
    const all = {};
    PAGES.forEach((p) => { all[p.id] = { view: true, edit: true }; });
    return all;
  }
  const matrix = getPermMatrix();
  const roleMatrix = matrix[role] || {};
  const result = {};
  PAGES.forEach((p) => { result[p.id] = roleMatrix[p.id] || { view: false, edit: false }; });
  return result;
}

function hasPerm(role, pageId, level) {
  if (role === 'admin') return true;
  const perms = effectivePerms(role);
  const p = perms[pageId];
  if (!p) return false;
  return level === 'edit' ? p.edit : p.view;
}

function getSetting(key, fallback = null) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : fallback;
}

function setSetting(key, value) {
  db.prepare(
    `INSERT INTO settings (key, value) VALUES (?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value`
  ).run(key, value);
}

module.exports = {
  db, JWT_SECRET, RECORDINGS_DIR, PHOTOS_DIR, DATA_DIR, getSetting, setSetting, transaction,
  PAGES, getPermMatrix, setPermMatrix, effectivePerms, hasPerm, importUserId,
};
