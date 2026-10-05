const path = require('path');
const fs = require('fs');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');

const {
  db, JWT_SECRET, RECORDINGS_DIR, PHOTOS_DIR, DATA_DIR, getSetting, setSetting, transaction,
  PAGES, getPermMatrix, setPermMatrix, effectivePerms, hasPerm, importUserId,
} = require('./db');
const { evaluateRecording, evaluateTranscript, DEFAULT_MODEL } = require('./gemini');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

// Behind a hosting provider's HTTPS proxy (Render etc.) — needed for secure cookies.
if (IS_PROD) app.set('trust proxy', 1);

app.get('/healthz', (req, res) => res.send('ok'));

app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Auth helpers ----------

function signToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role, full_name: user.full_name, branch_id: user.branch_id },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

function auth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'AUTH_REQUIRED' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'INVALID_TOKEN' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'FORBIDDEN' });
    next();
  };
}

// Per-role page permissions (view/edit), configurable by admin from the "თანამშრომლები
// და როლები" page. admin always passes (see db.js effectivePerms/hasPerm).
function requirePerm(pageId, level) {
  return (req, res, next) => {
    if (!hasPerm(req.user.role, pageId, level)) return res.status(403).json({ error: 'FORBIDDEN' });
    next();
  };
}

// Separate auth path for the external import endpoint (POST /api/import/recording) —
// called by an outside script/process, not a browser with a login cookie, so it
// authenticates with a static key (Settings → API იმპორტის გასაღები) instead of a JWT.
function requireApiKey(req, res, next) {
  const key = getSetting('api_import_key');
  const provided = req.header('X-API-Key');
  if (!key || !provided || provided !== key) return res.status(401).json({ error: 'INVALID_API_KEY' });
  next();
}

// ---------- Multer (audio upload) ----------

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, RECORDINGS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '.webm';
    cb(null, `${Date.now()}_${uuidv4()}${ext}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 500 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (/^audio\//.test(file.mimetype) || /\.(mp3|wav|m4a|aac|ogg|flac|webm|opus|aiff|mp4)$/i.test(file.originalname)) {
      cb(null, true);
    } else {
      cb(new Error('UNSUPPORTED_FILE_TYPE'));
    }
  },
});

// ---------- Multer (photo upload) ----------

const photoStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, PHOTOS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '.jpg';
    cb(null, `${Date.now()}_${uuidv4()}${ext}`);
  },
});
const uploadPhoto = multer({
  storage: photoStorage,
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (/^image\//.test(file.mimetype) || /\.(jpg|jpeg|png|webp|gif|heic|heif)$/i.test(file.originalname)) {
      cb(null, true);
    } else {
      cb(new Error('UNSUPPORTED_FILE_TYPE'));
    }
  },
});

// ---------- Auth routes ----------

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'MISSING_FIELDS' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !user.active || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'INVALID_CREDENTIALS' });
  }
  const token = signToken(user);
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PROD,
    maxAge: 30 * 24 * 3600 * 1000,
  });
  res.json({ id: user.id, username: user.username, full_name: user.full_name, role: user.role, branch_id: user.branch_id });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json(req.user);
});

app.post('/api/auth/change-password', auth, (req, res) => {
  const { current_password, new_password } = req.body || {};
  if (!new_password || new_password.length < 6) return res.status(400).json({ error: 'WEAK_PASSWORD' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(current_password || '', user.password_hash)) {
    return res.status(401).json({ error: 'WRONG_CURRENT_PASSWORD' });
  }
  const hash = bcrypt.hashSync(new_password, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, user.id);
  res.json({ ok: true });
});

// ---------- Users (admin) ----------

app.get('/api/users', auth, requireRole('admin', 'manager'), (req, res) => {
  const rows = db.prepare(
    `SELECT u.id, u.username, u.full_name, u.role, u.branch_id, u.active, b.name AS branch_name
     FROM users u LEFT JOIN branches b ON b.id = u.branch_id ORDER BY u.full_name`
  ).all();
  res.json(rows);
});

app.post('/api/users', auth, requirePerm('users', 'edit'), (req, res) => {
  const { username, password, full_name, role, branch_id } = req.body || {};
  if (!username || !password || !full_name || !role) return res.status(400).json({ error: 'MISSING_FIELDS' });
  if (!['admin', 'manager', 'employee'].includes(role)) return res.status(400).json({ error: 'INVALID_ROLE' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare(
      `INSERT INTO users (username, password_hash, full_name, role, branch_id) VALUES (?, ?, ?, ?, ?)`
    ).run(username, hash, full_name, role, branch_id || null);
    res.json({ id: info.lastInsertRowid });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'USERNAME_TAKEN' });
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.put('/api/users/:id', auth, requirePerm('users', 'edit'), (req, res) => {
  const { full_name, role, branch_id, active, password } = req.body || {};
  const existing = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'NOT_FOUND' });
  db.prepare(
    `UPDATE users SET full_name = ?, role = ?, branch_id = ?, active = ? WHERE id = ?`
  ).run(
    full_name ?? existing.full_name,
    role ?? existing.role,
    branch_id !== undefined ? branch_id : existing.branch_id,
    active !== undefined ? (active ? 1 : 0) : existing.active,
    req.params.id
  );
  if (password) {
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(password, 10), req.params.id);
  }
  res.json({ ok: true });
});

app.delete('/api/users/:id', auth, requirePerm('users', 'edit'), (req, res) => {
  if (Number(req.params.id) === req.user.id) return res.status(400).json({ error: 'CANNOT_DELETE_SELF' });
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ---------- Branches ----------

app.get('/api/branches', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM branches ORDER BY name').all());
});

app.post('/api/branches', auth, requirePerm('branches', 'edit'), (req, res) => {
  const { name } = req.body || {};
  if (!name) return res.status(400).json({ error: 'MISSING_FIELDS' });
  try {
    const info = db.prepare('INSERT INTO branches (name) VALUES (?)').run(name);
    res.json({ id: info.lastInsertRowid });
  } catch (e) {
    res.status(409).json({ error: 'BRANCH_EXISTS' });
  }
});

app.delete('/api/branches/:id', auth, requirePerm('branches', 'edit'), (req, res) => {
  db.prepare('DELETE FROM branches WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ---------- Criteria templates ----------

app.get('/api/criteria-templates', auth, requireRole('admin', 'manager'), (req, res) => {
  const templates = db.prepare('SELECT * FROM criteria_templates WHERE active = 1 ORDER BY name').all();
  const items = db.prepare('SELECT * FROM criteria_items WHERE template_id = ? ORDER BY order_index, id');
  for (const t of templates) t.items = items.all(t.id);
  res.json(templates);
});

app.post('/api/criteria-templates', auth, requirePerm('criteria', 'edit'), (req, res) => {
  const { name, description, items } = req.body || {};
  if (!name || !Array.isArray(items) || items.length === 0) return res.status(400).json({ error: 'MISSING_FIELDS' });
  const id = transaction(() => {
    const info = db.prepare(
      'INSERT INTO criteria_templates (name, description, created_by) VALUES (?, ?, ?)'
    ).run(name, description || null, req.user.id);
    const insertItem = db.prepare(
      'INSERT INTO criteria_items (template_id, text, max_score, order_index) VALUES (?, ?, ?, ?)'
    );
    items.forEach((it, idx) => insertItem.run(info.lastInsertRowid, it.text, it.max_score || 10, idx));
    return info.lastInsertRowid;
  });
  res.json({ id });
});

app.put('/api/criteria-templates/:id', auth, requirePerm('criteria', 'edit'), (req, res) => {
  const { name, description, items } = req.body || {};
  const existing = db.prepare('SELECT * FROM criteria_templates WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'NOT_FOUND' });
  transaction(() => {
    db.prepare('UPDATE criteria_templates SET name = ?, description = ? WHERE id = ?')
      .run(name ?? existing.name, description ?? existing.description, req.params.id);
    if (Array.isArray(items)) {
      db.prepare('DELETE FROM criteria_items WHERE template_id = ?').run(req.params.id);
      const insertItem = db.prepare(
        'INSERT INTO criteria_items (template_id, text, max_score, order_index) VALUES (?, ?, ?, ?)'
      );
      items.forEach((it, idx) => insertItem.run(req.params.id, it.text, it.max_score || 10, idx));
    }
  });
  res.json({ ok: true });
});

app.delete('/api/criteria-templates/:id', auth, requirePerm('criteria', 'edit'), (req, res) => {
  db.prepare('UPDATE criteria_templates SET active = 0 WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ---------- Recordings ----------

function recordingVisibleTo(user) {
  // returns { where, params } fragment restricting rows to what this user may see
  if (user.role === 'employee') return { where: 'r.employee_id = ?', params: [user.id] };
  return { where: '1=1', params: [] };
}

app.post('/api/recordings/observation', auth, requirePerm('observe', 'edit'), upload.single('audio'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'NO_FILE' });
  const { branch_id, note, duration_seconds, employee_id } = req.body || {};
  const targetEmployee = (req.user.role !== 'employee' && employee_id) ? Number(employee_id) : req.user.id;
  const info = db.prepare(
    `INSERT INTO recordings (type, employee_id, branch_id, note, file_path, original_filename, mime_type, duration_seconds, uploaded_by)
     VALUES ('observation', ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    targetEmployee,
    branch_id || req.user.branch_id || null,
    note || null,
    req.file.filename,
    req.file.originalname,
    req.file.mimetype,
    duration_seconds ? Number(duration_seconds) : null,
    req.user.id
  );
  maybeAutoEvaluate(info.lastInsertRowid);
  res.json({ id: info.lastInsertRowid });
});

app.post('/api/recordings/manual', auth, requirePerm('manual-upload', 'edit'), upload.array('audio', 20), (req, res) => {
  if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'NO_FILE' });
  const { branch_id, note, employee_id } = req.body || {};
  const insert = db.prepare(
    `INSERT INTO recordings (type, employee_id, branch_id, note, file_path, original_filename, mime_type, uploaded_by)
     VALUES ('manual', ?, ?, ?, ?, ?, ?, ?)`
  );
  const ids = req.files.map((f) =>
    insert.run(employee_id || null, branch_id || null, note || null, f.filename, f.originalname, f.mimetype, req.user.id).lastInsertRowid
  );
  ids.forEach(maybeAutoEvaluate);
  res.json({ ids });
});

// ---------- External import (for an outside pipeline that already has audio + transcript) ----------
// Authenticated with a static key (Settings → API იმპორტის გასაღები), not a login
// cookie — see requireApiKey. Employee/branch are matched by name (case-insensitive,
// trimmed exact match against users.full_name / branches.name) so the caller doesn't
// need to know internal numeric IDs; an unmatched name is kept visible in the note
// instead of silently dropped. Evaluation runs against the already-known transcript
// (no audio sent to Gemini, no re-transcription) and happens in the background —
// this endpoint responds as soon as the recording is stored.
app.post('/api/import/recording', requireApiKey, upload.single('audio'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'NO_FILE' });
  const { transcript, employee_name, employee_id, branch_name, branch_id, note, recorded_at } = req.body || {};
  if (!transcript || !String(transcript).trim()) return res.status(400).json({ error: 'NO_TRANSCRIPT' });

  let resolvedEmployeeId = employee_id ? Number(employee_id) : null;
  let employeeMatched = !!resolvedEmployeeId;
  if (!resolvedEmployeeId && employee_name) {
    const match = db.prepare(
      "SELECT id FROM users WHERE trim(full_name) = trim(?) COLLATE NOCASE"
    ).get(String(employee_name));
    if (match) { resolvedEmployeeId = match.id; employeeMatched = true; }
  }

  let resolvedBranchId = branch_id ? Number(branch_id) : null;
  let branchMatched = !!resolvedBranchId;
  if (!resolvedBranchId && branch_name) {
    const match = db.prepare(
      "SELECT id FROM branches WHERE trim(name) = trim(?) COLLATE NOCASE"
    ).get(String(branch_name));
    if (match) { resolvedBranchId = match.id; branchMatched = true; }
  }

  const noteParts = [];
  if (employee_name && !employeeMatched) noteParts.push(`[იმპორტი: თანამშრომელი „${employee_name}" ვერ მოიძებნა]`);
  if (branch_name && !branchMatched) noteParts.push(`[იმპორტი: ფილიალი „${branch_name}" ვერ მოიძებნა]`);
  if (note) noteParts.push(String(note));
  const finalNote = noteParts.length ? noteParts.join(' ') : null;

  let createdAt = null;
  if (recorded_at) {
    const d = new Date(recorded_at);
    if (!isNaN(d.getTime())) createdAt = d.toISOString().slice(0, 19).replace('T', ' ');
  }

  const info = db.prepare(
    `INSERT INTO recordings (type, employee_id, branch_id, note, file_path, original_filename, mime_type, uploaded_by${createdAt ? ', created_at' : ''})
     VALUES ('manual', ?, ?, ?, ?, ?, ?, ?${createdAt ? ', ?' : ''})`
  ).run(
    ...[resolvedEmployeeId, resolvedBranchId, finalNote, req.file.filename, req.file.originalname, req.file.mimetype, importUserId]
      .concat(createdAt ? [createdAt] : [])
  );

  res.json({ id: info.lastInsertRowid, employee_matched: employeeMatched, branch_matched: branchMatched });

  // Evaluate in the background so the caller doesn't wait on Gemini.
  let templateIds = [];
  if (req.body && req.body.template_ids) {
    try { templateIds = JSON.parse(req.body.template_ids); } catch (e) { templateIds = []; }
  }
  if (!Array.isArray(templateIds) || templateIds.length === 0) {
    try { templateIds = JSON.parse(getSetting('auto_evaluate_template_ids', '[]')); } catch (e) { templateIds = []; }
  }
  if (Array.isArray(templateIds) && templateIds.length > 0) {
    runEvaluationFromTranscript(info.lastInsertRowid, templateIds, null, String(transcript))
      .catch(() => { /* status/error already recorded on the recording */ });
  }
});

app.get('/api/recordings', auth, requirePerm('recordings', 'view'), (req, res) => {
  const { from, to, branch_id, employee_id, status, type } = req.query;
  const vis = recordingVisibleTo(req.user);
  let where = [vis.where];
  let params = [...vis.params];
  if (from) { where.push('date(r.created_at) >= date(?)'); params.push(from); }
  if (to) { where.push('date(r.created_at) <= date(?)'); params.push(to); }
  if (branch_id) { where.push('r.branch_id = ?'); params.push(branch_id); }
  if (employee_id) { where.push('r.employee_id = ?'); params.push(employee_id); }
  if (status) { where.push('r.status = ?'); params.push(status); }
  if (type) { where.push('r.type = ?'); params.push(type); }

  const sql = `
    SELECT r.*, u.full_name AS employee_name, b.name AS branch_name, up.full_name AS uploaded_by_name,
           e.overall_score, e.max_score AS eval_max_score
    FROM recordings r
    LEFT JOIN users u ON u.id = r.employee_id
    LEFT JOIN branches b ON b.id = r.branch_id
    LEFT JOIN users up ON up.id = r.uploaded_by
    LEFT JOIN evaluations e ON e.id = (SELECT id FROM evaluations WHERE recording_id = r.id ORDER BY id DESC LIMIT 1)
    WHERE ${where.join(' AND ')}
    ORDER BY r.created_at DESC
    LIMIT 500
  `;
  res.json(db.prepare(sql).all(...params));
});

app.get('/api/recordings/:id', auth, (req, res) => {
  const rec = db.prepare(
    `SELECT r.*, u.full_name AS employee_name, b.name AS branch_name
     FROM recordings r
     LEFT JOIN users u ON u.id = r.employee_id
     LEFT JOIN branches b ON b.id = r.branch_id
     WHERE r.id = ?`
  ).get(req.params.id);
  if (!rec) return res.status(404).json({ error: 'NOT_FOUND' });
  if (req.user.role === 'employee' && rec.employee_id !== req.user.id) return res.status(403).json({ error: 'FORBIDDEN' });

  const evaluation = db.prepare('SELECT * FROM evaluations WHERE recording_id = ? ORDER BY id DESC LIMIT 1').get(rec.id);
  if (evaluation) {
    evaluation.items = db.prepare('SELECT * FROM evaluation_items WHERE evaluation_id = ?').all(evaluation.id);
    evaluation.template_ids = JSON.parse(evaluation.template_ids || '[]');
  }
  const photos = db.prepare('SELECT id, original_filename, mime_type, created_at FROM recording_photos WHERE recording_id = ? ORDER BY id').all(rec.id);
  res.json({ ...rec, evaluation: evaluation || null, photos });
});

app.get('/api/recordings/:id/audio', auth, (req, res) => {
  const rec = db.prepare('SELECT * FROM recordings WHERE id = ?').get(req.params.id);
  if (!rec) return res.status(404).end();
  if (req.user.role === 'employee' && rec.employee_id !== req.user.id) return res.status(403).end();
  const filePath = path.join(RECORDINGS_DIR, rec.file_path);
  if (!fs.existsSync(filePath)) return res.status(404).end();
  res.sendFile(filePath);
});

app.delete('/api/recordings/:id', auth, requireRole('admin'), (req, res) => {
  const rec = db.prepare('SELECT * FROM recordings WHERE id = ?').get(req.params.id);
  if (!rec) return res.status(404).json({ error: 'NOT_FOUND' });
  const photoFiles = db.prepare('SELECT file_path FROM recording_photos WHERE recording_id = ?').all(rec.id);
  const filePath = path.join(RECORDINGS_DIR, rec.file_path);
  db.prepare('DELETE FROM recordings WHERE id = ?').run(req.params.id);
  fs.unlink(filePath, () => {});
  photoFiles.forEach((p) => fs.unlink(path.join(PHOTOS_DIR, p.file_path), () => {}));
  res.json({ ok: true });
});

// ---------- Recording photos ----------

app.post('/api/recordings/:id/photos', auth, uploadPhoto.array('photos', 20), (req, res) => {
  const rec = db.prepare('SELECT * FROM recordings WHERE id = ?').get(req.params.id);
  if (!rec) return res.status(404).json({ error: 'NOT_FOUND' });
  if (req.user.role === 'employee' && rec.employee_id !== req.user.id) return res.status(403).json({ error: 'FORBIDDEN' });
  if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'NO_FILE' });

  const insert = db.prepare(
    'INSERT INTO recording_photos (recording_id, file_path, original_filename, mime_type, uploaded_by) VALUES (?, ?, ?, ?, ?)'
  );
  const ids = req.files.map((f) => insert.run(rec.id, f.filename, f.originalname, f.mimetype, req.user.id).lastInsertRowid);
  res.json({ ids });
});

app.get('/api/recordings/:id/photos/:photoId', auth, (req, res) => {
  const rec = db.prepare('SELECT * FROM recordings WHERE id = ?').get(req.params.id);
  if (!rec) return res.status(404).end();
  if (req.user.role === 'employee' && rec.employee_id !== req.user.id) return res.status(403).end();
  const photo = db.prepare('SELECT * FROM recording_photos WHERE id = ? AND recording_id = ?').get(req.params.photoId, rec.id);
  if (!photo) return res.status(404).end();
  const filePath = path.join(PHOTOS_DIR, photo.file_path);
  if (!fs.existsSync(filePath)) return res.status(404).end();
  res.sendFile(filePath);
});

app.delete('/api/recordings/:id/photos/:photoId', auth, (req, res) => {
  const rec = db.prepare('SELECT * FROM recordings WHERE id = ?').get(req.params.id);
  if (!rec) return res.status(404).json({ error: 'NOT_FOUND' });
  const canManage = req.user.role === 'admin' || req.user.role === 'manager' || rec.employee_id === req.user.id;
  if (!canManage) return res.status(403).json({ error: 'FORBIDDEN' });
  const photo = db.prepare('SELECT * FROM recording_photos WHERE id = ? AND recording_id = ?').get(req.params.photoId, rec.id);
  if (!photo) return res.status(404).json({ error: 'NOT_FOUND' });
  db.prepare('DELETE FROM recording_photos WHERE id = ?').run(photo.id);
  fs.unlink(path.join(PHOTOS_DIR, photo.file_path), () => {});
  res.json({ ok: true });
});

// ---------- Evaluation ----------

// Shared by runEvaluation (audio -> Gemini transcribes + scores) and
// runEvaluationFromTranscript (transcript already known -> Gemini only scores):
// looks up the recording + criteria items, marks the recording "processing", calls
// the given Gemini function, and persists the result (or records the error).
async function runEvaluationCore(recordingId, templateIds, userId, callGemini) {
  const rec = db.prepare('SELECT * FROM recordings WHERE id = ?').get(recordingId);
  if (!rec) throw Object.assign(new Error('NOT_FOUND'), { code: 'NOT_FOUND' });

  const placeholders = templateIds.map(() => '?').join(',');
  const items = db.prepare(
    `SELECT * FROM criteria_items WHERE template_id IN (${placeholders}) ORDER BY template_id, order_index`
  ).all(...templateIds);
  if (items.length === 0) throw Object.assign(new Error('TEMPLATES_HAVE_NO_ITEMS'), { code: 'TEMPLATES_HAVE_NO_ITEMS' });

  db.prepare("UPDATE recordings SET status = 'processing', error_message = NULL WHERE id = ?").run(rec.id);

  try {
    const { parsed, raw } = await callGemini(rec, items);

    const overall = parsed.criteria_results.reduce((s, c) => s + (Number(c.score) || 0), 0);
    const maxTotal = parsed.criteria_results.reduce((s, c) => s + (Number(c.max_score) || 0), 0);

    const evalId = transaction(() => {
      const info = db.prepare(
        `INSERT INTO evaluations (recording_id, template_ids, transcript, overall_score, max_score, summary, raw_response, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(rec.id, JSON.stringify(templateIds), parsed.transcript, overall, maxTotal, parsed.summary + '\n\n' + (parsed.overall_comment || ''), raw, userId || null);
      const insertItem = db.prepare(
        'INSERT INTO evaluation_items (evaluation_id, criterion_text, score, max_score, comment) VALUES (?, ?, ?, ?, ?)'
      );
      for (const c of parsed.criteria_results) {
        insertItem.run(info.lastInsertRowid, c.criterion, Number(c.score) || 0, Number(c.max_score) || 0, c.comment || '');
      }
      db.prepare("UPDATE recordings SET status = 'evaluated' WHERE id = ?").run(rec.id);
      return info.lastInsertRowid;
    });
    return { evalId, overall, maxTotal };
  } catch (e) {
    console.error('Evaluation failed:', e);
    let msg = 'შეფასება ვერ განხორციელდა. სცადეთ თავიდან.';
    if (e.code === 'GEMINI_API_KEY_MISSING') msg = 'GEMINI API გასაღები არ არის მითითებული პარამეტრებში.';
    db.prepare("UPDATE recordings SET status = 'error', error_message = ? WHERE id = ?").run(msg, rec.id);
    throw Object.assign(new Error(msg), { code: e.code, userMessage: msg });
  }
}

// Audio -> Gemini transcribes and scores. Used by the manual "evaluate" endpoint
// and the optional auto-evaluate trigger on new recordings made in-app.
function runEvaluation(recordingId, templateIds, userId) {
  return runEvaluationCore(recordingId, templateIds, userId, (rec, items) => {
    const filePath = path.join(RECORDINGS_DIR, rec.file_path);
    return evaluateRecording({ filePath, criteriaItems: items, note: rec.note });
  });
}

// Transcript already known (e.g. supplied by an external import) -> Gemini only
// scores against the criteria, no audio is sent. Used by POST /api/import/recording.
function runEvaluationFromTranscript(recordingId, templateIds, userId, transcript) {
  return runEvaluationCore(recordingId, templateIds, userId, (rec, items) =>
    evaluateTranscript({ transcript, criteriaItems: items, note: rec.note })
  );
}

// Fire-and-forget auto-evaluation, only if the admin has switched it on and
// picked default templates in settings. Never blocks the upload response.
function maybeAutoEvaluate(recordingId) {
  const enabled = getSetting('auto_evaluate_enabled') === '1';
  if (!enabled) return;
  let templateIds = [];
  try { templateIds = JSON.parse(getSetting('auto_evaluate_template_ids', '[]')); } catch (e) {}
  if (!Array.isArray(templateIds) || templateIds.length === 0) return;
  runEvaluation(recordingId, templateIds, null).catch(() => { /* status/error already recorded on the recording */ });
}

app.post('/api/recordings/:id/evaluate', auth, requirePerm('recordings', 'edit'), async (req, res) => {
  const { template_ids } = req.body || {};
  if (!Array.isArray(template_ids) || template_ids.length === 0) {
    return res.status(400).json({ error: 'NO_TEMPLATES' });
  }
  try {
    const { evalId, overall, maxTotal } = await runEvaluation(req.params.id, template_ids, req.user.id);
    res.json({ ok: true, evaluation_id: evalId, overall_score: overall, max_score: maxTotal });
  } catch (e) {
    const status = e.code === 'NOT_FOUND' ? 404 : e.code === 'TEMPLATES_HAVE_NO_ITEMS' ? 400 : 500;
    res.status(status).json({ error: e.userMessage || e.message });
  }
});

// ---------- Analytics ----------

app.get('/api/analytics', auth, requirePerm('analytics', 'view'), (req, res) => {
  const { from, to, branch_id } = req.query;

  let where = ['e.id IN (SELECT MAX(id) FROM evaluations GROUP BY recording_id)', 'e.max_score > 0'];
  let params = [];
  if (from) { where.push('date(r.created_at) >= date(?)'); params.push(from); }
  if (to) { where.push('date(r.created_at) <= date(?)'); params.push(to); }
  if (branch_id) { where.push('r.branch_id = ?'); params.push(branch_id); }
  const whereSql = where.join(' AND ');

  // Overall counts (all recordings matching the date/branch filter, evaluated or not)
  let recWhere = ['1=1'];
  let recParams = [];
  if (from) { recWhere.push('date(created_at) >= date(?)'); recParams.push(from); }
  if (to) { recWhere.push('date(created_at) <= date(?)'); recParams.push(to); }
  if (branch_id) { recWhere.push('branch_id = ?'); recParams.push(branch_id); }
  const summaryRow = db.prepare(
    `SELECT COUNT(*) AS total, SUM(CASE WHEN status = 'evaluated' THEN 1 ELSE 0 END) AS evaluated
     FROM recordings WHERE ${recWhere.join(' AND ')}`
  ).get(...recParams);

  const avgRow = db.prepare(
    `SELECT AVG(e.overall_score * 100.0 / e.max_score) AS avgPct
     FROM evaluations e JOIN recordings r ON r.id = e.recording_id
     WHERE ${whereSql}`
  ).get(...params);

  const trend = db.prepare(
    `SELECT date(r.created_at) AS date, AVG(e.overall_score * 100.0 / e.max_score) AS avgPct, COUNT(*) AS n
     FROM evaluations e JOIN recordings r ON r.id = e.recording_id
     WHERE ${whereSql}
     GROUP BY date(r.created_at) ORDER BY date`
  ).all(...params);

  const byBranch = db.prepare(
    `SELECT r.branch_id, COALESCE(b.name, 'ფილიალის გარეშე') AS branch_name,
            COUNT(*) AS n, AVG(e.overall_score * 100.0 / e.max_score) AS avgPct
     FROM evaluations e JOIN recordings r ON r.id = e.recording_id
     LEFT JOIN branches b ON b.id = r.branch_id
     WHERE ${whereSql}
     GROUP BY r.branch_id ORDER BY avgPct DESC`
  ).all(...params);

  const criterionWhere = where.map((w) => w).join(' AND '); // same filters, applied via r below
  const byCriterion = db.prepare(
    `SELECT ei.criterion_text, AVG(ei.score * 100.0 / ei.max_score) AS avgPct, COUNT(*) AS n
     FROM evaluation_items ei
     JOIN evaluations e ON e.id = ei.evaluation_id
     JOIN recordings r ON r.id = e.recording_id
     WHERE ${criterionWhere} AND ei.max_score > 0
     GROUP BY ei.criterion_text ORDER BY avgPct ASC`
  ).all(...params);

  const byBranchCriterionRows = db.prepare(
    `SELECT r.branch_id, COALESCE(b.name, 'ფილიალის გარეშე') AS branch_name,
            ei.criterion_text, AVG(ei.score * 100.0 / ei.max_score) AS avgPct, COUNT(*) AS n
     FROM evaluation_items ei
     JOIN evaluations e ON e.id = ei.evaluation_id
     JOIN recordings r ON r.id = e.recording_id
     LEFT JOIN branches b ON b.id = r.branch_id
     WHERE ${criterionWhere} AND ei.max_score > 0
     GROUP BY r.branch_id, ei.criterion_text`
  ).all(...params);

  const byBranchMap = new Map();
  for (const row of byBranchCriterionRows) {
    const key = row.branch_id ?? 'null';
    if (!byBranchMap.has(key)) byBranchMap.set(key, { branch_id: row.branch_id, branch_name: row.branch_name, items: [] });
    byBranchMap.get(key).items.push({ criterion_text: row.criterion_text, avgPct: row.avgPct, n: row.n });
  }
  const strengthsWeaknesses = Array.from(byBranchMap.values()).map((b) => {
    const sorted = [...b.items].sort((a, c) => c.avgPct - a.avgPct);
    return {
      branch_id: b.branch_id,
      branch_name: b.branch_name,
      strengths: sorted.slice(0, 2),
      weaknesses: sorted.slice(-2).reverse().filter((it) => !sorted.slice(0, 2).includes(it)),
    };
  });

  res.json({
    summary: {
      total: summaryRow.total || 0,
      evaluated: summaryRow.evaluated || 0,
      avgPct: avgRow.avgPct,
    },
    trend,
    byBranch,
    byCriterion,
    strengthsWeaknesses,
  });
});

// ---------- Role permissions ----------
// admin has full, non-configurable access everywhere. Only manager/employee rows are
// stored — see db.js PAGES / DEFAULT_PERMISSIONS for the fixed page list and the
// defaults that reproduce the platform's previous hardcoded role rules.

app.get('/api/permissions', auth, requireRole('admin'), (req, res) => {
  res.json({ pages: PAGES, matrix: getPermMatrix() });
});

app.put('/api/permissions', auth, requireRole('admin'), (req, res) => {
  const { matrix } = req.body || {};
  if (!matrix || typeof matrix !== 'object') return res.status(400).json({ error: 'INVALID_BODY' });
  setPermMatrix(matrix);
  res.json({ ok: true });
});

app.get('/api/permissions/me', auth, (req, res) => {
  res.json(effectivePerms(req.user.role));
});

// ---------- Settings ----------

app.get('/api/settings', auth, requirePerm('settings', 'view'), (req, res) => {
  const key = getSetting('gemini_api_key');
  const importKey = getSetting('api_import_key');
  let autoTemplateIds = [];
  try { autoTemplateIds = JSON.parse(getSetting('auto_evaluate_template_ids', '[]')); } catch (e) {}
  res.json({
    gemini_api_key_set: !!key,
    gemini_api_key_masked: key ? `${key.slice(0, 4)}••••••••${key.slice(-4)}` : null,
    gemini_model: getSetting('gemini_model', DEFAULT_MODEL),
    auto_evaluate_enabled: getSetting('auto_evaluate_enabled') === '1',
    auto_evaluate_template_ids: autoTemplateIds,
    api_import_key_set: !!importKey,
    api_import_key_masked: importKey ? `${importKey.slice(0, 4)}••••••••${importKey.slice(-4)}` : null,
  });
});

app.put('/api/settings', auth, requirePerm('settings', 'edit'), (req, res) => {
  const {
    gemini_api_key, gemini_model, auto_evaluate_enabled, auto_evaluate_template_ids,
    regenerate_api_import_key,
  } = req.body || {};
  if (gemini_api_key) setSetting('gemini_api_key', gemini_api_key);
  if (gemini_model) setSetting('gemini_model', gemini_model);
  if (auto_evaluate_enabled !== undefined) setSetting('auto_evaluate_enabled', auto_evaluate_enabled ? '1' : '0');
  if (Array.isArray(auto_evaluate_template_ids)) setSetting('auto_evaluate_template_ids', JSON.stringify(auto_evaluate_template_ids));

  let newApiImportKey;
  if (regenerate_api_import_key) {
    newApiImportKey = require('crypto').randomBytes(24).toString('hex');
    setSetting('api_import_key', newApiImportKey);
  }
  if (newApiImportKey) return res.json({ ok: true, api_import_key: newApiImportKey });
  res.json({ ok: true });
});

// ---------- Fallback to SPA ----------

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------- Backup / restore (admin only) ----------
// Backup: whole data folder (DB + audio + photos + secrets) as one .tar.gz.
// Restore: the uploaded archive is parked as restore-pending.tar.gz and unpacked by db.js
// on the next start (the process exits right after replying so the host restarts it).

app.get('/api/admin/backup', auth, requireRole('admin'), (req, res) => {
  try { db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch (e) { /* best effort */ }
  const stamp = new Date().toISOString().slice(0, 10);
  res.setHeader('Content-Type', 'application/gzip');
  res.setHeader('Content-Disposition', `attachment; filename="observation-qa-backup-${stamp}.tar.gz"`);
  const tar = require('child_process').spawn('tar', ['-czf', '-', '-C', DATA_DIR, '.']);
  tar.stdout.pipe(res);
  tar.on('error', () => res.destroy());
});

const restoreUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, DATA_DIR),
    filename: (req, file, cb) => cb(null, 'restore-pending.tar.gz'),
  }),
  limits: { fileSize: 2 * 1024 * 1024 * 1024 },
});

app.post('/api/admin/restore', auth, requireRole('admin'), restoreUpload.single('backup'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'NO_FILE' });
  let listing = '';
  try {
    listing = require('child_process').execFileSync('tar', ['-tzf', req.file.path], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  } catch (e) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'INVALID_BACKUP' });
  }
  if (!/(^|\n)(\.\/)?app\.db\n/.test(listing)) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'INVALID_BACKUP' });
  }
  res.json({ ok: true, restarting: true });
  setTimeout(() => process.exit(0), 800);
});

app.use((err, req, res, next) => {
  console.error(err);
  if (err.message === 'UNSUPPORTED_FILE_TYPE') return res.status(400).json({ error: 'UNSUPPORTED_FILE_TYPE' });
  res.status(500).json({ error: 'SERVER_ERROR' });
});

app.listen(PORT, () => {
  console.log(`სერვერი გაშვებულია: http://localhost:${PORT}`);
});
