const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const basicAuth = require('basic-auth');
const helmet = require('helmet');
const cors = require('cors');
const Database = require('better-sqlite3');
const { nanoid } = require('nanoid');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 8000);
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data.db');
const JWT_SECRET = process.env.JWT_SECRET || 'change-me';
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'change-me-admin';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';
const ADMIN_IP_ALLOWLIST = (process.env.ADMIN_IP_ALLOWLIST || '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);
const CORS_ALLOW_ORIGINS = (process.env.CORS_ALLOW_ORIGINS || '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);
const RATE_LIMIT_PER_MIN = Number(process.env.RATE_LIMIT_PER_MIN || 120);
const ADMIN_RATE_LIMIT_PER_MIN = Number(process.env.ADMIN_RATE_LIMIT_PER_MIN || 30);
const TOKEN_TTL_SECONDS = Number(process.env.TOKEN_TTL_SECONDS || 60 * 60 * 24 * 30);
const AUDIT_LOG_TTL_DAYS = Number(process.env.AUDIT_LOG_TTL_DAYS || 30);
const CLEANUP_INTERVAL_MS = Number(process.env.CLEANUP_INTERVAL_MS || 5 * 60 * 1000);

const app = express();
app.set('trust proxy', true);
app.use(helmet());
app.use(
  cors({
    origin: CORS_ALLOW_ORIGINS.length ? CORS_ALLOW_ORIGINS : false,
    credentials: true,
  })
);
app.use(express.json({ limit: '1mb' }));

const db = new Database(DB_PATH);

db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT,
    token_version INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS devices (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    name TEXT,
    last_seen_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, device_id)
  );

  CREATE TABLE IF NOT EXISTS user_data (
    user_id TEXT NOT NULL,
    collection TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT,
    expires_at TEXT,
    version INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, collection, key)
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    action TEXT NOT NULL,
    ip TEXT NOT NULL,
    status INTEGER NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti TEXT PRIMARY KEY,
    revoked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_user_data_lookup ON user_data (user_id, collection, updated_at);
  CREATE INDEX IF NOT EXISTS idx_user_data_expires ON user_data (expires_at);
  CREATE INDEX IF NOT EXISTS idx_devices_user ON devices (user_id);
  CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log (created_at);
`);

const rateBuckets = new Map();

const nowIso = () => new Date().toISOString();

const getIp = (req) => req.ip || req.connection?.remoteAddress || 'unknown';

const rateLimit = ({ limitPerMin, keyResolver }) => (req, res, next) => {
  const key = keyResolver(req);
  if (!key) {
    return res.status(400).json({ error: 'rate-limit-key-missing' });
  }
  const now = Date.now();
  const bucket = rateBuckets.get(key) || { count: 0, resetAt: now + 60_000 };
  if (now > bucket.resetAt) {
    bucket.count = 0;
    bucket.resetAt = now + 60_000;
  }
  bucket.count += 1;
  rateBuckets.set(key, bucket);
  res.setHeader('X-RateLimit-Limit', String(limitPerMin));
  res.setHeader('X-RateLimit-Remaining', String(Math.max(0, limitPerMin - bucket.count)));
  res.setHeader('X-RateLimit-Reset', String(bucket.resetAt));
  if (bucket.count > limitPerMin) {
    return res.status(429).json({ error: 'rate-limit-exceeded' });
  }
  return next();
};

const adminIpAllowlist = (req, res, next) => {
  if (!ADMIN_IP_ALLOWLIST.length) {
    return next();
  }
  const ip = getIp(req);
  if (!ADMIN_IP_ALLOWLIST.includes(ip)) {
    return res.status(403).send('Forbidden');
  }
  return next();
};

const requireAdminKey = (req, res, next) => {
  const key = req.header('X-Admin-Api-Key');
  if (!key || key !== ADMIN_API_KEY) {
    return res.status(401).json({ error: 'invalid-admin-key' });
  }
  return next();
};

const requireBasicAuth = (req, res, next) => {
  const credentials = basicAuth(req);
  if (!credentials || credentials.name !== ADMIN_USERNAME || credentials.pass !== ADMIN_PASSWORD) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin"');
    return res.status(401).send('Authentication required');
  }
  return next();
};

const getUserById = (userId) =>
  db.prepare('SELECT user_id, token_version FROM users WHERE user_id = ?').get(userId);

const ensureUser = (userId, displayName = null) => {
  const existing = getUserById(userId);
  if (existing) {
    return existing;
  }
  const createdAt = nowIso();
  db.prepare(
    'INSERT INTO users (user_id, display_name, token_version, created_at) VALUES (?, ?, 0, ?)'
  ).run(userId, displayName, createdAt);
  return getUserById(userId);
};

const issueToken = (userId) => {
  const user = ensureUser(userId);
  const jti = nanoid();
  const payload = {
    sub: user.user_id,
    tv: user.token_version,
    jti,
  };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_TTL_SECONDS });
  return { token, jti, token_version: user.token_version };
};

const revokeToken = (jti, expiresAt) => {
  db.prepare(
    'INSERT OR REPLACE INTO revoked_tokens (jti, revoked_at, expires_at) VALUES (?, ?, ?)'
  ).run(jti, nowIso(), expiresAt);
};

const isRevoked = (jti) => {
  if (!jti) return false;
  const record = db.prepare('SELECT jti FROM revoked_tokens WHERE jti = ?').get(jti);
  return Boolean(record);
};

const authenticate = (req, res, next) => {
  const authHeader = req.header('Authorization') || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: 'missing-token' });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (isRevoked(payload.jti)) {
      return res.status(401).json({ error: 'token-revoked' });
    }
    const user = getUserById(payload.sub);
    if (!user) {
      return res.status(401).json({ error: 'unknown-user' });
    }
    if (payload.tv !== user.token_version) {
      return res.status(401).json({ error: 'token-version-mismatch' });
    }
    req.authUserId = payload.sub;
    req.authTokenJti = payload.jti;
    return next();
  } catch (error) {
    return res.status(401).json({ error: 'invalid-token' });
  }
};

const auditLog = (req, res, next) => {
  res.on('finish', () => {
    const action = `${req.method} ${req.originalUrl}`;
    const entry = {
      id: nanoid(),
      user_id: req.authUserId || null,
      action,
      ip: getIp(req),
      status: res.statusCode,
      created_at: nowIso(),
    };
    db.prepare(
      'INSERT INTO audit_log (id, user_id, action, ip, status, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(entry.id, entry.user_id, entry.action, entry.ip, entry.status, entry.created_at);
  });
  return next();
};

app.use(auditLog);

const adminRateLimit = rateLimit({
  limitPerMin: ADMIN_RATE_LIMIT_PER_MIN,
  keyResolver: (req) => `admin:${getIp(req)}`,
});

const userRateLimit = rateLimit({
  limitPerMin: RATE_LIMIT_PER_MIN,
  keyResolver: (req) => `user:${req.authUserId || getIp(req)}`,
});

const parseConflictPolicy = (policy) => {
  if (policy === 'max_numeric') return 'max_numeric';
  if (policy === 'server_time') return 'server_time';
  return 'last_write_wins';
};

const shouldApplyUpdate = ({ existing, incoming, policy }) => {
  if (!existing) return true;
  if (policy === 'server_time') return true;
  if (policy === 'max_numeric') {
    const existingValue = Number(existing.value);
    const incomingValue = Number(incoming.value);
    if (Number.isNaN(existingValue) || Number.isNaN(incomingValue)) {
      return incoming.updated_at >= existing.updated_at;
    }
    return incomingValue > existingValue;
  }
  return incoming.updated_at >= existing.updated_at;
};

const cleanupExpiredData = () => {
  const now = nowIso();
  db.prepare('DELETE FROM user_data WHERE expires_at IS NOT NULL AND expires_at <= ?').run(now);
  const auditCutoff = new Date(Date.now() - AUDIT_LOG_TTL_DAYS * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('DELETE FROM audit_log WHERE created_at <= ?').run(auditCutoff);
  db.prepare('DELETE FROM revoked_tokens WHERE expires_at <= ?').run(now);
};

setInterval(cleanupExpiredData, CLEANUP_INTERVAL_MS).unref();

const broadcastMap = new Map();
const broadcast = (userId, payload) => {
  const connections = broadcastMap.get(userId);
  if (!connections) return;
  const message = JSON.stringify(payload);
  connections.forEach((socket) => {
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(message);
    }
  });
};

app.post('/v1/admin/users', adminRateLimit, requireAdminKey, (req, res) => {
  const { user_id: userId, display_name: displayName } = req.body || {};
  if (!userId) {
    return res.status(400).json({ error: 'user_id-required' });
  }
  ensureUser(userId, displayName || null);
  const token = issueToken(userId);
  return res.status(201).json({ user_id: userId, display_name: displayName || null, ...token });
});

app.post('/v1/admin/users/:userId/rotate', adminRateLimit, requireAdminKey, (req, res) => {
  const userId = req.params.userId;
  const user = getUserById(userId);
  if (!user) {
    return res.status(404).json({ error: 'user-not-found' });
  }
  db.prepare('UPDATE users SET token_version = token_version + 1 WHERE user_id = ?').run(userId);
  const token = issueToken(userId);
  return res.status(200).json({ user_id: userId, ...token });
});

app.post('/v1/admin/tokens/revoke', adminRateLimit, requireAdminKey, (req, res) => {
  const { jti, exp } = req.body || {};
  if (!jti || !exp) {
    return res.status(400).json({ error: 'jti-and-exp-required' });
  }
  revokeToken(jti, new Date(exp * 1000).toISOString());
  return res.status(200).json({ status: 'revoked' });
});

app.post('/v1/devices/register', authenticate, userRateLimit, (req, res) => {
  const { user_id: userId, device_id: deviceId, name } = req.body || {};
  if (!userId || !deviceId) {
    return res.status(400).json({ error: 'user_id-and-device_id-required' });
  }
  if (userId !== req.authUserId) {
    return res.status(403).json({ error: 'user-mismatch' });
  }
  ensureUser(userId);
  const now = nowIso();
  db.prepare(
    `INSERT INTO devices (user_id, device_id, name, last_seen_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(user_id, device_id)
     DO UPDATE SET name = excluded.name, last_seen_at = excluded.last_seen_at, updated_at = excluded.updated_at`
  ).run(userId, deviceId, name || null, now, now, now);
  const data = { user_id: userId, device_id: deviceId, name: name || null, updated_at: now };
  broadcast(userId, { type: 'device.registered', data });
  return res.status(200).json(data);
});

const upsertData = ({ userId, collection, key, value, updatedAt, ttlSeconds, policy }) => {
  const normalizedPolicy = parseConflictPolicy(policy);
  const existing = db
    .prepare('SELECT value, updated_at FROM user_data WHERE user_id = ? AND collection = ? AND key = ?')
    .get(userId, collection, key);
  const incoming = {
    value,
    updated_at: normalizedPolicy === 'server_time' ? nowIso() : updatedAt || nowIso(),
  };
  if (!shouldApplyUpdate({ existing, incoming, policy: normalizedPolicy })) {
    return { applied: false, existing };
  }
  const expiresAt = ttlSeconds ? new Date(Date.now() + ttlSeconds * 1000).toISOString() : null;
  db.prepare(
    `INSERT INTO user_data (user_id, collection, key, value, updated_at, deleted_at, expires_at, version)
     VALUES (?, ?, ?, ?, ?, NULL, ?, 1)
     ON CONFLICT(user_id, collection, key)
     DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, deleted_at = NULL,
       expires_at = excluded.expires_at, version = user_data.version + 1`
  ).run(userId, collection, key, JSON.stringify(value), incoming.updated_at, expiresAt);
  return { applied: true, updated_at: incoming.updated_at, expires_at: expiresAt };
};

app.post('/v1/data', authenticate, userRateLimit, (req, res) => {
  const { user_id: userId, collection, key, value, updated_at: updatedAt, ttl_seconds: ttlSeconds } =
    req.body || {};
  const conflictPolicy = req.header('X-Conflict-Policy') || 'last_write_wins';
  if (!userId || !collection || !key) {
    return res.status(400).json({ error: 'user_id-collection-key-required' });
  }
  if (userId !== req.authUserId) {
    return res.status(403).json({ error: 'user-mismatch' });
  }
  ensureUser(userId);
  const result = upsertData({
    userId,
    collection,
    key,
    value,
    updatedAt,
    ttlSeconds,
    policy: conflictPolicy,
  });
  if (!result.applied) {
    return res.status(200).json({ applied: false, reason: 'conflict', existing: result.existing });
  }
  const payload = {
    user_id: userId,
    collection,
    key,
    value,
    updated_at: result.updated_at,
    expires_at: result.expires_at,
  };
  broadcast(userId, { type: 'data.updated', data: payload });
  return res.status(200).json({ applied: true, data: payload });
});

app.post('/v1/data/bulk', authenticate, userRateLimit, (req, res) => {
  const { user_id: userId, items } = req.body || {};
  if (!userId || !Array.isArray(items)) {
    return res.status(400).json({ error: 'user_id-and-items-required' });
  }
  if (userId !== req.authUserId) {
    return res.status(403).json({ error: 'user-mismatch' });
  }
  ensureUser(userId);
  const results = items.map((item) => {
    const result = upsertData({
      userId,
      collection: item.collection,
      key: item.key,
      value: item.value,
      updatedAt: item.updated_at,
      ttlSeconds: item.ttl_seconds,
      policy: item.conflict_policy || 'last_write_wins',
    });
    if (result.applied) {
      broadcast(userId, {
        type: 'data.updated',
        data: {
          user_id: userId,
          collection: item.collection,
          key: item.key,
          value: item.value,
          updated_at: result.updated_at,
          expires_at: result.expires_at,
        },
      });
    }
    return { key: item.key, collection: item.collection, ...result };
  });
  return res.status(200).json({ results });
});

app.get('/v1/data/:userId/:collection', authenticate, userRateLimit, (req, res) => {
  const { userId, collection } = req.params;
  if (userId !== req.authUserId) {
    return res.status(403).json({ error: 'user-mismatch' });
  }
  const includeDeleted = req.query.include_deleted === 'true';
  const updatedSince = req.query.updated_since;
  const limit = Math.min(Number(req.query.limit || 100), 500);
  const cursor = req.query.cursor ? JSON.parse(Buffer.from(req.query.cursor, 'base64').toString()) : null;
  const clauses = ['user_id = ?', 'collection = ?'];
  const values = [userId, collection];
  if (!includeDeleted) {
    clauses.push('deleted_at IS NULL');
  }
  clauses.push('(expires_at IS NULL OR expires_at > ?)');
  values.push(nowIso());
  if (updatedSince) {
    clauses.push('updated_at > ?');
    values.push(updatedSince);
  }
  if (cursor?.updated_at && cursor?.key) {
    clauses.push('(updated_at > ? OR (updated_at = ? AND key > ?))');
    values.push(cursor.updated_at, cursor.updated_at, cursor.key);
  }
  const rows = db
    .prepare(
      `SELECT user_id, collection, key, value, updated_at, deleted_at, expires_at, version
       FROM user_data WHERE ${clauses.join(' AND ')}
       ORDER BY updated_at ASC, key ASC
       LIMIT ?`
    )
    .all(...values, limit);
  const nextCursor =
    rows.length === limit
      ? Buffer.from(JSON.stringify({ updated_at: rows[rows.length - 1].updated_at, key: rows[rows.length - 1].key }))
          .toString('base64')
      : null;
  const data = rows.map((row) => ({
    ...row,
    value: JSON.parse(row.value),
  }));
  return res.status(200).json({ data, next_cursor: nextCursor });
});

app.delete('/v1/data/:userId/:collection/:key', authenticate, userRateLimit, (req, res) => {
  const { userId, collection, key } = req.params;
  if (userId !== req.authUserId) {
    return res.status(403).json({ error: 'user-mismatch' });
  }
  const now = nowIso();
  db.prepare(
    `UPDATE user_data SET deleted_at = ?, updated_at = ?
     WHERE user_id = ? AND collection = ? AND key = ?`
  ).run(now, now, userId, collection, key);
  const payload = { user_id: userId, collection, key, deleted_at: now };
  broadcast(userId, { type: 'data.deleted', data: payload });
  return res.status(200).json({ status: 'deleted', ...payload });
});

app.get('/health', (req, res) => {
  const wsConnections = Array.from(broadcastMap.values()).reduce((sum, set) => sum + set.size, 0);
  const dbSize = fs.existsSync(DB_PATH) ? fs.statSync(DB_PATH).size : 0;
  return res.status(200).json({
    status: 'ok',
    uptime_seconds: process.uptime(),
    ws_connections: wsConnections,
    db_bytes: dbSize,
    time: nowIso(),
  });
});

app.get('/admin', adminRateLimit, adminIpAllowlist, requireBasicAuth, (req, res) => {
  const templatePath = path.join(__dirname, 'templates', 'admin.html');
  const html = fs.readFileSync(templatePath, 'utf-8');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.send(html);
});

app.get('/admin/data', adminRateLimit, adminIpAllowlist, requireBasicAuth, (req, res) => {
  const usersCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  const deviceCount = db.prepare('SELECT COUNT(*) as count FROM devices').get().count;
  const dataCount = db.prepare('SELECT COUNT(*) as count FROM user_data').get().count;
  const recentData = db
    .prepare(
      `SELECT user_id, collection, key, updated_at, deleted_at, expires_at
       FROM user_data ORDER BY updated_at DESC LIMIT 20`
    )
    .all();
  const recentAudit = db
    .prepare('SELECT user_id, action, ip, status, created_at FROM audit_log ORDER BY created_at DESC LIMIT 20')
    .all();
  return res.status(200).json({ usersCount, deviceCount, dataCount, recentData, recentAudit });
});

app.get('/admin/export/users.json', adminRateLimit, adminIpAllowlist, requireBasicAuth, (req, res) => {
  const users = db.prepare('SELECT user_id, display_name, token_version, created_at FROM users').all();
  return res.status(200).json({ users });
});

app.get('/admin/export/data.json', adminRateLimit, adminIpAllowlist, requireBasicAuth, (req, res) => {
  const data = db
    .prepare('SELECT user_id, collection, key, value, updated_at, deleted_at, expires_at FROM user_data')
    .all()
    .map((row) => ({ ...row, value: JSON.parse(row.value) }));
  return res.status(200).json({ data });
});

app.get('/admin/export/audit.csv', adminRateLimit, adminIpAllowlist, requireBasicAuth, (req, res) => {
  const rows = db.prepare('SELECT user_id, action, ip, status, created_at FROM audit_log').all();
  const header = 'user_id,action,ip,status,created_at';
  const lines = rows.map((row) =>
    [row.user_id || '', row.action, row.ip, row.status, row.created_at]
      .map((value) => `"${String(value).replace(/"/g, '""')}"`)
      .join(',')
  );
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="audit.csv"');
  return res.send([header, ...lines].join('\n'));
});

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

wss.on('connection', (socket, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const token = url.searchParams.get('token');
  if (!token) {
    socket.close(1008, 'missing token');
    return;
  }
  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (error) {
    socket.close(1008, 'invalid token');
    return;
  }
  if (isRevoked(payload.jti)) {
    socket.close(1008, 'revoked token');
    return;
  }
  const user = getUserById(payload.sub);
  if (!user || payload.tv !== user.token_version) {
    socket.close(1008, 'invalid user');
    return;
  }
  const userId = payload.sub;
  const connections = broadcastMap.get(userId) || new Set();
  connections.add(socket);
  broadcastMap.set(userId, connections);
  socket.on('close', () => {
    connections.delete(socket);
    if (!connections.size) {
      broadcastMap.delete(userId);
    }
  });
  socket.send(JSON.stringify({ type: 'connected', data: { user_id: userId } }));
});

server.listen(PORT, () => {
  console.log(`Realtime DB server listening on port ${PORT}`);
});
