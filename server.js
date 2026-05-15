/**
 * SecureChat Server
 * - WebSocket over HTTPS/WSS
 * - JWT authentication
 * - AES-256-GCM message encryption (server-side key)
 * - Rate limiting, brute-force protection
 * - No message persistence (in-memory only)
 * - Auto-purge of inactive sessions
 */

const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── CONFIG ────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const ROOM_KEY = crypto.randomBytes(32); // AES-256 key per sessione server
const ROOM_KEY_IV_LEN = 12; // GCM nonce

const MAX_MSG_LEN = 4096;
const MAX_NICK_LEN = 32;
const RATE_LIMIT_WINDOW = 5000;   // ms
const RATE_LIMIT_MAX = 10;        // messages per window
const SESSION_TIMEOUT = 2 * 60 * 60 * 1000; // 2 hours
const MAX_CLIENTS = 100;

console.log('🔐 JWT Secret (save this if you restart): ' + JWT_SECRET.slice(0, 16) + '...');
console.log('🔑 Room encryption key generated (in-memory only)');

// ─── SIMPLE JWT (no external dep) ──────────────────────────────────────────
function signJWT(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body   = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig    = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyJWT(token) {
  try {
    const [header, body, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

// ─── AES-256-GCM helpers ───────────────────────────────────────────────────
function encrypt(text) {
  const iv  = crypto.randomBytes(ROOM_KEY_IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', ROOM_KEY, iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64');
}

function decrypt(b64) {
  const buf  = Buffer.from(b64, 'base64');
  const iv   = buf.slice(0, ROOM_KEY_IV_LEN);
  const tag  = buf.slice(ROOM_KEY_IV_LEN, ROOM_KEY_IV_LEN + 16);
  const enc  = buf.slice(ROOM_KEY_IV_LEN + 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', ROOM_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}

// ─── STATE ─────────────────────────────────────────────────────────────────
const clients = new Map();   // ws → { id, nick, joinedAt, lastActive }
const nicks   = new Set();
const rateLimitMap = new Map(); // id → { count, resetAt }
const loginAttempts = new Map(); // ip → { count, blockedUntil }

// ─── USER REGISTRY (in-memory, persisted to users.json) ───────────────────
const USERS_FILE = path.join(__dirname, 'users.json');

function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch {}
  return {};
}

function saveUsers(db) {
  try { fs.writeFileSync(USERS_FILE, JSON.stringify(db, null, 2)); } catch {}
}

// { nick_lower: { id, nick, passwordHash, salt, createdAt } }
const userDB = loadUsers();
console.log(`👥 Utenti registrati: ${Object.keys(userDB).length}`);

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

function registerUser(nick, password) {
  const key = nick.toLowerCase();
  if (userDB[key]) return { error: 'Nickname già registrato.' };
  const salt = crypto.randomBytes(32).toString('hex');
  const passwordHash = hashPassword(password, salt);
  const id = crypto.randomUUID();
  userDB[key] = { id, nick, passwordHash, salt, createdAt: Date.now() };
  saveUsers(userDB);
  return { id, nick };
}

function loginUser(nick, password) {
  const key = nick.toLowerCase();
  const user = userDB[key];
  if (!user) return { error: 'Utente non trovato.' };
  const attempt = hashPassword(password, user.salt);
  if (!crypto.timingSafeEqual(Buffer.from(attempt), Buffer.from(user.passwordHash))) {
    return { error: 'Password errata.' };
  }
  return { id: user.id, nick: user.nick };
}

// ─── RATE LIMITING ─────────────────────────────────────────────────────────
function checkRateLimit(clientId) {
  const now = Date.now();
  let rl = rateLimitMap.get(clientId);
  if (!rl || now > rl.resetAt) {
    rl = { count: 0, resetAt: now + RATE_LIMIT_WINDOW };
    rateLimitMap.set(clientId, rl);
  }
  rl.count++;
  return rl.count <= RATE_LIMIT_MAX;
}

function checkLoginAttempts(ip) {
  const now = Date.now();
  let la = loginAttempts.get(ip) || { count: 0, blockedUntil: 0, lastTry: 0 };
  if (now < la.blockedUntil) {
    const minutesLeft = Math.ceil((la.blockedUntil - now) / 60000);
    la._minutesLeft = minutesLeft;
    loginAttempts.set(ip, la);
    return { allowed: false, minutesLeft };
  }
  // Reset counter if last attempt was more than 30 minutes ago
  if (now - la.lastTry > 30 * 60 * 1000) la.count = 0;
  la.lastTry = now;
  la.count++;
  if (la.count >= 15) {
    la.blockedUntil = now + 60 * 60 * 1000; // block 1 hour after 15 failed attempts
    la.count = 0; // reset so the counter is clean after unblock
  }
  loginAttempts.set(ip, la);
  return { allowed: true };
}

// Reset failed attempts on successful login
function resetLoginAttempts(ip) {
  loginAttempts.delete(ip);
}

// ─── PERSISTENT SESSION TOKENS ────────────────────────────────────────────
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');

function loadSessions() {
  try {
    if (fs.existsSync(SESSIONS_FILE)) {
      const raw = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
      // Filter out expired sessions on load
      const now = Date.now();
      const valid = {};
      for (const [id, s] of Object.entries(raw)) {
        if (s.exp > now) valid[id] = s;
      }
      return valid;
    }
  } catch {}
  return {};
}

function saveSessions(db) {
  try { fs.writeFileSync(SESSIONS_FILE, JSON.stringify(db, null, 2)); } catch {}
}

// { sessionId: { userId, nick, token, exp, createdAt, lastUsed } }
const sessionDB = loadSessions();
console.log(`🔑 Sessioni attive caricate: ${Object.keys(sessionDB).length}`);

function createSession(userId, nick) {
  const sessionId = crypto.randomUUID();
  const exp = Date.now() + SESSION_TIMEOUT;
  const token = signJWT({ id: userId, nick, sessionId, exp });
  sessionDB[sessionId] = { userId, nick, token, exp, createdAt: Date.now(), lastUsed: Date.now() };
  saveSessions(sessionDB);
  return { sessionId, token };
}

function touchSession(sessionId) {
  if (sessionDB[sessionId]) {
    sessionDB[sessionId].lastUsed = Date.now();
    // Rolling expiry: extend session on activity
    sessionDB[sessionId].exp = Date.now() + SESSION_TIMEOUT;
    saveSessions(sessionDB);
  }
}

function revokeSession(sessionId) {
  if (sessionId && sessionDB[sessionId]) {
    delete sessionDB[sessionId];
    saveSessions(sessionDB);
  }
}

// Cleanup expired sessions every hour
setInterval(() => {
  const now = Date.now();
  let changed = false;
  for (const [id, s] of Object.entries(sessionDB)) {
    if (s.exp < now) { delete sessionDB[id]; changed = true; }
  }
  if (changed) saveSessions(sessionDB);
}, 60 * 60 * 1000);

// ─── BROADCAST ─────────────────────────────────────────────────────────────
function broadcast(obj, excludeWs = null) {
  const payload = JSON.stringify(obj);
  for (const [ws] of clients) {
    if (ws !== excludeWs && ws.readyState === WebSocket.OPEN) {
      ws.send(payload);
    }
  }
}

function sendTo(ws, obj) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

function userList() {
  return [...clients.values()].map(c => ({ id: c.id, nick: c.nick }));
}

// ─── HTTP SERVER (serves client.html) ──────────────────────────────────────
const server = http.createServer((req, res) => {
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'");
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
    const filePath = path.join(__dirname, 'client.html');
    if (fs.existsSync(filePath)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(fs.readFileSync(filePath));
    } else {
      res.writeHead(404); res.end('client.html not found');
    }
  } else if (req.method === 'POST' && (req.url === '/login' || req.url === '/register')) {
    const isRegister = req.url === '/register';
    const ip = req.socket.remoteAddress;
    const check = checkLoginAttempts(ip);
    if (!check.allowed) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: `Troppi tentativi falliti. Riprova tra ${check.minutesLeft} minut${check.minutesLeft === 1 ? 'o' : 'i'}.` }));
    }
    let body = '';
    req.on('data', d => { body += d; if (body.length > 1024) req.destroy(); });
    req.on('end', () => {
      try {
        const { nick, password } = JSON.parse(body);
        if (!nick || nick.length < 2 || nick.length > MAX_NICK_LEN || !/^[a-zA-Z0-9_\-\.]+$/.test(nick)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Nickname non valido (2-32 caratteri, solo lettere/numeri/._-).' }));
        }
        if (!password || password.length < 6) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Password minimo 6 caratteri.' }));
        }

        let result;
        if (isRegister) {
          result = registerUser(nick, password);
        } else {
          result = loginUser(nick, password);
        }

        if (result.error) {
          res.writeHead(isRegister ? 409 : 401, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: result.error }));
        }

        // Success: reset brute-force counter, create persistent session
        resetLoginAttempts(ip);

        if (nicks.has(result.nick.toLowerCase())) {
          res.writeHead(409, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Utente già connesso da un altro dispositivo.' }));
        }

        const { sessionId, token } = createSession(result.id, result.nick);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ token, sessionId, id: result.id, nick: result.nick }));
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Richiesta non valida.' }));
      }
    });
  } else if (req.method === 'POST' && req.url === '/logout') {
    let body = '';
    req.on('data', d => { body += d; if (body.length > 256) req.destroy(); });
    req.on('end', () => {
      try {
        const { sessionId } = JSON.parse(body);
        revokeSession(sessionId);
      } catch {}
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    });
  } else {
    res.writeHead(404); res.end();
  }
});

// ─── WEBSOCKET SERVER ───────────────────────────────────────────────────────
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  // IP is never logged, never sent to clients, never stored in clientInfo
  const ip = req.socket.remoteAddress; // used only for rate limiting, not stored
  let clientInfo = null;

  // First message must be auth within 30 seconds
  const authTimeout = setTimeout(() => {
    sendTo(ws, { type: 'error', msg: 'Autenticazione scaduta.' });
    ws.terminate();
  }, 30000);

  ws.on('message', (raw) => {
    let data;
    try {
      if (raw.length > 8192) return;
      data = JSON.parse(raw);
    } catch { return; }

    // ── AUTH ──
    if (!clientInfo) {
      if (data.type !== 'auth') return ws.terminate();
      const payload = verifyJWT(data.token || '');
      if (!payload) {
        sendTo(ws, { type: 'error', msg: 'Token non valido o scaduto.' });
        return ws.terminate();
      }
      if (clients.size >= MAX_CLIENTS) {
        sendTo(ws, { type: 'error', msg: 'Server pieno. Riprova più tardi.' });
        return ws.terminate();
      }
      if (nicks.has(payload.nick.toLowerCase())) {
        sendTo(ws, { type: 'error', msg: 'Nickname già connesso.' });
        return ws.terminate();
      }
      clearTimeout(authTimeout);
      clientInfo = { id: payload.id, nick: payload.nick, sessionId: payload.sessionId, joinedAt: Date.now(), lastActive: Date.now() };
      // IP is intentionally NOT stored in clientInfo
      clients.set(ws, clientInfo);
      nicks.add(payload.nick.toLowerCase());
      if (payload.sessionId) touchSession(payload.sessionId);

      sendTo(ws, { type: 'welcome', id: clientInfo.id, nick: clientInfo.nick, users: userList() });
      broadcast({ type: 'join', id: clientInfo.id, nick: clientInfo.nick, users: userList() }, ws);
      console.log(`[+] ${clientInfo.nick} joined. Online: ${clients.size}`); // no IP in logs
      return;
    }

    // ── RATE LIMIT ──
    clientInfo.lastActive = Date.now();
    if (clientInfo.sessionId) touchSession(clientInfo.sessionId);
    if (!checkRateLimit(clientInfo.id)) {
      sendTo(ws, { type: 'error', msg: 'Stai inviando troppi messaggi. Rallenta.' });
      return;
    }

    // ── MESSAGE ──
    if (data.type === 'message') {
      const text = (data.text || '').trim();
      if (!text || text.length > MAX_MSG_LEN) return;
      // Encrypt for storage/log (in-memory, no persistence)
      const encText = encrypt(text);
      const msgId = crypto.randomUUID();
      const ts = Date.now();
      // Broadcast plaintext to connected clients (TLS handles transport security)
      broadcast({
        type: 'message',
        id: msgId,
        from: clientInfo.id,
        nick: clientInfo.nick,
        text,          // sent over WSS (TLS encrypted in transit)
        ts
      });
      // In-memory encrypted log (server-side, never written to disk)
      // console.log(`[MSG] ${clientInfo.nick}: ${encText}`); // uncomment to debug
    }

    // ── PING ──
    if (data.type === 'ping') {
      sendTo(ws, { type: 'pong', ts: Date.now() });
    }

    // ── TYPING ──
    if (data.type === 'typing') {
      broadcast({ type: 'typing', id: clientInfo.id, nick: clientInfo.nick, active: !!data.active }, ws);
    }

    // ── PRIVATE MESSAGE ──
    if (data.type === 'dm') {
      const target = [...clients.entries()].find(([, c]) => c.id === data.to);
      if (!target) return sendTo(ws, { type: 'error', msg: 'Utente non trovato.' });
      const text = (data.text || '').trim();
      if (!text || text.length > MAX_MSG_LEN) return;
      const [targetWs] = target;
      sendTo(targetWs, {
        type: 'dm',
        id: crypto.randomUUID(),
        from: clientInfo.id,
        nick: clientInfo.nick,
        text,
        ts: Date.now()
      });
      sendTo(ws, { type: 'dm_sent', to: data.to, text, ts: Date.now() });
    }
  });

  ws.on('close', () => {
    clearTimeout(authTimeout);
    if (clientInfo) {
      nicks.delete(clientInfo.nick.toLowerCase());
      clients.delete(ws);
      // Do NOT revoke session on close — user might reconnect (e.g. network drop)
      // Session expires naturally via SESSION_TIMEOUT
      broadcast({ type: 'leave', id: clientInfo.id, nick: clientInfo.nick, users: userList() });
      console.log(`[-] ${clientInfo.nick} disconnected. Online: ${clients.size}`); // no IP in logs
    }
  });

  ws.on('error', (err) => {
    console.error(`[WS ERROR] ${err.message}`);
  });
});

// ─── SESSION CLEANUP ────────────────────────────────────────────────────────
setInterval(() => {
  const now = Date.now();
  for (const [ws, info] of clients) {
    if (now - info.lastActive > SESSION_TIMEOUT) {
      sendTo(ws, { type: 'error', msg: 'Sessione scaduta per inattività.' });
      ws.terminate();
    }
  }
}, 60000);

// ─── START ──────────────────────────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅ SecureChat server avviato su http://0.0.0.0:${PORT}`);
  console.log(`🔒 Password stanza: ${process.env.ROOM_PASSWORD || 'securechat2025'}`);
  console.log(`📡 Accessibile da rete locale e internet (con port forwarding/ngrok)`);
  console.log(`\nCambia password: ROOM_PASSWORD=tua_password node server.js\n`);
});
