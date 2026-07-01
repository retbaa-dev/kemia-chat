// =============================================================
// KEMIA RAILWAY — Chat Interface Server
// Node.js + Express + WebSocket — v2.0
// =============================================================
const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const crypto = require('crypto');

// --- Security: charge .env si présent (docker/machine) ---
try {
  if (fs.existsSync('/root/kemia-chat/.env')) {
    const envFile = fs.readFileSync('/root/kemia-chat/.env', 'utf-8');
    envFile.split('\n').forEach(line => {
      const [k, ...v] = line.split('=');
      if (k && v.length && !process.env[k.trim()]) {
        process.env[k.trim()] = v.join('=').trim();
      }
    });
  }
} catch (e) { /* silent */ }

// --- Configuration ---
const PORT = process.env.PORT || 8888;
const KEMIA_STATE_URL = process.env.KEMIA_STATE_URL || 'https://nmmxamnm.gensparkclaw.com/kemia-state';
const LOG_DIR = path.join(__dirname, 'logs');
const SESSION_TIMEOUT_MS = 24 * 60 * 60 * 1000; // 24h
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX = 30; // max requests per window

// --- LLM Keys (env only) ---
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY || '';
const DEEPSEEK_KEY = process.env.DEEPSEEK_API_KEY || '';
const LLM_PROVIDER = ANTHROPIC_KEY ? 'Anthropic Claude' : (DEEPSEEK_KEY ? 'DeepSeek' : 'None');

if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const sessions = new Map();
const rateLimits = new Map(); // IP → {count, windowStart}

function log(level, msg) {
  const line = `[${new Date().toISOString()}] [${level}] ${msg}`;
  console.log(line);
  try { fs.appendFileSync(path.join(LOG_DIR, 'chat.log'), line + '\n'); } catch (e) { /* silent */ }
}

function cleanExpiredSessions() {
  const now = Date.now();
  for (const [token, session] of sessions) {
    if (now - session.createdAt > SESSION_TIMEOUT_MS) {
      sessions.delete(token);
      log('SECURITY', `Session expirée purgée: ${token.substring(0,8)}...`);
    }
  }
}
setInterval(cleanExpiredSessions, 60 * 60 * 1000); // toutes les heures

function rateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  if (!rateLimits.has(ip) || now - rateLimits.get(ip).windowStart > RATE_LIMIT_WINDOW) {
    rateLimits.set(ip, { count: 0, windowStart: now });
  }
  const rl = rateLimits.get(ip);
  rl.count++;
  if (rl.count > RATE_LIMIT_MAX) {
    log('SECURITY', `Rate limit exceeded: ${ip}`);
    return res.status(429).json({ error: 'Trop de requêtes. Réessayez dans une minute.' });
  }
  next();
}

function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentification requise' });
  }
  const token = authHeader.slice(7);
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: 'Session invalide ou expirée' });
  }
  const session = sessions.get(token);
  if (Date.now() - session.createdAt > SESSION_TIMEOUT_MS) {
    sessions.delete(token);
    return res.status(401).json({ error: 'Session expirée' });
  }
  req.session = session;
  next();
}

// --- Security headers ---
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', 
    "default-src 'self'; " +
    "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "connect-src 'self' https://nmmxamnm.gensparkclaw.com https://api.anthropic.com https://api.deepseek.com; " +
    "script-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:;"
  );
  next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '100kb' }));

// --- Login par code PIN (4 chiffres) ---
const PIN_HASH = crypto.createHash('sha256').update(process.env.PIN_CODE || '0000').digest('hex');

app.post('/api/login', rateLimit, (req, res) => {
  const { pin } = req.body;
  if (!pin || typeof pin !== 'string') {
    return res.status(400).json({ error: 'Code PIN requis' });
  }
  const inputHash = crypto.createHash('sha256').update(pin).digest('hex');
  if (inputHash !== PIN_HASH) {
    log('AUTH', `PIN incorrect depuis ${req.ip}`);
    return res.status(401).json({ error: 'Code incorrect' });
  }
  const token = uuidv4();
  sessions.set(token, { id: token, authenticated: true, createdAt: Date.now() });
  log('AUTH', `Login PIN: ${token.substring(0,8)}...`);
  res.json({ token });
});

app.get('/api/state', authenticate, async (req, res) => {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const resp = await fetch(KEMIA_STATE_URL, { signal: controller.signal });
    clearTimeout(timeoutId);
    const text = await resp.text();
    const match = text.match(/## ⚡ État technique actuel[\s\S]*?(?=##|$)/);
    res.json({ state: match ? match[0].trim() : 'No state available' });
  } catch (err) {
    res.json({ state: 'Indisponible: ' + err.message });
  }
});

app.post('/api/exec', authenticate, (req, res) => {
  const { cmd } = req.body;
  if (!cmd || typeof cmd !== 'string') return res.status(400).json({ error: 'cmd requis' });
  
  // Securité : blacklist des commandes dangereuses
  const dangerous = ['rm -rf', 'mkfs', 'dd if=', ':(){ :|:& };:', '> /dev/', '> /dev/sda', 'chmod 777 /', 'wget http', 'curl http'];
  const cmdLower = cmd.toLowerCase();
  for (const d of dangerous) {
    if (cmdLower.includes(d)) {
      log('SECURITY', `Commande dangereuse bloquée depuis ${req.ip}: ${cmd.substring(0,80)}`);
      return res.status(403).json({ error: 'Commande non autorisée' });
    }
  }
  
  log('EXEC', cmd.substring(0, 200));
  exec(cmd, { timeout: 30000, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
    const output = stdout || '';
    const error = stderr || '';
    log('EXEC_RESULT', `Exit: ${err ? err.code || 'error' : 0}`);
    res.json({ ok: !err, code: err ? err.code : 0, output: output.substring(0, 50000), error: error.substring(0, 10000) });
  });
});

app.get('/api/logs', authenticate, (req, res) => {
  const lines = Math.min(parseInt(req.query.lines) || 50, 500);
  try {
    const logFile = path.join(LOG_DIR, 'chat.log');
    if (!fs.existsSync(logFile)) return res.json({ logs: [] });
    const content = fs.readFileSync(logFile, 'utf-8');
    const allLines = content.split('\n').filter(Boolean);
    res.json({ logs: allLines.slice(-lines) });
  } catch (err) {
    res.json({ logs: [], error: err.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    uptime: process.uptime(),
    sessions: sessions.size,
    llm: LLM_PROVIDER
  });
});

// --- Documentation KB ---
const DOCS_BASE = process.env.DOCS_PATH || "/root/kemia-docs";
app.get('/api/docs', authenticate, (req, res) => {
  const docs = [];
  try {
    const walk = (dir, prefix) => {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const e of entries) {
        if (e.name.startsWith('.')) continue;
        if (e.name === 'node_modules' || e.name === 'logs' || e.name === '.git') continue;
        const full = path.join(dir, e.name);
        const rel = path.join(prefix, e.name);
        if (e.isDirectory()) {
          docs.push({ type: 'dir', name: e.name, path: rel });
          walk(full, rel);
        } else if (e.name.endsWith('.md')) {
          const content = fs.readFileSync(full, 'utf-8');
          docs.push({ type: 'file', name: e.name, path: rel, size: content.length, content });
        }
      }
    };
    if (fs.existsSync(DOCS_BASE)) walk(DOCS_BASE, '');
    res.json({ docs, count: docs.filter(d => d.type === 'file').length });
  } catch (err) {
    res.json({ docs: [], error: err.message });
  }
});

// --- LLM Call (rate limited côté serveur) ---
async function callLLM(messages) {
  if (ANTHROPIC_KEY) {
    try {
      const resp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': ANTHROPIC_KEY,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model: 'claude-sonnet-4-20250514',
          max_tokens: 2000,
          system: messages[0].content,
          messages: messages.slice(1).map(m => ({ role: m.role, content: m.content }))
        })
      });
      if (!resp.ok) {
        const errData = await resp.text();
        throw new Error(`Anthropic ${resp.status}: ${errData.substring(0, 200)}`);
      }
      const json = await resp.json();
      if (json.content && json.content[0]) return json.content[0].text;
      throw new Error('Anthropic: réponse vide');
    } catch (err) {
      log('ERR', `Anthropic failed: ${err.message}`);
      if (!DEEPSEEK_KEY) throw err;
    }
  }

  if (DEEPSEEK_KEY) {
    const resp = await fetch('https://api.deepseek.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${DEEPSEEK_KEY}`
      },
      body: JSON.stringify({
        model: 'deepseek-chat',
        messages: messages.map(m => ({ role: m.role, content: m.content })),
        max_tokens: 2000
      })
    });
    if (!resp.ok) {
      const errData = await resp.text();
      throw new Error(`DeepSeek ${resp.status}: ${errData.substring(0, 200)}`);
    }
    const json = await resp.json();
    if (json.choices && json.choices[0]) return json.choices[0].message.content;
    throw new Error('DeepSeek: réponse vide');
  }

  throw new Error('Aucun LLM configuré');
}

// --- WebSocket avec gestion robuste ---
let userMessageCount = 0;

wss.on('connection', (ws, req) => {
  let authenticated = false;
  let userSessionId = null;
  const clientIp = req.socket?.remoteAddress || 'unknown';
  log('WS', `New connection from ${clientIp}`);

  ws.on('message', async (data) => {
    try {
      const msg = JSON.parse(data.toString());

      if (msg.type === 'auth') {
        if (msg.token && sessions.has(msg.token)) {
          authenticated = true;
          userSessionId = msg.token;
          ws.send(JSON.stringify({ type: 'auth_ok', message: 'Authentifié' }));
          log('WS', `Session authenticated: ${msg.token.substring(0,8)}...`);
        } else {
          ws.send(JSON.stringify({ type: 'auth_error', message: 'Token invalide' }));
        }
        return;
      }

      if (!authenticated) {
        ws.send(JSON.stringify({ type: 'error', message: 'Authentification requise' }));
        return;
      }

      if (msg.type === 'message') {
        const userMsg = msg.text?.trim();
        if (!userMsg) return;

        // Rate limit par session
        const session = sessions.get(userSessionId);
        if (session) {
          session.msgCount = (session.msgCount || 0) + 1;
          if (session.msgCount > RATE_LIMIT_MAX && Date.now() - session.createdAt < RATE_LIMIT_WINDOW) {
            ws.send(JSON.stringify({ type: 'error', message: 'Trop de messages. Patientez un instant.' }));
            return;
          }
          // Reset counter each window
          if (Date.now() - session.createdAt > RATE_LIMIT_WINDOW) {
            session.msgCount = 0;
          }
        }

        userMessageCount++;
        log('CHAT', `User: ${userMsg.substring(0, 100)}`);
        ws.send(JSON.stringify({ type: 'typing', status: true }));

        const systemMsg = {
          role: 'system',
          content: [
            'Tu es Kemia Railway, Chief of Staff IA de Retbaa (Cultural Luxury).',
            'Réponds en français. Style : direct, sobre, exécutable.',
            'Toujours terminer par une prochaine action concrète si pertinent.',
            'Contexte : tu es connectée aux systèmes Retbaa OS (Supabase, Vercel, GitHub).',
            'Règle absolue : ne jamais écrire "afro-luxe" ou "luxe africain" — toujours "Cultural Luxury".'
          ].join(' ')
        };
        const userMsgObj = { role: 'user', content: userMsg };

        let reply = '';
        try {
          reply = await callLLM([systemMsg, userMsgObj]);
        } catch (err) {
          log('ERR', `LLM call failed: ${err.message}`);
          reply = `⚠️ Désolée, erreur de connexion au LLM. ${err.message}`;
        }

        ws.send(JSON.stringify({ type: 'typing', status: false }));
        ws.send(JSON.stringify({ type: 'message', text: reply, timestamp: new Date().toISOString() }));
        log('CHAT', `Kemia replied: ${reply.substring(0, 100)}...`);
      }
    } catch (err) {
      log('WS_ERR', err.message);
      try { ws.send(JSON.stringify({ type: 'error', message: 'Erreur interne' })); } catch (e) { /* offline */ }
    }
  });

  ws.on('close', () => {
    log('WS', `Connection closed: ${clientIp}`);
  });

  ws.on('error', (err) => {
    log('WS_ERR', `Socket error: ${err.message}`);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  log('INFO', `KEMIA RAILWAY CHAT v2.0 — https://kemia.retbaa.com`);
  log('INFO', `LLM: ${LLM_PROVIDER} configured`);
});
