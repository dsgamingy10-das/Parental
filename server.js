/**
 * Parental Control Backend — SLIM (important features only)
 * Call, SMS, Location, App block (commands), Protection/security,
 * Web dashboard, Auth, Pair, Fast connect
 * Pure Node.js — no npm deps
 */
'use strict';
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT || 8080;
const ROOT = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(ROOT, 'db.json');
try { fs.mkdirSync(ROOT, { recursive: true }); } catch (e) {}

let MEM_DB = null;
let saveBusy = false;
let saveQueued = null;

function rid() { return crypto.randomBytes(8).toString('hex'); }
function token() { return crypto.randomBytes(24).toString('hex'); }
function hash(p) { return crypto.createHash('sha256').update(String(p) + 'pc-salt-v1').digest('hex'); }
function now() { return new Date().toISOString(); }
function nowMs() { return Date.now(); }

function ensureDefaults(db) {
  const defaults = {
    parents: [], devices: [], commands: [], calls: [], sms: [], locations: [],
    alerts: [], settings: {}, events: [], keystrokes: [], contacts: [], usage: []
  };
  if (!db || typeof db !== 'object') db = {};
  for (const k of Object.keys(defaults)) {
    if (db[k] == null) db[k] = defaults[k];
  }
  if (!Array.isArray(db.parents)) db.parents = [];
  if (!Array.isArray(db.devices)) db.devices = [];
  if (!Array.isArray(db.commands)) db.commands = [];
  if (!Array.isArray(db.calls)) db.calls = [];
  if (!Array.isArray(db.sms)) db.sms = [];
  if (!Array.isArray(db.locations)) db.locations = [];
  if (!Array.isArray(db.alerts)) db.alerts = [];
  if (!Array.isArray(db.events)) db.events = [];
  if (!Array.isArray(db.keystrokes)) db.keystrokes = [];
  if (!Array.isArray(db.contacts)) db.contacts = [];
  if (!Array.isArray(db.usage)) db.usage = [];
  if (!db.settings || typeof db.settings !== 'object') db.settings = {};
  return db;
}

function readJsonFile(f) {
  try {
    if (!fs.existsSync(f)) return null;
    return JSON.parse(fs.readFileSync(f, 'utf8'));
  } catch (e) {
    return null;
  }
}

function load() {
  if (MEM_DB) return MEM_DB;
  let db = readJsonFile(DB_FILE);
  if (db === null) {
    const bak = readJsonFile(DB_FILE + '.bak');
    if (bak) db = bak;
  }
  MEM_DB = ensureDefaults(db || {});
  return MEM_DB;
}

function _saveInner(db) {
  const next = ensureDefaults(db || MEM_DB || {});
  MEM_DB = next;
  try {
    const tmp = DB_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(next));
    try { if (fs.existsSync(DB_FILE)) fs.copyFileSync(DB_FILE, DB_FILE + '.bak'); } catch (e) {}
    fs.renameSync(tmp, DB_FILE);
  } catch (e) {
    console.error('save error', e.message);
  }
}

function save(db) {
  if (saveBusy) {
    saveQueued = db || MEM_DB;
    return;
  }
  saveBusy = true;
  try {
    _saveInner(db);
  } finally {
    saveBusy = false;
    if (saveQueued) {
      const q = saveQueued;
      saveQueued = null;
      try { save(q); } catch (e) {}
    }
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const max = 8 * 1024 * 1024;
    req.on('data', (c) => {
      size += c.length;
      if (size > max) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      const buf = Buffer.concat(chunks);
      const raw = buf.toString('utf8');
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (e) {
        resolve({ _raw: raw });
      }
    });
    req.on('error', reject);
  });
}

function send(res, code, obj) {
  const body = typeof obj === 'string' ? obj : JSON.stringify(obj == null ? {} : obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Session-Token, X-Child-Token',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

function sendHtml(res, code, html) {
  res.writeHead(code, {
    'Content-Type': 'text/html; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-store'
  });
  res.end(html);
}

function bearerToken(headers) {
  if (!headers) return '';
  const a = headers['authorization'] || headers['Authorization'] || '';
  if (typeof a === 'string' && a.toLowerCase().startsWith('bearer ')) return a.slice(7).trim();
  return '';
}

function parentOf(body, q, headers) {
  const t = (body && body.sessionToken) || q.sessionToken || (headers && (headers['x-session-token'] || headers['X-Session-Token'])) || bearerToken(headers);
  if (!t) return null;
  return load().parents.find(p => p.sessionToken === t) || null;
}

function childOf(body, q, headers) {
  let t = (body && body.childToken) || q.childToken || (headers && (headers['x-child-token'] || headers['X-Child-Token'])) || bearerToken(headers);
  t = t ? String(t).trim() : '';
  const did = String((body && (body.deviceId || body.childId)) || q.deviceId || q.childId || '').trim();
  const db = load();
  if (t) {
    const d = db.devices.find(x => x.childToken === t || x.token === t);
    if (d) return d;
  }
  if (did) {
    const d = db.devices.find(x => String(x.id) === did || String(x.deviceId) === did);
    if (d) return d;
  }
  return null;
}

function familyCode() {
  return String(Math.floor(10000000 + Math.random() * 90000000));
}

function qparse(u) {
  const out = {};
  try {
    for (const [k, v] of u.searchParams) out[k] = v;
  } catch (e) {}
  return out;
}

function markOnline(dev) {
  if (!dev) return;
  dev.lastSeen = now();
  dev.lastSeenMs = nowMs();
  dev.online = true;
}

/** Fast command reclaim — stuck CLAIMED back to PENDING quickly */
function reclaimCommands(db) {
  const t = nowMs();
  for (const c of db.commands) {
    if (!c || c.status !== 'CLAIMED') continue;
    const started = Number(c.claimedAt || c.startedAt || 0);
    const age = started ? (t - started) : 999999;
    const type = String(c.type || c.command || '');
    const fast = /place_call|send_sms|end_call|sync_call|sync_sms|block_app|unblock_app|hide_app|set_security|set_secret|pair/i.test(type);
    const limit = fast ? 20000 : 45000;
    if (age > limit) {
      c.status = 'PENDING';
      c.claimedAt = 0;
    }
  }
}

function addCommand(db, deviceId, type, payload) {
  const cmd = {
    id: rid(),
    deviceId: String(deviceId),
    type: String(type),
    command: String(type),
    payload: payload || {},
    status: 'PENDING',
    createdAt: nowMs(),
    claimedAt: 0
  };
  db.commands.push(cmd);
  // soft trim
  if (db.commands.length > 2000) {
    const pending = db.commands.filter(c => c.status === 'PENDING' || c.status === 'CLAIMED');
    const done = db.commands.filter(c => c.status !== 'PENDING' && c.status !== 'CLAIMED').slice(-500);
    db.commands = pending.concat(done);
  }
  return cmd;
}

function upsertCall(db, row) {
  if (!row) return;
  const deviceId = String(row.deviceId || '');
  const androidId = row.androidId != null ? String(row.androidId) : '';
  let found = null;
  if (androidId && androidId.indexOf('evt-') !== 0) {
    found = db.calls.find(c => String(c.deviceId) === deviceId && String(c.androidId || '') === androidId);
  }
  if (!found && row.number) {
    const n = String(row.number).replace(/\D/g, '').slice(-10);
    const dir = String(row.direction || row.type || '');
    const ts = Number(row.startedMs || row.date || row.ts || 0);
    found = db.calls.find(c => {
      if (String(c.deviceId) !== deviceId) return false;
      const cn = String(c.number || '').replace(/\D/g, '').slice(-10);
      if (cn !== n) return false;
      if (String(c.direction || c.type || '') !== dir) return false;
      const ct = Number(c.startedMs || c.date || c.ts || 0);
      return Math.abs(ct - ts) < 60000;
    });
  }
  if (found) {
    if (row.duration != null && Number(row.duration) >= Number(found.duration || 0)) found.duration = Number(row.duration);
    if (row.name) found.name = row.name;
    if (row.number) found.number = row.number;
    found.deletedBy = null;
    found.updatedAt = nowMs();
  } else {
    db.calls.push({
      id: rid(),
      deviceId,
      androidId: androidId || ('c-' + rid()),
      number: row.number || '',
      name: row.name || '',
      direction: row.direction || row.type || '',
      type: row.direction || row.type || '',
      duration: Number(row.duration || 0),
      startedMs: Number(row.startedMs || row.date || row.ts || nowMs()),
      date: Number(row.startedMs || row.date || row.ts || nowMs()),
      ts: Number(row.startedMs || row.date || row.ts || nowMs()),
      deletedBy: null,
      createdAt: nowMs()
    });
  }
  if (db.calls.length > 5000) db.calls = db.calls.slice(-4000);
}

function upsertSms(db, row) {
  if (!row) return;
  const deviceId = String(row.deviceId || '');
  const androidId = row.androidId != null ? String(row.androidId) : '';
  let found = null;
  if (androidId) {
    found = db.sms.find(s => String(s.deviceId) === deviceId && String(s.androidId || '') === androidId);
  }
  if (!found) {
    const n = String(row.number || row.address || '').replace(/\D/g, '').slice(-10);
    const body = String(row.body || row.message || '').slice(0, 500);
    const dir = String(row.direction || row.type || '');
    const ts = Number(row.date || row.ts || 0);
    found = db.sms.find(s => {
      if (String(s.deviceId) !== deviceId) return false;
      if (String(s.androidId || '') && androidId && String(s.androidId) !== androidId) return false;
      const sn = String(s.number || s.address || '').replace(/\D/g, '').slice(-10);
      if (sn !== n) return false;
      if (String(s.body || s.message || '').slice(0, 500) !== body) return false;
      if (String(s.direction || s.type || '') !== dir) return false;
      const st = Number(s.date || s.ts || 0);
      return Math.abs(st - ts) < 45000;
    });
  }
  if (found) {
    found.deletedBy = null;
    found.updatedAt = nowMs();
  } else {
    db.sms.push({
      id: rid(),
      deviceId,
      androidId: androidId || ('s-' + rid()),
      number: row.number || row.address || '',
      address: row.number || row.address || '',
      body: row.body || row.message || '',
      message: row.body || row.message || '',
      direction: row.direction || row.type || '',
      type: row.direction || row.type || '',
      date: Number(row.date || row.ts || nowMs()),
      ts: Number(row.date || row.ts || nowMs()),
      deletedBy: null,
      createdAt: nowMs()
    });
  }
  if (db.sms.length > 8000) db.sms = db.sms.slice(-6000);
}

const WEB_HTML = `<!DOCTYPE html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Parental Dashboard</title>
<style>
body{font-family:sans-serif;background:#0F1221;color:#fff;margin:0;padding:16px}
h1{font-size:20px}a{color:#4F7CFF} .card{background:#1A1F2E;padding:12px;border-radius:8px;margin:8px 0}
</style></head><body>
<h1>Parental Control — Web</h1>
<div class="card">Backend slim mode: Call, SMS, Location, App block, Protection, Pair.</div>
<div class="card">Use the <b>Parent App</b> for full control. API health: <a href="/health">/health</a></div>
</body></html>`;

async function handler(req, res) {
  try {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Session-Token, X-Child-Token',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
      });
      return res.end();
    }

    const u = new URL(req.url, 'http://localhost');
    let pathname = u.pathname || '/';
    if (pathname.length > 1 && pathname.endsWith('/')) pathname = pathname.slice(0, -1);
    const q = qparse(u);
    const method = req.method || 'GET';

    // timeouts
    req.setTimeout(120000);
    res.setTimeout(120000);

    if (pathname === '/health' || pathname === '/') {
      return send(res, 200, {
        ok: true,
        phase: 300,
        mode: 'slim',
        features: {
          auth: true, pair: true, commands: true,
          calls: true, sms: true, location: true,
          web: true, protection: true, appBlock: true
        }
      });
    }

    if (pathname === '/web' || pathname === '/dashboard') {
      return sendHtml(res, 200, WEB_HTML);
    }

    const body = (method === 'POST' || method === 'PUT') ? await readBody(req) : {};
    const db = load();

    // ---- AUTH ----
    if (pathname === '/auth/register' && method === 'POST') {
      const email = String(body.email || body.user || '').trim().toLowerCase();
      const pass = String(body.password || '');
      if (!email || pass.length < 6) return send(res, 400, { ok: false, error: 'email + password(6+) required' });
      if (db.parents.find(p => p.email === email)) return send(res, 400, { ok: false, error: 'email exists' });
      const p = {
        id: rid(),
        email,
        passwordHash: hash(pass),
        sessionToken: token(),
        familyCode: familyCode(),
        createdAt: now()
      };
      db.parents.push(p);
      save(db);
      return send(res, 200, { ok: true, sessionToken: p.sessionToken, familyCode: p.familyCode, parentId: p.id, email: p.email });
    }

    if (pathname === '/auth/login' && method === 'POST') {
      const email = String(body.email || body.user || '').trim().toLowerCase();
      const pass = String(body.password || '');
      const p = db.parents.find(x => x.email === email && x.passwordHash === hash(pass));
      if (!p) return send(res, 401, { ok: false, error: 'invalid login' });
      p.sessionToken = token();
      if (!p.familyCode) p.familyCode = familyCode();
      save(db);
      return send(res, 200, { ok: true, sessionToken: p.sessionToken, familyCode: p.familyCode, parentId: p.id, email: p.email });
    }

    if (pathname === '/auth/logout' && method === 'POST') {
      const p = parentOf(body, q, req.headers);
      if (p) { p.sessionToken = token(); save(db); }
      return send(res, 200, { ok: true });
    }

    if (pathname === '/auth/me' && method === 'GET') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      return send(res, 200, { ok: true, email: p.email, familyCode: p.familyCode, parentId: p.id });
    }

    // ---- PAIR / DEVICES ----
    if ((pathname === '/pair/claim' || pathname === '/device/claim' || pathname === '/pair') && method === 'POST') {
      const code = String(body.familyCode || body.code || body.pairCode || '').replace(/\D/g, '');
      const name = String(body.name || body.childName || 'Child').slice(0, 40);
      if (code.length < 6) return send(res, 400, { ok: false, paired: false, error: 'invalid code' });
      const parent = db.parents.find(p => String(p.familyCode) === code);
      if (!parent) return send(res, 404, { ok: false, paired: false, error: 'invalid or used code' });
      const childToken = token();
      const deviceId = rid();
      const model = String(body.model || body.phoneName || '').slice(0, 80);
      const dev = {
        id: deviceId,
        deviceId,
        parentId: parent.id,
        name,
        model,
        phoneName: String(body.phoneName || model).slice(0, 80),
        androidId: String(body.deviceId || body.androidId || '').slice(0, 64),
        childToken,
        token: childToken,
        createdAt: now(),
        lastSeen: now(),
        lastSeenMs: nowMs(),
        online: true,
        battery: -1,
        charging: false
      };
      db.devices.push(dev);
      save(db);
      return send(res, 200, {
        ok: true, paired: true,
        childToken, deviceId, device: { id: deviceId, name }
      });
    }

    if (pathname === '/devices' && method === 'GET') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const list = db.devices.filter(d => d.parentId === p.id).map(d => {
        const age = d.lastSeenMs ? Math.max(0, Math.floor((nowMs() - Number(d.lastSeenMs)) / 1000)) : -1;
        const online = !!(d.lastSeenMs && (nowMs() - Number(d.lastSeenMs) < 120000));
        return {
          id: d.id,
          deviceId: d.deviceId || d.id,
          name: d.name || 'Child',
          model: d.model || '',
          phoneName: d.phoneName || d.model || '',
          battery: (d.battery == null ? -1 : Number(d.battery)),
          charging: !!d.charging,
          online: online ? 1 : 0,
          lastSeen: d.lastSeen || '',
          lastSeenAgeSec: age
        };
      });
      return send(res, 200, { ok: true, devices: list });
    }

    if ((pathname === '/device/heartbeat' || pathname === '/child/heartbeat' || pathname === '/heartbeat') && method === 'POST') {
      const ch = childOf(body, q, req.headers);
      if (ch) {
        markOnline(ch);
        if (body.battery != null || body.batteryLevel != null) {
          const b = Number(body.battery != null ? body.battery : body.batteryLevel);
          if (isFinite(b)) ch.battery = b;
        }
        if (body.charging != null || body.batteryCharging != null) {
          ch.charging = !!(body.charging || body.batteryCharging);
        }
        if (body.model) ch.model = String(body.model).slice(0, 80);
        if (body.phoneName) ch.phoneName = String(body.phoneName).slice(0, 80);
        if (body.appVersion) ch.appVersion = String(body.appVersion).slice(0, 20);
        save(db);
      }
      return send(res, 200, { ok: true });
    }

    if (pathname === '/device/config' && (method === 'GET' || method === 'POST')) {
      const ch = childOf(body, q, req.headers);
      if (!ch) return send(res, 401, { ok: false, error: 'unauthorized' });
      markOnline(ch);
      const rules = db.settings[String(ch.id)] && db.settings[String(ch.id)].rules
        ? db.settings[String(ch.id)].rules : [];
      return send(res, 200, { ok: true, rules: rules, deviceId: ch.id });
    }

    // ---- COMMANDS (app block, security, sync) — FAST ----
    if (pathname === '/commands/send' && method === 'POST') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const deviceId = String(body.deviceId || body.childId || '');
      const type = String(body.type || body.command || '');
      if (!deviceId || !type) return send(res, 400, { ok: false, error: 'deviceId + type required' });
      const dev = db.devices.find(d => String(d.id) === deviceId || String(d.deviceId) === deviceId);
      if (!dev || dev.parentId !== p.id) return send(res, 404, { ok: false, error: 'device not found' });
      const cmd = addCommand(db, dev.id, type, body.payload || body.data || body);
      save(db);
      return send(res, 200, { ok: true, id: cmd.id, command: cmd });
    }

    if (pathname === '/commands/pending' && method === 'GET') {
      reclaimCommands(db);
      const ch = childOf(body, q, req.headers);
      if (!ch) return send(res, 401, { ok: false, error: 'unauthorized' });
      markOnline(ch);
      const did = String(ch.id || ch.deviceId);
      // newest first, claim atomically
      const pending = db.commands
        .filter(c => String(c.deviceId) === did && c.status === 'PENDING')
        .sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0))
        .slice(0, 30);
      const out = [];
      for (const c of pending) {
        if (c.status !== 'PENDING') continue;
        c.status = 'CLAIMED';
        c.claimedAt = nowMs();
        out.push({
          id: c.id,
          type: c.type || c.command,
          command: c.type || c.command,
          payload: c.payload || {},
          createdAt: c.createdAt
        });
      }
      if 
