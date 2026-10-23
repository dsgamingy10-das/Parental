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

const PORT = Number(process.env.PORT) || 8080;
const HOST = process.env.HOST || '0.0.0.0';
const ROOT = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(ROOT, 'db.json');
try { fs.mkdirSync(ROOT, { recursive: true }); } catch (e) {
  console.error('mkdir data failed', e && e.message);
}

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
  const bak = readJsonFile(DB_FILE + '.bak');
  if (db === null && bak) db = bak;
  // If main file parsed but looks wiped while bak is richer, prefer bak
  if (db && bak && Array.isArray(db.parents) && Array.isArray(bak.parents)) {
    if (db.parents.length === 0 && bak.parents.length > 0) db = bak;
    else if ((db.devices || []).length === 0 && (bak.devices || []).length > (db.devices || []).length) {
      if ((db.parents || []).length <= (bak.parents || []).length) db = bak;
    }
  }
  MEM_DB = ensureDefaults(db || {});
  return MEM_DB;
}

function _saveInner(db) {
  const next = ensureDefaults(db || MEM_DB || {});
  MEM_DB = next;
  let json;
  try {
    json = JSON.stringify(next);
  } catch (e) {
    console.error('save stringify', e && e.message);
    return;
  }
  try {
    const tmp = DB_FILE + '.tmp';
    fs.writeFileSync(tmp, json);
    try { if (fs.existsSync(DB_FILE)) fs.copyFileSync(DB_FILE, DB_FILE + '.bak'); } catch (e) {}
    try {
      fs.renameSync(tmp, DB_FILE);
    } catch (e) {
      try { fs.writeFileSync(DB_FILE, json); } catch (e2) {
        console.error('save direct write error', e2.message);
      }
      try { fs.unlinkSync(tmp); } catch (e3) {}
    }
  } catch (e) {
    console.error('save error', e.message);
    try { fs.writeFileSync(DB_FILE, json); } catch (e2) {
      console.error('save fallback error', e2.message);
    }
  }
}

function save(db) {
  // Update RAM immediately so concurrent requests see fresh data
  const next = ensureDefaults(db || MEM_DB || {});
  MEM_DB = next;
  if (saveBusy) {
    saveQueued = MEM_DB;
    return;
  }
  saveBusy = true;
  setImmediate(function () {
    try {
      _saveInner(MEM_DB);
    } catch (e) {
      console.error('save async', e && e.message);
    } finally {
      saveBusy = false;
      if (saveQueued) {
        const q = saveQueued;
        saveQueued = null;
        try { save(q); } catch (e2) {}
      }
    }
  });
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    let done = false;
    const max = 8 * 1024 * 1024;
    const finish = (val) => {
      if (done) return;
      done = true;
      resolve(val || {});
    };
    req.on('data', (c) => {
      if (done) return;
      size += c.length;
      if (size > max) {
        try { req.destroy(); } catch (e) {}
        finish({ _error: 'body too large' });
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        const buf = Buffer.concat(chunks);
        const raw = buf.toString('utf8');
        if (!raw) return finish({});
        try {
          finish(JSON.parse(raw));
        } catch (e) {
          finish({ _raw: raw.slice(0, 2000) });
        }
      } catch (e) {
        finish({});
      }
    });
    req.on('error', () => finish({}));
    req.on('aborted', () => finish({}));
  });
}

function send(res, code, obj) {
  try {
    if (res.headersSent || res.writableEnded) return;
    const body = typeof obj === 'string' ? obj : JSON.stringify(obj == null ? {} : obj);
    res.writeHead(code, {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Session-Token, X-Child-Token',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Cache-Control': 'no-store'
    });
    res.end(body);
  } catch (e) {
    try { res.end(); } catch (e2) {}
  }
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
  let t = (body && body.sessionToken) || q.sessionToken || (headers && (headers['x-session-token'] || headers['X-Session-Token'])) || bearerToken(headers);
  t = t ? String(t).trim() : '';
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
    // Token is source of truth — ignore stale deviceId from child prefs (offline/reinstall mismatch was 401)
    if (d) return d;
    return null;
  }
  // SECURITY: deviceId-only auth is OFF by default (anyone who guessed id could inject data).
  // Enable only with env ALLOW_LEGACY_DEVICE_AUTH=1 for ancient clients.
  if (did && process.env.ALLOW_LEGACY_DEVICE_AUTH === '1') {
    const d = db.devices.find(x => String(x.id) === did || String(x.deviceId) === did);
    if (d) return d;
  }
  return null;
}

function familyCode() {
  // 8-digit, avoid collisions with existing parents
  const db = MEM_DB || load();
  for (let i = 0; i < 20; i++) {
    const c = String(Math.floor(10000000 + Math.random() * 90000000));
    if (!(db.parents || []).some(p => String(p.familyCode) === c)) return c;
  }
  return String(Math.floor(10000000 + Math.random() * 90000000));
}

function qparse(u) {
  const out = {};
  try {
    for (const [k, v] of u.searchParams) out[k] = v;
  } catch (e) {}
  return out;
}

// Sticky presence (from old Protect package) — avoid false OFFLINE on battery/doze blips
const ONLINE_MS = 120000;      // soft: 2 min silence still online
const ONLINE_HARD_MS = 300000; // hard: 5 min = real disconnect
const PRESENCE_FLIP_COOLDOWN_MS = 25000;
const presenceRam = new Map(); // deviceId -> { lastMs, online, lastFlipMs }

function markOnline(dev) {
  if (!dev) return;
  const t = nowMs();
  dev.lastSeen = now();
  dev.lastSeenMs = t;
  dev.online = true;
  try {
    const key = String(dev.id || dev.deviceId || '');
    if (key) {
      const prev = presenceRam.get(key);
      presenceRam.set(key, {
        lastMs: t,
        online: true,
        lastFlipMs: (prev && prev.online === false) ? t : (prev && prev.lastFlipMs ? prev.lastFlipMs : 0)
      });
    }
  } catch (e) {}
}

function isDeviceOnline(d) {
  if (!d) return false;
  const t = nowMs();
  const last = Number(d.lastSeenMs || 0);
  if (!last) return false;
  const age = t - last;
  if (age < ONLINE_MS) return true;
  if (age < ONLINE_HARD_MS) {
    // soft zone: keep showing online unless flipped recently to offline intentionally
    const key = String(d.id || d.deviceId || '');
    const prev = presenceRam.get(key);
    if (prev && prev.online === false) return false;
    return true;
  }
  return false;
}

/** Fast command reclaim — stuck CLAIMED back to PENDING quickly; prune old DONE. */
function reclaimCommands(db) {
  const t = nowMs();
  for (const c of db.commands) {
    if (!c) continue;
    if (c.status === 'CLAIMED') {
      const started = Number(c.claimedAt || c.startedAt || 0);
      const age = started ? (t - started) : 999999;
      const type = String(c.type || c.command || '');
      const fast = /place_call|send_sms|delete_sms|delete_call|end_call|sync_call|sync_sms|contact_|app_block|app_unblock|apps_list|sync_apps|block_app|unblock_app|hide_app|set_security|set_secret|pair/i.test(type);
      const limit = fast ? 8000 : 45000;
      if (age > limit) {
        c.status = 'PENDING';
        c.claimedAt = 0;
      }
    }
  }
  // Drop DONE older than 24h; keep last 2000 commands max
  const cut = t - 24 * 3600 * 1000;
  if (db.commands.length > 500) {
    db.commands = db.commands.filter(c => {
      if (!c) return false;
      if (c.status === 'DONE' && Number(c.doneAt || c.createdAt || 0) < cut) return false;
      return true;
    });
  }
  if (db.commands.length > 2000) {
    db.commands = db.commands.slice(-2000);
  }
}


function pruneLight(db) {
  try {
    const t = nowMs();
    const cutK = t - 15 * 24 * 3600 * 1000;
    if (Array.isArray(db.keystrokes) && db.keystrokes.length > 10000) {
      db.keystrokes = db.keystrokes.filter(k => Number(k.createdMs || 0) >= cutK).slice(-80000);
    }
    if (Array.isArray(db.alerts) && db.alerts.length > 2000) {
      db.alerts = db.alerts.slice(-1500);
    }
    if (Array.isArray(db.locations) && db.locations.length > 20000) {
      db.locations = db.locations.slice(-15000);
    }
  } catch (e) {}
}

function deviceIdSet(db, queryId) {
  const ids = new Set();
  const q = String(queryId || '');
  if (q) ids.add(q);
  const d = (db.devices || []).find(x => String(x.id) === q || String(x.deviceId || '') === q);
  if (d) {
    ids.add(String(d.id));
    if (d.deviceId) ids.add(String(d.deviceId));
  }
  return ids;
}
function rowOnDevice(db, storedDeviceId, queryId) {
  if (!queryId) return true;
  return deviceIdSet(db, queryId).has(String(storedDeviceId || ''));
}

/** Extract array rows for sync without treating the whole auth body as one row. */
function syncRows(body, arrayKeys) {
  if (!body || typeof body !== 'object') return [];
  for (const k of arrayKeys) {
    if (Array.isArray(body[k])) return body[k].slice(0, 500);
  }
  if (Array.isArray(body.items)) return body.items.slice(0, 500);
  // Single-object payload only if it looks like a data row (not auth envelope)
  const authKeys = { childToken:1, sessionToken:1, token:1, deviceId:1, childId:1, _error:1, _raw:1 };
  const keys = Object.keys(body);
  const dataKeys = keys.filter(k => !authKeys[k]);
  if (dataKeys.length === 0) return [];
  // Must have at least one field that indicates call/sms/contact row
  const markers = ['androidId','number','address','body','message','direction','type','duration','startedMs','date','name','phone','lat','latitude','packageName','pkg','text'];
  if (markers.some(m => body[m] != null && String(body[m]).length > 0)) return [body];
  return [];
}

function queryDeviceId(body, q) {
  return String((q && (q.deviceId || q.childId)) || (body && (body.deviceId || body.childId)) || '').trim();
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
  if (!deviceId) return;
  const androidId = row.androidId != null ? String(row.androidId) : '';
  const numCheck = String(row.number || '').replace(/\D/g, '');
  if (!androidId && !numCheck) return; // ignore auth-envelope / empty rows
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
      if (androidId && c.androidId && String(c.androidId) !== androidId) return false;
      const cn = String(c.number || '').replace(/\D/g, '').slice(-10);
      if (cn !== n) return false;
      if (String(c.direction || c.type || '') !== dir) return false;
      const ct = Number(c.startedMs || c.date || c.ts || 0);
      return Math.abs(ct - ts) < 60000;
    });
  }
  if (found) {
    // NEVER revive parent/child deleted rows on sync
    if (found.deleted || found.deletedBy) {
      if (row.duration != null && Number(row.duration) >= Number(found.duration || 0)) found.duration = Number(row.duration);
      found.updatedAt = nowMs();
      return;
    }
    if (row.duration != null && Number(row.duration) >= Number(found.duration || 0)) found.duration = Number(row.duration);
    if (row.name) found.name = row.name;
    if (row.number) found.number = row.number;
    found.updatedAt = nowMs();
  } else {
    // Do not re-insert a call that was parent-deleted (same number+dir+time)
    const n2 = String(row.number || '').replace(/\D/g, '').slice(-10);
    const dir2 = String(row.direction || row.type || '');
    const ts2 = Number(row.startedMs || row.date || row.ts || 0);
    const wasDeleted = db.calls.some(c => {
      if (String(c.deviceId) !== deviceId) return false;
      if (!c.deleted && !c.deletedBy) return false;
      const cn = String(c.number || '').replace(/\D/g, '').slice(-10);
      if (n2 && cn && cn === n2) {
        if (String(c.direction || c.type || '') === dir2) {
          const ct = Number(c.startedMs || c.date || c.ts || 0);
          if (Math.abs(ct - ts2) < 120000) return true;
        }
      }
      if (androidId && String(c.androidId || '') === androidId) return true;
      return false;
    });
    if (wasDeleted) return;
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
      deleted: false,
      createdAt: nowMs()
    });
  }
  if (db.calls.length > 5000) db.calls = db.calls.slice(-4000);
}

function upsertSms(db, row) {
  if (!row) return;
  const deviceId = String(row.deviceId || '');
  if (!deviceId) return;
  const androidId = row.androidId != null ? String(row.androidId) : '';
  const numCheck = String(row.number || row.address || '').replace(/\D/g, '');
  const bodyCheck = String(row.body || row.message || '');
  if (!androidId && !numCheck && !bodyCheck) return;
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
      if (String(s.androidId || '') && androidId && String(s.androidId) !== androidId) {
        const aid = String(s.androidId || '');
        if (aid.indexOf('pending-') !== 0 && aid.indexOf('out-') !== 0) return false;
      }
      const sn = String(s.number || s.address || '').replace(/\D/g, '').slice(-10);
      if (sn !== n) return false;
      if (String(s.body || s.message || '').slice(0, 500) !== body) return false;
      if (String(s.direction || s.type || '') !== dir) return false;
      const st = Number(s.date || s.ts || 0);
      return Math.abs(st - ts) < 45000;
    });
  }
  if (found) {
    if (found.deleted || found.deletedBy) {
      found.updatedAt = nowMs();
      return;
    }
    if (androidId && String(found.androidId || '').indexOf('pending-') === 0) found.androidId = androidId;
    if (row.body || row.message) {
      found.body = row.body || row.message;
      found.message = found.body;
    }
    found.updatedAt = nowMs();
  } else {
    const n2 = String(row.number || row.address || '').replace(/\D/g, '').slice(-10);
    const body2 = String(row.body || row.message || '').slice(0, 80);
    const dir2 = String(row.direction || row.type || '');
    const ts2 = Number(row.date || row.ts || 0);
    const wasDeleted = db.sms.some(s => {
      if (String(s.deviceId) !== deviceId) return false;
      if (!s.deleted && !s.deletedBy) return false;
      if (androidId && String(s.androidId || '') === androidId) return true;
      const sn = String(s.number || s.address || '').replace(/\D/g, '').slice(-10);
      if (n2 && sn === n2 && String(s.body || s.message || '').slice(0, 80) === body2) {
        const st = Number(s.date || s.ts || 0);
        if (Math.abs(st - ts2) < 120000) return true;
      }
      return false;
    });
    if (wasDeleted) return;
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
      deleted: false,
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
    try { pathname = decodeURIComponent(pathname); } catch (e) {}
    if (pathname.length > 1 && pathname.endsWith('/')) pathname = pathname.slice(0, -1);
    // normalize
    if (pathname.indexOf('..') >= 0) pathname = '/';
    const q = qparse(u);
    const method = req.method || 'GET';

    // timeouts
    req.setTimeout(120000);
    res.setTimeout(120000);

    if (pathname === '/health' || pathname === '/') {
      return send(res, 200, {
        ok: true,
        phase: 323,
        mode: 'slim',
        features: {
          auth: true, pair: true, commands: true,
          calls: true, sms: true, location: true,
          web: true, protection: true, appBlock: true, keylogger: true
        }
      });
    }

    if (pathname === '/web' || pathname === '/dashboard') {
      return sendHtml(res, 200, WEB_HTML);
    }

    const body = (method === 'POST' || method === 'PUT') ? await readBody(req) : {};
    if (body && body._error === 'body too large') {
      return send(res, 413, { ok: false, error: 'body too large' });
    }
    const db = load();

    // ---- AUTH ----
    if (pathname === '/auth/register' && method === 'POST') {
      const email = String(body.email || body.user || '').trim().toLowerCase();
      const pass = String(body.password || '');
      if (!email || pass.length < 6) return send(res, 400, { ok: false, error: 'email + password(6+) required' });
      if (email.indexOf('@') < 1 || email.indexOf('.') < 3) return send(res, 400, { ok: false, error: 'invalid email' });
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
      const androidId = String(body.deviceId || body.androidId || body.android_id || '').slice(0, 64);
      const model = String(body.model || body.phoneName || '').slice(0, 80);
      // Re-pair same physical phone → refresh token, do not create duplicate device
      let dev = null;
      if (androidId) {
        dev = db.devices.find(d => String(d.parentId) === String(parent.id) && String(d.androidId || '') === androidId);
      }
      // Also re-pair if client still has old childToken
      if (!dev) {
        const oldTok = String(body.childToken || body.token || '').trim();
        if (oldTok) {
          dev = db.devices.find(d => String(d.parentId) === String(parent.id) && (d.childToken === oldTok || d.token === oldTok));
        }
      }
      const childToken = token();
      if (dev) {
        dev.childToken = childToken;
        dev.token = childToken;
        dev.name = name || dev.name;
        if (model) { dev.model = model; dev.phoneName = String(body.phoneName || model).slice(0, 80); }
        dev.lastSeen = now();
        dev.lastSeenMs = nowMs();
        dev.online = true;
        save(db);
        return send(res, 200, {
          ok: true, paired: true, repaired: true,
          childToken, deviceId: dev.id, device: { id: dev.id, name: dev.name }
        });
      }
      const deviceId = rid();
      dev = {
        id: deviceId,
        deviceId,
        parentId: parent.id,
        name,
        model,
        phoneName: String(body.phoneName || model).slice(0, 80),
        androidId: androidId,
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
      const list = db.devices.filter(d => String(d.parentId) === String(p.id)).map(d => {
        const age = d.lastSeenMs ? Math.max(0, Math.floor((nowMs() - Number(d.lastSeenMs)) / 1000)) : -1;
        const online = isDeviceOnline(d);
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
      let type = String(body.type || body.command || '').trim().slice(0, 64);
      type = type.replace(/[^a-zA-Z0-9_\-./]/g, '');
      if (!deviceId || !type) return send(res, 400, { ok: false, error: 'deviceId + type required' });
      const dev = db.devices.find(d => String(d.id) === deviceId || String(d.deviceId) === deviceId);
      if (!dev || String(dev.parentId) !== String(p.id)) return send(res, 404, { ok: false, error: 'device not found' });
      let payload = body.payload || body.data || {};
      if (!body.payload && !body.data && body && typeof body === 'object') {
        payload = Object.assign({}, body);
        delete payload.sessionToken;
        delete payload.childToken;
        delete payload.token;
        delete payload.password;
        delete payload.passwordHash;
      }
      if (payload && typeof payload === 'object') {
        delete payload.sessionToken;
        delete payload.childToken;
        delete payload.token;
        delete payload.password;
      }
      const cmd = addCommand(db, dev.id, type, payload);
      save(db);
      return send(res, 200, { ok: true, id: cmd.id, command: { id: cmd.id, type: cmd.type, deviceId: cmd.deviceId, status: cmd.status } });
    }

    if (pathname === '/commands/pending' && method === 'GET') {
      reclaimCommands(db);
      try { pruneLight(db); } catch (e) {}
      const ch = childOf(body, q, req.headers);
      if (!ch) return send(res, 401, { ok: false, error: 'unauthorized' });
      markOnline(ch);
      const did = String(ch.id || ch.deviceId);
      const did2 = String(ch.deviceId || ch.id);
      // newest first, claim atomically (match both id forms)
      const pending = db.commands
        .filter(c => {
          const cd = String(c.deviceId || '');
          return (cd === did || cd === did2) && c.status === 'PENDING';
        })
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
      markOnline(ch);
      save(db);
      return send(res, 200, { ok: true, commands: out });
    }

    if (pathname === '/commands/ack' && method === 'POST') {
      const ch = childOf(body, q, req.headers);
      if (!ch) return send(res, 401, { ok: false, error: 'unauthorized' });
      const did = String(ch.id || '');
      const did2 = String(ch.deviceId || ch.id || '');
      const ids = [];
      if (body.id || body.commandId) ids.push(String(body.id || body.commandId));
      if (Array.isArray(body.ids)) body.ids.forEach(x => { if (x != null) ids.push(String(x)); });
      let n = 0;
      for (const id of ids) {
        const c = db.commands.find(x => String(x.id) === id);
        if (!c) continue;
        const cd = String(c.deviceId || '');
        if (cd === did || cd === did2) {
          c.status = 'DONE';
          c.doneAt = nowMs();
          n++;
        }
      }
      if (n) save(db);
      return send(res, 200, { ok: true, acked: n });
    }

    // ---- CALLS ----
    if ((pathname === '/calls' || pathname === '/calls/log' || pathname === '/call-log') && method === 'GET') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const deviceId = queryDeviceId(body, q);
      let list = db.calls.filter(c => {
        if (deviceId && !rowOnDevice(db, c.deviceId, deviceId)) return false;
        const dev = db.devices.find(d => String(d.id) === String(c.deviceId) || String(d.deviceId) === String(c.deviceId));
        return !!dev && String(dev.parentId) === String(p.id);
      });
      list = list.filter(c => !c.deleted && !c.deletedBy).sort((a, b) => Number(b.startedMs || b.ts || 0) - Number(a.startedMs || a.ts || 0));
      return send(res, 200, { ok: true, calls: list.slice(0, 500) });
    }

    if ((pathname === '/calls' || pathname === '/calls/sync' || pathname === '/call-log') && method === 'POST') {
      const ch = childOf(body, q, req.headers);
      if (!ch) return send(res, 401, { ok: false, error: 'unauthorized' });
      markOnline(ch);
      const did = String(ch.id || ch.deviceId);
      const rows = syncRows(body, ['calls', 'callLog', 'log']);
      for (const r of rows) {
        if (!r || typeof r !== 'object') continue;
        r.deviceId = did;
        upsertCall(db, r);
      }
      save(db);
      return send(res, 200, { ok: true });
    }

    if ((pathname === '/calls/place' || pathname === '/call/place') && method === 'POST') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const deviceId = String(body.deviceId || body.childId || '');
      const number = String(body.number || body.phone || '').trim();
      if (!deviceId || !number) return send(res, 400, { ok: false, error: 'deviceId + number required' });
      const dev = db.devices.find(d => String(d.id) === deviceId || String(d.deviceId) === deviceId);
      if (!dev || String(dev.parentId) !== String(p.id)) return send(res, 404, { ok: false, error: 'device not found' });
      // dedupe PENDING same number 12s
      const t = nowMs();
      const exists = db.commands.find(c =>
        String(c.deviceId) === String(dev.id) &&
        (c.type === 'place_call' || c.command === 'place_call') &&
        (c.status === 'PENDING' || c.status === 'CLAIMED') &&
        String((c.payload && c.payload.number) || '') === number &&
        (t - Number(c.createdAt || 0)) < 12000
      );
      if (exists) return send(res, 200, { ok: true, id: exists.id, deduped: true });
      const cmd = addCommand(db, dev.id, 'place_call', { number });
      save(db);
      return send(res, 200, { ok: true, id: cmd.id });
    }

    if ((pathname === '/calls/end' || pathname === '/call/end' || pathname === '/calls/hangup') && method === 'POST') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const deviceId = String(body.deviceId || body.childId || '');
      const dev = db.devices.find(d => String(d.id) === deviceId || String(d.deviceId) === deviceId);
      if (!dev || String(dev.parentId) !== String(p.id)) return send(res, 404, { ok: false, error: 'device not found' });
      const cmd = addCommand(db, dev.id, 'end_call', {});
      save(db);
      return send(res, 200, { ok: true, id: cmd.id });
    }

    if ((pathname === '/calls/delete' || pathname === '/call/delete') && method === 'POST') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const id = String(body.id || body.callId || '');
      const androidId = String(body.androidId || '');
      const number = String(body.number || body.address || '').trim();
      const deviceId = String(body.deviceId || body.childId || '');
      let targets = [];
      if (id) {
        const c = db.calls.find(x => String(x.id) === id);
        if (c) targets.push(c);
      }
      if (androidId) {
        for (const x of db.calls) {
          if (String(x.androidId || '') === androidId && !targets.includes(x)) targets.push(x);
        }
      }
      // last resort: deviceId + number + only if single match recent
      if (targets.length === 0 && deviceId && number) {
        const n = number.replace(/\D/g, '').slice(-10);
        const matches = db.calls.filter(x => {
          if (String(x.deviceId) !== deviceId) return false;
          if (x.deleted || x.deletedBy) return false;
          const xn = String(x.number || '').replace(/\D/g, '').slice(-10);
          return xn === n;
        });
        if (matches.length === 1) targets.push(matches[0]);
      }
      let count = 0;
      for (const c of targets) {
        const dev = db.devices.find(d => String(d.id) === String(c.deviceId) || String(d.deviceId) === String(c.deviceId));
        if (!dev || String(dev.parentId) !== String(p.id)) continue;
        c.deletedBy = 'parent';
        c.deleted = true;
        addCommand(db, dev.id, 'delete_call', {
          androidId: c.androidId || androidId || '',
          number: c.number || number,
          id: c.id
        });
        count++;
      }
      save(db);
      return send(res, 200, { ok: true, deleted: count > 0, count });
    }


    // ---- SMS ----
    if (pathname === '/sms' && method === 'GET') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const deviceId = queryDeviceId(body, q);
      let list = db.sms.filter(s => {
        if (deviceId && !rowOnDevice(db, s.deviceId, deviceId)) return false;
        const dev = db.devices.find(d => String(d.id) === String(s.deviceId) || String(d.deviceId) === String(s.deviceId));
        return !!dev && String(dev.parentId) === String(p.id);
      });
      list = list.filter(s => !s.deleted && !s.deletedBy).sort((a, b) => Number(b.date || b.ts || 0) - Number(a.date || a.ts || 0));
      return send(res, 200, { ok: true, sms: list.slice(0, 800) });
    }

    if ((pathname === '/sms' || pathname === '/sms/sync') && method === 'POST') {
      const ch = childOf(body, q, req.headers);
      if (!ch) return send(res, 401, { ok: false, error: 'unauthorized' });
      markOnline(ch);
      const did = String(ch.id || ch.deviceId);
      const rows = syncRows(body, ['sms', 'messages', 'message']);
      for (const r of rows) {
        if (!r || typeof r !== 'object') continue;
        r.deviceId = did;
        upsertSms(db, r);
      }
      save(db);
      return send(res, 200, { ok: true });
    }

    if (pathname === '/sms/send' && method === 'POST') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const deviceId = String(body.deviceId || body.childId || body.device_id || '');
      const number = String(body.number || body.to || body.address || body.phone || body.msisdn || '').trim();
      const text = String(body.body || body.message || body.text || body.sms || '');
      if (!deviceId) return send(res, 400, { ok: false, error: 'deviceId required' });
      if (!number) return send(res, 400, { ok: false, error: 'number required' });
      if (!text) return send(res, 400, { ok: false, error: 'message required' });
      let dev = db.devices.find(d => String(d.id) === deviceId || String(d.deviceId) === deviceId);
      if (!dev) {
        // fallback: any device of this parent (single-child case)
        const own = db.devices.filter(d => String(d.parentId) === String(p.id));
        if (own.length === 1) dev = own[0];
      }
      if (!dev || String(dev.parentId) !== String(p.id)) return send(res, 404, { ok: false, error: 'device not found', deviceId });
      const payload = { number, to: number, address: number, phone: number, body: text, message: text, text };
      if (body.subscriptionId != null) payload.subscriptionId = body.subscriptionId;
      if (body.subId != null) payload.subId = body.subId;
      if (body.simSlot != null) payload.simSlot = body.simSlot;
      const cmd = addCommand(db, dev.id, 'send_sms', payload);
      // Show the outgoing SMS on parent immediately (child sync merges this row)
      upsertSms(db, {
        deviceId: String(dev.id),
        androidId: 'pending-' + cmd.id,
        number,
        address: number,
        body: text,
        message: text,
        direction: 'OUT',
        type: 'OUT',
        date: nowMs(),
        ts: nowMs(),
        pending: true
      });
      // also mirror under deviceId alias if different
      if (String(dev.deviceId || '') && String(dev.deviceId) !== String(dev.id)) {
        // commands filtered by both forms in pending — deviceId field is dev.id
      }
      save(db);
      return send(res, 200, { ok: true, id: cmd.id, command: 'send_sms', deviceId: dev.id });
    }

    if (pathname === '/sms/delete' && method === 'POST') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const id = String(body.id || body.smsId || '');
      const androidId = String(body.androidId || '');
      const address = String(body.address || body.number || '').trim();
      const smsBody = String(body.body || body.message || '');
      const deviceId = String(body.deviceId || body.childId || '');
      let targets = [];
      if (id) {
        const s = db.sms.find(x => String(x.id) === id);
        if (s) targets.push(s);
      }
      if (androidId) {
        for (const x of db.sms) {
          if (String(x.androidId || '') === androidId && !targets.includes(x)) targets.push(x);
        }
      }
      if (targets.length === 0 && deviceId && address && smsBody) {
        const n10 = address.replace(/\D/g, '').slice(-10);
        for (const x of db.sms) {
          if (!rowOnDevice(db, x.deviceId, deviceId)) continue;
          const xn = String(x.number || x.address || '').replace(/\D/g, '').slice(-10);
          if (xn !== n10) continue;
          if (String(x.body || x.message || '').slice(0, 80) !== smsBody.slice(0, 80)) continue;
          if (!targets.includes(x)) targets.push(x);
        }
      }
      let n = 0;
      for (const s of targets) {
        const dev = db.devices.find(d => String(d.id) === String(s.deviceId) || String(d.deviceId) === String(s.deviceId));
        if (!dev || String(dev.parentId) !== String(p.id)) continue;
        s.deletedBy = 'parent';
        s.deleted = true;
        addCommand(db, dev.id, 'delete_sms', {
          androidId: s.androidId || '',
          address: s.address || s.number || address,
          body: s.body || s.message || smsBody,
          id: s.id
        });
        n++;
      }
      // If nothing matched but deviceId+id given, still try soft-delete by inventing marker
      if (n === 0 && deviceId && id) {
        const dev = db.devices.find(d => String(d.id) === deviceId || String(d.deviceId) === deviceId);
        if (dev && String(dev.parentId) === String(p.id)) {
          const row = db.sms.find(x => String(x.deviceId) === String(dev.id) && String(x.id) === id);
          if (row) {
            row.deletedBy = 'parent';
            row.deleted = true;
            addCommand(db, dev.id, 'delete_sms', { androidId: row.androidId || '', address, body: smsBody, id });
            n = 1;
          }
        }
      }
      save(db);
      return send(res, 200, { ok: true, deleted: n > 0, count: n });
    }

    // ---- LOCATION ----
    if (pathname === '/location' && method === 'POST') {
      const ch = childOf(body, q, req.headers);
      if (!ch) return send(res, 401, { ok: false, error: 'unauthorized' });
      markOnline(ch);
      const lat = Number(body.lat || body.latitude);
      const lng = Number(body.lng || body.longitude || body.lon);
      if (!isFinite(lat) || !isFinite(lng)) return send(res, 400, { ok: false, error: 'lat/lng required' });
      const row = {
        id: rid(),
        deviceId: String(ch.id || ch.deviceId),
        lat, lng,
        accuracy: Number(body.accuracy || 0),
        ts: nowMs(),
        at: now()
      };
      db.locations.push(row);
      ch.lastLocation = { lat, lng, ts: row.ts };
      if (db.locations.length > 20000) db.locations = db.locations.slice(-15000);
      save(db);
      return send(res, 200, { ok: true });
    }

    if ((pathname === '/location' || pathname === '/location/history') && method === 'GET') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const deviceId = queryDeviceId(body, q);
      const since = nowMs() - 7 * 24 * 3600 * 1000;
      let list = db.locations.filter(l => {
        if (Number(l.ts || 0) < since) return false;
        if (deviceId && String(l.deviceId) !== deviceId) return false;
        const dev = db.devices.find(d => String(d.id) === String(l.deviceId));
        return !!dev && String(dev.parentId) === String(p.id);
      });
      list.sort((a, b) => Number(b.ts || 0) - Number(a.ts || 0));
      return send(res, 200, { ok: true, locations: list.slice(0, 2000), location: list[0] || null });
    }

    // ---- PROTECTION / SECURITY settings ----
    if ((pathname === '/child/security' || pathname === '/child/settings' || pathname === '/settings') && method === 'POST') {
      const p = parentOf(body, q, req.headers);
      const ch = childOf(body, q, req.headers);
      if (p) {
        const deviceId = String(body.deviceId || body.childId || '');
        const dev = db.devices.find(d => String(d.id) === deviceId || String(d.deviceId) === deviceId);
        if (!dev || String(dev.parentId) !== String(p.id)) return send(res, 404, { ok: false, error: 'device not found' });
        const payload = {
          wizard_secret: body.wizard_secret || body.calculator_secret || body.secret,
          access_code: body.access_code || body.admin_password || body.password,
          app_info_password: body.app_info_password || body.appInfoPassword,
          remove_access_code: !!body.remove_access_code
        };
        const cmd = addCommand(db, dev.id, 'set_security', payload);
        save(db);
        return send(res, 200, { ok: true, id: cmd.id });
      }
      if (ch) {
        markOnline(ch);
        return send(res, 200, { ok: true });
      }
      return send(res, 401, { ok: false, error: 'unauthorized' });
    }

    // ---- TAMPER / protection events ----
    if ((pathname === '/events/tamper' || pathname === '/events/alert' || pathname === '/alerts') && method === 'POST') {
      const ch = childOf(body, q, req.headers);
      if (ch) {
        markOnline(ch);
        db.alerts.push({
          id: rid(),
          deviceId: String(ch.id || ch.deviceId),
          type: body.type || 'tamper',
          message: String(body.message || body.text || 'alert').slice(0, 2000),
          ts: nowMs()
        });
        if (db.alerts.length > 1000) db.alerts = db.alerts.slice(-800);
        save(db);
      }
      return send(res, 200, { ok: true });
    }

    if (pathname === '/alerts' && method === 'GET') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const deviceId = queryDeviceId(body, q);
      const list = db.alerts.filter(a => {
        if (deviceId && !rowOnDevice(db, a.deviceId, deviceId)) return false;
        const dev = db.devices.find(d => String(d.id) === String(a.deviceId) || String(d.deviceId) === String(a.deviceId));
        return !!dev && String(dev.parentId) === String(p.id);
      }).sort((a, b) => Number(b.ts || 0) - Number(a.ts || 0));
      return send(res, 200, { ok: true, alerts: list.slice(0, 200) });
    }

    // ---- Soft stubs (old Core may call) — no crash ----
    if ((pathname === '/device/rename' || pathname === '/devices/rename') && method === 'POST') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const deviceId = String(body.deviceId || body.childId || '');
      const name = String(body.name || body.childName || '').trim().slice(0, 40);
      if (!deviceId || name.length < 1) return send(res, 400, { ok: false, error: 'deviceId + name required' });
      const dev = db.devices.find(d => String(d.id) === deviceId || String(d.deviceId) === deviceId);
      if (!dev || String(dev.parentId) !== String(p.id)) return send(res, 404, { ok: false, error: 'device not found' });
      dev.name = name;
      save(db);
      return send(res, 200, { ok: true, deviceId: dev.id, name: dev.name });
    }

    if ((pathname === '/device/remove' || pathname === '/devices/remove' || pathname === '/device/unlink') && method === 'POST') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const deviceId = String(body.deviceId || body.childId || '');
      if (!deviceId) return send(res, 400, { ok: false, error: 'deviceId required' });
      const before = db.devices.length;
      const removedIds = new Set();
      db.devices = db.devices.filter(d => {
        if (String(d.parentId) !== String(p.id)) return true;
        const id = String(d.id || '');
        const did = String(d.deviceId || '');
        if (id === deviceId || did === deviceId) {
          removedIds.add(id);
          if (did) removedIds.add(did);
          return false;
        }
        return true;
      });
      // drop commands for removed device (both id forms)
      db.commands = db.commands.filter(c => !removedIds.has(String(c.deviceId || '')));
      save(db);
      return send(res, 200, { ok: true, removed: before - db.devices.length });
    }


    if ((pathname === '/family/code/refresh' || pathname === '/family/refresh-code') && method === 'POST') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      p.familyCode = familyCode();
      save(db);
      return send(res, 200, { ok: true, familyCode: p.familyCode });
    }


    // ---- KEYLOGGER (fixed: events[] + items[] + tab text + password empty) ----
    if (pathname === '/keystrokes/log' && method === 'POST') {
      const ch = childOf(body, q, req.headers);
      if (!ch) return send(res, 401, { ok: false, error: 'unauthorized' });
      markOnline(ch);
      if (!db.keystrokes) db.keystrokes = [];
      const deviceId = String(ch.id || ch.deviceId || '');
      let saved = 0;
      const pushOne = (pkg, text, ts, extra) => {
        const raw = text == null ? '' : String(text);
        const isPw = !!(extra && (extra.password || extra.is_password || extra.isPassword
          || (raw.indexOf('[PASSWORD]') >= 0) || (raw.indexOf('[SECURE_FIELD]') >= 0)));
        // allow empty text only for password/secure markers
        if (!raw.trim() && !isPw) return;
        let createdAt = now();
        let createdMs = nowMs();
        try {
          if (typeof ts === 'number' && isFinite(ts)) {
            createdMs = (ts > 1e11) ? ts : (ts > 1e9 ? ts * 1000 : nowMs());
            createdAt = new Date(createdMs).toISOString();
          } else if (ts) {
            const p = Date.parse(String(ts));
            if (!isNaN(p) && p > 1e11) { createdMs = p; createdAt = new Date(p).toISOString(); }
          }
        } catch (e) {}
        const field = (extra && (extra.field || extra.info || extra.fieldInfo)) ? String(extra.field || extra.info || extra.fieldInfo) : '';
        db.keystrokes.push({
          id: rid(),
          deviceId,
          packageName: pkg || (extra && extra.pkg) || '',
          text: raw.slice(0, 32000),
          field: field.slice(0, 500),
          isPassword: isPw,
          createdAt,
          createdMs
        });
        saved++;
      };

      // 1) Modern batch: events: [{ts,pkg,text,field,password}] (cap 500/request)
      if (Array.isArray(body.events)) {
        body.events.slice(0, 500).forEach(k => {
          if (!k) return;
          pushOne(k.pkg || k.packageName || '', k.text, k.ts || k.createdMs || k.createdAt, k);
        });
      }
      // 2) Legacy items: [{packageName,text,createdMs}] (cap 500/request)
      if (Array.isArray(body.items)) {
        body.items.slice(0, 500).forEach(k => {
          if (!k) return;
          pushOne(k.packageName || k.pkg || '', k.text, k.createdMs || k.createdAt || k.ts, k);
        });
      }
      // 3) Client KeystrokeLogger: text = "ts\tpkg\ttext" lines joined by \n
      if (body.text != null && String(body.text).length > 0) {
        String(body.text).split(/\n/).slice(0, 500).forEach(line => {
          if (!line || !String(line).trim()) return;
          // JSONL line support
          const s = String(line).trim();
          if (s.charAt(0) === '{') {
            try {
              const o = JSON.parse(s);
              pushOne(o.pkg || o.packageName || '', o.text, o.ts || o.createdMs, o);
              return;
            } catch (e) {}
          }
          const parts = s.split('\t');
          if (parts.length >= 3) {
            const ms = Number(parts[0]) || nowMs();
            pushOne(parts[1], parts.slice(2).join('\t'), ms, null);
          } else if (s.indexOf(': ') > 0) {
            // "pkg: text" plain joined form
            const idx = s.indexOf(': ');
            pushOne(s.slice(0, idx), s.slice(idx + 2), nowMs(), null);
          } else {
            pushOne(body.packageName || body.pkg || '', s, nowMs(), null);
          }
        });
      } else if (body.packageName || body.pkg) {
        pushOne(body.packageName || body.pkg || '', body.text || '', body.ts || nowMs(), body);
      }

      const cut = nowMs() - 15 * 24 * 60 * 60 * 1000;
      db.keystrokes = db.keystrokes.filter(k => {
        const ms = k.createdMs || Date.parse(String(k.createdAt || '')) || 0;
        return !ms || ms >= cut;
      });
      if (db.keystrokes.length > 80000) db.keystrokes = db.keystrokes.slice(-80000);
      save(db);
      return send(res, 200, { ok: true, saved });
    }

    if (pathname === '/keystrokes' && method === 'GET') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const deviceId = queryDeviceId(body, q);
      if (!db.keystrokes) db.keystrokes = [];
      let list = db.keystrokes.filter(k => {
        const kd = String(k.deviceId || '');
        // Always scope to this parent's devices
        const dev = db.devices.find(d => String(d.id) === kd || String(d.deviceId || '') === kd);
        if (!dev || String(dev.parentId) !== String(p.id)) return false;
        if (deviceId) {
          const want = String(deviceId);
          if (kd === want) return true;
          // Parent may pass alternate id
          if (String(dev.id) === want || String(dev.deviceId || '') === want) return true;
          return false;
        }
        return true;
      });
      list = list.slice().sort((a, b) => {
        const am = a.createdMs || Date.parse(String(a.createdAt || '')) || 0;
        const bm = b.createdMs || Date.parse(String(b.createdAt || '')) || 0;
        return bm - am;
      }).slice(0, 8000);
      return send(res, 200, { ok: true, keystrokes: list });
    }



    // ---- compatibility: paths Core/Parent still call ----
    if (pathname === '/location/update' && method === 'POST') {
      const ch = childOf(body, q, req.headers);
      if (!ch) return send(res, 401, { ok: false, error: 'unauthorized' });
      markOnline(ch);
      const lat = Number(body.lat != null ? body.lat : body.latitude);
      const lng = Number(body.lng != null ? body.lng : (body.longitude != null ? body.longitude : body.lon));
      if (isFinite(lat) && isFinite(lng)) {
        db.locations.push({ id: rid(), deviceId: String(ch.id), lat, lng, accuracy: Number(body.accuracy || 0), ts: nowMs(), at: now() });
        ch.lastLocation = { lat, lng, ts: nowMs() };
        if (db.locations.length > 20000) db.locations = db.locations.slice(-15000);
        save(db);
      }
      return send(res, 200, { ok: true });
    }

    if (pathname === '/device/offline' && method === 'POST') {
      const ch = childOf(body, q, req.headers);
      if (ch) {
        ch.online = false;
        ch.lastSeen = now();
        try {
          const key = String(ch.id || ch.deviceId || '');
          if (key) presenceRam.set(key, { lastMs: Number(ch.lastSeenMs || nowMs()), online: false, lastFlipMs: nowMs() });
        } catch (e) {}
        save(db);
      }
      return send(res, 200, { ok: true });
    }

    if (pathname === '/pair/create' && method === 'POST') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      if (!p.familyCode) { p.familyCode = familyCode(); save(db); }
      return send(res, 200, { ok: true, familyCode: p.familyCode, code: p.familyCode, pairingCode: p.familyCode });
    }

    if ((pathname === '/security/set' || pathname === '/settings/device') && method === 'POST') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const deviceId = String(body.deviceId || body.childId || '');
      const dev = db.devices.find(d => String(d.id) === deviceId || String(d.deviceId) === deviceId);
      if (!dev || String(dev.parentId) !== String(p.id)) return send(res, 404, { ok: false, error: 'device not found' });
      const payload = {
        wizard_secret: body.wizard_secret || body.calculator_secret || body.secret,
        access_code: body.access_code || body.admin_password || body.password,
        app_info_password: body.app_info_password || body.appInfoPassword,
        remove_access_code: !!body.remove_access_code
      };
      const cmd = addCommand(db, dev.id, 'set_security', payload);
      save(db);
      return send(res, 200, { ok: true, id: cmd.id });
    }

    if (pathname === '/rules/set' && method === 'POST') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const deviceId = String(body.deviceId || body.childId || '');
      const dev = db.devices.find(d => String(d.id) === deviceId || String(d.deviceId) === deviceId);
      if (!dev || String(dev.parentId) !== String(p.id)) return send(res, 404, { ok: false, error: 'device not found' });
      if (!db.settings[dev.id]) db.settings[dev.id] = {};
      const rules = body.rules || body.rule || body;
      db.settings[dev.id].rules = rules;
      const cmd = addCommand(db, dev.id, 'rules_set', { rules });
      save(db);
      return send(res, 200, { ok: true, id: cmd.id });
    }

    if ((pathname === '/apps/index' || pathname === '/apps') && method === 'POST') {
      const ch = childOf(body, q, req.headers);
      if (!ch) return send(res, 401, { ok: false, error: 'unauthorized' });
      markOnline(ch);
      const items = Array.isArray(body.apps) ? body.apps : (Array.isArray(body.items) ? body.items : []);
      ch.apps = items.slice(0, 800);
      ch.appsAt = nowMs();
      save(db);
      return send(res, 200, { ok: true, count: ch.apps.length });
    }

    if (pathname === '/apps' && method === 'GET') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const deviceId = queryDeviceId(body, q);
      const filter = String(q.filter || 'all').toLowerCase();
      const dev = db.devices.find(d => (String(d.id) === deviceId || String(d.deviceId) === deviceId) && String(d.parentId) === String(p.id));
      let apps = (dev && Array.isArray(dev.apps)) ? dev.apps.slice() : [];
      const total = apps.length;
      if (filter === 'user') apps = apps.filter(a => a && !a.system);
      else if (filter === 'system') apps = apps.filter(a => a && a.system);
      else if (filter === 'blocked') apps = apps.filter(a => a && a.blocked);
      else if (filter === 'hidden') apps = apps.filter(a => a && a.hidden);
      return send(res, 200, { ok: true, apps, total, filter, appsAt: (dev && dev.appsAt) || 0 });
    }

    if ((pathname === '/contacts/sync' || pathname === '/contacts') && method === 'POST') {
      const ch = childOf(body, q, req.headers);
      if (!ch) return send(res, 401, { ok: false, error: 'unauthorized' });
      markOnline(ch);
      const items = Array.isArray(body.contacts) ? body.contacts : (Array.isArray(body.items) ? body.items : []);
      const did = String(ch.id);
      if (body.replace === true || body.full === true) {
        db.contacts = db.contacts.filter(c => String(c.deviceId) !== did);
      }
      for (const c of items) {
        if (!c) continue;
        const num = String(c.number || c.phone || '');
        const name = String(c.name || '');
        let found = db.contacts.find(x => String(x.deviceId) === did && String(x.number || '') === num && String(x.name || '') === name);
        if (!found) db.contacts.push({ id: rid(), deviceId: did, name, number: num, createdAt: now() });
      }
      if (db.contacts.length > 20000) db.contacts = db.contacts.slice(-15000);
      save(db);
      return send(res, 200, { ok: true });
    }

    if (pathname === '/contacts' && method === 'GET') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const deviceId = queryDeviceId(body, q);
      const list = db.contacts.filter(c => {
        if (deviceId && !rowOnDevice(db, c.deviceId, deviceId)) return false;
        const dev = db.devices.find(d => String(d.id) === String(c.deviceId) || String(d.deviceId) === String(c.deviceId));
        return !!dev && String(dev.parentId) === String(p.id);
      });
      return send(res, 200, { ok: true, contacts: list.slice(0, 3000) });
    }

    if ((pathname === '/contacts/add' || pathname === '/contacts/delete' || pathname === '/contacts/rename') && method === 'POST') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const deviceId = String(body.deviceId || '');
      const dev = db.devices.find(d => (String(d.id) === deviceId || String(d.deviceId) === deviceId) && String(d.parentId) === String(p.id));
      if (!dev) return send(res, 404, { ok: false, error: 'device not found' });
      const type = pathname.split('/').pop();
      const num = String(body.number || body.phone || '').trim();
      const nm = String(body.name || body.newName || '').trim();
      const did = String(dev.id);
      if (type === 'rename' && num && nm) {
        const n10 = num.replace(/\D/g, '').slice(-10);
        for (const c of db.contacts) {
          if (String(c.deviceId) !== did) continue;
          const cn = String(c.number || '').replace(/\D/g, '').slice(-10);
          if (cn && n10 && cn === n10) c.name = nm;
        }
        for (const c of db.calls) {
          if (String(c.deviceId) !== did || c.deleted || c.deletedBy) continue;
          const cn = String(c.number || '').replace(/\D/g, '').slice(-10);
          if (cn && n10 && cn === n10) c.name = nm;
        }
      } else if (type === 'add' && num) {
        db.contacts.push({ id: rid(), deviceId: did, name: nm, number: num, createdAt: now() });
      } else if (type === 'delete' && num) {
        const n10 = num.replace(/\D/g, '').slice(-10);
        db.contacts = db.contacts.filter(c => {
          if (String(c.deviceId) !== did) return true;
          const cn = String(c.number || '').replace(/\D/g, '').slice(-10);
          return !(cn && n10 && cn === n10);
        });
      }
      const cmd = addCommand(db, dev.id, 'contact_' + type, {
        name: nm,
        newName: nm,
        number: num,
        phone: num,
        contactId: String(body.contactId || body.id || ''),
        id: String(body.contactId || body.id || '')
      });
      save(db);
      return send(res, 200, { ok: true, id: cmd.id });
    }

    if ((pathname === '/usage/sync' || pathname === '/usage') && method === 'POST') {
      const ch = childOf(body, q, req.headers);
      if (!ch) return send(res, 401, { ok: false, error: 'unauthorized' });
      markOnline(ch);
      const items = syncRows(body, ['usage', 'stats']);
      for (const u of items) {
        if (!u || typeof u !== 'object') continue;
        const pkg = String(u.packageName || u.pkg || '').slice(0, 200);
        const sec = Number(u.seconds || u.foregroundSeconds || 0);
        if (!pkg && !sec) continue;
        db.usage.push({ id: rid(), deviceId: String(ch.id), pkg: pkg, seconds: sec, day: String(u.day || '').slice(0, 32), ts: nowMs() });
      }
      if (db.usage.length > 20000) db.usage = db.usage.slice(-15000);
      save(db);
      return send(res, 200, { ok: true });
    }

    if (pathname === '/usage' && method === 'GET') {
      const p = parentOf(body, q, req.headers);
      if (!p) return send(res, 401, { ok: false, error: 'unauthorized' });
      const deviceId = queryDeviceId(body, q);
      const list = db.usage.filter(u => {
        if (deviceId && String(u.deviceId) !== deviceId) return false;
        const dev = db.devices.find(d => String(d.id) === String(u.deviceId));
        return !!dev && String(dev.parentId) === String(p.id);
      }).slice(-500);
      return send(res, 200, { ok: true, usage: list });
    }

    if (pathname === '/privacy/pending' || pathname === '/privacy/active') {
      return send(res, 200, { ok: true, pending: [], active: null });
    }
    if (pathname.startsWith('/privacy/')) {
      return send(res, 200, { ok: true });
    }

    if (pathname === '/updates/check') {
      return send(res, 200, { ok: true, update: false });
    }
    if (pathname === '/parent/pin/status') {
      return send(res, 200, { ok: true, set: false });
    }
    if (pathname === '/parent/pin/verify') {
      return send(res, 200, { ok: true, valid: true });
    }


    if (pathname.startsWith('/media') || pathname.startsWith('/live') || pathname.startsWith('/gallery') ||
        pathname.startsWith('/files') || pathname.startsWith('/webrtc') || pathname.startsWith('/record')) {
      return send(res, 200, { ok: true, items: [], media: [], skipped: true, mode: 'slim' });
    }

    // Unknown child/parent poll: acknowledge so the app does not crash the loop.
    if (method === 'GET' || method === 'POST') {
      return send(res, 200, { ok: true, items: [], skipped: true, path: pathname });
    }
    return send(res, 404, { ok: false, error: 'not found', path: pathname });
  } catch (e) {
    console.error('handler', e);
    try { send(res, 500, { ok: false, error: String(e.message || e) }); } catch (e2) {}
  }
}

const server = http.createServer((req, res) => {
  try {
    handler(req, res).catch(e => {
      console.error('handler async', e && e.stack ? e.stack : e);
      try {
        if (!res.headersSent) send(res, 500, { ok: false, error: 'server error' });
        else res.end();
      } catch (e2) {}
    });
  } catch (e) {
    console.error('handler sync', e && e.stack ? e.stack : e);
    try {
      if (!res.headersSent) send(res, 500, { ok: false, error: 'server error' });
      else res.end();
    } catch (e2) {}
  }
});

server.requestTimeout = 120000;
server.headersTimeout = 120000;
server.keepAliveTimeout = 65000;
server.timeout = 120000;

server.on('error', (e) => {
  console.error('server error event', e && e.message);
});

server.listen(PORT, HOST, () => {
  try { load(); } catch (e) { console.error('load on start', e && e.message); }
  console.log('[slim-backend] listening on', HOST + ':' + PORT, 'phase 323');
});

// Never exit on stray errors — Railway restarts on exit; keep process alive.
process.on('uncaughtException', (e) => {
  console.error('uncaught', e && e.stack ? e.stack : e);
});
process.on('unhandledRejection', (e) => {
  console.error('unhandled', e && (e.stack || e));
});
process.on('SIGTERM', () => {
  console.log('SIGTERM — closing');
  try { _saveInner(MEM_DB); } catch (e) {}
  try { server.close(() => process.exit(0)); } catch (e) { process.exit(0); }
  setTimeout(() => process.exit(0), 8000).unref();
});
process.on('SIGINT', () => {
  try { _saveInner(MEM_DB); } catch (e) {}
  process.exit(0);
});
