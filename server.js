/**
 * Parental Control backend - ZERO external dependencies (Node.js only)
 * Run: node server.js
 * Listens: http://0.0.0.0:8080/
 */
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');


process.on('uncaughtException', (e) => { console.error('uncaught', e); });
process.on('unhandledRejection', (e) => { console.error('unhandled', e); });


const PORT = process.env.PORT || 8080;
// Optional strongest online LLM (OpenAI-compatible). Set AI_API_KEY + AI_API_URL.
// Example: AI_API_URL=https://api.openai.com/v1/chat/completions  AI_API_KEY=sk-...
// Or xAI: AI_API_URL=https://api.x.ai/v1/chat/completions
const AI_API_KEY = process.env.AI_API_KEY || '';
const AI_API_URL = process.env.AI_API_URL || '';
const AI_MODEL = process.env.AI_MODEL || 'gpt-4o-mini';

const webrtcSignals = Object.create(null);
function webrtcAliasTokens(token) {
  const keys = [];
  const t = String(token || '');
  if (!t) return keys;
  keys.push(t);
  try {
    const db = load();
    const d = (db.devices || []).find(x =>
      (x.deviceId && String(x.deviceId) === t) ||
      (x.childToken && String(x.childToken) === t) ||
      (x.token && String(x.token) === t)
    );
    if (d) {
      if (d.deviceId && keys.indexOf(String(d.deviceId)) < 0) keys.push(String(d.deviceId));
      if (d.childToken && keys.indexOf(String(d.childToken)) < 0) keys.push(String(d.childToken));
    }
  } catch (e) {}
  return keys;
}
function pushWebRtcSignal(token, signal) {
  if (!token || signal == null) return;
  const payload = typeof signal === 'object' ? Object.assign({ ts: Date.now() }, signal) : { ts: Date.now(), raw: signal };
  const keys = webrtcAliasTokens(token);
  for (const t of keys) {
    if (!webrtcSignals[t]) webrtcSignals[t] = [];
    webrtcSignals[t].push(payload);
    if (webrtcSignals[t].length > 50) webrtcSignals[t] = webrtcSignals[t].slice(-50);
  }
}
function drainWebRtcSignals(token) {
  // Drain ONLY the polled key so parent/child cannot steal each other's mailbox.
  const t = String(token || '');
  const arr = webrtcSignals[t] || [];
  webrtcSignals[t] = [];
  return arr;
}



// ===== Remote Control (AirDroid-style) — RAM only, low latency =====
const remoteQueues = Object.create(null);   // deviceId -> events[]
const remoteWaiters = Object.create(null);  // deviceId -> {res, timer}
const remoteMeta = Object.create(null);     // deviceId -> {w,h,a11y,ts}
const remoteInjectRate = Object.create(null); // deviceId -> {n, windowStart}
const REMOTE_ALLOWED_TYPES = new Set([
  'tap','click','swipe','drag','hold','longpress','long_press','nav','global',
  'back','home','recents','notifications','qs','quicksettings','power','lock',
  'screenshot','split','menu','vol_up','volume_up','vol_down','volume_down',
  'mute','vol_mute','unmute','vol_unmute','wake','screen_on','unlock',
  'unlock_screen','dismiss_keyguard','pin_digit','key','pin_enter','enter','ok',
  'pin_del','delete','backspace','type','text','type_text','torch','flashlight',
  'snap','take_screenshot','batch','path'
]);
function remoteFlush(deviceId) {
  let q = remoteQueues[deviceId] || [];
  if (q.length > 25) {
    remoteQueues[deviceId] = q.slice(25);
    q = q.slice(0, 25);
  } else {
    remoteQueues[deviceId] = [];
  }
  const w = remoteWaiters[deviceId];
  if (w) {
    try { clearTimeout(w.timer); } catch (e) {}
    delete remoteWaiters[deviceId];
    try { send(w.res, 200, { ok: true, events: q, needHello: remoteNeedHello(deviceId) }); } catch (e) {}
  }
  return q;
}
function remotePush(deviceId, events) {
  if (!deviceId || !events || !events.length) return 0;
  if (!remoteQueues[deviceId]) remoteQueues[deviceId] = [];
  const now = Date.now();
  let added = 0;
  for (const e of events) {
    if (!e || typeof e !== 'object') continue;
    const type = String(e.type || e.action || '').trim().toLowerCase();
    if (!type || type.length > 40) continue;
    if (!REMOTE_ALLOWED_TYPES.has(type)) continue;
    const o = Object.assign({}, e);
    o.type = type;
    if (!o.ts && !o.serverTs) o.serverTs = now;
    if (!o.eventId) o.eventId = now + '-' + Math.random().toString(36).slice(2, 10);
    // clamp coords if present
    for (const k of ['x','y','nx','ny','x1','y1','x2','y2']) {
      if (typeof o[k] === 'number') {
        if (o[k] < 0) o[k] = 0;
        if (o[k] > 1) o[k] = 1;
      }
    }
    if (typeof o.text === 'string' && o.text.length > 500) o.text = o.text.slice(0, 500);
    remoteQueues[deviceId].push(o);
    added++;
  }
  if (remoteQueues[deviceId].length > 200) {
    remoteQueues[deviceId] = remoteQueues[deviceId].slice(-200);
  }
  remoteFlush(deviceId);
  return added;
}
function remoteRateOk(deviceId) {
  const now = Date.now();
  let s = remoteInjectRate[deviceId];
  if (!s || now - s.windowStart > 1000) {
    remoteInjectRate[deviceId] = { n: 1, windowStart: now };
    return true;
  }
  s.n++;
  return s.n <= 40; // max 40 inject batches/sec per device
}
function remoteNeedHello(deviceId) {
  const m = remoteMeta[deviceId];
  return !m || !m.hello;
}
function remoteClearDevice(deviceId) {
  if (!deviceId) return;
  delete remoteQueues[deviceId];
  if (remoteWaiters[deviceId]) {
    try { clearTimeout(remoteWaiters[deviceId].timer); } catch (e) {}
    try { send(remoteWaiters[deviceId].res, 200, { ok: true, events: [], needHello: true }); } catch (e) {}
    delete remoteWaiters[deviceId];
  }
  delete remoteMeta[deviceId];
  delete remoteInjectRate[deviceId];
}
// Prune idle remote state every 60s
setInterval(function () {
  const now = Date.now();
  for (const k of Object.keys(remoteMeta)) {
    // Keep meta longer while a waiter is active (parent controlling)
    if (remoteWaiters[k]) {
      remoteMeta[k].ts = now;
      continue;
    }
    if (now - (remoteMeta[k].ts || 0) > 3600000) delete remoteMeta[k];
  }
  for (const k of Object.keys(remoteQueues)) {
    if (!remoteQueues[k] || !remoteQueues[k].length) {
      if (!remoteWaiters[k]) delete remoteQueues[k];
    }
  }
  for (const k of Object.keys(remoteInjectRate)) {
    if (now - (remoteInjectRate[k].windowStart || 0) > 60000) delete remoteInjectRate[k];
  }
}, 60000);


function localStrongClassify(text) {
  const t = String(text || '');
  const low = t.toLowerCase();
  const hits = [];
  const rules = [
    { id: 'LOVE', risk: 70, re: /(i love you|love you|miss you|pyar|mohabbat|bhalobashi|saranghae|사랑|ভালোবাসি|प्यार)/i },
    { id: 'MEET', risk: 75, re: /(meet me|let'?s meet|aa jao|milte|come over|밀나|দেখা)/i },
    { id: 'LOCATION', risk: 65, re: /(where are you|where are you going|kahan|kidhar|location|address|কোথায়|어디)/i },
    { id: 'IDENTITY', risk: 40, re: /(who are you|who is this|tum kaun|kaun ho|তুমি কে|누구)/i },
    { id: 'SECRECY', risk: 80, re: /(don'?t tell|delete this|keep secret|mat batana|kisi ko mat|গোপন)/i },
    { id: 'THREAT', risk: 90, re: /(kill|suicide|self harm|threaten|marunga)/i },
    { id: 'SEXUAL', risk: 85, re: /(nudes?|sext|porn|onlyfans|\bsex\b)/i },
    { id: 'DRUGS', risk: 85, re: /(weed|cocaine|ganja|drugs?)/i },
    { id: 'WELLBEING', risk: 15, re: /(how are you|i'?m fine|kaise ho|kemon acho)/i },
    { id: 'FLIRT', risk: 35, re: /(cute|handsome|beautiful|sweetheart)/i }
  ];
  for (const r of rules) {
    if (r.re.test(t) || r.re.test(low)) hits.push({ intent: r.id, risk: r.risk });
  }
  let risk = 0;
  const intents = [];
  for (const h of hits) {
    intents.push(h.intent);
    if (h.risk > risk) risk = h.risk;
  }
  const style = [];
  if (/(please|pls|plz)/i.test(t)) style.push('polite');
  if (/(lol|haha|😂|🤣)/i.test(t)) style.push('playful');
  if (/(urgent|now|jaldi|abhi)/i.test(t)) style.push('urgent');
  if (/(secret|gopan|raaz)/i.test(t)) style.push('secretive');
  if (t.length > 120) style.push('long_message');
  if (/[\u0900-\u097F]/.test(t)) style.push('hindi_script');
  if (/[\u0980-\u09FF]/.test(t)) style.push('bengali_script');
  if (/[\uAC00-\uD7AF]/.test(t)) style.push('korean_script');
  return {
    intents: intents.length ? intents : ['GENERAL_CHAT'],
    risk: intents.length ? risk : 5,
    style,
    summary: intents.length
      ? ('Detected: ' + intents.join(', ') + (style.length ? (' | style: ' + style.join(',')) : ''))
      : 'Casual chat',
    engine: 'local-strong'
  };
}

async function llmAnalyze(text, meta) {
  if (!AI_API_KEY || !AI_API_URL) return null;
  const system = `You are a parental-control conversation analyst. Analyze the child's message for safety.
Return STRICT JSON only:
{"intents":["LOVE|MEET|LOCATION|IDENTITY|SECRECY|THREAT|SEXUAL|DRUGS|BULLYING|WELLBEING|FLIRT|GENERAL_CHAT"],"risk":0-100,"style":["string"],"summary":"one short sentence for parent","languages":["en|hi|bn|ko|other"]}
Detect meaning even if slang, romanized Hindi/Bengali, or mixed languages. Be sensitive to meetups, secrecy, self-harm, sexual content.`;
  const user = `App: ${meta.packageName || '?'} | Source: ${meta.source || '?'} | Contact: ${meta.contact || '?'}
Message: ${String(text).slice(0, 1500)}`;
  try {
    const body = {
      model: AI_MODEL,
      temperature: 0.1,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user }
      ]
    };
    const res = await fetch(AI_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + AI_API_KEY
      },
      body: JSON.stringify(body)
    });
    if (!res.ok) return null;
    const data = await res.json();
    let content = '';
    if (data.choices && data.choices[0] && data.choices[0].message) content = data.choices[0].message.content || '';
    else if (data.output_text) content = data.output_text;
    content = String(content).trim();
    const m = content.match(/\{[\s\S]*\}/);
    if (!m) return null;
    const parsed = JSON.parse(m[0]);
    return {
      intents: Array.isArray(parsed.intents) ? parsed.intents : ['GENERAL_CHAT'],
      risk: Math.max(0, Math.min(100, Number(parsed.risk) || 0)),
      style: Array.isArray(parsed.style) ? parsed.style : [],
      summary: String(parsed.summary || '').slice(0, 240),
      languages: Array.isArray(parsed.languages) ? parsed.languages : [],
      engine: 'llm:' + AI_MODEL
    };
  } catch (e) {
    return null;
  }
}

async function onlineAiAnalyze(text, meta) {
  const local = localStrongClassify(text);
  const llm = await llmAnalyze(text, meta || {});
  if (!llm) return local;
  // Merge: take higher risk, union intents
  const intents = Array.from(new Set([].concat(llm.intents || [], local.intents || [])));
  return {
    intents,
    risk: Math.max(local.risk || 0, llm.risk || 0),
    style: Array.from(new Set([].concat(llm.style || [], local.style || []))),
    summary: llm.summary || local.summary,
    languages: llm.languages || [],
    engine: llm.engine + '+local'
  };
}



// ===== Presence (AirDroid-style online/offline in ~1s) =====
// Heartbeats update RAM instantly; disk save is debounced so Railway does not hang.
const presenceRam = new Map(); // deviceId -> { lastMs, online, name, parentId, token }
const presenceWaiters = []; // { parentId, res, timer, done }
let presenceDirty = false;
let presenceSaveTimer = null;
// Was 8s — caused ONLINE/OFFLINE flapping on mobile even with good internet.
// Child heartbeats ~2.5s; allow long grace so brief net blips do not flip status.
// Sticky presence — AirDroid-style: do not flap on brief mobile blips
const ONLINE_MS = 90000; // 90s silence before pulse-based OFFLINE
const ONLINE_HARD_MS = 180000; // 3 min = real disconnect
const PRESENCE_FLIP_COOLDOWN_MS = 25000;
const OFFLINE_MISS_NEEDED = 5;
const presenceHolds = new Map(); // deviceId -> { a:{alive,t,gen}, b:{alive,t,gen} }

function holdRecord(deviceId) {
  let rec = presenceHolds.get(deviceId);
  if (!rec) {
    rec = { a: null, b: null, wa: null, wb: null };
    presenceHolds.set(deviceId, rec);
  } else {
    // Hot-upgrade old records missing WS slots after process lifetime
    if (!('wa' in rec)) rec.wa = null;
    if (!('wb' in rec)) rec.wb = null;
    if (!('a' in rec)) rec.a = null;
    if (!('b' in rec)) rec.b = null;
  }
  return rec;
}
function linkCount(deviceId) {
  const rec = presenceHolds.get(deviceId);
  if (!rec) return 0;
  const nowMs = Date.now();
  const fresh = (s) => s && s.alive && (nowMs - s.t) < 50000;
  let n = 0;
  if (fresh(rec.a)) n++;
  if (fresh(rec.b)) n++;
  if (fresh(rec.wa)) n++;
  if (fresh(rec.wb)) n++;
  return n;
}
function anyHoldAlive(deviceId) {
  const rec = presenceHolds.get(deviceId);
  if (!rec) return false;
  const nowMs = Date.now();
  const fresh = (s) => s && s.alive && (nowMs - s.t) < 50000;
  return fresh(rec.a) || fresh(rec.b) || fresh(rec.wa) || fresh(rec.wb);
}

function last10(n) {
  return String(n || '').replace(/\D/g, '').slice(-10);
}
function ensureTomb(db) {
  if (!db.deletedSms) db.deletedSms = [];
  if (!db.deletedCalls) db.deletedCalls = [];
  if (!db.deletedContacts) db.deletedContacts = [];
}
function smsTomb(db, deviceId, androidId, address, body) {
  ensureTomb(db);
  const aid = String(androidId || '');
  const ad = String(address || '');
  const bd = String(body || '');
  if ((db.deletedSms || []).some(t => String(t.deviceId||'') === String(deviceId||'') && ((aid && String(t.androidId||'')===aid) || (ad && bd && t.address===ad && t.body===bd)))) return;
  db.deletedSms.push({ deviceId, androidId: aid, address: ad, body: bd, at: Date.now() });
  if (db.deletedSms.length > 2000) db.deletedSms = db.deletedSms.slice(-1500);
}
function callTomb(db, deviceId, androidId, id, number) {
  ensureTomb(db);
  const aid = String(androidId || '');
  const sid = String(id || '');
  const num = String(number || '');
  db.deletedCalls.push({ deviceId, androidId: aid, id: sid, number: num, at: Date.now() });
  if (db.deletedCalls.length > 2000) db.deletedCalls = db.deletedCalls.slice(-1500);
}
function isSmsTomb(db, deviceId, androidId, address, body) {
  ensureTomb(db);
  const aid = String(androidId || '');
  const ad = String(address || '');
  const bd = String(body || '');
  return (db.deletedSms || []).some(t => {
    if (String(t.deviceId||'') !== String(deviceId||'')) return false;
    // Exact id only. Body+number match hid every later "ok"/OTP to that contact.
    if (aid && aid !== 'undefined' && aid !== 'null' && (String(t.androidId||'') === aid || String(t.id||'') === aid)) return true;
    return false;
  });
}
function isCallTomb(db, deviceId, androidId, number, createdAt) {
  ensureTomb(db);
  const aid = String(androidId || '');
  const num = String(number || '');
  const n10 = last10(num);
  return (db.deletedCalls || []).some(t => {
    if (String(t.deviceId||'') !== String(deviceId||'')) return false;
    // Exact androidId / server id match — strongest
    // Exact id only. Number match hid every later call to that contact.
    if (aid && aid !== 'undefined' && aid !== 'null' && (String(t.androidId||'')===aid || String(t.id||'')===aid)) return true;
    if (t.id && aid && String(t.id)===aid) return true;
    return false;
  });
}
function contactTomb(db, deviceId, id, contactId, number) {
  ensureTomb(db);
  const row = { deviceId, id: String(id||''), contactId: String(contactId||''), number: String(number||''), n10: last10(number), at: Date.now() };
  db.deletedContacts.push(row);
  if (db.deletedContacts.length > 2000) db.deletedContacts = db.deletedContacts.slice(-1500);
}
function isContactTomb(db, deviceId, id, contactId, number) {
  ensureTomb(db);
  const sid = String(id || '');
  const cid = String(contactId || '');
  const n10 = last10(number);
  return (db.deletedContacts || []).some(t => String(t.deviceId||'') === String(deviceId||'') && (
    (sid && (String(t.id||'')===sid || String(t.contactId||'')===sid)) ||
    (cid && (String(t.contactId||'')===cid || String(t.id||'')===cid)) ||
    (n10 && n10.length >= 8 && last10(t.number || t.n10) === n10)
  ));
}


function presenceKey(d) { return String(d.deviceId || d.id || ''); }

function notifyPresenceWaiters(parentId) {
  try {
    const keep = [];
    for (const w of presenceWaiters) {
      if (w.done || w.res.writableEnded) continue;
      if (parentId && w.parentId && w.parentId !== parentId) { keep.push(w); continue; }
      w.done = true;
      try { clearTimeout(w.timer); } catch (e) {}
      try {
        send(w.res, 200, { ok: true, changed: true, ts: Date.now() });
      } catch (e) {}
    }
    presenceWaiters.length = 0;
    for (const w of keep) presenceWaiters.push(w);
  } catch (e) { console.error("notifyPresenceWaiters", e); }
}

function pushPresenceAlert(db, d, online, reason) {
  try {
    if (!db.alerts) db.alerts = [];
    const name = d.name || d.childName || "Child";
    db.alerts.push({
      id: Date.now() + Math.floor(Math.random() * 999),
      parentId: d.parentId,
      deviceId: d.deviceId,
      title: online ? (name + " is ONLINE") : (name + " is OFFLINE"),
      message: online
        ? (name + " phone connected" + (reason ? (" · " + reason) : ""))
        : (name + " phone disconnected" + (reason ? (" · " + reason) : " · restart / network / app killed")),
      type: "PRESENCE",
      subtype: online ? "CHILD_ONLINE" : "CHILD_OFFLINE",
      read: false,
      createdAt: now()
    });
    if (db.alerts.length > 400) db.alerts = db.alerts.slice(-250);
    presenceDirty = true;
  } catch (e) {}
}

function markPresence(d, online, reason) {
  if (!d || !d.deviceId) return;
  const prev = presenceRam.get(d.deviceId);
  const was = prev ? !!prev.online : (d.online ? true : false);
  const nowMs = Date.now();
  // Explicit offline (power off) always wins; timeout offline respects cooldown
  const lastFlip = prev && prev.lastFlipMs ? prev.lastFlipMs : 0;
  if (!!was !== !!online && reason !== 'power off' && reason !== 'power off / restart') {
    if (lastFlip && (nowMs - lastFlip) < PRESENCE_FLIP_COOLDOWN_MS && !online) {
      // Still update lastMs bookkeeping but do not flap OFFLINE during cooldown
      presenceRam.set(d.deviceId, {
        lastMs: prev && prev.lastMs ? prev.lastMs : nowMs,
        online: true,
        name: d.name,
        parentId: d.parentId,
        token: d.childToken,
        lastFlipMs: lastFlip,
        misses: prev && prev.misses ? prev.misses : 0,
        // Keep deferred power-off marker through cooldown
        pendingOffMs: prev && prev.pendingOffMs ? prev.pendingOffMs : 0
      });
      return;
    }
  }
  presenceRam.set(d.deviceId, {
    lastMs: online ? nowMs : (prev && prev.lastMs ? prev.lastMs : nowMs),
    online: !!online,
    name: d.name,
    parentId: d.parentId,
    token: d.childToken,
    lastFlipMs: (!!was !== !!online) ? nowMs : lastFlip,
    misses: online ? 0 : (prev && prev.misses ? prev.misses : 0),
    // Real online beat cancels deferred power-off; offline clears it too
    pendingOffMs: online ? 0 : 0
  });
  if (!!was !== !!online) {
    const db = load();
    pushPresenceAlert(db, d, !!online, reason || "");
    d.online = online ? 1 : 0;
    if (online) d.lastSeen = now();
    schedulePresenceSave();
    notifyPresenceWaiters(d.parentId);
    console.log("presence", d.name || d.deviceId, online ? "ONLINE" : "OFFLINE", reason || "");
  } else if (online) {
    const cur = presenceRam.get(d.deviceId);
    if (cur) cur.lastMs = nowMs;
    // Do NOT dirty-save db.json on every 2.5s beat — that froze Railway and looked like disconnect.
    return;
  }
}

function schedulePresenceSave() {
  presenceDirty = true;
  if (presenceSaveTimer) return;
  presenceSaveTimer = setTimeout(() => {
    presenceSaveTimer = null;
    if (!presenceDirty) return;
    presenceDirty = false;
    try { save(load()); } catch (e) { console.error("presence save", e); }
  }, 4000);
}

function sweepPresence() {
  try {
    const db = load();
    const nowMs = Date.now();
    let changed = false;
    for (const d of (db.devices || [])) {
      if (!d || !d.deviceId) continue;
      const held = anyHoldAlive(d.deviceId);
