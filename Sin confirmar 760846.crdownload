// Gusanix · servidor: sirve el juego (index.html), cuentas con recuperación, guardado en la nube y salas en línea.
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { WebSocketServer } = require('ws');
const PORT = process.env.PORT || 3000;
const DIR = process.env.DATA_DIR || path.join(__dirname, 'data');   // en producción: apunta a un disco persistente
const FILE = path.join(DIR, 'users.json');
const MAX_ROOM = +process.env.MAX_ROOM || 16;
fs.mkdirSync(DIR, { recursive: true });

let DB = { users: {} };
try { DB = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) {}
let saveT = 0;
const saveDB = () => { clearTimeout(saveT); saveT = setTimeout(() => fs.writeFile(FILE + '.tmp', JSON.stringify(DB), err => { if (!err) fs.rename(FILE + '.tmp', FILE, () => {}); }), 400); };
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const scrypt = (s, salt) => crypto.scryptSync(s, salt, 32).toString('hex');
const same = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const rid = n => crypto.randomBytes(n).toString('hex');
const rcode = () => { const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; let s = ''; for (const b of crypto.randomBytes(12)) s += A[b % A.length]; return s.match(/.{4}/g).join('-'); };
const normRc = s => String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
const TOK = {};   // sha(token) -> clave de usuario
for (const k in DB.users) for (const t of DB.users[k].toks || []) TOK[t] = k;

function issue(k) {
  const u = DB.users[k], tok = rid(24), h = sha(tok);
  u.toks = (u.toks || []).slice(-4); u.toks.push(h); TOK[h] = k; saveDB(); return tok;
}
const fails = {};
function blocked(ip) { const f = fails[ip]; return f && f.n >= 8 && Date.now() - f.t < 600000; }
function fail(ip) { const f = fails[ip] = fails[ip] && Date.now() - fails[ip].t < 600000 ? fails[ip] : { n: 0, t: Date.now() }; f.n++; }

const server = http.createServer((req, res) => {
  if (req.url === '/health') { res.end('ok'); return; }
  if (req.url === '/' || req.url.startsWith('/?') || req.url === '/index.html') {
    fs.readFile(path.join(__dirname, 'index.html'), (e, d) => { if (e) { res.writeHead(404); res.end('Falta index.html'); } else { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(d); } });
    return;
  }
  res.writeHead(404); res.end('No encontrado');
});

// ---------- Mundo compartido por sala: bots IA (30), comida y poderes ----------
const WS = 7200, C = 3600, R = 3500, NBOT = +process.env.NBOT || 30, NPOW = 24;
const rad = w => 8 + Math.sqrt(w.m) * .55, nseg = w => Math.min(260, Math.floor(10 + w.m * .25));
const rnd = (a, b) => a + Math.random() * (b - a);
const rp = m => { const a = Math.random() * 6.283, d = Math.sqrt(Math.random()) * (R - m); return [C + Math.cos(a) * d, C + Math.sin(a) * d]; };
const EMOV = [2, 1, 2, 4, 4, 3, 1, 2], cells = [], cellById = {};
for (let c = 0; c < 1600; c++) {   // misma fórmula que el cliente
  const h = Math.imul(c + 1, 2654435761) >>> 0, gx = c % 40, gy = (c / 40) | 0;
  const x = gx * 180 + 90 + ((h & 255) / 255 - .5) * 120, y = gy * 180 + 90 + (((h >> 8) & 255) / 255 - .5) * 120;
  if (Math.hypot(x - C, y - C) > R - 150) continue;
  const v = EMOV[(h >>> 16) % 8], f = { id: 'c' + c, x, y, v, sz: 7 + v * 1.8 }; cells.push(f); cellById[f.id] = f;
}
const BN = ['Pipo','Lola','Gusi','Max','Nube','Rayo','Kiwi','Toby','Luna','Zeta','Coco','Bimbo','Fufi','Tito','Nina','Bruno','Chispa','Mango','Pelusa','Tango'];
const PK = [[2, 1], [4, 1], [5, 3], [6, 3], [7, 3], [8, 3], [9, 1.5], [10, .7]];   // sin mordisco, escarcha ni torbellino
function chain(w) {
  const s = w.segs, sd = rad(w) * .5;
  for (let i = 1; i < s.length; i++) { const a = s[i - 1], b = s[i], dx = a.x - b.x, dy = a.y - b.y, d = Math.hypot(dx, dy) || 1; if (d > sd) { b.x = a.x - dx / d * sd; b.y = a.y - dy / d * sd; } }
  const n = nseg(w); while (s.length < n) { const q = s[s.length - 1]; s.push({ x: q.x, y: q.y }); } while (s.length > n) s.pop();
}
function newBot(r) {
  const [x, y] = rp(500), a = rnd(0, 6.28);
  const b = { id: 'b' + (++r.nb), name: BN[Math.random() * BN.length | 0], ci: Math.random() * 8 | 0, pi: Math.random() * 9 | 0, m: rnd(15, 45), ang: a, tang: a, alive: 1, tmr: Math.random() * 15 | 0, tgt: null, tt: 0, segs: [], e: [], q: 0, ne: 0, isNew: 1, sent: 0, rt: 0 };
  for (let i = 0; i < nseg(b); i++) b.segs.push({ x: x - Math.cos(a) * i * 4, y: y - Math.sin(a) * i * 4 });
  return b;
}
function newPow(r) { let s = PK.reduce((t, p) => t + p[1], 0) * Math.random(), i = 0; while (i < PK.length - 1 && s > PK[i][1]) { s -= PK[i][1]; i++; } const q = rp(150); return { id: 'w' + (++r.np), x: Math.round(q[0]), y: Math.round(q[1]), k: PK[i][0] }; }
function mkRoom() { const r = { peers: new Map(), bots: [], orbs: new Map(), off: new Map(), ig: new Map(), pows: [], left: [], nb: 0, np: 0, tk: 0 }; for (let i = 0; i < NBOT; i++) r.bots.push(newBot(r)); for (let i = 0; i < NPOW; i++) r.pows.push(newPow(r)); return r; }
const isGone = (r, f, now) => f.o ? !!f.gone : (r.off.get(f.id) || 0) > now;
function aiB(r, b, now, W) {
  const h = b.segs[0], rr = rad(b); b.tmr++;
  if (b.tgt) { b.tt++; const g = b.tgt; if (b.tt > 140 || (b.tt > 30 && Math.hypot(g.x - h.x, g.y - h.y) < 170)) { r.ig.set(g.id, now + 15000); b.tgt = null; b.tt = 0; } }
  if (!b.tgt || isGone(r, b.tgt, now) || b.tmr % 15 == 0) {
    let best = -1, bf = null;
    const test = f => { if ((r.ig.get(f.id) || 0) > now || Math.hypot(f.x - C, f.y - C) > R - 140) return; const dx = f.x - h.x, dy = f.y - h.y, s = f.v * (f.o ? 3 : 1) / (Math.sqrt(dx * dx + dy * dy) + 60); if (s > best) { best = s; bf = f; } };
    for (const c of cells) if ((r.off.get(c.id) || 0) <= now) test(c);
    for (const o of r.orbs.values()) test(o);
    if (bf !== b.tgt) b.tt = 0; b.tgt = bf;
  }
  const tg = b.tgt; let vx = Math.cos(b.ang) * .3, vy = Math.sin(b.ang) * .3;
  if (tg) { const dx = tg.x - h.x, dy = tg.y - h.y, d = Math.hypot(dx, dy) || 1; vx += dx / d; vy += dy / d; }
  { const dx = h.x - C, dy = h.y - C, d = Math.hypot(dx, dy) || 1, e = R - d; if (e < 170) { const k = (1 - e / 170) * 3; vx -= dx / d * k; vy -= dy / d * k; } }
  for (const o of W) {
    if (o === b) continue; const or = rad(o), oh = o.segs[0], D = rr + or + 110, reach = o.segs.length * or * .5 + D;
    if (Math.abs(h.x - oh.x) > reach || Math.abs(h.y - oh.y) > reach) continue;
    for (let i = 0; i < o.segs.length; i += 2) { const s = o.segs[i], dx = h.x - s.x, dy = h.y - s.y, d2 = dx * dx + dy * dy; if (d2 < D * D) { const d = Math.sqrt(d2) || 1, k = (1 - d / D) * (1 - d / D) * 6; vx += dx / d * k; vy += dy / d * k; } }
  }
  b.tang = Math.atan2(vy, vx);
}
function mv(b) {
  const d = b.tang - b.ang, df = Math.atan2(Math.sin(d), Math.cos(d)), tr = .11 / (1 + rad(b) * .02);
  b.ang += Math.max(-tr, Math.min(tr, df)); const h = b.segs[0]; h.x += Math.cos(b.ang) * 2.7; h.y += Math.sin(b.ang) * 2.7; chain(b);
}
function rec(b, id) { b.e.push([id, ++b.q]); if (b.e.length > 12) b.e.shift(); b.ne = 1; }
function eatB(r, b, now) {
  const h = b.segs[0], rr = rad(b);
  for (const c of cells) { if (Math.abs(h.x - c.x) > 60 || Math.abs(h.y - c.y) > 60 || (r.off.get(c.id) || 0) > now) continue; const dx = h.x - c.x, dy = h.y - c.y; if (dx * dx + dy * dy < (rr + c.sz * .4 + 4) ** 2) { b.m += c.v; r.off.set(c.id, now + 25000); rec(b, c.id); } }
  for (const [id, o] of r.orbs) { if (Math.abs(h.x - o.x) > 60 || Math.abs(h.y - o.y) > 60) continue; const dx = h.x - o.x, dy = h.y - o.y; if (dx * dx + dy * dy < (rr + o.sz * .4 + 4) ** 2) { b.m += o.v; o.gone = 1; r.orbs.delete(id); rec(b, id); } }
}
function hitB(b, W) {
  const h = b.segs[0], rr = rad(b); if (Math.hypot(h.x - C, h.y - C) > R - rr) return { by: null };
  for (const o of W) {
    if (o === b) continue; const or = rad(o), lim = rr * .7 + or * .8, oh = o.segs[0], reach = lim + o.segs.length * or * .5 + 10;
    if (Math.abs(h.x - oh.x) > reach || Math.abs(h.y - oh.y) > reach) continue;
    for (let i = 0; i < o.segs.length; i += 2) { const s = o.segs[i], dx = h.x - s.x, dy = h.y - s.y; if (dx * dx + dy * dy < lim * lim) return { by: o.id }; }
  }
  return null;
}
function addOrbs(r, owner, list, v, ci) {
  list.forEach((q, j) => { const id = 'o' + owner + '_' + j; if (r.orbs.has(id) || !q || q.length != 2) return; r.orbs.set(id, { id, x: +q[0] || 0, y: +q[1] || 0, v, ci: ci | 0, o: 1, sz: 6 + Math.min(v, 8) * 1.2 }); });
  while (r.orbs.size > 700) { const k = r.orbs.keys().next().value; r.orbs.get(k).gone = 1; r.orbs.delete(k); }
}
function killB(r, b, by) {
  b.alive = 0; const n = b.segs.length, v = Math.max(1, b.m * .6 / (n / 2)); b.d = [];
  for (let i = 0; i < n && b.d.length < 130; i += 2) b.d.push([Math.round(b.segs[i].x), Math.round(b.segs[i].y)]);
  b.dv = v; b.by = by; b.rt = 60; addOrbs(r, b.id, b.d, v, b.ci);
}
function botG(b, full) { const g = { x: Math.round(b.segs[0].x), y: Math.round(b.segs[0].y), a: +b.ang.toFixed(2), m: Math.round(b.m), b: 0, al: 1 }; if (full) { g.n = b.name; g.c = b.ci; g.p = b.pi; g.e = b.e; g.q = b.q; } return g; }
function simulate(r, now) {
  const W = [];
  for (const [id, e] of r.peers) {   // cuerpos de jugadores reconstruidos desde la cabeza
    const g = e.g; if (!g || !g.al) { e.bd = null; continue; }
    const x = +g.x || 0, y = +g.y || 0; if (!e.bd) e.bd = { id, m: 10, segs: [{ x, y }] };
    const bd = e.bd; bd.m = Math.min(5000, Math.max(10, +g.m || 10)); const h = bd.segs[0];
    if ((h.x - x) ** 2 + (h.y - y) ** 2 > 250000) { h.x = x; h.y = y; } else { h.x += (x - h.x) * .5; h.y += (y - h.y) * .5; }
    chain(bd); W.push(bd);
  }
  for (const b of r.bots) if (b.alive) W.push(b);
  for (const b of r.bots) if (b.alive) { aiB(r, b, now, W); for (let k = 0; k < 3; k++) { mv(b); eatB(r, b, now); } }
  for (const b of r.bots) if (b.alive) { const c = hitB(b, W); if (c) killB(r, b, c.by); }
  for (let i = 0; i < r.bots.length; i++) { const b = r.bots[i]; if (!b.alive && b.sent && --b.rt <= 0) { r.left.push(b.id); r.bots[i] = newBot(r); } }
}
function bcast(r) {
  const bl = [];
  for (const b of r.bots) {
    if (b.alive) { const g = botG(b, b.isNew); b.isNew = 0; if (b.ne) { g.e = b.e; g.q = b.q; b.ne = 0; } bl.push({ peer: b.id, presence: { g } }); }
    else if (!b.sent) { b.sent = 1; bl.push({ peer: b.id, presence: { g: { al: 0, d: b.d, dv: b.dv, by: b.by } } }); }
  }
  const left = r.left.splice(0);
  for (const [id, e] of r.peers) {
    const list = bl.slice(); for (const [i, x] of r.peers) if (i !== id && x.pg) list.push({ peer: i, presence: { g: x.pg } });
    if (list.length || left.length) send(e.ws, { t: 'peers', peers: list, left });
  }
  for (const e of r.peers.values()) e.pg = null;
}
function snapshot(r, ws, now) {
  send(ws, { t: 'world', off: [...r.off].filter(([, t]) => t > now).map(([id, t]) => [+id.slice(1), Math.ceil((t - now) / 1000)]), orbs: [...r.orbs.values()].map(o => [o.id, Math.round(o.x), Math.round(o.y), o.v, o.ci]) });
  send(ws, { t: 'pows', list: r.pows });
  const peers = []; for (const [id, e] of r.peers) if (e.ws !== ws && e.g) peers.push({ peer: id, presence: { g: e.g } });
  for (const b of r.bots) if (b.alive) peers.push({ peer: b.id, presence: { g: botG(b, true) } });
  if (peers.length) send(ws, { t: 'peers', peers });
}
function eatenId(r, id, now) { if (id[0] === 'c') { if (cellById[id]) r.off.set(id, now + 25000); } else if (id[0] === 'o') { const o = r.orbs.get(id); if (o) { o.gone = 1; r.orbs.delete(id); } } }
function onPres(r, id, e, g, now) {
  g.al = g.al ? 1 : 0; const was = e.g || {};
  if (Array.isArray(g.e)) for (const x of g.e.slice(0, 30)) { if (!Array.isArray(x)) continue; const q = +x[1]; if (q > (e.lq || 0)) { e.lq = q; eatenId(r, String(x[0]), now); } }
  if (g.al && !was.al) e.lq = g.e ? e.lq : 0;
  if (!g.al && !e.dead) { e.dead = 1; e.bd = null; if (Array.isArray(g.d)) addOrbs(r, id, g.d.slice(0, 140), +g.dv || 1, g.c != null ? g.c : was.c); }
  if (g.al) e.dead = 0;
}

const rooms = [];            // salas: humanos + 30 bots IA compartidos
const online = new Map();    // usuario -> ws (una sesión de juego por cuenta)
const send = (ws, m) => { if (ws.readyState === 1) ws.send(JSON.stringify(m)); };
function leave(ws) {
  const r = ws.room; if (!r) return;
  const e = r.peers.get(ws.id); r.peers.delete(ws.id); ws.room = null;
  if (e && e.g) for (const p of r.peers.values()) send(p.ws, { t: 'peers', peers: [], left: [ws.id] });
  if (!r.peers.size) rooms.splice(rooms.indexOf(r), 1);
}

const wss = new WebSocketServer({ server, maxPayload: 16384 });
wss.on('connection', (ws, req) => {
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  ws.id = rid(4); ws.u = null; ws.room = null; ws.n = 0; ws.lt = Date.now();
  ws.on('message', raw => {
    const now = Date.now(); if (now - ws.lt > 1000) { ws.lt = now; ws.n = 0; } if (++ws.n > 40) return;
    let m; try { m = JSON.parse(raw); } catch (e) { return; }
    if (!m || typeof m.t !== 'string') return;
    const auth = k => { ws.u = DB.users[k].name; return { t: 'authed', u: ws.u, tok: issue(k), data: DB.users[k].data || null }; };
    const cred = () => { const u = String(m.u || ''), p = String(m.p || ''); return { u, p, k: u.toLowerCase() }; };
    switch (m.t) {
      case 'reg': {
        const { u, p, k } = cred();
        if (blocked(ip)) return send(ws, { t: 'err', m: 'Demasiados intentos. Espera unos minutos.' });
        if (!/^[A-Za-z0-9_]{3,16}$/.test(u)) return send(ws, { t: 'err', m: 'Usuario: 3 a 16 letras, números o _' });
        if (p.length < 6 || p.length > 64) return send(ws, { t: 'err', m: 'La contraseña debe tener al menos 6 caracteres' });
        if (DB.users[k]) return send(ws, { t: 'err', m: 'Ese usuario ya existe' });
        const salt = rid(8), rs = rid(8), rc = rcode();
        DB.users[k] = { name: u, salt, hash: scrypt(p, salt), rs, rh: scrypt(normRc(rc), rs), data: null, toks: [], created: Date.now() };
        const a = auth(k); a.rc = rc; send(ws, a); break;
      }
      case 'login': {
        const { p, k } = cred(); const U = DB.users[k];
        if (blocked(ip)) return send(ws, { t: 'err', m: 'Demasiados intentos. Espera unos minutos.' });
        if (!U || !same(U.hash, scrypt(p, U.salt))) { fail(ip); return send(ws, { t: 'err', m: 'Usuario o contraseña incorrectos' }); }
        send(ws, auth(k)); break;
      }
      case 'rec': {
        const { p, k } = cred(); const U = DB.users[k];
        if (blocked(ip)) return send(ws, { t: 'err', m: 'Demasiados intentos. Espera unos minutos.' });
        if (p.length < 6 || p.length > 64) return send(ws, { t: 'err', m: 'La nueva contraseña debe tener al menos 6 caracteres' });
        if (!U || !same(U.rh, scrypt(normRc(m.rc), U.rs))) { fail(ip); return send(ws, { t: 'err', m: 'Usuario o código de recuperación incorrectos' }); }
        const rc = rcode(); U.salt = rid(8); U.hash = scrypt(p, U.salt); U.rs = rid(8); U.rh = scrypt(normRc(rc), U.rs);
        for (const h of U.toks || []) delete TOK[h]; U.toks = [];
        const a = auth(k); a.rc = rc; send(ws, a); break;
      }
      case 'tok': {
        const k = TOK[sha(String(m.tok || ''))];
        if (!k || !DB.users[k]) return send(ws, { t: 'err', m: 'Sesión vencida' });
        ws.u = DB.users[k].name; send(ws, { t: 'authed', u: ws.u, tok: m.tok, data: DB.users[k].data || null }); break;
      }
      case 'out': { const h = sha(String(m.tok || '')), k = TOK[h]; if (k) { delete TOK[h]; DB.users[k].toks = (DB.users[k].toks || []).filter(x => x !== h); saveDB(); } leave(ws); ws.u = null; break; }
      case 'save': {
        if (!ws.u) return; const s = JSON.stringify(m.data || null);
        if (s.length > 20000) return; DB.users[ws.u.toLowerCase()].data = JSON.parse(s); saveDB(); break;
      }
      case 'join': {
        if (!ws.u) return send(ws, { t: 'err', m: 'Inicia sesión para jugar en línea' });
        leave(ws);
        const old = online.get(ws.u); if (old && old !== ws) { leave(old); send(old, { t: 'err', m: 'Tu cuenta se abrió en otro lugar' }); }
        online.set(ws.u, ws);
        let r = rooms.find(x => x.peers.size < MAX_ROOM); if (!r) { r = mkRoom(); rooms.push(r); }
        r.peers.set(ws.id, { ws, g: null, pg: null, lq: 0, bd: null, dead: 0 }); ws.room = r;
        send(ws, { t: 'joined', me: ws.id });
        break;
      }
      case 'sync': if (ws.room) snapshot(ws.room, ws, Date.now()); break;
      case 'pw': {
        const r = ws.room; if (!r) return; const i = r.pows.findIndex(p => p.id === m.id);
        if (i >= 0) { r.pows.splice(i, 1); r.pows.push(newPow(r)); for (const p of r.peers.values()) send(p.ws, { t: 'pows', list: r.pows }); }
        break;
      }
      case 'p': {
        const r = ws.room, e = r && r.peers.get(ws.id); if (!e) return;
        if (m.g === null) { if (e.g) { e.g = null; e.pg = null; e.bd = null; for (const p of r.peers.values()) if (p.ws !== ws) send(p.ws, { t: 'peers', peers: [], left: [ws.id] }); } }
        else if (m.g && typeof m.g === 'object' && JSON.stringify(m.g).length < 5000) {
          const g = m.g; g.n = ws.u; onPres(r, ws.id, e, g, Date.now());
          e.g = Object.assign(e.g || {}, g); e.pg = Object.assign(e.pg || {}, g);
        }
        break;
      }
      case 'leave': leave(ws); break;
    }
  });
  ws.on('close', () => { leave(ws); if (ws.u && online.get(ws.u) === ws) online.delete(ws.u); });
  ws.on('error', () => {});
});

setInterval(() => {
  const now = Date.now();
  for (const r of rooms) { try { simulate(r, now); if ((++r.tk) % 2 === 0) bcast(r); } catch (e) { console.error(e); } }
}, 50);

server.listen(PORT, () => console.log('Gusanix en el puerto ' + PORT));
