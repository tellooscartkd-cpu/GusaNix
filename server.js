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

const rooms = [];            // { peers: Map(id -> {ws,g,d}) }
const online = new Map();    // usuario -> ws (una sesión de juego por cuenta)
const send = (ws, m) => { if (ws.readyState === 1) ws.send(JSON.stringify(m)); };

function leave(ws) {
  const r = ws.room; if (!r) return;
  const e = r.peers.get(ws.id); r.peers.delete(ws.id); ws.room = null;
  if (e && e.g) for (const p of r.peers.values()) send(p.ws, { t: 'peers', left: [ws.id] });
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
        let r = rooms.find(x => x.peers.size < MAX_ROOM); if (!r) { r = { peers: new Map() }; rooms.push(r); }
        r.peers.set(ws.id, { ws, g: null, d: 0 }); ws.room = r;
        send(ws, { t: 'joined', me: ws.id });
        const snap = [...r.peers].filter(([id, e]) => e.g && id !== ws.id).map(([id, e]) => ({ peer: id, presence: { g: e.g } }));
        if (snap.length) send(ws, { t: 'peers', peers: snap });
        break;
      }
      case 'p': {
        const r = ws.room, e = r && r.peers.get(ws.id); if (!e) return;
        if (m.g === null) { if (e.g) { e.g = null; for (const p of r.peers.values()) if (p.ws !== ws) send(p.ws, { t: 'peers', left: [ws.id] }); } }
        else if (m.g && typeof m.g === 'object' && JSON.stringify(m.g).length < 5000) { m.g.n = ws.u; e.g = m.g; e.d = 1; }
        break;
      }
      case 'leave': leave(ws); break;
    }
  });
  ws.on('close', () => { leave(ws); if (ws.u && online.get(ws.u) === ws) online.delete(ws.u); });
  ws.on('error', () => {});
});

setInterval(() => {
  for (const r of rooms) {
    const dirty = [...r.peers].filter(([, e]) => e.d && e.g);
    if (!dirty.length) continue;
    for (const [id, e] of r.peers) {
      const list = dirty.filter(([i]) => i !== id).map(([i, x]) => ({ peer: i, presence: { g: x.g } }));
      if (list.length) send(e.ws, { t: 'peers', peers: list });
    }
    for (const [, e] of dirty) e.d = 0;
  }
}, 100);

server.listen(PORT, () => console.log('Gusanix en el puerto ' + PORT));
