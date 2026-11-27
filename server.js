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


// ---------- Recuperación por correo / SMS ----------
// Correo: RESEND_KEY + MAIL_FROM (resend.com).  SMS: TWILIO_SID + TWILIO_TOKEN + TWILIO_FROM (twilio.com).
// Sin claves: el código sale solo en la consola del servidor (modo pruebas; GX_DEV=1 lo devuelve también al cliente).
const https = require('https');
process.on('uncaughtException', e => console.log('Excepción no controlada:', e && e.stack || e));
process.on('unhandledRejection', e => console.log('Error no controlado:', e && e.message));
const CODES = {}, sendLog = {};
const normCt = s => { s = String(s || '').trim(); if (/^[^\s@]{1,64}@[^\s@]{1,190}\.[A-Za-z]{2,}$/.test(s) && s.length <= 254) return { k: 'e', v: s.toLowerCase() }; const d = s.replace(/[^\d+]/g, ''); if (/^\+\d{8,15}$/.test(d)) return { k: 'p', v: d }; return null; };
const maskCt = c => !c ? '' : c.k === 'e' ? c.v.replace(/^(.).*(@.*)$/, (m, a, b) => a + '***' + b) : c.v.slice(0, 3) + '*****' + c.v.slice(-2);
function postJSON(host, pth, headers, body) {
  return new Promise((ok, no) => { const d = typeof body === 'string' ? body : JSON.stringify(body);
    const r = https.request({ host, path: pth, method: 'POST', headers: Object.assign({ 'Content-Length': Buffer.byteLength(d) }, headers) }, res => { let o = ''; res.on('data', c => o += c); res.on('end', () => res.statusCode < 300 ? ok(o) : no(new Error(host + ' ' + res.statusCode + ' ' + o.slice(0, 200)))); });
    r.on('error', no); r.setTimeout(10000, () => r.destroy(new Error('timeout'))); r.end(d); });
}
async function deliver(c, code) {
  const txt = 'Tu código de Gusanix es ' + code + '. Vence en 10 minutos. Si no lo pediste, ignóralo.';
  if (c.k === 'e' && process.env.RESEND_KEY) { await postJSON('api.resend.com', '/emails', { 'Authorization': 'Bearer ' + process.env.RESEND_KEY, 'Content-Type': 'application/json' }, { from: process.env.MAIL_FROM || 'Gusanix <onboarding@resend.dev>', to: [c.v], subject: 'Código de Gusanix: ' + code, text: txt }); return true; }
  if (c.k === 'p' && process.env.TWILIO_SID && process.env.TWILIO_TOKEN && process.env.TWILIO_FROM) {
    await postJSON('api.twilio.com', '/2010-04-01/Accounts/' + process.env.TWILIO_SID + '/Messages.json', { 'Authorization': 'Basic ' + Buffer.from(process.env.TWILIO_SID + ':' + process.env.TWILIO_TOKEN).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' }, new URLSearchParams({ To: c.v, From: process.env.TWILIO_FROM, Body: txt }).toString()); return true; }
  console.log('[MODO PRUEBAS] código para ' + c.v + ': ' + code); return false;
}
// envía un código (propósito 'v' = verificar contacto, 'r' = recuperar). Devuelve {ok,wait,dev}
async function sendCode(key, purpose, c, ip) {
  const now = Date.now(), L = sendLog[ip] = (sendLog[ip] || []).filter(x => now - x < 600000);
  if (L.length >= 6) return { wait: 1 };
  const id = purpose + ':' + key, old = CODES[id]; if (old && now - old.t < 60000) return { wait: 1 };
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0'); L.push(now);
  CODES[id] = { h: sha(code + id), exp: now + 600000, t: now, n: 0, c };
  let real = false; try { real = await deliver(c, code); } catch (e) { console.log('Error enviando código:', e.message); }
  return { ok: 1, dev: process.env.GX_DEV === '1' ? code : undefined, real };
}
function checkCode(key, purpose, code) {
  const id = purpose + ':' + key, o = CODES[id]; if (!o || Date.now() > o.exp) { delete CODES[id]; return null; }
  if (++o.n > 5) { delete CODES[id]; return null; }
  if (!same(o.h, sha(String(code || '').replace(/\D/g, '') + id))) return null;
  delete CODES[id]; return o.c;
}
setInterval(() => { const n = Date.now(); for (const k in CODES) if (n > CODES[k].exp) delete CODES[k]; }, 300000).unref();

// ---------- Verificación de celular con Firebase Auth (SMS gestionado por Firebase) ----------
// El navegador pide y confirma el SMS con Firebase; el servidor solo comprueba la firma del token (no necesita claves secretas).
const UNLOCK = process.env.UNLOCK_ALL !== '0';   // por ahora todas las apariencias están desbloqueadas; UNLOCK_ALL=0 exige compra en línea
const FB_PROJECT = process.env.FB_PROJECT || 'gusanix-b5829';
let FBK = { exp: 0, keys: {} };
function getJSON(url) { return new Promise((ok, no) => https.get(url, res => { let o = ''; res.on('data', c => o += c); res.on('end', () => { try { ok(JSON.parse(o)); } catch (e) { no(e); } }); }).on('error', no).setTimeout(10000, function () { this.destroy(new Error('timeout')); })); }
async function fbKeys() {
  if (process.env.FB_TEST_KEYS) return JSON.parse(process.env.FB_TEST_KEYS);
  if (Date.now() < FBK.exp) return FBK.keys;
  FBK = { exp: Date.now() + 3600000, keys: await getJSON('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com') }; return FBK.keys;
}
async function fbVerify(idt, kind) {
  try {
    const [h, p, sg] = String(idt || '').split('.'); if (!h || !p || !sg) return null;
    const H = JSON.parse(Buffer.from(h, 'base64url')), P = JSON.parse(Buffer.from(p, 'base64url')), pem = (await fbKeys())[H.kid];
    if (H.alg !== 'RS256' || !pem) return null;
    if (!crypto.createVerify('RSA-SHA256').update(h + '.' + p).verify(pem, Buffer.from(sg, 'base64url'))) return null;
    const n = Date.now() / 1000;
    if (P.aud !== FB_PROJECT || P.iss !== 'https://securetoken.google.com/' + FB_PROJECT || !P.sub || P.exp < n || P.iat > n + 60) return null;
    if (kind === 'email') { if (!P.firebase || P.firebase.sign_in_provider !== 'password' || P.email_verified !== true || !/^[^\s@]{1,64}@[^\s@]{1,190}\.[A-Za-z]{2,}$/.test(P.email || '')) return null; P.email = P.email.toLowerCase(); return P; }
    if (!P.firebase || P.firebase.sign_in_provider !== 'phone' || !/^\+\d{8,15}$/.test(P.phone_number || '')) return null;
    return P;
  } catch (e) { return null; }
}

const server = http.createServer((req, res) => {
  if (req.url === '/health') { res.end('ok v5 - IA por sala: ' + NBOT + ' - salas activas: ' + rooms.length); return; }
  if (req.url === '/' || req.url.startsWith('/?') || req.url === '/index.html') {
    fs.readFile(path.join(__dirname, 'index.html'), (e, d) => { if (e) { res.writeHead(404); res.end('Falta index.html'); } else { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache, must-revalidate' }); res.end(d); } });
    return;
  }
  res.writeHead(404); res.end('No encontrado');
});

// ---------- Mundo compartido por sala: bots IA (30), comida y poderes ----------
const WS = 7200, C = 3600, R = 3500, NBOT = process.env.NBOT !== undefined && process.env.NBOT !== '' ? Math.max(0, +process.env.NBOT || 0) : 30, NPOW = 24;
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
const PK = [[0, 3], [1, 3], [2, 3], [3, 3], [4, 1.5], [5, .7], [6, 1], [7, 1], [8, 1.5], [9, 1], [10, 1.2], [11, 1.3]];   // 0 velocidad, 1 aspiradora, 2 lupa, 3-5 puntos x2/x5/x10, 6 jardín, 7 piñata, 8 escudo, 9 manos (sin mordisco en línea)
function chain(w) {const s=w.segs,sd=rad(w)*.5,h=s[0];let T=w.tr;if(!T){T=w.tr=[];for(let i=s.length-1;i>=0;i--)T.push({x:s[i].x,y:s[i].y})}
const L=T[T.length-1];if(!L||(h.x-L.x)**2+(h.y-L.y)**2>=2.25)T.push({x:h.x,y:h.y});
const n=nseg(w);while(s.length<n){const q=s[s.length-1];s.push({x:q.x,y:q.y})}while(s.length>n)s.pop();
let acc=0,k=T.length-1,px=h.x,py=h.y,i=1;
while(i<s.length&&k>=0){const q=T[k],dx=q.x-px,dy=q.y-py,d=Math.sqrt(dx*dx+dy*dy);if(acc+d>=sd){const f=d>0?(sd-acc)/d:0;px+=dx*f;py+=dy*f;s[i].x=px;s[i].y=py;i++;acc=0}else{acc+=d;px=q.x;py=q.y;k--}}
for(;i<s.length;i++){s[i].x=px;s[i].y=py}
if(k>40)T.splice(0,k-8)}
const HL = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 22, 23, 24], TL = [10, 11, 12, 13, 14, 15, 16, 27], GL = [17, 18, 19, 20, 21, 25, 26];
function newBot(r) {
  const [x, y] = rp(500), a = rnd(0, 6.28);
  const b = { id: 'b' + (++r.nb), name: BN[Math.random() * BN.length | 0], ci: Math.random() * 8 | 0, pi: Math.random() * 9 | 0, m: rnd(15, 45), ang: a, tang: a, alive: 1, tmr: Math.random() * 15 | 0, tgt: null, tt: 0, segs: [], e: [], q: 0, ne: 0, isNew: 1, sent: 0, rt: 0, z: [Math.random() < .45 ? HL[Math.random() * HL.length | 0] : -1, Math.random() < .4 ? TL[Math.random() * TL.length | 0] : -1, Math.random() < .3 ? GL[Math.random() * GL.length | 0] : -1] };
  for (let i = 0; i < nseg(b); i++) b.segs.push({ x: x - Math.cos(a) * i * rad(b) * .5, y: y - Math.sin(a) * i * rad(b) * .5 });
  return b;
}
function newPow(r) { let s = PK.reduce((t, p) => t + p[1], 0) * Math.random(), i = 0; while (i < PK.length - 1 && s > PK[i][1]) { s -= PK[i][1]; i++; } const q = rp(150); return { id: 'w' + (++r.np), x: Math.round(q[0]), y: Math.round(q[1]), k: PK[i][0] }; }
function mkRoom() { const r = { peers: new Map(), bots: [], orbs: new Map(), off: new Map(), ig: new Map(), pows: [], left: [], nb: 0, np: 0, tk: 0 }; for (let i = 0; i < NBOT; i++) r.bots.push(newBot(r)); for (let i = 0; i < NPOW; i++) r.pows.push(newPow(r)); return r; }
const isGone = (r, f, now) => f.o ? !!f.gone : (r.off.get(f.id) || 0) > now;
function aiB(r, b, now, W) {
  const h = b.segs[0], rr = rad(b); b.tmr++;
  if (b.agg == null) b.agg = Math.random() < .5 ? 1 : 0;
  if (!b.wp || Math.hypot(b.wp.x - h.x, b.wp.y - h.y) < 260 || b.tmr % 900 == 0) { const q = rp(350); b.wp = { x: q[0], y: q[1] }; }
  if (b.tgt) { b.tt++; const g = b.tgt; if (b.tt > 140 || (b.tt > 30 && Math.hypot(g.x - h.x, g.y - h.y) < 170)) { r.ig.set(g.id, now + 15000); b.tgt = null; b.tt = 0; } }
  if (!b.tgt || isGone(r, b.tgt, now) || b.tmr % 15 == 0) {
    let best = -1, bf = null; const RA = 650 + rr * 5;
    const test = f => { if ((r.ig.get(f.id) || 0) > now || Math.hypot(f.x - C, f.y - C) > R - 140) return; const dx = f.x - h.x, dy = f.y - h.y; if (Math.abs(dx) > RA || Math.abs(dy) > RA) return; const s = f.v * (f.o ? 3 : 1) / (Math.sqrt(dx * dx + dy * dy) + 60); if (s > best) { best = s; bf = f; } };
    for (const c of cells) if ((r.off.get(c.id) || 0) <= now) test(c);
    for (const o of r.orbs.values()) test(o);
    if (bf !== b.tgt) b.tt = 0; b.tgt = bf;
  }
  // caza: los agresivos buscan cerrarle el paso a un gusano cercano que no sea más grande
  if (b.hunt && (b.hunt.until < now || !W.includes(b.hunt.o) || b.hunt.o.alive === 0)) b.hunt = null;
  if (b.agg && !b.hunt && b.tmr % 20 == 0 && Math.random() < .35) {
    let bo = null, bd = 760;
    for (const o of W) { if (o === b || o.m > b.m * 1.15) continue; const d = Math.hypot(o.segs[0].x - h.x, o.segs[0].y - h.y) * (o.human ? .7 : 1); if (d < bd) { bd = d; bo = o; } }
    if (bo) b.hunt = { o: bo, until: now + 6000 };
  }
  let vx = Math.cos(b.ang) * .3, vy = Math.sin(b.ang) * .3;
  if (b.hunt) {
    const o = b.hunt.o, oh = o.segs[0], d0 = Math.hypot(oh.x - h.x, oh.y - h.y), lead = Math.min(480, d0 * .8 + rad(o) * 4), tx = oh.x + Math.cos(o.ang || 0) * lead, ty = oh.y + Math.sin(o.ang || 0) * lead, dx = tx - h.x, dy = ty - h.y, d = Math.hypot(dx, dy) || 1;
    vx += dx / d * 2; vy += dy / d * 2;
  } else if (b.tgt) { const tg = b.tgt, dx = tg.x - h.x, dy = tg.y - h.y, d = Math.hypot(dx, dy) || 1; vx += dx / d; vy += dy / d; }
  else { const dx = b.wp.x - h.x, dy = b.wp.y - h.y, d = Math.hypot(dx, dy) || 1; vx += dx / d * 1.2; vy += dy / d * 1.2; }
  { const dx = h.x - C, dy = h.y - C, d = Math.hypot(dx, dy) || 1, e = R - d; if (e < 170) { const k = (1 - e / 170) * 3; vx -= dx / d * k; vy -= dy / d * k; } }
  for (const o of W) {   // separación suave entre bots para que se repartan por el mapa
    if (o === b || o.human) continue; const oh = o.segs[0], dx = h.x - oh.x, dy = h.y - oh.y, d2 = dx * dx + dy * dy;
    if (d2 < 520 * 520 && !(b.hunt && b.hunt.o === o)) { const d = Math.sqrt(d2) || 1, k = (1 - d / 520) * 1.1; vx += dx / d * k; vy += dy / d * k; }
  }
  for (const o of W) {
    if (o === b) continue; const or = rad(o), oh = o.segs[0], D = rr + or + 50, reach = o.segs.length * or * .5 + D;
    if (Math.abs(h.x - oh.x) > reach || Math.abs(h.y - oh.y) > reach) continue;
    for (let i = 0; i < o.segs.length; i += 2) { const s = o.segs[i], dx = h.x - s.x, dy = h.y - s.y, d2 = dx * dx + dy * dy; if (d2 < D * D) { const d = Math.sqrt(d2) || 1, k = (1 - d / D) * (1 - d / D) * 3.2; vx += dx / d * k; vy += dy / d * k; } }
  }
  b.tang = Math.atan2(vy, vx);
}
function mv(b) {
  const d = b.tang - b.ang, df = Math.atan2(Math.sin(d), Math.cos(d)), tr = .11 / (1 + rad(b) * .02);
  b.ang += Math.max(-tr, Math.min(tr, df)); const h = b.segs[0]; const k = Math.max(.7, 1 / (1 + Math.max(0, rad(b) - 10) * .008)); h.x += Math.cos(b.ang) * 2.7 * k; h.y += Math.sin(b.ang) * 2.7 * k; chain(b);
}
function rec(b, id) { b.e.push([id, ++b.q]); if (b.e.length > 12) b.e.shift(); b.ne = 1; }
function eatB(r, b, now) {
  const h = b.segs[0], rr = rad(b);
  for (const c of cells) { if (Math.abs(h.x - c.x) > 60 || Math.abs(h.y - c.y) > 60 || (r.off.get(c.id) || 0) > now) continue; const dx = h.x - c.x, dy = h.y - c.y; if (dx * dx + dy * dy < (rr + c.sz * .4 + 4) ** 2) { b.m += c.v; r.off.set(c.id, now + 25000); rec(b, c.id); } }
  for (const [id, o] of r.orbs) { if (Math.abs(h.x - o.x) > 60 || Math.abs(h.y - o.y) > 60) continue; const dx = h.x - o.x, dy = h.y - o.y; if (dx * dx + dy * dy < (rr + o.sz * .4 + 4) ** 2) { b.m += o.v; o.gone = 1; r.orbs.delete(id); rec(b, id); } }
}
const angd = (a, b) => Math.atan2(Math.sin(a - b), Math.cos(a - b));
function loses(a, b) {
  const A = a.segs[0], B = b.segs[0], g = Math.atan2(B.y - A.y, B.x - A.x), ga = Math.abs(angd(a.ang, g)), gb = Math.abs(angd(b.ang, g + Math.PI));
  if (Math.abs(ga - gb) >= .349) return ga > gb;
  const ia = String(a.id), ib = String(b.id), k = (ia < ib ? ia + '|' + ib : ib + '|' + ia) + Math.round((A.x + B.x) / 1000) + Math.round((A.y + B.y) / 1000);
  let s = 0; for (let i = 0; i < k.length; i++) s = (s * 31 + k.charCodeAt(i)) >>> 0;
  return (s & 1) ? ia < ib : ia >= ib;
}
function hitB(b, W) {
  const h = b.segs[0], rr = rad(b); if (Math.hypot(h.x - C, h.y - C) > R - rr) return { by: null };
  for (const o of W) {
    if (o === b) continue; const or = rad(o), lim = rr * .7 + or * .8, oh = o.segs[0], reach = lim + o.segs.length * or * .5 + 10;
    if (Math.abs(h.x - oh.x) > reach || Math.abs(h.y - oh.y) > reach) continue;
    if (Math.hypot(h.x - oh.x, h.y - oh.y) < lim) { if (o.human) continue; if (loses(b, o)) return { by: o.id }; continue; }
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
function botG(b, full) { const g = { x: Math.round(b.segs[0].x), y: Math.round(b.segs[0].y), a: +b.ang.toFixed(2), m: Math.round(b.m), b: 0, al: 1 }; if (full) { g.n = b.name; g.c = b.ci; g.p = b.pi; g.z = b.z; g.e = b.e; g.q = b.q; } return g; }
function simulate(r, now) {
  const W = [];
  for (const [id, e] of r.peers) {   // cuerpos de jugadores reconstruidos desde la cabeza
    const g = e.g; if (!g || !g.al) { e.bd = null; continue; }
    const x = +g.x || 0, y = +g.y || 0; if (!e.bd) e.bd = { id, m: 10, segs: [{ x, y }] };
    const bd = e.bd; bd.human = 1; bd.ang = +g.a || 0; bd.m = Math.min(5000, Math.max(10, +g.m || 10)); const h = bd.segs[0];
    const ex = (g.b ? 4.6 : 2.7) * 8, tx = x + Math.cos(bd.ang) * ex, ty = y + Math.sin(bd.ang) * ex;
    if ((h.x - tx) ** 2 + (h.y - ty) ** 2 > 250000) { h.x = tx; h.y = ty; } else { h.x += (tx - h.x) * .7; h.y += (ty - h.y) * .7; }
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

const sStart = n => Date.UTC(2026, 11 + n - 1, 1, 5), SEASKIN = { 1: 9 };   // temporada 1 = diciembre 2026 (hora de Bogotá)
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
  ws.id = 'h' + rid(4); ws.u = null; ws.room = null; ws.n = 0; ws.lt = Date.now();
  ws.on('message', async raw => {
    const now = Date.now(); if (now - ws.lt > 1000) { ws.lt = now; ws.n = 0; } if (++ws.n > 40) return;
    let m; try { m = JSON.parse(raw); } catch (e) { return; }
    if (!m || typeof m.t !== 'string') return;
    const ctInfo = U => U.ct ? { ct: maskCt(U.ct), cv: U.ct.ok ? 1 : 0 } : { ct: '', cv: 0 };
    const auth = k => { ws.u = DB.users[k].name; return Object.assign({ t: 'authed', u: ws.u, tok: issue(k), data: DB.users[k].data || null }, ctInfo(DB.users[k])); };
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
        const a = auth(k); a.rc = rc;
        const c0 = m.c ? normCt(m.c) : null;
        if (c0) { DB.users[k].ct = { k: c0.k, v: c0.v, ok: 0 }; saveDB(); const r = await sendCode(k, 'v', c0, ip); Object.assign(a, ctInfo(DB.users[k])); a.sent = r.ok ? 1 : 0; if (r.dev) a.dev = r.dev; }
        send(ws, a); break;
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
      case 'ctset': {   // vincular o cambiar correo/celular (requiere sesión); envía código de verificación
        if (!ws.u) return; const k = ws.u.toLowerCase(), U = DB.users[k], c = normCt(m.c);
        if (!c) return send(ws, { t: 'ctr', e: 'Escribe un correo válido o un celular con código de país (ej: +573001234567)' });
        const r = await sendCode(k, 'v', c, ip); if (r.wait) return send(ws, { t: 'ctr', e: 'Espera un minuto antes de pedir otro código' });
        U.ct = { k: c.k, v: c.v, ok: 0 }; saveDB(); send(ws, { t: 'ctr', sent: 1, ct: maskCt(U.ct), cv: 0, dev: r.dev, real: r.real ? 1 : 0 }); break;
      }
      case 'ctok': {    // confirmar el código recibido
        if (!ws.u) return; const k = ws.u.toLowerCase(), U = DB.users[k];
        if (blocked(ip)) return send(ws, { t: 'ctr', e: 'Demasiados intentos. Espera unos minutos.' });
        const c = U.ct && checkCode(k, 'v', m.code);
        if (!c || c.v !== U.ct.v) { fail(ip); return send(ws, { t: 'ctr', e: 'Código incorrecto o vencido' }); }
        U.ct.ok = 1; saveDB(); send(ws, { t: 'ctr', ok: 1, ct: maskCt(U.ct), cv: 1 }); break;
      }
      case 'ctdel': { if (!ws.u) return; const U = DB.users[ws.u.toLowerCase()]; delete U.ct; delete CODES['v:' + ws.u.toLowerCase()]; saveDB(); send(ws, { t: 'ctr', del: 1, ct: '', cv: 0 }); break; }
      case 'rq': {      // olvidé mi contraseña: pedir código al contacto verificado (la respuesta nunca revela si la cuenta existe)
        const k = String(m.u || '').toLowerCase(), U = DB.users[k];
        if (blocked(ip)) return send(ws, { t: 'err', m: 'Demasiados intentos. Espera unos minutos.' });
        let r = {}; if (U && U.ct && U.ct.ok) r = await sendCode(k, 'r', U.ct, ip); else if (!sendLog[ip] || sendLog[ip].length < 6) (sendLog[ip] = sendLog[ip] || []).push(Date.now());
        if (r.wait) return send(ws, { t: 'rqr', e: 'Espera un minuto antes de pedir otro código' });
        send(ws, { t: 'rqr', ok: 1, dev: r.dev }); break;
      }
      case 'rv': {      // cambiar contraseña con el código recibido
        const { p, k } = cred(); const U = DB.users[k];
        if (blocked(ip)) return send(ws, { t: 'err', m: 'Demasiados intentos. Espera unos minutos.' });
        if (p.length < 6 || p.length > 64) return send(ws, { t: 'err', m: 'La nueva contraseña debe tener al menos 6 caracteres' });
        const c = U && U.ct && U.ct.ok ? checkCode(k, 'r', m.code) : null;
        if (!c || c.v !== U.ct.v) { fail(ip); return send(ws, { t: 'err', m: 'Código incorrecto o vencido' }); }
        const rc = rcode(); U.salt = rid(8); U.hash = scrypt(p, U.salt); U.rs = rid(8); U.rh = scrypt(normRc(rc), U.rs);
        for (const h of U.toks || []) delete TOK[h]; U.toks = [];
        const a = auth(k); a.rc = rc; send(ws, a); break;
      }
      case 'ctfb': {    // vincular celular ya verificado por Firebase
        if (!ws.u) return; const k = ws.u.toLowerCase(), U = DB.users[k];
        if (blocked(ip)) return send(ws, { t: 'ctr', e: 'Demasiados intentos. Espera unos minutos.' });
        const P = await fbVerify(m.idt); if (!P) { fail(ip); return send(ws, { t: 'ctr', e: 'No se pudo verificar el celular. Intenta de nuevo.' }); }
        U.ct = { k: 'p', v: P.phone_number, ok: 1 }; saveDB(); send(ws, { t: 'ctr', ok: 1, ct: maskCt(U.ct), cv: 1 }); break;
      }
      case 'rfb': {     // recuperar contraseña con celular verificado por Firebase
        const { p, k } = cred(); const U = DB.users[k];
        if (blocked(ip)) return send(ws, { t: 'err', m: 'Demasiados intentos. Espera unos minutos.' });
        if (p.length < 6 || p.length > 64) return send(ws, { t: 'err', m: 'La nueva contraseña debe tener al menos 6 caracteres' });
        const P = await fbVerify(m.idt);
        if (!P || !U || !U.ct || !U.ct.ok || U.ct.k !== 'p' || U.ct.v !== P.phone_number) { fail(ip); return send(ws, { t: 'err', m: 'Ese celular no está vinculado a esa cuenta' }); }
        const rc = rcode(); U.salt = rid(8); U.hash = scrypt(p, U.salt); U.rs = rid(8); U.rh = scrypt(normRc(rc), U.rs);
        for (const h of U.toks || []) delete TOK[h]; U.toks = [];
        const a = auth(k); a.rc = rc; send(ws, a); break;
      }
      case 'ctem': {    // vincular correo confirmado por Firebase (enlace mágico)
        if (!ws.u) return; const k = ws.u.toLowerCase(), U = DB.users[k];
        if (blocked(ip)) return send(ws, { t: 'ctr', e: 'Demasiados intentos. Espera unos minutos.' });
        const P = await fbVerify(m.idt, 'email'); if (!P) { fail(ip); return send(ws, { t: 'ctr', e: 'No se pudo verificar el correo. Pide un enlace nuevo.' }); }
        U.ct = { k: 'e', v: P.email, ok: 1 }; saveDB(); send(ws, { t: 'ctr', ok: 1, ct: maskCt(U.ct), cv: 1 }); break;
      }
      case 'rem': {     // recuperar contraseña con correo confirmado por Firebase
        const { p, k } = cred(); const U = DB.users[k];
        if (blocked(ip)) return send(ws, { t: 'err', m: 'Demasiados intentos. Espera unos minutos.' });
        if (p.length < 6 || p.length > 64) return send(ws, { t: 'err', m: 'La nueva contraseña debe tener al menos 6 caracteres' });
        const P = await fbVerify(m.idt, 'email');
        if (!P || !U || !U.ct || !U.ct.ok || U.ct.k !== 'e' || U.ct.v !== P.email) { fail(ip); return send(ws, { t: 'err', m: 'Ese correo no está vinculado a esa cuenta' }); }
        const rc = rcode(); U.salt = rid(8); U.hash = scrypt(p, U.salt); U.rs = rid(8); U.rh = scrypt(normRc(rc), U.rs);
        for (const h of U.toks || []) delete TOK[h]; U.toks = [];
        const a = auth(k); a.rc = rc; send(ws, a); break;
      }
      case 'tok': {
        const k = TOK[sha(String(m.tok || ''))];
        if (!k || !DB.users[k]) return send(ws, { t: 'err', m: 'Sesión vencida' });
        ws.u = DB.users[k].name; send(ws, Object.assign({ t: 'authed', u: ws.u, tok: m.tok, data: DB.users[k].data || null }, ctInfo(DB.users[k]))); break;
      }
      case 'out': { const h = sha(String(m.tok || '')), k = TOK[h]; if (k) { delete TOK[h]; DB.users[k].toks = (DB.users[k].toks || []).filter(x => x !== h); saveDB(); } leave(ws); ws.u = null; break; }
      case 'save': {
        if (!ws.u) return; const s = JSON.stringify(m.data || null);
        if (s.length > 20000) return;
        const U = DB.users[ws.u.toLowerCase()], now = Date.now(), nd = JSON.parse(s), old = (U.data && U.data.SV) || {};
        if (nd && nd.SV && typeof nd.SV === 'object') {
          const v = nd.SV; v.sT = v.sT && typeof v.sT === 'object' ? v.sT : {}; v.sB = v.sB && typeof v.sB === 'object' ? v.sB : {};
          v.own = Array.isArray(v.own) ? v.own.filter(x => Number.isInteger(x)) : [0, 1, 2]; v.claimed = Array.isArray(v.claimed) ? v.claimed.filter(x => typeof x === 'string') : [];
          v.oa = Array.isArray(v.oa) ? [...new Set(v.oa.filter(x => Number.isInteger(x) && x >= 0 && x < 40))] : [];
          if (nd.skin) { for (const k of ['h', 't', 'g']) { const q = nd.skin[k]; nd.skin[k] = Number.isInteger(q) && q >= 0 && q < 40 && (UNLOCK || v.oa.includes(q)) ? q : -1; } if (!Number.isInteger(nd.skin.p) || nd.skin.p < 0 || nd.skin.p > 9) nd.skin.p = 0; }
          const wall = U.lastSave ? (now - U.lastSave) / 1000 + 90 : 86400;   // el tiempo acreditado no puede superar el tiempo real transcurrido
          for (const n of Object.keys(v.sT)) { const o = (old.sT && +old.sT[n]) || 0; let x = +v.sT[n] || 0; x = Math.min(x, Math.max(0, (now - sStart(+n)) / 1000), o + wall); v.sT[n] = x > 0 ? Math.round(x) : 0; }
          for (const n of Object.keys(v.sB)) { let x = Math.min(+v.sB[n] || 0, 3600, v.sT[n] || 0); v.sB[n] = x > 0 ? Math.round(x) : 0; }
          for (const n in SEASKIN) { const sk = SEASKIN[n]; if (v.own.includes(sk) && (v.sT[n] || 0) + (v.sB[n] || 0) < 14400 - 60) { v.own = v.own.filter(x => x !== sk); v.claimed = v.claimed.filter(x => x !== 's' + n + 'c10'); if (nd.skin && nd.skin.p === sk) nd.skin.p = 0; } }
          U.lastSave = now;
        }
        U.data = nd; saveDB(); break;
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
      case 'claim': {
        const r = ws.room, e = r && r.peers.get(ws.id); if (!e || !e.g || !e.g.al || !e.bd) return;
        const now = Date.now(), v = String(m.v || ''); if (e.killedAt && now - e.killedAt < 900) return;
        const near = (x, y, rr) => { const lim = rr * .7 + rad(e.bd) * .8 + 110; for (let i = 3; i < e.bd.segs.length; i += 2) { const s = e.bd.segs[i], dx = x - s.x, dy = y - s.y; if (dx * dx + dy * dy < lim * lim) return true; } return false; };
        const bot = r.bots.find(b => b.id === v);
        if (bot) { if (bot.alive && near(bot.segs[0].x, bot.segs[0].y, rad(bot))) killB(r, bot, ws.id); break; }
        const ve = r.peers.get(v); if (!ve || !ve.g || !ve.g.al || ve.dead || ve.g.ch || (ve.killedAt && now - ve.killedAt < 900) || (ve.brkAt && now - ve.brkAt < 1500) || !ve.bd) break;
        if (near(ve.bd.segs[0].x, ve.bd.segs[0].y, rad(ve.bd))) { ve.killedAt = now; send(ve.ws, { t: 'killed', by: ws.id }); }
        break;
      }
      case 'mord': {   // mordisco: cada uno quita 6% de masa (ya no parte el cuerpo)
        const r = ws.room, e = r && r.peers.get(ws.id); if (!e || !e.g || !e.g.al || !e.bd || e.dead) return;
        const now = Date.now(); if (e.mordAt && now - e.mordAt < 600) return;
        const id = String(m.v || ''), n = 1; let hh = e.bd.segs[0]; { const px = +m.x, py = +m.y; if (isFinite(px) && isFinite(py) && Math.hypot(px - hh.x, py - hh.y) < 450) hh = { x: px, y: py }; }
        const nearB = o => { const lim = rad(o) * .8 + rad(e.bd) * .7 + 100; for (let i = 0; i < o.segs.length; i += 2) { const q = o.segs[i], dx = hh.x - q.x, dy = hh.y - q.y; if (dx * dx + dy * dy < lim * lim) return true; } return false; };
        const bot = r.bots.find(b => b.id === id);
        if (bot) {
          if (!bot.alive || !nearB(bot)) break; e.mordAt = now;
          if (n < 3) { bot.m = Math.max(10, bot.m * .94); break; }
          const i = Math.max(2, Math.min(bot.segs.length - 1, +m.i || 2)); if (bot.segs.length < 6 || i >= bot.segs.length) break;
          const cut = bot.segs.splice(i), tot = i + cut.length, v = Math.max(1, bot.m * (cut.length / tot) * .7 / (cut.length / 2)), list = [];
          for (let j = 0; j < cut.length && list.length < 60; j += 2) list.push([Math.round(cut[j].x), Math.round(cut[j].y)]);
          bot.m = Math.max(10, bot.m * i / tot); bot.tr = null; const own = bot.id + 'k' + (++r.nb); addOrbs(r, own, list, v, bot.ci);
          const ol = list.map((q, j) => ['o' + own + '_' + j, q[0], q[1], v, bot.ci]); for (const pe of r.peers.values()) send(pe.ws, { t: 'world', orbs: ol });
          break;
        }
        const ve = r.peers.get(id); if (!ve || !ve.g || !ve.g.al || ve.dead || !ve.bd || id === ws.id) break;
        if (!nearB(ve.bd)) break; e.mordAt = now;
        if (n >= 3) send(ve.ws, { t: 'cut', i: Math.max(2, Math.min(260, +m.i || 6)), by: ws.id }); else send(ve.ws, { t: 'chomp', n, i: Math.max(2, Math.min(260, +m.i || 2)), by: ws.id });
        break;
      }
      case 'hit': {
        const r = ws.room, e = r && r.peers.get(ws.id); if (!e || !e.g || !e.g.al || !e.bd || e.dead) return;
        const now = Date.now(), v = String(m.v || ''); if (e.killedAt && now - e.killedAt < 900) return; if (e.brkAt && now - e.brkAt < 1500) return;
        const ve = r.peers.get(v);
        if (!ve || (ve.killedAt && now - ve.killedAt < 900)) return; // el otro ya murió: yo sobrevivo
        if (!ve.bd) return;
        const lim = rad(ve.bd) * .8 + rad(e.bd) * .7 + 70, h = e.bd.segs[0];
        let ok = false; for (let i = 0; i < ve.bd.segs.length && !ok; i += 2) { const s = ve.bd.segs[i], dx = h.x - s.x, dy = h.y - s.y; if (dx * dx + dy * dy < lim * lim) ok = true; }
        if (!ok) return;
        e.killedAt = now; send(ws, { t: 'killed', by: v });
        break;
      }
      case 'brk': {   // un gusano atrapado más grande rompe el anillo del que lo rodea
        const r = ws.room, e = r && r.peers.get(ws.id); if (!e || !e.g || !e.g.al || !e.bd) return;
        const now = Date.now(); if (e.brkAt && now - e.brkAt < 800) return;
        const ve = r.peers.get(String(m.v || '')); if (!ve || !ve.g || !ve.g.al || !ve.bd) return;
        const lim = rad(ve.bd) * .8 + rad(e.bd) * .7 + 90, h = e.bd.segs[0]; let ok = false;
        for (let i = 0; i < ve.bd.segs.length && !ok; i += 2) { const q = ve.bd.segs[i], dx = h.x - q.x, dy = h.y - q.y; if (dx * dx + dy * dy < lim * lim) ok = true; }
        if (!ok) return; e.brkAt = now; send(ve.ws, { t: 'cut', i: Math.max(2, Math.min(260, +m.i || 6)), by: ws.id });
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
          const g = m.g; g.n = ws.u;
          { const dd = (DB.users[ws.u.toLowerCase()] || {}).data, sv0 = (dd && dd.SV) || {}, own = Array.isArray(sv0.own) ? sv0.own : [0, 1, 2], oa = Array.isArray(sv0.oa) ? sv0.oa : [];   // en línea solo se usan apariencias que la cuenta ya compró
            if ('p' in g && (!Number.isInteger(g.p) || g.p < 0 || g.p > 9 || !(UNLOCK || own.includes(g.p)))) g.p = 0;
            if (Array.isArray(g.z)) g.z = g.z.slice(0, 3).map(x => Number.isInteger(x) && x >= 0 && x < 40 && (UNLOCK || oa.includes(x)) ? x : -1); }
          onPres(r, ws.id, e, g, Date.now());
          e.g = Object.assign(e.g || {}, g); e.pg = Object.assign(e.pg || {}, g);
        }
        break;
      }
      case 'leave': leave(ws); break;
    }
  });
  ws.on('error', () => {});
  ws.alive = true; ws.on('pong', () => { ws.alive = true; });
  ws.on('close', () => { leave(ws); if (ws.u && online.get(ws.u) === ws) online.delete(ws.u); });
  ws.on('error', () => {});
});

setInterval(() => {
  const now = Date.now();
  for (const r of rooms) { try { simulate(r, now); if ((++r.tk) % 2 === 0) bcast(r); } catch (e) { console.error(e); } }
}, 50);

wss.on('error', e => console.log('wss error:', e && e.message)); server.on('error', e => console.log('http error:', e && e.message));
setInterval(() => { for (const c of wss.clients) { if (c.alive === false) { try { c.terminate(); } catch (e) {} continue; } c.alive = false; try { c.ping(); } catch (e) {} } }, 30000).unref();
server.listen(PORT, () => console.log('Gusanix en el puerto ' + PORT));
