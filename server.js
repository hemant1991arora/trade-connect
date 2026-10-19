import express from 'express';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const E = process.env;
const MODEL = E.MODEL || 'claude-sonnet-5-5';
const SECRET = E.SESSION_SECRET || '';
const DATA_DIR = path.resolve(E.DATA_DIR || './data');
const AUTO = E.AUTO_APPROVE === 'true';
const SITE = E.SITE_NAME || 'TradeConnect';
if (!E.ANTHROPIC_API_KEY) console.warn('! ANTHROPIC_API_KEY not set: internet auto-fill and image import will fail.');
if (SECRET.length < 16) { console.error('Set SESSION_SECRET (16+ random characters).'); process.exit(1); }
fs.mkdirSync(path.join(DATA_DIR, 'uploads'), { recursive: true });

/* ---------- database ---------- */
const db = new Database(path.join(DATA_DIR, 'market.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(email TEXT PRIMARY KEY, pass TEXT NOT NULL, role TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS suppliers(id TEXT PRIMARY KEY, user TEXT, status TEXT NOT NULL, verified INTEGER DEFAULT 0, company TEXT, city TEXT, category TEXT, btext TEXT, data TEXT NOT NULL, es TEXT, ee TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS products(id TEXT PRIMARY KEY, sid TEXT NOT NULL, name TEXT NOT NULL, category TEXT, price REAL, unit TEXT, moq TEXT, brand TEXT, description TEXT, image TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS enquiries(id TEXT PRIMARY KEY, sid TEXT NOT NULL, pid TEXT, pname TEXT, name TEXT, phone TEXT, email TEXT, qty TEXT, message TEXT, status TEXT DEFAULT 'new', created_at INTEGER);
CREATE INDEX IF NOT EXISTS ix_p ON products(sid); CREATE INDEX IF NOT EXISTS ix_e ON enquiries(sid);
`);
const hash = (pw) => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(pw, s, 64).toString('hex'); };
const verify = (pw, h) => { const [s, k] = h.split(':'); return crypto.timingSafeEqual(crypto.scryptSync(pw, s, 64), Buffer.from(k, 'hex')); };
if (!db.prepare("SELECT 1 FROM users WHERE role='admin'").get()) {
  if (!E.ADMIN_EMAIL || !E.ADMIN_PASSWORD) { console.error('Set ADMIN_EMAIL and ADMIN_PASSWORD for the first start.'); process.exit(1); }
  db.prepare('INSERT INTO users VALUES(?,?,?)').run(E.ADMIN_EMAIL.toLowerCase(), hash(E.ADMIN_PASSWORD), 'admin');
}

/* ---------- helpers ---------- */
const now = () => Date.now();
const id = () => crypto.randomUUID();
const str = (v, n) => String(v ?? '').trim().slice(0, n);
const SF = { company: 200, owner: 120, phone: 40, email: 160, website: 200, address: 400, city: 80, state: 80, country: 80, category: 100, about: 2000, gst: 20, year: 10 };
const validEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
const limits = new Map();
const limit = (key, max, ms) => { const t = limits.get(key) || { n: 0, at: now() }; if (now() - t.at > ms) { t.n = 0; t.at = now(); } t.n++; limits.set(key, t); return t.n > max; };
const like = (s) => '%' + s.replace(/[\\%_]/g, '\\$&') + '%';

function cleanSupplier(o, base = {}) {
  const d = { ...base };
  for (const k in SF) if (k in o) d[k] = str(o[k], SF[k]);
  if ('brands' in o) d.brands = (Array.isArray(o.brands) ? o.brands : String(o.brands || '').split(/[,;|\/]/)).map((b) => str(b, 60)).filter(Boolean).slice(0, 60);
  if (Array.isArray(o._auto)) d._auto = o._auto.filter((x) => x in SF || x === 'brands');
  d.brands = d.brands || [];
  return d;
}
const upS = db.prepare(`INSERT INTO suppliers(id,user,status,verified,company,city,category,btext,data,es,created_at) VALUES(@id,@user,@status,0,@company,@city,@category,@btext,@data,@es,@ts)
  ON CONFLICT(id) DO UPDATE SET company=@company,city=@city,category=@category,btext=@btext,data=@data`);
function saveSupplier(sid, d, extra = {}) {
  upS.run({ id: sid, user: extra.user ?? null, status: extra.status ?? 'pending', es: extra.es ?? null, ts: now(), company: d.company || '', city: d.city || '', category: d.category || '', btext: (d.brands || []).join(' '), data: JSON.stringify(d) });
}
const full = (r) => ({ ...JSON.parse(r.data), id: r.id, status: r.status, verified: !!r.verified, es: r.es, ee: r.ee, user: r.user });
const pub = (r, withContact) => {
  const d = JSON.parse(r.data);
  const o = { id: r.id, company: d.company, owner: d.owner, city: d.city, state: d.state, country: d.country, category: d.category, about: d.about, brands: d.brands || [], website: d.website, year: d.year, address: d.address, verified: !!r.verified };
  if (withContact) o.phone = d.phone;
  return o;
};

/* ---------- sessions ---------- */
const sign = (s) => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
const cookies = (req) => Object.fromEntries((req.headers.cookie || '').split(';').map((c) => c.trim().split('=')).filter((p) => p[0]));
function who(req) {
  const t = (cookies(req).sid || '').split('.');
  if (t.length === 3 && t[2] === sign(t[0] + '.' + t[1]) && +t[1] > now()) return db.prepare('SELECT email, role FROM users WHERE email=?').get(Buffer.from(t[0], 'base64url').toString()) || null;
  return null;
}
const attach = (req, res, next) => { req.user = who(req); next(); };
const need = (req, res, next) => (req.user ? next() : res.status(401).json({ error: 'Please sign in' }));
const supplierOnly = (req, res, next) => {
  const r = req.user && db.prepare('SELECT * FROM suppliers WHERE user=?').get(req.user.email);
  if (!r) return res.status(403).json({ error: 'Supplier account required' });
  req.sup = r; next();
};
const adminOnly = (req, res, next) => (req.user?.role === 'admin' ? next() : res.status(403).json({ error: 'Admins only' }));
function login(req, res, email, role) {
  const exp = now() + 30 * 864e5, body = Buffer.from(email).toString('base64url') + '.' + exp;
  res.setHeader('Set-Cookie', `sid=${body}.${sign(body)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30 * 86400}${req.secure ? '; Secure' : ''}`);
}

/* ---------- Claude ---------- */
async function claude(body) {
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': E.ANTHROPIC_API_KEY || '', 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: MODEL, max_tokens: 2500, ...body }), signal: AbortSignal.timeout(150000),
  });
  const j = await r.json();
  if (!r.ok) throw new Error(j.error?.message || 'API error ' + r.status);
  return j.content.filter((b) => b.type === 'text').map((b) => b.text).join('\n');
}
const parseJson = (t, o, c) => { const a = t.indexOf(o), b = t.lastIndexOf(c); if (a < 0 || b < a) throw new Error('No structured result returned'); return JSON.parse(t.slice(a, b + 1)); };
const EF = ['owner', 'phone', 'email', 'website', 'address', 'city', 'state', 'country', 'category', 'about'];
function merge(d, r, force) {
  const auto = new Set(d._auto || []);
  for (const k of EF) {
    const v = str(r[k], SF[k]);
    if (v && (!d[k] || (force && auto.has(k))) && d[k] !== v) { d[k] = v; auto.add(k); }
  }
  d.brands = d.brands || [];
  for (const x of Array.isArray(r.brands) ? r.brands : []) { const s = str(x, 60); if (s && !d.brands.some((y) => y.toLowerCase() === s.toLowerCase())) d.brands.push(s); }
  d._auto = [...auto];
  d.sources = (Array.isArray(r.sources) ? r.sources : []).filter((u) => /^https?:\/\//.test(u)).slice(0, 8);
  d.confidence = ['high', 'medium', 'low'].includes(r.confidence) ? r.confidence : 'low';
  d.enriched_at = now();
}
async function enrich({ sid, force }) {
  const row = db.prepare('SELECT * FROM suppliers WHERE id=?').get(sid); if (!row) return;
  try {
    const d = JSON.parse(row.data);
    const hint = [d.city && 'city: ' + d.city, d.website && 'website: ' + d.website, d.phone && 'phone: ' + d.phone].filter(Boolean).join(', ');
    const text = await claude({
      tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: 6 }],
      messages: [{ role: 'user', content: `Research the business "${d.company}"${hint ? ' (' + hint + ')' : ''}. Use web search to find its real, current details.\nReturn ONLY one JSON object: {"owner":"owner, founder or proprietor name","phone":"","email":"","website":"official website URL","address":"","city":"","state":"","country":"","category":"main business category","about":"2-3 sentence factual description","brands":["brands or product lines it deals in, distributes or makes"],"sources":["URLs the facts came from"],"confidence":"high|medium|low"}\nRules: only include facts found on web pages. Use "" or [] when not found. Never guess. If several businesses share this name and you cannot tell which is meant, return confidence "low" and empty fields.` }],
    });
    merge(d, parseJson(text, '{', '}'), force);
    saveSupplier(sid, d, { user: row.user, status: row.status });
    db.prepare("UPDATE suppliers SET es='done', ee=NULL WHERE id=?").run(sid);
  } catch (e) { db.prepare("UPDATE suppliers SET es='error', ee=? WHERE id=?").run(String(e.message).slice(0, 300), sid); }
}
const queue = []; let running = 0;
function enqueue(sid, force) {
  if (!queue.some((j) => j.sid === sid)) queue.push({ sid, force });
  db.prepare("UPDATE suppliers SET es='pending', ee=NULL WHERE id=?").run(sid); pump();
}
function pump() { while (running < 2 && queue.length) { running++; enrich(queue.shift()).finally(() => { running--; pump(); }); } }
db.prepare("SELECT id FROM suppliers WHERE es='pending'").all().forEach((r) => enqueue(r.id, false));

/* ---------- app ---------- */
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '8mb' }));
app.use('/uploads', express.static(path.join(DATA_DIR, 'uploads'), { setHeaders: (r) => r.setHeader('X-Content-Type-Options', 'nosniff') }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', attach);
app.get('/api/config', (req, res) => res.json({ site: SITE, autoApprove: AUTO }));

/* auth */
app.post('/api/login', (req, res) => {
  if (limit('login' + req.ip, 10, 9e5)) return res.status(429).json({ error: 'Too many attempts, try again in 15 minutes' });
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(str(req.body.email, 160).toLowerCase());
  if (!u || !verify(String(req.body.password || ''), u.pass)) return res.status(401).json({ error: 'Wrong email or password' });
  login(req, res, u.email); res.json({ email: u.email, role: u.role });
});
app.post('/api/logout', (req, res) => { res.setHeader('Set-Cookie', 'sid=; Path=/; Max-Age=0'); res.json({ ok: true }); });
app.post('/api/register', (req, res) => {
  if (limit('reg' + req.ip, 5, 36e5)) return res.status(429).json({ error: 'Too many sign-ups from this network, try later' });
  const b = req.body, email = str(b.email, 160).toLowerCase(), pw = String(b.password || '');
  if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email' });
  if (pw.length < 8) return res.status(400).json({ error: 'Password needs 8+ characters' });
  if (!str(b.company, 200)) return res.status(400).json({ error: 'Company name is required' });
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) return res.status(400).json({ error: 'This email is already registered' });
  const sid = id(), d = cleanSupplier({ company: b.company, phone: b.phone, city: b.city, email });
  db.transaction(() => { db.prepare("INSERT INTO users VALUES(?,?,'supplier')").run(email, hash(pw)); saveSupplier(sid, d, { user: email, status: AUTO ? 'approved' : 'pending' }); })();
  enqueue(sid, false); login(req, res, email); res.json({ email, role: 'supplier' });
});
app.get('/api/me', (req, res) => {
  if (!req.user) return res.json(null);
  const r = db.prepare('SELECT * FROM suppliers WHERE user=?').get(req.user.email);
  res.json({ ...req.user, supplier: r ? full(r) : null });
});

/* public marketplace */
app.get('/api/categories', (req, res) => res.json(db.prepare(`SELECT category name, COUNT(*) n FROM (
  SELECT p.category FROM products p JOIN suppliers s ON s.id=p.sid WHERE s.status='approved' AND p.category<>''
  UNION ALL SELECT category FROM suppliers WHERE status='approved' AND category<>'') GROUP BY category ORDER BY n DESC LIMIT 30`).all()));
app.get('/api/search', (req, res) => {
  const type = req.query.type === 'suppliers' ? 'suppliers' : 'products';
  const terms = str(req.query.q, 100).split(/\s+/).filter(Boolean).slice(0, 6), city = str(req.query.city, 80), cat = str(req.query.cat, 100);
  const page = Math.max(0, parseInt(req.query.page) || 0), PS = 24, args = [];
  let where = "s.status='approved'";
  const cols = type === 'products' ? ['p.name', 'p.category', 'p.brand', 'p.description', 's.company', 's.btext'] : ['s.company', 's.category', 's.btext', 'json_extract(s.data,\'$.about\')', '(SELECT group_concat(name) FROM products WHERE sid=s.id)'];
  for (const t of terms) { where += ' AND (' + cols.map((c) => c + " LIKE ? ESCAPE '\\'").join(' OR ') + ')'; cols.forEach(() => args.push(like(t))); }
  if (city) { where += " AND (s.city LIKE ? ESCAPE '\\' OR json_extract(s.data,'$.state') LIKE ? ESCAPE '\\')"; args.push(like(city), like(city)); }
  if (cat) { where += type === 'products' ? ' AND p.category=?' : ' AND (s.category=? OR EXISTS(SELECT 1 FROM products WHERE sid=s.id AND category=?))'; args.push(cat); if (type !== 'products') args.push(cat); }
  if (type === 'products') {
    const from = 'FROM products p JOIN suppliers s ON s.id=p.sid WHERE ' + where;
    const total = db.prepare('SELECT COUNT(*) n ' + from).get(...args).n;
    const items = db.prepare(`SELECT p.id,p.name,p.category,p.price,p.unit,p.moq,p.brand,p.image,s.id sid,s.company,s.city,s.verified ${from} ORDER BY s.verified DESC, p.created_at DESC LIMIT ${PS} OFFSET ${page * PS}`).all(...args);
    return res.json({ total, items: items.map((x) => ({ ...x, verified: !!x.verified })) });
  }
  const from = 'FROM suppliers s WHERE ' + where;
  const total = db.prepare('SELECT COUNT(*) n ' + from).get(...args).n;
  const rows = db.prepare(`SELECT s.*, (SELECT COUNT(*) FROM products WHERE sid=s.id) pc ${from} ORDER BY s.verified DESC, s.created_at DESC LIMIT ${PS} OFFSET ${page * PS}`).all(...args);
  res.json({ total, items: rows.map((r) => ({ ...pub(r, false), products: r.pc })) });
});
app.get('/api/supplier/:id', (req, res) => {
  const r = db.prepare("SELECT * FROM suppliers WHERE id=? AND status='approved'").get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Supplier not found' });
  res.json({ ...pub(r, true), products: db.prepare('SELECT id,name,category,price,unit,moq,brand,description,image FROM products WHERE sid=? ORDER BY created_at DESC').all(r.id) });
});
app.post('/api/enquiries', (req, res) => {
  const b = req.body;
  if (b.website) return res.json({ ok: true });
  if (limit('enq' + req.ip, 10, 36e5)) return res.status(429).json({ error: 'Too many enquiries, please try later' });
  const s = db.prepare("SELECT id FROM suppliers WHERE id=? AND status='approved'").get(b.sid);
  const name = str(b.name, 100), phone = str(b.phone, 20).replace(/[^\d+ -]/g, ''), email = str(b.email, 160);
  if (!s) return res.status(404).json({ error: 'Supplier not found' });
  if (!name || phone.replace(/\D/g, '').length < 8) return res.status(400).json({ error: 'Please enter your name and a valid phone number' });
  if (email && !validEmail(email)) return res.status(400).json({ error: 'Email looks invalid' });
  const p = b.pid ? db.prepare('SELECT name FROM products WHERE id=? AND sid=?').get(b.pid, s.id) : null;
  db.prepare('INSERT INTO enquiries(id,sid,pid,pname,name,phone,email,qty,message,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(id(), s.id, p ? b.pid : null, p?.name || null, name, phone, email, str(b.qty, 40), str(b.message, 1500), now());
  res.json({ ok: true });
});

/* supplier dashboard */
const mine = express.Router(); mine.use(need, supplierOnly);
mine.put('/supplier', (req, res) => {
  const d = cleanSupplier(req.body, JSON.parse(req.sup.data));
  if (!d.company) return res.status(400).json({ error: 'Company name is required' });
  saveSupplier(req.sup.id, d, { user: req.sup.user, status: req.sup.status });
  res.json(full(db.prepare('SELECT * FROM suppliers WHERE id=?').get(req.sup.id)));
});
mine.post('/enrich', (req, res) => { enqueue(req.sup.id, !!req.body.force); res.json({ ok: true }); });
const cleanP = (o) => {
  const price = o.price === '' || o.price == null ? null : Number(o.price);
  return { name: str(o.name, 200), category: str(o.category, 100), price: Number.isFinite(price) && price >= 0 ? price : null, unit: str(o.unit, 30), moq: str(o.moq, 30), brand: str(o.brand, 80), description: str(o.description, 2000), image: /^\/uploads\/[\w-]+\.(jpg|png|webp)$/.test(o.image || '') ? o.image : '' };
};
mine.get('/products', (req, res) => res.json(db.prepare('SELECT * FROM products WHERE sid=? ORDER BY created_at DESC').all(req.sup.id)));
mine.post('/products', (req, res) => {
  const p = cleanP(req.body); if (!p.name) return res.status(400).json({ error: 'Product name is required' });
  const pid = /^[\w-]{8,40}$/.test(req.body.id || '') ? req.body.id : id();
  db.prepare('INSERT OR REPLACE INTO products VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(pid, req.sup.id, p.name, p.category, p.price, p.unit, p.moq, p.brand, p.description, p.image, now());
  res.json({ id: pid });
});
mine.put('/products/:id', (req, res) => {
  const p = cleanP(req.body); if (!p.name) return res.status(400).json({ error: 'Product name is required' });
  db.prepare('UPDATE products SET name=?,category=?,price=?,unit=?,moq=?,brand=?,description=?,image=? WHERE id=? AND sid=?').run(p.name, p.category, p.price, p.unit, p.moq, p.brand, p.description, p.image, req.params.id, req.sup.id);
  res.json({ ok: true });
});
mine.delete('/products/:id', (req, res) => { db.prepare('DELETE FROM products WHERE id=? AND sid=?').run(req.params.id, req.sup.id); res.json({ ok: true }); });
mine.get('/enquiries', (req, res) => res.json(db.prepare('SELECT * FROM enquiries WHERE sid=? ORDER BY created_at DESC LIMIT 500').all(req.sup.id)));
mine.post('/enquiries/:id', (req, res) => {
  if (!['new', 'contacted', 'closed'].includes(req.body.status)) return res.status(400).json({ error: 'Bad status' });
  db.prepare('UPDATE enquiries SET status=? WHERE id=? AND sid=?').run(req.body.status, req.params.id, req.sup.id); res.json({ ok: true });
});
mine.post('/upload', (req, res) => {
  const { mediaType, data } = req.body, ext = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' }[mediaType];
  if (!ext || !data) return res.status(400).json({ error: 'Use a JPG, PNG or WebP image' });
  const buf = Buffer.from(data, 'base64'); if (buf.length > 2.5e6) return res.status(400).json({ error: 'Image is too large (max 2.5 MB)' });
  const name = id() + '.' + ext; fs.writeFileSync(path.join(DATA_DIR, 'uploads', name), buf); res.json({ url: '/uploads/' + name });
});
app.use('/api/me', mine);

/* admin */
const adm = express.Router(); adm.use(need, adminOnly);
adm.get('/suppliers', (req, res) => res.json(db.prepare(`SELECT s.*, (SELECT COUNT(*) FROM products WHERE sid=s.id) pc, (SELECT COUNT(*) FROM enquiries WHERE sid=s.id) ec FROM suppliers s ORDER BY (s.status='pending') DESC, s.created_at DESC LIMIT 1000`).all().map((r) => ({ ...full(r), pc: r.pc, ec: r.ec }))));
adm.post('/suppliers/:id', (req, res) => {
  if (req.body.status && ['pending', 'approved', 'rejected'].includes(req.body.status)) db.prepare('UPDATE suppliers SET status=? WHERE id=?').run(req.body.status, req.params.id);
  if ('verified' in req.body) db.prepare('UPDATE suppliers SET verified=? WHERE id=?').run(req.body.verified ? 1 : 0, req.params.id);
  res.json({ ok: true });
});
adm.delete('/suppliers/:id', (req, res) => {
  const r = db.prepare('SELECT user FROM suppliers WHERE id=?').get(req.params.id);
  db.transaction(() => { db.prepare('DELETE FROM products WHERE sid=?').run(req.params.id); db.prepare('DELETE FROM enquiries WHERE sid=?').run(req.params.id); db.prepare('DELETE FROM suppliers WHERE id=?').run(req.params.id); if (r?.user) db.prepare("DELETE FROM users WHERE email=? AND role='supplier'").run(r.user); })();
  res.json({ ok: true });
});
adm.post('/import', (req, res) => {
  const list = Array.isArray(req.body.suppliers) ? req.body.suppliers.slice(0, 2000) : [];
  const have = new Set(db.prepare('SELECT lower(company) c FROM suppliers').all().map((r) => r.c)); const created = []; let skipped = 0;
  db.transaction(() => { for (const o of list) { const d = cleanSupplier(o); if (!d.company) continue; if (have.has(d.company.toLowerCase())) { skipped++; continue; } have.add(d.company.toLowerCase()); const sid = id(); saveSupplier(sid, d, { status: 'approved' }); created.push(sid); } })();
  if (req.body.enrich) created.forEach((s) => enqueue(s, false));
  res.json({ created: created.length, skipped });
});
adm.post('/extract', async (req, res) => {
  try {
    const { mediaType, data } = req.body;
    if (!/^image\/(png|jpeg|gif|webp)$/.test(mediaType || '') || !data) return res.status(400).json({ error: 'Use a PNG, JPG, GIF or WebP image' });
    const text = await claude({ messages: [{ role: 'user', content: [{ type: 'image', source: { type: 'base64', media_type: mediaType, data } }, { type: 'text', text: 'List every company shown in this image. Return ONLY a JSON array of objects like {"company":"","owner":"","phone":"","email":"","website":"","address":"","city":"","brands":[]}. Use "" or [] when not visible. Do not invent anything.' }] }] });
    res.json({ suppliers: parseJson(text, '[', ']') });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.use('/api/admin', adm);

app.listen(E.PORT || 3000, () => console.log(SITE + ' running on port ' + (E.PORT || 3000)));
