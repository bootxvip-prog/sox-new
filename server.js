// SO X server: auth, subscriptions, cards, orders, Vodafone Cash payments, reports, notifications
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const E = process.env;
const PORT = E.PORT || 3000;
const SECRET = E.JWT_SECRET;
if (!SECRET || SECRET.length < 16) throw new Error('Set a long JWT_SECRET in the environment');
// Plans are public and shown to the customer before paying. 'trial' is first-time subscribers only.
const PLANS = {
  trial:     { price: 10,  days: 30,  label: 'الشهر الأول (تجربة)' },
  monthly:   { price: 30,  days: 30,  label: 'شهري' },
  quarterly: { price: 75,  days: 90,  label: '3 شهور' },
  yearly:    { price: 240, days: 365, label: 'سنوي' }
};
const COMMISSION = 0.04;   // 4% on each card sale, the seller's first sale is commission-free
const REFERRAL_DAYS = 7;   // real bonus for the inviter when the invited friend pays

const db = new Database('sox.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, pass TEXT,
  role TEXT DEFAULT 'user', banned INTEGER DEFAULT 0, sub_until TEXT, ref_code TEXT UNIQUE,
  referred_by INTEGER, ref_rewarded INTEGER DEFAULT 0, created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS cards(id INTEGER PRIMARY KEY, seller_id INTEGER, name TEXT, type TEXT,
  price REAL, descr TEXT, image TEXT, status TEXT DEFAULT 'active', created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, ref TEXT UNIQUE, kind TEXT, user_id INTEGER,
  card_id INTEGER, plan TEXT, commission REAL DEFAULT 0, amount REAL, status TEXT DEFAULT 'pending', sender_phone TEXT, paid_at TEXT,
  created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, card_id INTEGER, reporter_id INTEGER,
  reason TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sms_inbox(id INTEGER PRIMARY KEY, phone TEXT, amount REAL, used INTEGER DEFAULT 0, created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at TEXT DEFAULT CURRENT_TIMESTAMP, who INTEGER, action TEXT, detail TEXT);
`);

const log = (who, action, detail) => db.prepare('INSERT INTO audit(who,action,detail) VALUES(?,?,?)').run(who, action, detail || '');

// Notify the owner on every payment event (Telegram, with console fallback)
async function notify(text) {
  const stamp = new Date().toLocaleString('ar-EG', { timeZone: 'Africa/Cairo' });
  const msg = `${text}\n${stamp}`;
  console.log('[notify]', msg);
  if (E.TELEGRAM_BOT_TOKEN && E.TELEGRAM_CHAT_ID) {
    try {
      await fetch(`https://api.telegram.org/bot${E.TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: E.TELEGRAM_CHAT_ID, text: msg })
      });
    } catch (e) { console.error('telegram failed', e.message); }
  }
}

const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json({ limit: '3mb' })); // card images sent as base64
app.use(cookieParser());
app.use('/api/', rateLimit({ windowMs: 60_000, max: 120 }));
const authLimiter = rateLimit({ windowMs: 15 * 60_000, max: 10 });

const sign = u => jwt.sign({ id: u.id, role: u.role }, SECRET, { expiresIn: '7d' });
function auth(req, res, next) {
  try {
    const p = jwt.verify(req.cookies.t || '', SECRET);
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(p.id);
    if (!u || u.banned) return res.status(403).json({ error: 'الحساب غير متاح' });
    req.user = u; next();
  } catch { res.status(401).json({ error: 'سجّل الدخول أولًا' }); }
}
const admin = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'غير مسموح' });
const subscribed = (req, res, next) =>
  req.user.sub_until && new Date(req.user.sub_until) > new Date() ? next() : res.status(402).json({ error: 'يلزم اشتراك نشط' });

// ---------- Auth ----------
app.post('/api/register', authLimiter, (req, res) => {
  const { name, email, password, invite } = req.body || {};
  if (!name || !/^\S+@\S+\.\S+$/.test(email || '') || (password || '').length < 8)
    return res.status(400).json({ error: 'بيانات غير صحيحة (كلمة المرور 8 أحرف على الأقل)' });
  try {
    const role = email.toLowerCase() === (E.ADMIN_EMAIL || '').toLowerCase() ? 'admin' : 'user';
    const inviter = invite ? db.prepare('SELECT id FROM users WHERE ref_code=?').get(String(invite).toUpperCase()) : null;
    const code = crypto.randomBytes(3).toString('hex').toUpperCase();
    const r = db.prepare('INSERT INTO users(name,email,pass,role,ref_code,referred_by) VALUES(?,?,?,?,?,?)')
      .run(name.slice(0, 60), email.toLowerCase(), bcrypt.hashSync(password, 12), role, code, inviter ? inviter.id : null);
    res.cookie('t', sign({ id: r.lastInsertRowid, role }), { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 6048e5 });
    res.json({ ok: true, message: 'أهلًا بك في SO X! اشترك لتبدأ بنشر كروتك.' });
  } catch { res.status(409).json({ error: 'البريد مسجّل بالفعل' }); }
});
app.post('/api/login', authLimiter, (req, res) => {
  const { email, password } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE email=?').get((email || '').toLowerCase());
  if (!u || !bcrypt.compareSync(password || '', u.pass)) return res.status(401).json({ error: 'بيانات الدخول خاطئة' });
  if (u.banned) return res.status(403).json({ error: 'الحساب محظور' });
  res.cookie('t', sign(u), { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 6048e5 });
  res.json({ ok: true });
});
app.post('/api/logout', (req, res) => { res.clearCookie('t'); res.json({ ok: true }); });

// ---------- Public card gallery ----------
app.get('/api/cards', (req, res) => {
  res.json(db.prepare(`SELECT c.id,c.name,c.type,c.price,c.descr,c.image,u.name AS seller
    FROM cards c JOIN users u ON u.id=c.seller_id WHERE c.status='active' AND u.banned=0 ORDER BY c.id DESC LIMIT 100`).all());
});

// ---------- Seller: publish a card (needs active subscription) ----------
app.post('/api/cards', auth, subscribed, (req, res) => {
  const { name, type, price, descr, image } = req.body || {};
  if (!name || !type || !(price > 0) || !descr || !/^data:image\/(png|jpe?g|webp);base64,/.test(image || ''))
    return res.status(400).json({ error: 'أكمل البيانات وأرفق صورة صحيحة' });
  const r = db.prepare('INSERT INTO cards(seller_id,name,type,price,descr,image) VALUES(?,?,?,?,?,?)')
    .run(req.user.id, name.slice(0, 60), type.slice(0, 40), price, descr.slice(0, 300), image);
  log(req.user.id, 'card.create', String(r.lastInsertRowid));
  res.json({ ok: true, id: r.lastInsertRowid });
});

// ---------- Payments ----------
// The wallet number is shown openly to the customer together with a unique reference.
function createOrder(kind, userId, cardId, amount, plan, commission) {
  const ref = 'SOX-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  db.prepare('INSERT INTO orders(ref,kind,user_id,card_id,plan,commission,amount) VALUES(?,?,?,?,?,?,?)')
    .run(ref, kind, userId, cardId, plan || null, commission || 0, amount);
  return {
    ref, amount,
    pay_to: { wallet: 'Vodafone Cash', number: E.VODAFONE_CASH_NUMBER, name: E.VODAFONE_CASH_NAME },
    instructions: `حوّل ${amount} جنيه إلى الرقم المعروض، ثم أدخل رقم هاتفك الذي حوّلت منه وكود الطلب ${ref}. يُؤكَّد الطلب بعد مراجعة التحويل.`
  };
}
app.get('/api/plans', (req, res) => res.json({ plans: PLANS, commission: COMMISSION, referral_days: REFERRAL_DAYS }));
app.get('/api/me', auth, (req, res) => {
  const { id, name, email, role, sub_until, ref_code } = req.user;
  res.json({ id, name, email, role, sub_until, ref_code });
});
app.post('/api/subscribe', auth, async (req, res) => {
  const paidBefore = db.prepare("SELECT 1 FROM orders WHERE user_id=? AND kind='subscription' AND status='paid'").get(req.user.id);
  const key = req.body.plan || (paidBefore ? 'monthly' : 'trial');
  const plan = PLANS[key];
  if (!plan) return res.status(400).json({ error: 'باقة غير معروفة' });
  if (key === 'trial' && paidBefore) return res.status(400).json({ error: 'الشهر التجريبي للمشتركين الجدد فقط' });
  const o = createOrder('subscription', req.user.id, null, plan.price, key, 0);
  await notify(`طلب اشتراك ${o.ref} (${plan.label}) من ${req.user.email} بمبلغ ${plan.price} ج`);
  res.json(o);
});
app.post('/api/buy/:id', auth, async (req, res) => {
  const c = db.prepare("SELECT * FROM cards WHERE id=? AND status='active'").get(req.params.id);
  if (!c) return res.status(404).json({ error: 'الكارت غير متاح' });
  const sold = db.prepare("SELECT COUNT(*) n FROM cards WHERE seller_id=? AND status='sold'").get(c.seller_id).n;
  const commission = sold === 0 ? 0 : Math.round(c.price * COMMISSION * 100) / 100;
  const o = createOrder('card', req.user.id, c.id, c.price, null, commission);
  await notify(`طلب شراء ${o.ref}: ${c.name} بمبلغ ${c.price} ج من ${req.user.email}`);
  res.json(o);
});
// Customer reports the sender phone after transferring
app.post('/api/orders/:ref/paid', auth, async (req, res) => {
  const phone = String(req.body.sender_phone || '');
  if (!/^01[0125]\d{8}$/.test(phone)) return res.status(400).json({ error: 'رقم الهاتف غير صحيح' });
  const r = db.prepare("UPDATE orders SET sender_phone=?,status='awaiting_review' WHERE ref=? AND user_id=? AND status='pending'")
    .run(phone, req.params.ref, req.user.id);
  if (!r.changes) return res.status(404).json({ error: 'الطلب غير موجود' });
  await notify(`تحويل بانتظار المراجعة ${req.params.ref} من الرقم ${phone}`);
  await autoMatch();
  res.json({ ok: true, message: 'استلمنا بياناتك. يُؤكَّد الدفع تلقائيًا فور وصول التحويل.' });
});
// Admin confirms after seeing the Vodafone Cash SMS
app.post('/api/admin/orders/:ref/confirm', auth, admin, async (req, res) => {
  const o = db.prepare("SELECT * FROM orders WHERE ref=? AND status!='paid'").get(req.params.ref);
  if (!o) return res.status(404).json({ error: 'الطلب غير موجود أو مؤكد' });
  settle(o); log(req.user.id, 'order.confirm', o.ref);
  await notify(`تم تأكيد الدفع ${o.ref} بمبلغ ${o.amount} ج`);
  res.json({ ok: true });
});
function extend(userId, days) {
  const u = db.prepare('SELECT sub_until FROM users WHERE id=?').get(userId);
  const base = u.sub_until && new Date(u.sub_until) > new Date() ? new Date(u.sub_until) : new Date();
  base.setDate(base.getDate() + days);
  db.prepare('UPDATE users SET sub_until=? WHERE id=?').run(base.toISOString(), userId);
}
// Real numbers only, shown on the homepage
app.get('/api/stats', (req, res) => res.json({
  active_cards: db.prepare("SELECT COUNT(*) n FROM cards WHERE status='active'").get().n,
  sold_cards: db.prepare("SELECT COUNT(*) n FROM cards WHERE status='sold'").get().n,
  sellers: db.prepare("SELECT COUNT(*) n FROM users WHERE sub_until > datetime('now')").get().n
}));
function settle(o) {
  db.prepare("UPDATE orders SET status='paid',paid_at=CURRENT_TIMESTAMP WHERE id=?").run(o.id);
  if (o.kind === 'subscription') {
    extend(o.user_id, (PLANS[o.plan] || PLANS.monthly).days);
    const u = db.prepare('SELECT referred_by, ref_rewarded FROM users WHERE id=?').get(o.user_id);
    if (u.referred_by && !u.ref_rewarded) {           // inviter gets a real free week
      extend(u.referred_by, REFERRAL_DAYS);
      db.prepare('UPDATE users SET ref_rewarded=1 WHERE id=?').run(o.user_id);
      notify(`مكافأة دعوة: أسبوع إضافي للمستخدم ${u.referred_by}`);
    }
  } else {
    db.prepare("UPDATE cards SET status='sold' WHERE id=?").run(o.card_id);
  }
}

// Automatic confirmation via Paymob (Vodafone Cash wallet integration), after opening a merchant account
app.post('/api/paymob/webhook', (req, res) => {
  const t = req.body && req.body.obj;
  if (!t || !E.PAYMOB_HMAC_SECRET) return res.sendStatus(400);
  const f = [t.amount_cents, t.created_at, t.currency, t.error_occured, t.has_parent_transaction, t.id,
    t.integration_id, t.is_3d_secure, t.is_auto_captured, t.is_capture, t.is_refunded, t.is_standalone_payment,
    t.is_voided, t.order && t.order.id, t.owner, t.pending, t.source_data && t.source_data.pn,
    t.source_data && t.source_data.sub_type, t.source_data && t.source_data.type, t.success].join('');
  const mac = crypto.createHmac('sha512', E.PAYMOB_HMAC_SECRET).update(f).digest('hex');
  const given = String(req.query.hmac || '');
  if (mac.length !== given.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(given))) return res.sendStatus(403);
  const ref = t.order && t.order.merchant_order_id;
  const o = db.prepare("SELECT * FROM orders WHERE ref=? AND status!='paid'").get(ref);
  if (o && t.success === true && t.amount_cents === Math.round(o.amount * 100)) {
    settle(o); log(0, 'order.auto_paid', ref);
    notify(`دفع تلقائي ناجح ${ref} بمبلغ ${o.amount} ج`);
  }
  res.sendStatus(200);
});

// ---------- Reports and moderation ----------
app.post('/api/cards/:id/report', auth, (req, res) => {
  db.prepare('INSERT INTO reports(card_id,reporter_id,reason) VALUES(?,?,?)')
    .run(req.params.id, req.user.id, String(req.body.reason || '').slice(0, 300));
  const n = db.prepare('SELECT COUNT(*) n FROM reports WHERE card_id=?').get(req.params.id).n;
  if (n >= 3) db.prepare("UPDATE cards SET status='review' WHERE id=?").run(req.params.id); // auto-hide pending review
  notify(`بلاغ على الكارت ${req.params.id} (إجمالي ${n})`);
  res.json({ ok: true });
});
app.post('/api/admin/users/:id/ban', auth, admin, (req, res) => {
  db.prepare('UPDATE users SET banned=1 WHERE id=?').run(req.params.id);
  db.prepare("UPDATE cards SET status='removed' WHERE seller_id=?").run(req.params.id);
  log(req.user.id, 'user.ban', req.params.id);
  res.json({ ok: true });
});
app.get('/api/admin/orders', auth, admin, (req, res) =>
  res.json(db.prepare("SELECT * FROM orders WHERE status IN ('pending','awaiting_review') ORDER BY id DESC").all()));

// ---------- Automatic Vodafone Cash confirmation ----------
// An SMS-forwarder app on the phone that owns the wallet POSTs each "money received" SMS here as {"text":"..."}
// with header x-sms-secret. We read the amount and sender number and match them to an order.
async function autoMatch() {
  for (const s of db.prepare('SELECT * FROM sms_inbox WHERE used=0').all()) {
    const o = db.prepare("SELECT * FROM orders WHERE status='awaiting_review' AND sender_phone=? AND amount=?").get(s.phone, s.amount);
    if (o) {
      settle(o);
      db.prepare('UPDATE sms_inbox SET used=1 WHERE id=?').run(s.id);
      log(0, 'order.sms_paid', o.ref);
      await notify(`تم تأكيد الدفع تلقائيًا ${o.ref} بمبلغ ${o.amount} ج من ${s.phone}`);
    }
  }
}
app.post('/api/sms-webhook', async (req, res) => {
  const given = Buffer.from(String(req.get('x-sms-secret') || ''));
  const want = Buffer.from(E.SMS_WEBHOOK_SECRET || '');
  if (!want.length || given.length !== want.length || !crypto.timingSafeEqual(given, want)) return res.sendStatus(403);
  const text = String((req.body && (req.body.text || req.body.message)) || '');
  const amt = (text.match(/(\d+(?:[.,]\d+)?)\s*(?:EGP|جنيه|ج\.م|LE)/i) || [])[1];
  const phone = (text.match(/01[0125]\d{8}/g) || []).find(p => p !== E.VODAFONE_CASH_NUMBER);
  if (!amt || !phone) { await notify('رسالة محفظة لم تُفهم تلقائيًا، راجعها يدويًا:\n' + text.slice(0, 200)); return res.json({ ok: false }); }
  db.prepare('INSERT INTO sms_inbox(phone,amount) VALUES(?,?)').run(phone, Number(amt.replace(',', '.')));
  await autoMatch();
  res.json({ ok: true });
});

// ---------- User dashboards ----------
app.get('/api/my/orders', auth, (req, res) =>
  res.json(db.prepare('SELECT ref,kind,plan,amount,status,created FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 20').all(req.user.id)));
app.get('/api/my/cards', auth, (req, res) =>
  res.json(db.prepare('SELECT id,name,price,status FROM cards WHERE seller_id=? ORDER BY id DESC').all(req.user.id)));
app.get('/api/admin/reports', auth, admin, (req, res) =>
  res.json(db.prepare('SELECT r.card_id,r.reason,r.created,c.name,c.seller_id FROM reports r JOIN cards c ON c.id=r.card_id ORDER BY r.id DESC LIMIT 50').all()));

// Expire unpaid orders after 24 hours
setInterval(() => db.prepare("UPDATE orders SET status='expired' WHERE status='pending' AND created < datetime('now','-1 day')").run(), 3600_000);

app.use(express.static('public')); // put the SO X page here as index.html
app.listen(PORT, () => console.log('SO X running on', PORT));
