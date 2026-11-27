const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const Razorpay = require("razorpay");
const twilio = require("twilio");

const db = new Pool({ connectionString: process.env.DATABASE_URL });
const rzp = new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET });
const sms = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const VERIFY = process.env.TWILIO_VERIFY_SID;

const app = express();
app.use(cors({ origin: process.env.FRONTEND_URL }));

app.post("/webhook/razorpay", express.raw({ type: "application/json" }), async (req, res) => {
  const sig = req.headers["x-razorpay-signature"];
  const expected = crypto.createHmac("sha256", process.env.RAZORPAY_WEBHOOK_SECRET).update(req.body).digest("hex");
  if (!sig || sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected)))
    return res.status(400).end();
  const ev = JSON.parse(req.body);
  if (ev.event === "payment.captured") {
    const p = ev.payload.payment.entity;
    const c = await db.connect();
    try {
      await c.query("BEGIN");
      const t = await c.query(
        "UPDATE topups SET status='paid', payment_id=$1 WHERE order_id=$2 AND status='created' RETURNING user_id, coins",
        [p.id, p.order_id]);
      if (t.rowCount) {
        await c.query("UPDATE users SET balance = balance + $1 WHERE id=$2", [t.rows[0].coins, t.rows[0].user_id]);
        await c.query("INSERT INTO ledger(user_id, delta, reason) VALUES($1,$2,'topup')", [t.rows[0].user_id, t.rows[0].coins]);
      }
      await c.query("COMMIT");
    } catch (e) { await c.query("ROLLBACK"); return res.status(500).end(); }
    finally { c.release(); }
  }
  res.json({ ok: true });
});

app.use(express.json());
app.use(rateLimit({ windowMs: 10 * 60 * 1000, max: 100 }));
const otpLimit = rateLimit({ windowMs: 10 * 60 * 1000, max: 5 });

const auth = (req, res, next) => {
  try { req.uid = jwt.verify((req.headers.authorization || "").replace("Bearer ", ""), process.env.JWT_SECRET).uid; next(); }
  catch { res.status(401).json({ error: "Login required" }); }
};
const okPhone = (p) => /^[6-9]\d{9}$/.test(p);
const okGmail = (e) => /^[\w.+\-]+@gmail\.com$/i.test(e);

app.post("/auth/send-otp", otpLimit, async (req, res) => {
  const { phone, email, name } = req.body;
  if (!name || !okGmail(email) || !okPhone(phone)) return res.status(400).json({ error: "Invalid details" });
  try { await sms.verify.v2.services(VERIFY).verifications.create({ to: "+91" + phone, channel: "sms" }); res.json({ ok: true }); }
  catch { res.status(500).json({ error: "Could not send OTP" }); }
});

app.post("/auth/verify-otp", otpLimit, async (req, res) => {
  const { phone, email, name, code } = req.body;
  try {
    const r = await sms.verify.v2.services(VERIFY).verificationChecks.create({ to: "+91" + phone, code });
    if (r.status !== "approved") return res.status(401).json({ error: "Wrong OTP" });
    const u = await db.query(
      `INSERT INTO users(name,email,phone) VALUES($1,$2,$3)
       ON CONFLICT (phone) DO UPDATE SET name=users.name RETURNING id,name,email,phone,balance`, [name, email.toLowerCase(), phone]);
    const token = jwt.sign({ uid: u.rows[0].id }, process.env.JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, user: u.rows[0] });
  } catch { res.status(401).json({ error: "OTP failed or expired" }); }
});

app.get("/me", auth, async (req, res) =>
  res.json((await db.query("SELECT id,name,email,phone,balance FROM users WHERE id=$1", [req.uid])).rows[0]));

app.get("/products", async (req, res) =>
  res.json((await db.query("SELECT id,name,emoji,price,stock FROM products WHERE active ORDER BY id")).rows));

app.post("/wallet/topup", auth, async (req, res) => {
  const amt = Math.floor(+req.body.amount);
  if (!(amt >= 10 && amt <= 10000)) return res.status(400).json({ error: "Amount must be 10 to 10000" });
  const o = await rzp.orders.create({ amount: amt * 100, currency: "INR", receipt: "t" + Date.now() });
  await db.query("INSERT INTO topups(user_id, order_id, coins) VALUES($1,$2,$3)", [req.uid, o.id, amt]);
  res.json({ order_id: o.id, key: process.env.RAZORPAY_KEY_ID, amount: amt * 100 });
});

app.post("/orders", auth, async (req, res) => {
  const { items, address } = req.body;
  if (!Array.isArray(items) || !items.length || !address || address.length < 10)
    return res.status(400).json({ error: "Items and full address required" });
  const c = await db.connect();
  try {
    await c.query("BEGIN");
    let total = 0;
    const lines = [];
    for (const it of items) {
      const qty = Math.floor(+it.qty);
      if (!(qty > 0 && qty <= 20)) throw new Error("Bad quantity");
      const p = await c.query("UPDATE products SET stock = stock - $1 WHERE id=$2 AND active AND stock >= $1 RETURNING id,name,price", [qty, it.id]);
      if (!p.rowCount) throw new Error("Out of stock");
      total += p.rows[0].price * qty;
      lines.push([p.rows[0].id, p.rows[0].name, p.rows[0].price, qty]);
    }
    const u = await c.query("UPDATE users SET balance = balance - $1 WHERE id=$2 AND balance >= $1 RETURNING balance", [total, req.uid]);
    if (!u.rowCount) throw new Error("Not enough coins");
    const o = await c.query("INSERT INTO orders(user_id,total,address,status) VALUES($1,$2,$3,'placed') RETURNING id", [req.uid, total, address]);
    for (const l of lines) await c.query("INSERT INTO order_items(order_id,product_id,name,price,qty) VALUES($1,$2,$3,$4,$5)", [o.rows[0].id, ...l]);
    await c.query("INSERT INTO ledger(user_id, delta, reason) VALUES($1,$2,'order')", [req.uid, -total]);
    await c.query("COMMIT");
    res.json({ order_id: o.rows[0].id, total, balance: u.rows[0].balance });
  } catch (e) { await c.query("ROLLBACK"); res.status(400).json({ error: e.message }); }
  finally { c.release(); }
});

app.get("/orders", auth, async (req, res) =>
  res.json((await db.query(
    `SELECT o.id,o.total,o.status,o.created_at,
            json_agg(json_build_object('name',i.name,'qty',i.qty,'price',i.price)) items
     FROM orders o JOIN order_items i ON i.order_id=o.id
     WHERE o.user_id=$1 GROUP BY o.id ORDER BY o.id DESC`, [req.uid])).rows));

app.listen(process.env.PORT || 3000, () => console.log("Mega Mart API running"));
