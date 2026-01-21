const express = require("express");
const path = require("path");
const fs = require("fs/promises");
const dotenv = require("dotenv");
const helmet = require("helmet");
const morgan = require("morgan");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const csurf = require("csurf");

dotenv.config();

const app = express();

const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PROD = NODE_ENV === "production";

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "2h";

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

// ملف تخزين الأخبار
const NEWS_PATH = path.join(__dirname, "data", "news.json");

// إعدادات الكوكيز
const COOKIE_SECURE = (process.env.COOKIE_SECURE || "").toLowerCase() === "true" ? true : IS_PROD;
const COOKIE_SAMESITE = "strict"; // مناسب للوحات إدارة نفس الموقع

// ====== Middleware ======
app.use(helmet());
app.use(morgan("dev"));
app.use(express.json({ limit: "200kb" }));
app.use(cookieParser());

// Rate limit أساسي
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 120,
    standardHeaders: true,
    legacyHeaders: false
  })
);

// CSRF باستخدام Cookie (Double Submit-ish مع csurf)
// ملاحظة: csurf يتحقق من توكن يُرسل مع الطلب مقابل السر المخزن/الموقع في cookie حسب الإعدادات.
const csrfProtection = csurf({
  cookie: {
    httpOnly: true,           // cookie الخاصة بـ CSRF نفسها httpOnly
    sameSite: COOKIE_SAMESITE,
    secure: COOKIE_SECURE
  }
});

// ====== Helpers ======
async function readNews() {
  try {
    const raw = await fs.readFile(NEWS_PATH, "utf8");
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch (e) {
    return [];
  }
}

async function writeNews(items) {
  await fs.mkdir(path.dirname(NEWS_PATH), { recursive: true });
  await fs.writeFile(NEWS_PATH, JSON.stringify(items, null, 2), "utf8");
}

function signJwt(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function verifyJwtFromCookie(req) {
  const token = req.cookies?.token;
  if (!token) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const decoded = verifyJwtFromCookie(req);
  if (!decoded) return res.status(401).json({ error: "Unauthorized" });
  req.user = decoded;
  next();
}

// ====== Routes ======

// حماية dashboard.html (لا نتركها للـ static)
app.get("/dashboard.html", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// تقديم ملفات static (index/login)
app.use(express.static(path.join(__dirname, "public")));

// CSRF token endpoint (للاستخدام من الواجهات)
app.get("/api/csrf", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Public: قراءة الأخبار
app.get("/api/news", async (req, res) => {
  const items = await readNews();
  // الأحدث أولاً
  items.sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));
  res.json({ items });
});

// Login (محمي بـ CSRF)
app.post("/api/login", csrfProtection, async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Invalid payload" });
  }

  // تحقق بسيط: اسم المستخدم + كلمة المرور (مع bcrypt لتقليل المخاطر داخل الذاكرة)
  // في تطبيق فعلي: خزّن hash في DB/ENV بدل كلمة المرور plaintext.
  const okUser = username === ADMIN_USERNAME;
  const passOk = await bcrypt.compare(password, await bcrypt.hash(ADMIN_PASSWORD, 10));

  if (!okUser || !passOk) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = signJwt({ sub: username, role: "admin" });

  res.cookie("token", token, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAMESITE,
    maxAge: 2 * 60 * 60 * 1000 // 2 ساعات
  });

  res.json({ ok: true });
});

// Logout (CSRF + Auth)
app.post("/api/logout", requireAuth, csrfProtection, (req, res) => {
  res.clearCookie("token");
  res.json({ ok: true });
});

// Admin: من أنا
app.get("/api/admin/me", requireAuth, (req, res) => {
  res.json({ user: { username: req.user.sub, role: req.user.role } });
});

// Admin: CRUD الأخبار (كل POST/DELETE محمية CSRF)
app.get("/api/admin/news", requireAuth, async (req, res) => {
  const items = await readNews();
  items.sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));
  res.json({ items });
});

app.post("/api/admin/news", requireAuth, csrfProtection, async (req, res) => {
  const { title, body } = req.body || {};
  if (typeof title !== "string" || title.trim().length < 2) {
    return res.status(400).json({ error: "Title is required" });
  }
  if (typeof body !== "string" || body.trim().length < 2) {
    return res.status(400).json({ error: "Body is required" });
  }

  const items = await readNews();
  const item = {
    id: cryptoRandomId(),
    title: title.trim(),
    body: body.trim(),
    createdAt: new Date().toISOString()
  };
  items.push(item);
  await writeNews(items);
  res.json({ ok: true, item });
});

app.delete("/api/admin/news/:id", requireAuth, csrfProtection, async (req, res) => {
  const id = req.params.id;
  const items = await readNews();
  const next = items.filter((x) => x.id !== id);
  if (next.length === items.length) {
    return res.status(404).json({ error: "Not found" });
  }
  await writeNews(next);
  res.json({ ok: true });
});

// 404
app.use((req, res) => {
  res.status(404).send("Not Found");
});

// Error handler (خصوصاً csurf)
app.use((err, req, res, next) => {
  if (err && err.code === "EBADCSRFTOKEN") {
    return res.status(403).json({ error: "Bad CSRF token" });
  }
  console.error(err);
  res.status(500).json({ error: "Server error" });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

function cryptoRandomId() {
  // بدون اعتماد على crypto (للتوافق) – لو تحب نستخدم crypto.randomUUID() قولّي
  return (
    "n_" +
    Math.random().toString(16).slice(2) +
    "_" +
    Date.now().toString(16)
  );
}
