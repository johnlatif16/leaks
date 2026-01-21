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
const multer = require("multer");
const crypto = require("crypto");

dotenv.config();
const app = express();

// ====== Config ======
const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PROD = NODE_ENV === "production";

const JWT_SECRET = (process.env.JWT_SECRET || "dev_secret_change_me").trim();
const JWT_EXPIRES_IN = (process.env.JWT_EXPIRES_IN || "2h").trim();

const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || "admin").trim();
const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || "admin123").trim();

const NEWS_PATH = path.join(__dirname, "data", "news.json");

// Secure cookies لا تعمل على http
const COOKIE_SECURE =
  (process.env.COOKIE_SECURE || "").toLowerCase() === "true" ? true : IS_PROD;

// SameSite=Lax يقلل خطر CSRF شوية بدون csurf (مش حماية كاملة)
const COOKIE_SAMESITE = "lax";

// ====== Middleware ======
app.use(helmet());
app.use(morgan(IS_PROD ? "combined" : "dev"));
app.use(express.json({ limit: "4mb" }));
app.use(cookieParser());

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 120,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// ====== Uploads (multer) ======
const upload = multer({
  storage: multer.diskStorage({
    destination: async (req, file, cb) => {
      try {
        const dir = path.join(__dirname, "uploads");
        await fs.mkdir(dir, { recursive: true });
        cb(null, dir);
      } catch (e) {
        cb(e);
      }
    },
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname || "").toLowerCase();
      cb(null, `${Date.now()}_${crypto.randomBytes(6).toString("hex")}${ext}`);
    },
  }),
  limits: { fileSize: 20 * 1024 * 1024 }, // 20MB
  fileFilter: (req, file, cb) => {
    const ok = [
      "image/png",
      "image/jpeg",
      "image/webp",
      "image/gif",
      "video/mp4",
      "video/webm",
    ].includes(file.mimetype);
    if (!ok) return cb(new Error("Unsupported file type"), false);
    cb(null, true);
  },
});

// serve uploads
app.use(
  "/uploads",
  express.static(path.join(__dirname, "uploads"), {
    setHeaders(res) {
      res.setHeader("X-Content-Type-Options", "nosniff");
    },
  })
);

// ====== Helpers ======
async function readNews() {
  try {
    const raw = await fs.readFile(NEWS_PATH, "utf8");
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch {
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

function randomId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return "n_" + Math.random().toString(16).slice(2) + "_" + Date.now().toString(16);
}

function sortNewsNewestFirst(items) {
  return items.sort((a, b) =>
    String(b.createdAt || "").localeCompare(String(a.createdAt || ""))
  );
}

function sanitizeBlocks(blocks) {
  if (!Array.isArray(blocks)) return [];
  return blocks
    .slice(0, 50)
    .map((b) => {
      if (!b || typeof b !== "object") return null;
      const type = String(b.type || "");

      if (type === "paragraph") {
        return { type: "paragraph", text: String(b.text || "").slice(0, 5000) };
      }
      if (type === "image") {
        return {
          type: "image",
          url: String(b.url || "").slice(0, 2000),
          alt: String(b.alt || "").slice(0, 200),
        };
      }
      if (type === "video") {
        return { type: "video", url: String(b.url || "").slice(0, 2000) };
      }
      if (type === "table") {
        const headers = Array.isArray(b.headers)
          ? b.headers.map((x) => String(x).slice(0, 100)).slice(0, 12)
          : [];
        const rows = Array.isArray(b.rows)
          ? b.rows
              .map((r) =>
                Array.isArray(r)
                  ? r.map((x) => String(x).slice(0, 200)).slice(0, 12)
                  : []
              )
              .slice(0, 50)
          : [];
        return { type: "table", headers, rows };
      }
      return null;
    })
    .filter(Boolean);
}

// ====== Pages ======
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/login", (req, res) => {
  res.redirect("/login.html");
});

// Protect dashboard page
app.get("/dashboard.html", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// public static
app.use(express.static(path.join(__dirname, "public")));

// ====== API ======

// Public news
app.get("/api/news", async (req, res) => {
  const items = sortNewsNewestFirst(await readNews());
  res.json({ items });
});

// Password hash at startup
const ADMIN_PASSWORD_HASH = bcrypt.hashSync(ADMIN_PASSWORD, 12);

// Login (NO CSRF)
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Invalid payload" });
  }

  const okUser = username.trim() === ADMIN_USERNAME;
  const passOk = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);

  if (!okUser || !passOk) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = signJwt({ sub: ADMIN_USERNAME, role: "admin" });

  res.cookie("token", token, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAMESITE,
    maxAge: 2 * 60 * 60 * 1000, // 2h
  });

  res.json({ ok: true });
});

// Logout (NO CSRF)
app.post("/api/logout", requireAuth, (req, res) => {
  res.clearCookie("token");
  res.json({ ok: true });
});

// Admin me
app.get("/api/admin/me", requireAuth, (req, res) => {
  res.json({ user: { username: req.user.sub, role: req.user.role } });
});

// Upload (NO CSRF)
app.post("/api/admin/upload", requireAuth, upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });
  res.json({
    ok: true,
    url: `/uploads/${req.file.filename}`,
    mime: req.file.mimetype,
    size: req.file.size,
  });
});

// Admin list news
app.get("/api/admin/news", requireAuth, async (req, res) => {
  const items = sortNewsNewestFirst(await readNews());
  res.json({ items });
});

// Admin create news (NO CSRF)
app.post("/api/admin/news", requireAuth, async (req, res) => {
  const { title, blocks } = req.body || {};
  if (typeof title !== "string" || title.trim().length < 2) {
    return res.status(400).json({ error: "Title is required" });
  }
  const safeBlocks = sanitizeBlocks(blocks);
  if (safeBlocks.length === 0) {
    return res.status(400).json({ error: "Blocks are required" });
  }

  const items = await readNews();
  const item = {
    id: randomId(),
    title: title.trim(),
    blocks: safeBlocks,
    createdAt: new Date().toISOString(),
  };
  items.push(item);
  await writeNews(items);

  res.json({ ok: true, item });
});

// Admin delete news (NO CSRF)
app.delete("/api/admin/news/:id", requireAuth, async (req, res) => {
  const id = req.params.id;
  const items = await readNews();
  const next = items.filter((x) => x.id !== id);
  if (next.length === items.length) return res.status(404).json({ error: "Not found" });
  await writeNews(next);
  res.json({ ok: true });
});

// Errors
app.use((err, req, res, next) => {
  if (err && err.message === "Unsupported file type") {
    return res.status(400).json({ error: "Unsupported file type" });
  }
  if (err && err.code === "LIMIT_FILE_SIZE") {
    return res.status(400).json({ error: "File too large" });
  }
  console.error(err);
  res.status(500).json({ error: "Server error" });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`COOKIE_SECURE=${COOKIE_SECURE} | NODE_ENV=${NODE_ENV}`);
});
