require("dotenv").config();

const express = require("express");
const session = require("express-session");
const passport = require("passport");
const DiscordStrategy = require("passport-discord").Strategy;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === "production";

const BASE_URL =
  process.env.BASE_URL ||
  (IS_PRODUCTION ? "https://sniper.onrender.com" : `http://localhost:${PORT}`);

const PUBLIC_DIR = path.join(__dirname, "public");
const DATA_DIR = path.join(__dirname, "data");
const UPLOAD_DIR = path.join(PUBLIC_DIR, "uploads");
const ACCOUNTS_FILE = path.join(DATA_DIR, "accounts.json");

/* =========================================================
   DOSSIERS
========================================================= */

for (const folder of [PUBLIC_DIR, DATA_DIR, UPLOAD_DIR]) {
  if (!fs.existsSync(folder)) {
    fs.mkdirSync(folder, { recursive: true });
  }
}

/* =========================================================
   SECRET DE SESSION
========================================================= */

if (IS_PRODUCTION && !process.env.SESSION_SECRET) {
  console.warn(
    "[ATTENTION] Aucune variable SESSION_SECRET définie en production. " +
      "Utilise une valeur forte et unique dans ton .env."
  );
}

/* =========================================================
   BASE DE DONNÉES (fichier JSON)
========================================================= */

if (!fs.existsSync(ACCOUNTS_FILE)) {
  fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify({ accounts: [] }, null, 2));
}

function loadAccounts() {
  try {
    const data = JSON.parse(fs.readFileSync(ACCOUNTS_FILE, "utf8"));
    if (!Array.isArray(data.accounts)) data.accounts = [];
    return data;
  } catch {
    return { accounts: [] };
  }
}

function saveAccounts(data) {
  fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify(data, null, 2));
}

/* =========================================================
   HELPERS GÉNÉRAUX
========================================================= */

const RESERVED_USERNAMES = [
  "api",
  "auth",
  "login",
  "register",
  "logout",
  "uploads",
  "static",
  "admin",
  "assets",
  "favicon.ico",
  "robots.txt",
  "sitemap.xml"
];

function isReservedUsername(username) {
  return RESERVED_USERNAMES.includes(String(username).toLowerCase());
}

function slugify(value) {
  return String(value || "")
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9_-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 32);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function findById(id) {
  return loadAccounts().accounts.find((a) => a.id === id);
}

function findByUsername(username) {
  return loadAccounts().accounts.find(
    (a) => a.username.toLowerCase() === String(username).toLowerCase()
  );
}

function usernameAvailable(username, exceptId = null) {
  if (isReservedUsername(username)) return false;
  return !loadAccounts().accounts.some(
    (a) => a.id !== exceptId && a.username.toLowerCase() === username.toLowerCase()
  );
}

function generateUniqueUsername(base) {
  let username = slugify(base) || "user";
  if (isReservedUsername(username)) username = `${username}-1`;

  const original = username;
  let number = 1;

  while (!usernameAvailable(username)) {
    username = `${original}-${number}`;
    number++;
  }

  return username;
}

// Supprime un fichier uploadé (best-effort). Utilisé uniquement au
// moment où une modification est réellement SAUVEGARDÉE, jamais au
// moment de l'upload lui-même (sinon un "Réinitialiser" côté client
// pourrait pointer vers un fichier déjà supprimé du disque).
function deleteUploadedFile(url) {
  if (!url || typeof url !== "string") return;
  if (!url.startsWith("/uploads/")) return;

  const filename = path.basename(url);
  const filePath = path.join(UPLOAD_DIR, filename);

  if (!filePath.startsWith(UPLOAD_DIR)) return;

  fs.unlink(filePath, () => {});
}

/* =========================================================
   RATE LIMITING (basique, en mémoire, sans dépendance externe)
========================================================= */

function createRateLimiter({ windowMs, max }) {
  const hits = new Map();

  return (req, res, next) => {
    const key = req.user ? req.user.id : req.ip;
    const now = Date.now();

    const entry = hits.get(key) || { count: 0, reset: now + windowMs };

    if (now > entry.reset) {
      entry.count = 0;
      entry.reset = now + windowMs;
    }

    entry.count++;
    hits.set(key, entry);

    if (entry.count > max) {
      return res.status(429).json({ error: "Trop de requêtes, réessaie dans un instant." });
    }

    next();
  };
}

const uploadLimiter = createRateLimiter({ windowMs: 60 * 1000, max: 20 });
const profileLimiter = createRateLimiter({ windowMs: 60 * 1000, max: 30 });

/* =========================================================
   EXPRESS - CONFIG DE BASE
========================================================= */

app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

/* =========================================================
   SESSION
========================================================= */

app.use(
  session({
    secret: process.env.SESSION_SECRET || "sniper-local-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7,
      httpOnly: true,
      secure: IS_PRODUCTION,
      sameSite: "lax"
    }
  })
);

/* =========================================================
   PASSPORT
========================================================= */

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser((id, done) => {
  done(null, findById(id) || false);
});

/* =========================================================
   DISCORD OAUTH
========================================================= */

if (process.env.DISCORD_CLIENT_ID && process.env.DISCORD_CLIENT_SECRET) {
  passport.use(
    new DiscordStrategy(
      {
        clientID: process.env.DISCORD_CLIENT_ID,
        clientSecret: process.env.DISCORD_CLIENT_SECRET,
        callbackURL:
          process.env.DISCORD_CALLBACK_URL || `${BASE_URL}/auth/discord/callback`,
        scope: ["identify", "email"]
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const data = loadAccounts();

          let account = data.accounts.find((a) => a.discordId === profile.id);

          if (!account) {
            const username = generateUniqueUsername(profile.username || "discord");

            account = {
              id: `discord-${profile.id}`,
              provider: "Discord",
              discordId: profile.id,
              email: profile.email || "",
              username,
              displayName: profile.global_name || profile.username || username,
              avatar: profile.avatar
                ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png?size=512`
                : "",
              bio: "Bienvenue sur mon profil.",
              accent: "#5865f2",
              // Fond en image/vidéo uniquement : vide par défaut,
              // le type sera fixé automatiquement au premier import.
              background: { type: "image", value: "", opacity: 1 },
              music: "",
              cursor: "",
              links: [],
              createdAt: new Date().toISOString()
            };

            data.accounts.push(account);
          } else {
            account.displayName =
              profile.global_name || profile.username || account.displayName;

            if (profile.avatar) {
              account.avatar = `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png?size=512`;
            }
          }

          saveAccounts(data);
          done(null, account);
        } catch (error) {
          done(error);
        }
      }
    )
  );
}

/* =========================================================
   GOOGLE OAUTH
========================================================= */

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL:
          process.env.GOOGLE_CALLBACK_URL || `${BASE_URL}/auth/google/callback`
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const data = loadAccounts();

          let account = data.accounts.find((a) => a.googleId === profile.id);

          if (!account) {
            const email = profile.emails?.[0]?.value || "";
            const base = email ? email.split("@")[0] : "user";
            const username = generateUniqueUsername(base);

            account = {
              id: `google-${profile.id}`,
              provider: "Google",
              googleId: profile.id,
              email,
              username,
              displayName: profile.displayName || username,
              avatar: profile.photos?.[0]?.value || "",
              bio: "Bienvenue sur mon profil.",
              accent: "#8b5cf6",
              background: { type: "image", value: "", opacity: 1 },
              music: "",
              cursor: "",
              links: [],
              createdAt: new Date().toISOString()
            };

            data.accounts.push(account);
          }

          saveAccounts(data);
          done(null, account);
        } catch (error) {
          done(error);
        }
      }
    )
  );
}

/* =========================================================
   FICHIERS STATIQUES
========================================================= */

app.use(express.static(PUBLIC_DIR));

/* =========================================================
   PAGES LOGIN / REGISTER
========================================================= */

app.get("/login", (req, res) => {
  if (req.user) return res.redirect("/");
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

app.get("/register", (req, res) => {
  if (req.user) return res.redirect("/");
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

/* =========================================================
   DISCORD - LOGIN / CALLBACK
========================================================= */

app.get("/auth/discord", (req, res, next) => {
  if (req.user) return res.redirect("/");

  if (!process.env.DISCORD_CLIENT_ID || !process.env.DISCORD_CLIENT_SECRET) {
    return res
      .status(503)
      .send("<h2>Discord OAuth non configuré</h2><p>Ajoute DISCORD_CLIENT_ID et DISCORD_CLIENT_SECRET.</p>");
  }

  passport.authenticate("discord")(req, res, next);
});

app.get(
  "/auth/discord/callback",
  passport.authenticate("discord", { failureRedirect: "/login?error=discord" }),
  (req, res) => res.redirect("/?login=success")
);

/* =========================================================
   GOOGLE - LOGIN / CALLBACK
========================================================= */

app.get("/auth/google", (req, res, next) => {
  if (req.user) return res.redirect("/");

  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    return res
      .status(503)
      .send("<h2>Google OAuth non configuré</h2><p>Ajoute GOOGLE_CLIENT_ID et GOOGLE_CLIENT_SECRET.</p>");
  }

  passport.authenticate("google", { scope: ["profile", "email"] })(req, res, next);
});

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login?error=google" }),
  (req, res) => res.redirect("/?login=success")
);

/* =========================================================
   COMPTE COURANT
========================================================= */

app.get("/api/me", (req, res) => {
  if (!req.user) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, account: req.user });
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/logout", (req, res) => {
  req.logout((error) => {
    if (error) return res.status(500).json({ error: "Erreur lors de la déconnexion." });

    req.session.destroy((error) => {
      if (error) return res.status(500).json({ error: "Erreur lors de la déconnexion." });

      res.clearCookie("connect.sid");
      res.json({ success: true });
    });
  });
});

/* =========================================================
   UPLOAD DE FICHIERS
========================================================= */

const UPLOAD_RULES = {
  avatar: {
    exts: [".png", ".jpg", ".jpeg", ".webp", ".gif"],
    mimePrefixes: ["image/"],
    maxSize: 8 * 1024 * 1024
  },
  cursor: {
    exts: [".png", ".webp", ".ico", ".cur"],
    mimePrefixes: ["image/"],
    maxSize: 2 * 1024 * 1024
  },
  music: {
    exts: [".mp3", ".wav", ".ogg", ".m4a"],
    mimePrefixes: ["audio/"],
    maxSize: 25 * 1024 * 1024
  },
  background: {
    exts: [".png", ".jpg", ".jpeg", ".webp", ".gif", ".mp4", ".webm", ".mov"],
    mimePrefixes: ["image/", "video/"],
    maxSize: 60 * 1024 * 1024
  }
};

const HARD_MAX_SIZE = Math.max(...Object.values(UPLOAD_RULES).map((r) => r.maxSize));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const random = crypto.randomBytes(6).toString("hex");
    cb(null, `${req.user.id}-${Date.now()}-${random}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: HARD_MAX_SIZE },
  fileFilter: (req, file, cb) => {
    const kind = req.body.kind;
    const rule = UPLOAD_RULES[kind];

    if (!rule) {
      return cb(new Error("Type de fichier inconnu."));
    }

    const ext = path.extname(file.originalname).toLowerCase();
    const mimeOk = rule.mimePrefixes.some((prefix) => file.mimetype.startsWith(prefix));

    if (!rule.exts.includes(ext) || !mimeOk) {
      return cb(new Error("Format de fichier non autorisé pour ce type d'import."));
    }

    cb(null, true);
  }
});

app.post(
  "/api/upload",
  (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Non connecté." });
    next();
  },
  uploadLimiter,
  (req, res, next) => {
    upload.single("file")(req, res, (error) => {
      if (error) {
        return res.status(400).json({
          error:
            error.code === "LIMIT_FILE_SIZE"
              ? "Fichier trop volumineux."
              : error.message || "Upload impossible."
        });
      }
      next();
    });
  },
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: "Aucun fichier." });
    }

    const kind = req.body.kind;
    const rule = UPLOAD_RULES[kind];

    if (rule && req.file.size > rule.maxSize) {
      fs.unlink(req.file.path, () => {});
      return res.status(400).json({ error: "Fichier trop volumineux pour ce type d'import." });
    }

    const url = `/uploads/${req.file.filename}`;

    let type = "file";
    if (req.file.mimetype.startsWith("image/")) type = "image";
    if (req.file.mimetype.startsWith("audio/")) type = "audio";
    if (req.file.mimetype.startsWith("video/")) type = "video";

    // Remarque : on ne supprime PAS l'ancien fichier ici. Tant que la
    // modification n'est pas confirmée via /api/profile, l'utilisateur
    // peut encore cliquer sur "Réinitialiser" et revenir à l'ancien
    // fichier — celui-ci doit donc rester intact jusqu'à la sauvegarde.
    res.json({ success: true, type, url });
  }
);

/* =========================================================
   MISE À JOUR DU PROFIL
========================================================= */

const BACKGROUND_TYPES = ["image", "video"];

app.post("/api/profile", profileLimiter, (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Non connecté." });

  const data = loadAccounts();
  const index = data.accounts.findIndex((a) => a.id === req.user.id);

  if (index === -1) {
    return res.status(404).json({ error: "Compte introuvable." });
  }

  const account = data.accounts[index];

  // On garde une trace des anciens fichiers pour ne les supprimer
  // qu'une fois qu'on est sûr que la modification est bien enregistrée.
  const previousFiles = {
    avatar: account.avatar,
    music: account.music,
    cursor: account.cursor,
    background: account.background?.value
  };

  if (req.body.username !== undefined) {
    const username = slugify(req.body.username);

    if (username.length < 2) {
      return res.status(400).json({ error: "Nom trop court." });
    }

    if (isReservedUsername(username)) {
      return res.status(409).json({ error: "Ce nom est réservé, choisis-en un autre." });
    }

    if (!usernameAvailable(username, account.id)) {
      return res.status(409).json({ error: "Nom déjà utilisé." });
    }

    account.username = username;
  }

  if (req.body.displayName !== undefined) {
    account.displayName = String(req.body.displayName).slice(0, 60);
  }

  if (req.body.bio !== undefined) {
    account.bio = String(req.body.bio).slice(0, 1000);
  }

  if (req.body.avatar !== undefined) {
    account.avatar = String(req.body.avatar);
  }

  if (req.body.accent !== undefined) {
    const accent = String(req.body.accent);
    account.accent = /^#[0-9a-fA-F]{6}$/.test(accent) ? accent : account.accent;
  }

  if (req.body.background !== undefined && typeof req.body.background === "object") {
    const bg = req.body.background;
    const type = BACKGROUND_TYPES.includes(bg.type) ? bg.type : "image";

    let opacity = Number(bg.opacity);
    if (!Number.isFinite(opacity)) opacity = 1;
    opacity = Math.min(1, Math.max(0, opacity));

    const value = typeof bg.value === "string" ? bg.value.slice(0, 300) : "";

    account.background = { type, value, opacity };
  }

  if (req.body.music !== undefined) {
    account.music = String(req.body.music);
  }

  if (req.body.cursor !== undefined) {
    account.cursor = String(req.body.cursor);
  }

  if (Array.isArray(req.body.links)) {
    account.links = req.body.links
      .slice(0, 30)
      .filter((link) => link && typeof link === "object")
      .map((link) => ({
        type: String(link.type || "Website").slice(0, 32),
        prefix: String(link.prefix || "").slice(0, 100),
        value: String(link.value || "").slice(0, 200),
        label: String(link.label || link.type || "Lien").slice(0, 40)
      }));
  }

  account.updatedAt = new Date().toISOString();
  data.accounts[index] = account;
  saveAccounts(data);

  // Nettoyage différé : seuls les fichiers réellement remplacés par
  // une sauvegarde confirmée sont supprimés du disque.
  if (previousFiles.avatar && previousFiles.avatar !== account.avatar) {
    deleteUploadedFile(previousFiles.avatar);
  }
  if (previousFiles.music && previousFiles.music !== account.music) {
    deleteUploadedFile(previousFiles.music);
  }
  if (previousFiles.cursor && previousFiles.cursor !== account.cursor) {
    deleteUploadedFile(previousFiles.cursor);
  }
  if (previousFiles.background && previousFiles.background !== account.background?.value) {
    deleteUploadedFile(previousFiles.background);
  }

  res.json({ success: true, account });
});

/* =========================================================
   PAGE PUBLIQUE DU PROFIL
========================================================= */

app.get("/:username", (req, res, next) => {
  const username = req.params.username;

  if (isReservedUsername(username) || username.includes(".")) {
    return next();
  }

  const account = findByUsername(username);

  if (!account) {
    return res.status(404).send(renderNotFoundPage());
  }

  res.send(renderProfilePage(account));
});

function renderNotFoundPage() {
  return `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>404 — Sniper</title>
<style>
body{margin:0;min-height:100vh;display:flex;justify-content:center;align-items:center;background:#050505;color:white;font-family:Arial;text-align:center}
h1{font-size:100px;margin:0}
p{color:#777}
a{color:#8b5cf6}
</style>
</head>
<body>
<div>
<h1>404</h1>
<p>Ce profil n'existe pas.</p>
<a href="/">Retour à Sniper</a>
</div>
</body>
</html>`;
}

function renderProfilePage(account) {
  const bg = account.background || { type: "image", value: "", opacity: 1 };
  const accent = /^#[0-9a-fA-F]{6}$/.test(account.accent || "") ? account.accent : "#8b5cf6";

  // Fond par défaut si rien n'est encore configuré.
  let background = "#0b0b0f";
  let video = "";

  if (bg.type === "image" && bg.value) {
    background = `url("${escapeHtml(bg.value)}") center/cover fixed`;
  } else if (bg.type === "video" && bg.value) {
    background = "#000";
    video = `<video class="bg-video" autoplay muted loop playsinline><source src="${escapeHtml(bg.value)}"></video>`;
  } else if (bg.type === "color" && /^#[0-9a-fA-F]{6}$/.test(bg.value || "")) {
    // Compatibilité descendante pour d'anciens comptes qui avaient
    // encore un fond "couleur" (option retirée du panel).
    background = escapeHtml(bg.value);
  }

  const links = (account.links || [])
    .filter((link) => link.value && String(link.value).trim().length > 0)
    .map((link) => {
      const url = String(link.prefix || "") + String(link.value || "");
      return `<a class="link" href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(
        link.label || link.type || "Lien"
      )}</a>`;
    })
    .join("");

  const avatar = account.avatar
    ? `<img class="avatar" src="${escapeHtml(account.avatar)}">`
    : `<div class="avatar default">${escapeHtml(String(account.displayName || "S")[0].toUpperCase())}</div>`;

  const music = account.music
    ? `
<audio id="music" src="${escapeHtml(account.music)}" loop></audio>
<script>
document.addEventListener("click", () => {
  const music = document.getElementById("music");
  if (music) music.play().catch(() => {});
}, { once: true });
</script>`
    : "";

  return `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(account.displayName)} — Sniper</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;justify-content:center;align-items:center;padding:30px;background:${background};color:white;font-family:Arial}
.bg-video{position:fixed;inset:0;width:100%;height:100%;object-fit:cover;z-index:-2}
.profile{width:min(540px,100%);padding:40px 30px;text-align:center;border-radius:25px;background:rgba(5,5,5,.75);border:1px solid rgba(255,255,255,.1);backdrop-filter:blur(20px)}
.avatar{width:110px;height:110px;border-radius:50%;object-fit:cover;margin:auto;display:block;border:3px solid ${escapeHtml(accent)}}
.default{display:flex;justify-content:center;align-items:center;background:${escapeHtml(accent)};font-size:40px;font-weight:bold}
h1{margin-bottom:5px}
.username{color:#777}
.bio{margin:20px 0;color:#bbb;white-space:pre-wrap}
.links{display:flex;flex-direction:column;gap:10px}
.link{padding:14px;border-radius:12px;text-decoration:none;color:white;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08);transition:.15s}
.link:hover{border-color:${escapeHtml(accent)}}
</style>
</head>
<body>
${video}
<div class="profile">
${avatar}
<h1>${escapeHtml(account.displayName)}</h1>
<div class="username">@${escapeHtml(account.username)}</div>
<div class="bio">${escapeHtml(account.bio || "")}</div>
<div class="links">${links}</div>
</div>
${music}
</body>
</html>`;
}

/* =========================================================
   404 GÉNÉRIQUE
========================================================= */

app.use((req, res) => {
  res.status(404).send(`
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>404 — Sniper</title></head>
<body style="background:#050505;color:white;font-family:Arial;text-align:center;padding-top:100px">
<h1>404</h1>
<p>Route introuvable.</p>
<a href="/" style="color:#8b5cf6">Retour</a>
</body>
</html>`);
});

/* =========================================================
   GESTIONNAIRE D'ERREURS GLOBAL
========================================================= */

app.use((error, req, res, next) => {
  console.error(error);

  if (res.headersSent) return next(error);

  res.status(500).json({ error: "Erreur serveur." });
});

/* =========================================================
   DÉMARRAGE
========================================================= */

app.listen(PORT, "0.0.0.0", () => {
  console.log("");
  console.log("================================");
  console.log("          S N I P E R");
  console.log("================================");
  console.log("Local : " + `http://localhost:${PORT}`);
  console.log("Online : " + BASE_URL);
  console.log("Mode : " + (IS_PRODUCTION ? "ONLINE" : "LOCAL"));
  console.log("================================");
});