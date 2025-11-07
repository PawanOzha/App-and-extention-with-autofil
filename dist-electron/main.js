import { app as R, ipcMain as l, BrowserWindow as S } from "electron";
import { exec as M } from "child_process";
import { fileURLToPath as j } from "node:url";
import m from "node:path";
import J from "fs";
import "http";
import { WebSocket as z, WebSocketServer as q } from "ws";
import Q from "electron-store";
import N, { createHash as Z, randomUUID as F } from "crypto";
import ee from "better-sqlite3";
import re from "path";
import C from "os";
let h = null;
function te() {
  if (!h)
    try {
      const t = re.join(R.getPath("userData"), "database.sqlite");
      h = new ee(t, { verbose: console.log }), console.log("Database connected successfully at:", t), h.pragma("foreign_keys = ON"), h.exec(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          salt TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `), h.exec(`
        CREATE TABLE IF NOT EXISTS categories (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          color TEXT DEFAULT '#6366f1',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
          UNIQUE(user_id, name)
        )
      `), h.exec(`
        CREATE TABLE IF NOT EXISTS credentials (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          category_id INTEGER,
          title TEXT NOT NULL,
          site_link TEXT,
          username TEXT,
          password TEXT NOT NULL,
          description TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
        )
      `), h.exec(`
        CREATE TABLE IF NOT EXISTS notes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          title TEXT NOT NULL,
          content TEXT DEFAULT '',
          color TEXT DEFAULT '#fbbf24',
          is_pinned INTEGER DEFAULT 0,
          is_floating INTEGER DEFAULT 0,
          position_x INTEGER,
          position_y INTEGER,
          width INTEGER,
          height INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `), console.log("All database tables created/verified");
    } catch (t) {
      throw console.error("Database initialization error:", t), t;
    }
  return h;
}
function g() {
  if (!h)
    throw new Error("Database not initialized. Call initDb() first.");
  return h;
}
function se() {
  return N.randomBytes(16).toString("hex");
}
function H(t, r) {
  return N.pbkdf2Sync(t, r, 1e5, 64, "sha512").toString("hex");
}
function oe(t, r, e) {
  const s = H(t, r);
  return N.timingSafeEqual(
    Buffer.from(s, "hex"),
    Buffer.from(e, "hex")
  );
}
const w = /* @__PURE__ */ new Map();
function W(t) {
  const r = Date.now(), e = w.get(t);
  return e ? e.blockedUntil && e.blockedUntil > r ? {
    isBlocked: !0,
    waitTime: Math.ceil((e.blockedUntil - r) / 1e3),
    attemptsRemaining: 0
  } : r - e.firstAttempt > 15 * 60 * 1e3 ? (w.delete(t), { isBlocked: !1, waitTime: 0, attemptsRemaining: 5 }) : {
    isBlocked: !1,
    waitTime: 0,
    attemptsRemaining: Math.max(0, 5 - e.count)
  } : { isBlocked: !1, waitTime: 0, attemptsRemaining: 5 };
}
function $(t) {
  const r = Date.now(), e = w.get(t);
  if (!e) {
    w.set(t, {
      count: 1,
      firstAttempt: r,
      blockedUntil: null
    });
    return;
  }
  if (e.count++, e.count >= 5) {
    const s = Math.min(
      18e5,
      // Max 30 minutes
      3e5 * Math.pow(2, e.count - 5)
      // Exponential backoff
    );
    e.blockedUntil = r + s;
  }
  w.set(t, e);
}
function ne(t) {
  w.delete(t);
}
function ae() {
  const t = Date.now(), r = 60 * 60 * 1e3;
  for (const [e, s] of w.entries())
    t - s.firstAttempt > r && w.delete(e);
}
setInterval(ae, 60 * 60 * 1e3);
function O(t, r) {
  return N.scryptSync(t, r, 32);
}
function _(t, r) {
  try {
    const e = N.randomBytes(16), s = N.createCipheriv("aes-256-gcm", r, e);
    let a = s.update(t, "utf8", "hex");
    a += s.final("hex");
    const n = s.getAuthTag();
    return `${e.toString("hex")}:${n.toString("hex")}:${a}`;
  } catch (e) {
    throw console.error("Encryption error:", e), new Error("Failed to encrypt password");
  }
}
function L(t, r) {
  try {
    const e = t.split(":");
    if (e.length !== 3)
      throw new Error("Invalid encrypted data format");
    const [s, a, n] = e;
    if (!s || !a || !n)
      throw new Error("Invalid encrypted data: missing components");
    const d = Buffer.from(s, "hex"), u = Buffer.from(a, "hex");
    if (d.length !== 16)
      throw new Error("Invalid IV length");
    if (u.length !== 16)
      throw new Error("Invalid auth tag length");
    const f = N.createDecipheriv("aes-256-gcm", r, d);
    f.setAuthTag(u);
    let p = f.update(n, "hex", "utf8");
    return p += f.final("utf8"), p;
  } catch (e) {
    throw console.error("Decryption error:", e.message), e.message.includes("Unsupported state or unable to authenticate data") ? new Error("Decryption failed: Wrong password or corrupted data") : new Error("Failed to decrypt password");
  }
}
const P = m.dirname(j(import.meta.url));
process.env.APP_ROOT = m.join(P, "..");
const A = process.env.VITE_DEV_SERVER_URL, Ie = m.join(process.env.APP_ROOT, "dist-electron"), k = m.join(process.env.APP_ROOT, "dist");
process.env.VITE_PUBLIC = A ? m.join(process.env.APP_ROOT, "public") : k;
const K = process.env.NODE_ENV !== "production";
process.env.PORT;
const y = new Q();
let c = null, T = /* @__PURE__ */ new Map();
const B = 9876;
let b = null, v = /* @__PURE__ */ new Set(), U = "", I = /* @__PURE__ */ new Map();
const D = /* @__PURE__ */ new Map();
function G(t, r) {
  const e = Date.now(), s = D.get(t) || { attempts: 0, lastAttempt: e, blockedUntil: 0 };
  if (s.blockedUntil > e) {
    const n = Math.ceil((s.blockedUntil - e) / 1e3);
    return t.send(JSON.stringify({
      type: "error",
      message: `Too many attempts. Wait ${n} seconds.`
    })), !1;
  }
  e - s.lastAttempt > 6e4 && (s.attempts = 0), s.attempts++, s.lastAttempt = e;
  const a = r === "pair" ? 5 : 20;
  return s.attempts > a ? (s.blockedUntil = e + 5 * 60 * 1e3, D.set(t, s), t.send(JSON.stringify({
    type: "error",
    message: `Too many ${r} attempts. Blocked for 5 minutes.`
  })), !1) : (D.set(t, s), !0);
}
function ie() {
  const t = y.get("appId");
  if (t && t.length === 12) {
    console.log("[App] ⚠️ Found old 12-character App ID - upgrading to 256-bit for security");
    const e = (F() + F()).replace(/-/g, "").toUpperCase();
    return y.set("appId", e), console.log("[App] ✅ App ID upgraded to 256-bit! Please re-pair your browser extension."), e;
  }
  if (t && t.length === 64)
    return console.log("[App] Using existing 256-bit app ID"), t;
  const r = (F() + F()).replace(/-/g, "").toUpperCase();
  return y.set("appId", r), console.log("[App] Generated new permanent app ID (256-bit)"), r;
}
function ce() {
  try {
    U = ie(), b = new q({ port: B }), b.on("listening", () => {
      console.log(`[WebSocket] Server started on port ${B}`), console.log(`[WebSocket] 🔐 Permanent App ID: ${U}`);
    }), b.on("connection", (t) => {
      console.log("[WebSocket] Extension attempting connection..."), v.add(t), I.set(t, !1), t.on("message", async (r) => {
        try {
          const e = JSON.parse(r.toString());
          if (console.log("[WebSocket] Received:", e.type), e.type === "pair") {
            if (!G(t, "pair"))
              return;
            e.code === U ? (I.set(t, !0), D.delete(t), t.send(JSON.stringify({
              type: "pair-success",
              message: "Extension paired successfully",
              appId: U
            })), console.log("[WebSocket] ✅ Extension paired successfully")) : (t.send(JSON.stringify({
              type: "pair-failed",
              message: "Invalid app ID"
            })), console.log("[WebSocket] ❌ Invalid app ID"));
            return;
          }
          if (!I.get(t)) {
            t.send(JSON.stringify({
              type: "error",
              message: "Not paired. Please pair with the app first."
            }));
            return;
          }
          if (e.type === "request-credentials") {
            if (!G(t, "credentials"))
              return;
            console.log("[WebSocket] 📨 Credential request for:", e.url), await le(t, e.url);
            return;
          }
          e.type === "extension-connected" && console.log("[WebSocket] Extension confirmed connection");
        } catch (e) {
          console.error("[WebSocket] Error parsing message:", e);
        }
      }), t.on("close", () => {
        console.log("[WebSocket] Extension disconnected"), v.delete(t), I.delete(t), D.delete(t);
      }), t.on("error", (r) => {
        console.error("[WebSocket] Client error:", r), v.delete(t), I.delete(t), D.delete(t);
      });
    }), b.on("error", (t) => {
      console.error("[WebSocket] Server error:", t);
    });
  } catch (t) {
    console.error("[WebSocket] Failed to start server:", t);
  }
}
async function le(t, r) {
  try {
    if (!o) {
      t.send(JSON.stringify({
        type: "credentials-response",
        success: !1,
        error: "Not authenticated. Please log in to the app first."
      }));
      return;
    }
    if (!o.masterPassword) {
      t.send(JSON.stringify({
        type: "credentials-response",
        success: !1,
        error: "Vault locked. Please unlock your vault in the app first."
      })), console.log("[WebSocket] ⚠️ Vault locked - user needs to unlock");
      return;
    }
    let e = "";
    try {
      e = new URL(r.includes("://") ? r : "https://" + r).hostname;
    } catch {
      t.send(JSON.stringify({
        type: "credentials-response",
        success: !1,
        error: "Invalid URL"
      }));
      return;
    }
    console.log(`[WebSocket] Searching credentials for hostname: ${e}`);
    const a = g().prepare(`
      SELECT * FROM credentials 
      WHERE user_id = ? AND site_link LIKE ?
      ORDER BY created_at DESC
    `).all(o.userId, `%${e}%`);
    if (a.length === 0) {
      t.send(JSON.stringify({
        type: "credentials-response",
        success: !1,
        error: "No credentials found for this site"
      })), console.log("[WebSocket] No credentials found");
      return;
    }
    const n = a[0], d = await O(o.masterPassword, o.salt), u = n.username ? L(n.username, d) : "", f = L(n.password, d);
    t.send(JSON.stringify({
      type: "credentials-response",
      success: !0,
      url: r,
      username: u,
      password: f
    })), console.log("[WebSocket] ✅ Credentials sent to extension");
  } catch (e) {
    console.error("[WebSocket] Error handling credential request:", e), t.send(JSON.stringify({
      type: "credentials-response",
      success: !1,
      error: "Internal error"
    }));
  }
}
function de(t) {
  const r = JSON.stringify(t);
  let e = 0;
  return v.forEach((s) => {
    s.readyState === z.OPEN && I.get(s) && (s.send(r), e++);
  }), console.log(`[WebSocket] Sent message to ${e} paired extension(s)`), e > 0;
}
const V = async () => {
  c = new S({
    width: 900,
    height: 600,
    minWidth: 800,
    minHeight: 600,
    frame: !1,
    icon: m.join(process.env.VITE_PUBLIC, "favicon.ico"),
    webPreferences: {
      nodeIntegration: !1,
      contextIsolation: !0,
      preload: m.join(P, "preload.mjs"),
      webSecurity: !K
    },
    show: !1
  }), c.once("ready-to-show", () => {
    c == null || c.show(), c == null || c.webContents.setZoomFactor(0.67);
  }), c.webContents.on("did-finish-load", () => {
    c == null || c.webContents.send("main-process-message", (/* @__PURE__ */ new Date()).toLocaleString());
  }), A ? await c.loadURL(A) : await c.loadFile(m.join(k, "index.html")), c.on("close", (t) => {
    o && (o.masterPassword = void 0, o.encryptionKey = void 0), c && !c.isDestroyed() && c.webContents.send("clear-session-storage"), console.log("Window closing - cleared master password from session");
  }), c.on("closed", () => {
    c = null;
  });
}, ue = (t, r = {}) => {
  if (console.log("Creating sticky note window for note:", t), T.has(t)) {
    const n = T.get(t);
    if (n && !n.isDestroyed()) {
      n.focus();
      return;
    }
  }
  const e = new S({
    width: r.width || 300,
    height: r.height || 400,
    x: r.x,
    y: r.y,
    minWidth: 300,
    minHeight: 200,
    frame: !1,
    alwaysOnTop: r.alwaysOnTop !== !1,
    skipTaskbar: !1,
    resizable: !0,
    webPreferences: {
      nodeIntegration: !1,
      contextIsolation: !0,
      preload: m.join(P, "preload.mjs"),
      webSecurity: !K
    },
    backgroundColor: "#30302E",
    show: !1
  });
  T.set(t, e), e.once("ready-to-show", () => {
    e.show();
  });
  const s = A ? `${A}#/sticky-note/${t}` : `file://${m.join(k, "index.html")}#/sticky-note/${t}`;
  console.log("Loading sticky note URL:", s), A ? e.loadURL(s) : e.loadFile(m.join(k, "index.html"), {
    hash: `/sticky-note/${t}`
  });
  const a = () => {
    if (!e.isDestroyed()) {
      const n = e.getBounds();
      e.webContents.send("window-bounds-changed", n);
    }
  };
  return e.on("resize", a), e.on("move", a), e.on("closed", () => {
    T.delete(t), console.log("Sticky note window closed:", t);
  }), e;
};
l.on("window-minimize", () => {
  c && c.minimize();
});
l.on("window-maximize", () => {
  c && (c.isMaximized() ? c.restore() : c.maximize());
});
l.on("window-close", () => {
  c && c.close();
});
l.on("sticky-note-minimize", (t) => {
  const r = S.fromWebContents(t.sender);
  r && r.minimize();
});
l.on("sticky-note-close", (t) => {
  const r = S.fromWebContents(t.sender);
  r && r.close();
});
l.on("sticky-note-toggle-always-on-top", (t) => {
  const r = S.fromWebContents(t.sender);
  if (r) {
    const e = r.isAlwaysOnTop();
    r.setAlwaysOnTop(!e), t.reply("sticky-note-always-on-top-changed", !e);
  }
});
l.on("open-sticky-note", (t, r, e) => {
  console.log("Received open-sticky-note request:", r), ue(r, e);
});
l.on("close-sticky-note-window", (t, r) => {
  if (T.has(r)) {
    const e = T.get(r);
    e && !e.isDestroyed() && e.close(), T.delete(r);
  }
});
l.handle("get-window-bounds", (t) => {
  const r = S.fromWebContents(t.sender);
  return r ? r.getBounds() : null;
});
l.handle("get-app-id", () => ({ success: !0, appId: U }));
l.handle("open-in-browser", async (t, r, e, s) => {
  console.log(`Opening ${r} in ${e}`);
  try {
    const n = {
      chrome: [
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
      ],
      brave: [
        "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
        "C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"
      ],
      edge: [
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"
      ]
    }[e];
    let d = null;
    for (const u of n)
      if (J.existsSync(u)) {
        d = u;
        break;
      }
    if (!d)
      return console.error(`${e} not found in any of the expected locations`), { success: !1, error: `${e} not found` };
    if (s && o)
      try {
        if (console.log(`[Auto-Fill] Credential ID: ${s}, Session User: ${o.userId}`), !o.masterPassword)
          return console.error("[Auto-Fill] ❌ Master password not in memory! User needs to enter it first."), console.error("[Auto-Fill] Tip: View or edit a credential in the app to load master password into memory."), new Promise((p, i) => {
            M(`"${d}" "${r}"`, (E) => {
              E ? (console.error(`Failed to open ${e}:`, E), i({ success: !1, error: `Failed to launch ${e}` })) : (console.log(`Successfully opened ${r} in ${e}`), p({ success: !0, warning: "Master password not available for auto-fill" }));
            });
          });
        const f = g().prepare("SELECT * FROM credentials WHERE id = ? AND user_id = ?").get(s, o.userId);
        if (console.log(`[Auto-Fill] Credential found: ${f ? "Yes" : "No"}`), f) {
          console.log("[Auto-Fill] Decrypting credentials...");
          const p = await O(o.masterPassword, o.salt), i = f.username ? L(f.username, p) : "", E = L(f.password, p);
          console.log(`[Auto-Fill] Decrypted - Username: ${i ? "Yes" : "No"}, Password: ${E ? "Yes" : "No"}`), de({
            type: "credentials",
            url: r,
            username: i,
            password: E,
            autoClick: !0
            // Enable auto-click for app-launched pages
          }) ? console.log("[WebSocket] ✅ Credentials sent to extension") : console.warn("[WebSocket] ⚠️ No extension connected to receive credentials");
        } else
          console.error("[Auto-Fill] ❌ Credential not found in database");
      } catch (u) {
        console.error("[Auto-Fill] ❌ Error processing credentials:", u);
      }
    else s && !o && console.error("[Auto-Fill] ❌ No active session!");
    return new Promise((u, f) => {
      M(`"${d}" "${r}"`, (p) => {
        p ? (console.error(`Failed to open ${e}:`, p), f({ success: !1, error: `Failed to launch ${e}` })) : (console.log(`Successfully opened ${r} in ${e}`), u({ success: !0 }));
      });
    });
  } catch (a) {
    return console.error("Browser launch error:", a), { success: !1, error: "Failed to launch browser" };
  }
});
l.on("app-message", (t, r) => {
  console.log("Received message from renderer:", r), t.reply("app-reply", "Message received");
});
let o = null;
function Y() {
  const t = `${C.hostname()}-${C.platform()}-${C.arch()}-${C.userInfo().username}`;
  return Z("sha256").update(t).digest("hex").substring(0, 32);
}
l.handle("auth:signup", async (t, { username: r, password: e }) => {
  try {
    const s = g();
    if (s.prepare("SELECT * FROM users WHERE username = ?").get(r))
      return { success: !1, error: "Username already exists" };
    const n = se(), d = H(e, n);
    return {
      success: !0,
      user: {
        id: s.prepare(
          "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)"
        ).run(r, d, n).lastInsertRowid,
        username: r,
        salt: n
      }
    };
  } catch (s) {
    return console.error("Signup error:", s), { success: !1, error: s.message || "Signup failed" };
  }
});
l.handle("auth:login", async (t, { username: r, password: e }) => {
  try {
    const s = W(r);
    if (s.isBlocked)
      return {
        success: !1,
        error: `Too many failed login attempts. Please wait ${s.waitTime} seconds.`
      };
    const n = g().prepare("SELECT * FROM users WHERE username = ?").get(r);
    if (!n)
      return $(r), {
        success: !1,
        error: "Invalid username or password",
        attemptsRemaining: Math.max(0, 5 - (s.attemptsRemaining - 1))
      };
    if (!oe(e, n.salt, n.password_hash))
      return $(r), {
        success: !1,
        error: "Invalid username or password",
        attemptsRemaining: W(r).attemptsRemaining
      };
    ne(r), o = {
      userId: n.id,
      username: n.username,
      salt: n.salt,
      masterPassword: e
    };
    const u = Date.now() + 30 * 24 * 60 * 60 * 1e3, f = Y();
    return y.set("user", {
      id: n.id,
      username: n.username,
      salt: n.salt,
      expiresAt: u,
      deviceId: f
    }), console.log("User authenticated and persisted (expires in 30 days):", r), {
      success: !0,
      user: {
        id: n.id,
        username: n.username,
        salt: n.salt
      }
    };
  } catch (s) {
    return console.error("Login error:", s), { success: !1, error: s.message || "Login failed" };
  }
});
l.handle("auth:verify", async (t) => {
  if (o)
    return {
      success: !0,
      user: {
        id: o.userId,
        username: o.username,
        salt: o.salt
      }
    };
  const r = y.get("user");
  if (r) {
    console.log("Found persisted user, verifying session:", r.username);
    const e = Date.now();
    if (r.expiresAt && r.expiresAt < e)
      return console.log("Session expired, clearing"), y.delete("user"), { success: !1, error: "Session expired. Please log in again." };
    const s = Y();
    if (r.deviceId && r.deviceId !== s)
      return console.log("Device mismatch, clearing session"), y.delete("user"), { success: !1, error: "Session invalid on this device. Please log in again." };
    try {
      return g().prepare("SELECT id, username, salt FROM users WHERE id = ?").get(r.id) ? (console.log("User verified in database, restoring session"), o = {
        userId: r.id,
        username: r.username,
        salt: r.salt
      }, {
        success: !0,
        user: {
          id: r.id,
          username: r.username,
          salt: r.salt
        }
      }) : (console.log("User not found in database, clearing persisted session"), y.delete("user"), o = null, { success: !1, error: "Session expired or user not found" });
    } catch (a) {
      return console.error("Error verifying persisted user:", a), y.delete("user"), o = null, { success: !1, error: "Not authenticated" };
    }
  }
  return { success: !1, error: "Not authenticated" };
});
l.handle("auth:logout", async (t) => (o = null, y.delete("user"), console.log("User logged out and session cleared"), { success: !0 }));
l.handle("credentials:fetch", async (t, { masterPassword: r, categoryId: e, search: s }) => {
  try {
    if (!o)
      return { success: !1, error: "Not authenticated" };
    const a = await O(r, o.salt), n = g();
    let d = `
      SELECT 
        c.*,
        cat.name as category_name,
        cat.color as category_color
      FROM credentials c
      LEFT JOIN categories cat ON c.category_id = cat.id
      WHERE c.user_id = ?
    `;
    const u = [o.userId];
    if (e != null && (d += " AND c.category_id = ?", u.push(e)), s) {
      d += " AND (c.title LIKE ? OR c.description LIKE ? OR c.site_link LIKE ?)";
      const i = `%${s}%`;
      u.push(i, i, i);
    }
    d += " ORDER BY c.created_at DESC";
    const p = n.prepare(d).all(...u).map((i) => ({
      ...i,
      password: L(i.password, a),
      username: i.username ? L(i.username, a) : ""
    }));
    return o.masterPassword || (o.masterPassword = r, console.log("[Session] Master password loaded into memory for autofill")), { success: !0, credentials: p };
  } catch (a) {
    return console.error("Fetch credentials error:", a), { success: !1, error: a.message || "Failed to fetch credentials" };
  }
});
l.handle("credentials:create", async (t, r) => {
  try {
    if (!o)
      return { success: !1, error: "Not authenticated" };
    const { masterPassword: e, title: s, siteLink: a, username: n, password: d, description: u, categoryId: f } = r, p = await O(e, o.salt), i = _(d, p), E = n ? _(n, p) : "";
    return { success: !0, id: g().prepare(`
      INSERT INTO credentials (user_id, category_id, title, site_link, username, password, description)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      o.userId,
      f || null,
      s,
      a || "",
      E,
      i,
      u || ""
    ).lastInsertRowid };
  } catch (e) {
    return console.error("Create credential error:", e), { success: !1, error: e.message || "Failed to create credential" };
  }
});
l.handle("credentials:update", async (t, r) => {
  try {
    if (!o)
      return { success: !1, error: "Not authenticated" };
    const { id: e, masterPassword: s, title: a, siteLink: n, username: d, password: u, description: f, categoryId: p } = r, i = await O(s, o.salt), E = _(u, i), x = d ? _(d, i) : "";
    return g().prepare(`
      UPDATE credentials 
      SET category_id = ?, title = ?, site_link = ?, username = ?, password = ?, description = ?
      WHERE id = ? AND user_id = ?
    `).run(
      p || null,
      a,
      n || "",
      x,
      E,
      f || "",
      e,
      o.userId
    ), { success: !0 };
  } catch (e) {
    return console.error("Update credential error:", e), { success: !1, error: e.message || "Failed to update credential" };
  }
});
l.handle("credentials:delete", async (t, { id: r }) => {
  try {
    return o ? (g().prepare("DELETE FROM credentials WHERE id = ? AND user_id = ?").run(r, o.userId), { success: !0 }) : { success: !1, error: "Not authenticated" };
  } catch (e) {
    return console.error("Delete credential error:", e), { success: !1, error: e.message || "Failed to delete credential" };
  }
});
l.handle("categories:fetch", async (t) => {
  try {
    return o ? { success: !0, categories: g().prepare(`
      SELECT * FROM categories WHERE user_id = ? ORDER BY name ASC
    `).all(o.userId) } : { success: !1, error: "Not authenticated" };
  } catch (r) {
    return console.error("Fetch categories error:", r), { success: !1, error: r.message || "Failed to fetch categories" };
  }
});
l.handle("categories:create", async (t, { name: r, color: e }) => {
  try {
    return o ? { success: !0, id: g().prepare(`
      INSERT INTO categories (user_id, name, color) VALUES (?, ?, ?)
    `).run(o.userId, r, e || "#D97757").lastInsertRowid } : { success: !1, error: "Not authenticated" };
  } catch (s) {
    return console.error("Create category error:", s), { success: !1, error: s.message || "Failed to create category" };
  }
});
l.handle("categories:update", async (t, { id: r, name: e, color: s }) => {
  try {
    return o ? (g().prepare(`
      UPDATE categories 
      SET name = ?, color = ?
      WHERE id = ? AND user_id = ?
    `).run(e, s || "#D97757", r, o.userId), { success: !0 }) : { success: !1, error: "Not authenticated" };
  } catch (a) {
    return console.error("Update category error:", a), { success: !1, error: a.message || "Failed to update category" };
  }
});
l.handle("categories:delete", async (t, { id: r }) => {
  try {
    return o ? (g().prepare("DELETE FROM categories WHERE id = ? AND user_id = ?").run(r, o.userId), { success: !0 }) : { success: !1, error: "Not authenticated" };
  } catch (e) {
    return console.error("Delete category error:", e), { success: !1, error: e.message || "Failed to delete category" };
  }
});
l.handle("notes:fetch", async (t) => {
  try {
    return o ? { success: !0, notes: g().prepare(`
      SELECT * FROM notes WHERE user_id = ? ORDER BY updated_at DESC
    `).all(o.userId) } : { success: !1, error: "Not authenticated" };
  } catch (r) {
    return console.error("Fetch notes error:", r), { success: !1, error: r.message || "Failed to fetch notes" };
  }
});
l.handle("notes:create", async (t, { title: r, content: e, color: s }) => {
  try {
    return o ? { success: !0, id: g().prepare(`
      INSERT INTO notes (user_id, title, content, color)
      VALUES (?, ?, ?, ?)
    `).run(o.userId, r, e || "", s || "#fbbf24").lastInsertRowid } : { success: !1, error: "Not authenticated" };
  } catch (a) {
    return console.error("Create note error:", a), { success: !1, error: a.message || "Failed to create note" };
  }
});
l.handle("notes:update", async (t, { id: r, title: e, content: s, color: a, position_x: n, position_y: d, width: u, height: f }) => {
  try {
    if (!o)
      return { success: !1, error: "Not authenticated" };
    const p = g(), i = [], E = [];
    return e !== void 0 && (i.push("title = ?"), E.push(e)), s !== void 0 && (i.push("content = ?"), E.push(s)), a !== void 0 && (i.push("color = ?"), E.push(a)), n !== void 0 && (i.push("position_x = ?"), E.push(n)), d !== void 0 && (i.push("position_y = ?"), E.push(d)), u !== void 0 && (i.push("width = ?"), E.push(u)), f !== void 0 && (i.push("height = ?"), E.push(f)), i.push("updated_at = CURRENT_TIMESTAMP"), E.push(r, o.userId), p.prepare(`
      UPDATE notes SET ${i.join(", ")}
      WHERE id = ? AND user_id = ?
    `).run(...E), { success: !0 };
  } catch (p) {
    return console.error("Update note error:", p), { success: !1, error: p.message || "Failed to update note" };
  }
});
l.handle("notes:delete", async (t, { id: r }) => {
  try {
    return o ? (g().prepare("DELETE FROM notes WHERE id = ? AND user_id = ?").run(r, o.userId), { success: !0 }) : { success: !1, error: "Not authenticated" };
  } catch (e) {
    return console.error("Delete note error:", e), { success: !1, error: e.message || "Failed to delete note" };
  }
});
R.whenReady().then(async () => {
  try {
    console.log("Initializing database..."), te(), console.log("Database initialized"), ce(), await V();
  } catch (t) {
    console.error("Failed to start application:", t), R.quit();
  }
});
R.on("window-all-closed", () => {
  process.platform !== "darwin" && R.quit();
});
R.on("activate", async () => {
  S.getAllWindows().length === 0 && await V();
});
R.on("before-quit", () => {
  T.forEach((t) => {
    t.isDestroyed() || t.close();
  }), T.clear(), b && (console.log("[WebSocket] Closing server..."), v.forEach((t) => {
    t.close();
  }), v.clear(), b.close());
});
process.on("SIGINT", () => {
  process.exit();
});
process.on("SIGTERM", () => {
  process.exit();
});
export {
  Ie as MAIN_DIST,
  k as RENDERER_DIST,
  A as VITE_DEV_SERVER_URL
};
