// Backend for "กระดานสนทนา นศท." — Netlify Function + Netlify Blobs (no extra database needed)
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = { path: "/api/*" };

const DAY = 86400000;
const forum = () => getStore({ name: "forum", consistency: "strong" });
const creds = () => getStore({ name: "creds", consistency: "strong" });
const media = () => getStore({ name: "media", consistency: "strong" });

const CORS = { "access-control-allow-origin": "*", "access-control-allow-headers": "authorization, content-type", "access-control-allow-methods": "GET, POST, OPTIONS" };
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...CORS } });
const err = (status, code, message) => json({ error: code, message }, status);

const uid = () => Date.now().toString(36) + crypto.randomBytes(4).toString("hex").slice(0, 5);

/* ---------- state ---------- */
const emptyState = () => ({ users: [], posts: [], reposts: [], reports: [], events: [], notifs: [], trash: [], chats: {}, broadcasts: [], mart: null });

async function readState() {
  const r = await forum().getWithMetadata("state", { type: "json", consistency: "strong" });
  if (!r || !r.data) return { state: emptyState(), etag: null };
  return { state: r.data, etag: r.etag };
}
async function writeState(state, etag) {
  const opts = etag ? { onlyIfMatch: etag } : { onlyIfNew: true };
  const res = await forum().setJSON("state", state, opts);
  return res && res.modified !== false ? res.etag : null;
}

/* ---------- passwords / sessions ---------- */
function hashPw(pw, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(pw, salt, 64).toString("hex");
  return { salt, hash };
}
function checkPw(pw, rec) {
  if (!rec) return false;
  const a = Buffer.from(crypto.scryptSync(pw, rec.salt, 64).toString("hex"));
  const b = Buffer.from(rec.hash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
async function newSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  await creds().setJSON("s/" + token, { uid: userId, at: Date.now() });
  return token;
}
async function authUser(req, state) {
  const h = req.headers.get("authorization") || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!/^[0-9a-f]{64}$/.test(token)) return null;
  const s = await creds().get("s/" + token, { type: "json" });
  if (!s) return null;
  const u = state.users.find((x) => x.id === s.uid);
  return u ? { user: u, token } : null;
}

/* ---------- media: pull big data: URIs out of the state into Blobs ---------- */
async function externalizeMedia(val) {
  if (typeof val === "string") {
    const m = /^data:((?:image|video|audio)\/[\w.+-]+);base64,/.exec(val);
    if (m && val.length > 1500) {
      const id = uid() + crypto.randomBytes(3).toString("hex");
      const buf = Buffer.from(val.slice(m[0].length), "base64");
      await media().set(id, buf, { metadata: { type: m[1] } });
      return "/api/media/" + id;
    }
    return val;
  }
  if (Array.isArray(val)) {
    for (let i = 0; i < val.length; i++) val[i] = await externalizeMedia(val[i]);
    return val;
  }
  if (val && typeof val === "object") {
    for (const k of Object.keys(val)) val[k] = await externalizeMedia(val[k]);
  }
  return val;
}

/* ---------- path helpers (arrays of {id} objects are addressed by id) ---------- */
const isIdObj = (x) => x && typeof x === "object" && !Array.isArray(x) && typeof x.id === "string";
function child(container, seg) {
  if (Array.isArray(container)) return container.find((x) => isIdObj(x) && x.id === seg);
  if (container && typeof container === "object") return Object.prototype.hasOwnProperty.call(container, seg) ? container[seg] : undefined;
  return undefined;
}
const BAD = new Set(["__proto__", "constructor", "prototype"]);

function applyOp(root, op) {
  const p = op.p;
  if (!Array.isArray(p) || !p.length || p.some((s) => typeof s !== "string" || BAD.has(s))) return false;
  let cur = root;
  for (let i = 0; i < p.length - 1; i++) {
    cur = child(cur, p[i]);
    if (cur === undefined || cur === null || typeof cur !== "object") return false;
  }
  const last = p[p.length - 1];
  if (Array.isArray(cur)) {
    const idx = cur.findIndex((x) => isIdObj(x) && x.id === last);
    if (op.x) { if (idx >= 0) cur.splice(idx, 1); return true; }
    if (op.inc !== undefined) return false;
    if (!isIdObj(op.v) || op.v.id !== last) return false;
    if (idx >= 0) cur[idx] = op.v; else cur.push(op.v);
    return true;
  }
  if (op.x) { delete cur[last]; return true; }
  if (op.inc !== undefined) {
    const n = Number(op.inc);
    if (!Number.isFinite(n)) return false;
    const base = typeof cur[last] === "number" ? cur[last] : 0;
    let v = base + n;
    if (last === "stock" && v < 0) v = 0;
    cur[last] = v;
    return true;
  }
  cur[last] = op.v;
  return true;
}

/* ---------- permissions ---------- */
const USER_LOCKED_SELF = new Set(["id", "username", "first", "last", "gender", "year", "birth", "company", "platoon", "role", "banned", "suspendedUntil", "postBlockUntil", "tags", "password"]);
const POST_ADMIN_ONLY = new Set(["announce", "commentsOpen", "allowedReacts"]);

function allowed(op, me, st) {
  const admin = me.role === "admin";
  const p = op.p;
  const [a, b, c, ...r] = p;
  if (admin) return a !== "users" || !(p.length === 3 && (c === "id" || c === "password"));
  const blocked = me.postBlockUntil > Date.now();
  const byId = (arr, id) => (arr || []).find((x) => x.id === id);

  const commentRule = (item, rest) => {
    const cm = rest.length ? byId(item.comments, rest[0]) : undefined;
    if (!rest.length) return false;
    if (rest.length === 1) {
      if (op.x) return !!cm && (cm.userId === me.id || item.userId === me.id);
      if (!cm) return !blocked && op.v && op.v.userId === me.id;
      return cm.userId === me.id;
    }
    if (!cm) return false;
    if (rest[1] === "reacts") return rest.length === 3 && rest[2] === me.id;
    return cm.userId === me.id;
  };

  switch (a) {
    case "users": {
      if (b === me.id) {
        if (!c) return false;
        return !USER_LOCKED_SELF.has(c);
      }
      return c === "reportCount" && r.length === 0 && (op.inc !== undefined || typeof op.v === "number");
    }
    case "posts":
    case "reposts": {
      const item = byId(st[a], b);
      if (!c) {
        if (op.x) return !!item && item.userId === me.id;
        if (!item) {
          if (blocked || !op.v || op.v.userId !== me.id) return false;
          if (a === "posts" && (op.v.announce || op.v.allowedReacts || op.v.commentsOpen === false)) return false;
          return true;
        }
        return item.userId === me.id && !(a === "posts" && op.v && op.v.announce && !item.announce);
      }
      if (!item) return false;
      if (c === "comments") return commentRule(item, r);
      if (c === "reacts") return r.length === 1 && r[0] === me.id;
      if (a === "posts" && POST_ADMIN_ONLY.has(c)) return false;
      return item.userId === me.id;
    }
    case "reports": {
      const item = byId(st.reports, b);
      if (c) return false;
      return !item && !op.x && op.v && op.v.by === me.id;
    }
    case "notifs": {
      const item = byId(st.notifs, b);
      if (c) return !!item && item.userId === me.id;
      if (!item) return !op.x && op.v && st.users.some((u) => u.id === op.v.userId);
      return item.userId === me.id;
    }
    case "events": {
      const item = byId(st.events, b);
      if (item && c === "claimedBy" && !op.x && Array.isArray(op.v)) {
        const old = item.claimedBy || [];
        return old.every((x) => op.v.includes(x)) && op.v.filter((x) => !old.includes(x)).every((x) => x === me.id);
      }
      return false;
    }
    case "chats": {
      if (b !== me.id) return false;
      if (!c) return !op.x && !st.chats[b] && op.v && !op.v.muted && ["none", "pending"].includes(op.v.status) && !(op.v.msgs || []).some((m) => m.from !== "user");
      if (c === "muted") return false;
      if (c === "status") return !op.x && op.v === "pending";
      if (c === "msgs" && r.length === 1 && !op.x && op.v && op.v.from !== "user") {
        const old = byId((st.chats[b] || {}).msgs, r[0]);
        return !!old; // editing an existing message (e.g. reactions) is OK; creating non-user messages is not
      }
      return true;
    }
    case "mart": {
      if (p.length === 1) return !op.x && st.mart == null;
      const m = st.mart || {};
      if (b === "carts" || b === "favs") return c === me.id;
      if (b === "orders") {
        const o = byId(m.orders, c);
        if (!o) return !op.x && r.length === 0 && !!op.v && op.v.userId === me.id;
        return o.userId === me.id;
      }
      if (b === "products") return r.length === 1 && (r[0] === "stock" || r[0] === "restockAt");
      if (b === "logs") return !byId(m.logs, c) && !op.x && r.length === 0;
      return false;
    }
    default:
      return false;
  }
}

/* ---------- what each viewer may see ---------- */
function viewFor(st, me) {
  if (me.role === "admin") return st;
  const v = JSON.parse(JSON.stringify(st));
  v.users = v.users.map((u) => (u.id === me.id ? u : (delete u.log, delete u.claims, delete u.penalized, delete u.birth, u)));
  v.notifs = v.notifs.filter((n) => n.userId === me.id);
  v.reports = v.reports.filter((r) => r.by === me.id);
  v.trash = [];
  v.chats = v.chats[me.id] ? { [me.id]: v.chats[me.id] } : {};
  v.events = v.events.map((e) => (e.type === "egg" ? (delete e.code, e) : e));
  if (v.mart) {
    v.mart.orders = (v.mart.orders || []).filter((o) => o.userId === me.id);
    v.mart.carts = v.mart.carts && v.mart.carts[me.id] ? { [me.id]: v.mart.carts[me.id] } : {};
    v.mart.favs = v.mart.favs && v.mart.favs[me.id] ? { [me.id]: v.mart.favs[me.id] } : {};
    v.mart.logs = [];
  }
  return v;
}

const clientIp = (req) => (req.headers.get("x-nf-client-connection-ip") || "x").replace(/[^\w.:]/g, "");

/* ---------- handlers ---------- */
async function register(req) {
  const d = await req.json().catch(() => null);
  if (!d) return err(400, "bad", "ข้อมูลไม่ถูกต้อง");
  const un = String(d.username || "").trim();
  if (!/^[A-Za-z0-9_]{3,20}$/.test(un)) return err(400, "username", "ชื่อผู้ใช้ต้องเป็นอังกฤษ/ตัวเลข 3–20 ตัว");
  if (typeof d.password !== "string" || d.password.length < 6 || d.password.length > 100) return err(400, "password", "รหัสผ่านอย่างน้อย 6 ตัว");
  const low = un.toLowerCase();

  for (let attempt = 0; attempt < 6; attempt++) {
    const { state, etag } = await readState();
    const taken = state.users.some((u) => u.username.toLowerCase() === low) || state.trash.some((t) => t.user && t.user.username.toLowerCase() === low);
    if (taken) return err(409, "taken", "ชื่อผู้ใช้นี้ถูกใช้แล้ว");

    const hasAdmin = state.users.some((u) => u.role === "admin");
    let role = "member";
    if (!hasAdmin) {
      const code = process.env.ADMIN_CODE;
      if (!code) return err(503, "setup", "ยังไม่ได้ตั้งค่า ADMIN_CODE ใน Netlify (Site configuration → Environment variables)");
      if (String(d.adminCode || "") !== code) return err(403, "admincode", "ต้องใช้รหัสตั้งค่าแอดมิน (ADMIN_CODE) เพื่อสร้างบัญชีแอดมินคนแรก");
      role = "admin";
    }
    const str = (x, n) => String(x ?? "").slice(0, n);
    const company = Math.min(3, Math.max(1, +d.company || 1)), platoon = Math.min(4, Math.max(1, +d.platoon || 1));
    const room = [2 * platoon - 1, 2 * platoon].includes(+d.room) ? +d.room : 2 * platoon - 1;
    const user = {
      id: uid(), username: un, first: str(d.first, 60).trim(), last: str(d.last, 60).trim(),
      gender: ["male", "female", "other"].includes(d.gender) ? d.gender : "other",
      year: Math.min(3, Math.max(1, +d.year || 1)), company, platoon, room, birth: str(d.birth, 10),
      avatar: "", bio: "", socials: [], links: [], music: null, theme: { profile: "#2f6f8f", postBg: "" },
      score: 0, role, suspendedUntil: 0, reportCount: 0, createdAt: Date.now(), claims: [], penalized: [], log: [],
    };
    if (!user.first || !user.last) return err(400, "name", "กรอกชื่อและนามสกุล");
    state.users.push(user);
    const ok = await writeState(state, etag);
    if (!ok) continue; // someone else wrote first – retry
    await creds().setJSON("u/" + user.id, hashPw(d.password));
    const token = await newSession(user.id);
    const fresh = await readState();
    return json({ token, uid: user.id, etag: fresh.etag, state: viewFor(fresh.state, user) });
  }
  return err(503, "busy", "เซิร์ฟเวอร์ไม่ว่าง ลองใหม่อีกครั้ง");
}

async function login(req) {
  const d = await req.json().catch(() => null);
  if (!d) return err(400, "bad", "ข้อมูลไม่ถูกต้อง");
  const low = String(d.username || "").trim().toLowerCase();
  const rl = "a/" + low + "/" + clientIp(req);
  const att = (await creds().get(rl, { type: "json" })) || { n: 0, t: 0 };
  if (att.n >= 8 && Date.now() - att.t < 10 * 60000) return err(429, "ratelimit", "ลองผิดหลายครั้ง กรุณารอ 10 นาที");
  const { state, etag } = await readState();
  const u = state.users.find((x) => x.username.toLowerCase() === low);
  const rec = u ? await creds().get("u/" + u.id, { type: "json" }) : null;
  if (!u || !checkPw(String(d.password || ""), rec)) {
    await creds().setJSON(rl, { n: (Date.now() - att.t < 10 * 60000 ? att.n : 0) + 1, t: Date.now() });
    return err(401, "credentials", "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง");
  }
  if (att.n) await creds().delete(rl);
  if (u.banned) return err(403, "banned", "บัญชีถูกแบน");
  if (u.suspendedUntil > Date.now()) return err(403, "suspended", "บัญชีถูกพักการใช้งาน");
  const token = await newSession(u.id);
  return json({ token, uid: u.id, etag, state: viewFor(state, u) });
}

async function getState(req, url) {
  const { state, etag } = await readState();
  const au = await authUser(req, state);
  if (!au) return err(401, "auth", "กรุณาเข้าสู่ระบบ");
  if (au.user.banned) return err(403, "banned", "บัญชีถูกแบน");
  if (url.searchParams.get("etag") && url.searchParams.get("etag") === etag) return json({ same: true, etag });
  return json({ etag, state: viewFor(state, au.user) });
}

async function sync(req) {
  const d = await req.json().catch(() => null);
  if (!d || !Array.isArray(d.ops)) return err(400, "bad", "ข้อมูลไม่ถูกต้อง");
  if (d.ops.length > 600) return err(413, "big", "การเปลี่ยนแปลงมากเกินไป");
  for (let attempt = 0; attempt < 8; attempt++) {
    const { state, etag } = await readState();
    const au = await authUser(req, state);
    if (!au) return err(401, "auth", "กรุณาเข้าสู่ระบบ");
    const me = au.user;
    if (me.banned) return err(403, "banned", "บัญชีถูกแบน");
    let rejected = 0, changed = 0;
    for (const raw of d.ops) {
      const op = { p: raw.p, v: raw.v, x: raw.x, inc: raw.inc };
      if (!Array.isArray(op.p)) { rejected++; continue; }
      let ok = false;
      try { ok = allowed(op, me, state); } catch { ok = false; }
      if (!ok) { rejected++; continue; }
      if (op.v !== undefined) op.v = await externalizeMedia(op.v);
      if (applyOp(state, op)) changed++; else rejected++;
    }
    if (!changed) return json({ ok: true, rejected, etag, state: viewFor(state, me) });
    const newEtag = await writeState(state, etag);
    if (!newEtag) continue;
    return json({ ok: true, rejected, etag: newEtag, state: viewFor(state, me) });
  }
  return err(503, "busy", "เซิร์ฟเวอร์ไม่ว่าง ลองใหม่อีกครั้ง");
}

async function adminSetPw(req) {
  const d = await req.json().catch(() => null);
  const { state } = await readState();
  const au = await authUser(req, state);
  if (!au || au.user.role !== "admin") return err(403, "forbidden", "เฉพาะผู้ดูแล");
  if (!d || typeof d.password !== "string" || d.password.length < 6) return err(400, "password", "รหัสผ่านอย่างน้อย 6 ตัว");
  const target = state.users.find((u) => u.id === d.id) || (state.trash.find((t) => t.user && t.user.id === d.id) || {}).user;
  if (!target) return err(404, "nouser", "ไม่พบผู้ใช้");
  await creds().setJSON("u/" + target.id, hashPw(d.password));
  return json({ ok: true });
}

async function egg(req) {
  const d = await req.json().catch(() => null);
  const { state } = await readState();
  const au = await authUser(req, state);
  if (!au) return err(401, "auth", "กรุณาเข้าสู่ระบบ");
  const code = String((d && d.code) || "").trim().toLowerCase();
  const now = Date.now();
  const e = code && state.events.find((x) => x.type === "egg" && String(x.code).toLowerCase() === code && x.start <= now && x.end >= now);
  return json(e ? { id: e.id } : { id: null });
}

async function serveMedia(id) {
  if (!/^[\w]+$/.test(id)) return err(404, "nf", "ไม่พบไฟล์");
  const r = await media().getWithMetadata(id, { type: "arrayBuffer" });
  if (!r || !r.data) return err(404, "nf", "ไม่พบไฟล์");
  return new Response(r.data, { headers: { "content-type": (r.metadata && r.metadata.type) || "application/octet-stream", "cache-control": "public, max-age=31536000, immutable", "x-content-type-options": "nosniff" } });
}

export default async (req) => {
  const url = new URL(req.url);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  const path = url.pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
  try {
    if (req.method === "GET" && path === "status") {
      const { state } = await readState();
      return json({ needsAdmin: !state.users.some((u) => u.role === "admin"), adminCodeSet: !!process.env.ADMIN_CODE });
    }
    if (req.method === "GET" && path.startsWith("media/")) return await serveMedia(path.slice(6));
    if (req.method === "GET" && path === "state") return await getState(req, url);
    if (req.method === "POST" && path === "register") return await register(req);
    if (req.method === "POST" && path === "login") return await login(req);
    if (req.method === "POST" && path === "sync") return await sync(req);
    if (req.method === "POST" && path === "admin/setpw") return await adminSetPw(req);
    if (req.method === "POST" && path === "egg") return await egg(req);
    if (req.method === "POST" && path === "logout") {
      const h = req.headers.get("authorization") || "";
      const t = h.startsWith("Bearer ") ? h.slice(7) : "";
      if (/^[0-9a-f]{64}$/.test(t)) await creds().delete("s/" + t);
      return json({ ok: true });
    }
    return err(404, "nf", "ไม่พบเส้นทาง");
  } catch (e) {
    console.error(e);
    return err(500, "server", "เซิร์ฟเวอร์ขัดข้อง");
  }
};
