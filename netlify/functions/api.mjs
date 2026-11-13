// Vintage Nightlife staff site API.
// All private data (recipes, checklists, passwords, sign-offs) lives in Netlify Blobs,
// never in the public GitHub repo. Every request except /api/login needs a signed session cookie.
import { getStore } from "@netlify/blobs";

const COOKIE = "vn_session";
const SESSION_DAYS = 30;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILS = 8;
const SECTIONS = ["recipes", "checklists", "reference", "venues", "roles", "settings"];
const enc = new TextEncoder();

export const config = { path: "/api/*" };

export default async (req, context) => {
  try {
    const url = new URL(req.url);
    const path = url.pathname.replace(/^\/api\/?/, "").replace(/\/+$/, "");
    const method = req.method.toUpperCase();
    const store = getStore({ name: "vn-" + storeContext(context), consistency: "strong" });
    const secret = Netlify.env.get("SESSION_SECRET");
    if (!secret || secret.length < 32) return json({ error: "server_not_configured" }, 500);

    if (path === "login" && method === "POST") return login(req, context, store, secret);
    if (path === "logout" && method === "POST") return json({ ok: true }, 200, { "Set-Cookie": clearCookie() });
    if (path === "seed" && method === "POST") return seed(req, store);

    const session = await readSession(req, store, secret);
    if (!session) return json({ error: "not_logged_in" }, 401, { "Set-Cookie": clearCookie() });
    const isEditor = session.role === "editor";

    if (path === "data" && method === "GET") {
      const content = (await store.get("content", { type: "json" })) || emptyContent();
      return json({ session: publicSession(session), content });
    }

    const m = path.match(/^content\/(\w+)$/);
    if (m && method === "PUT") {
      if (!isEditor) return json({ error: "editors_only" }, 403);
      const section = m[1];
      if (!SECTIONS.includes(section)) return json({ error: "unknown_section" }, 400);
      const body = await req.json().catch(() => null);
      if (!body || body.data === undefined) return json({ error: "bad_request" }, 400);
      const content = (await store.get("content", { type: "json" })) || emptyContent();
      if (body.base && content.versions && content.versions[section] && body.base !== content.versions[section])
        return json({ error: "conflict", content }, 409);
      if (!validSection(section, body.data)) return json({ error: "invalid_data" }, 400);
      content[section] = body.data;
      content.versions = content.versions || {};
      content.versions[section] = new Date().toISOString();
      content.updatedBy = session.name;
      await store.setJSON("content", content);
      return json({ ok: true, content });
    }

    if (path === "passwords") {
      if (!isEditor) return json({ error: "editors_only" }, 403);
      const list = (await store.get("passwords", { type: "json" })) || [];
      if (method === "GET") return json({ passwords: list.map(publicPw) });
      if (method === "POST") {
        const b = await req.json().catch(() => ({}));
        const name = String(b.name || "").trim().slice(0, 60);
        const pw = String(b.password || "");
        const role = b.role === "editor" ? "editor" : "staff";
        if (!name) return json({ error: "name_required" }, 400);
        if (pw.length < 6) return json({ error: "password_too_short" }, 400);
        const lookup = await hmacHex(secret, "pw:" + pw);
        const owner = Netlify.env.get("OWNER_PASSWORD");
        if (list.some((p) => p.lookup === lookup) || (owner && pw === owner)) return json({ error: "password_in_use" }, 409);
        const salt = randomHex(16);
        const entry = { id: randomHex(8), name, role, shared: !!b.shared, lookup, salt, hash: await pbkdf2(pw, salt), createdAt: new Date().toISOString(), createdBy: session.name };
        list.push(entry);
        await store.setJSON("passwords", list);
        return json({ ok: true, password: publicPw(entry) });
      }
    }
    const pd = path.match(/^passwords\/(\w+)$/);
    if (pd && method === "DELETE") {
      if (!isEditor) return json({ error: "editors_only" }, 403);
      const list = (await store.get("passwords", { type: "json" })) || [];
      const next = list.filter((p) => p.id !== pd[1]);
      if (next.length === list.length) return json({ error: "not_found" }, 404);
      await store.setJSON("passwords", next);
      return json({ ok: true });
    }

    if (path === "submissions" && method === "POST") return submitChecklist(req, store, session);
    if (path === "submissions" && method === "GET") {
      if (!isEditor) return json({ error: "editors_only" }, 403);
      const { blobs } = await store.list({ prefix: "sub/" });
      const keys = blobs.map((b) => b.key).sort().reverse().slice(0, 150);
      const items = (await Promise.all(keys.map((k) => store.get(k, { type: "json" })))).filter(Boolean);
      return json({ submissions: items });
    }

    return json({ error: "not_found" }, 404);
  } catch (err) {
    console.error(err);
    return json({ error: "server_error" }, 500);
  }
};

/* ---------- login ---------- */
async function login(req, context, store, secret) {
  const ip = context.ip || "unknown";
  const rlKey = "ratelimit/" + (await hmacHex(secret, "ip:" + ip)).slice(0, 24);
  const now = Date.now();
  const rl = (await store.get(rlKey, { type: "json" })) || { fails: [] };
  rl.fails = rl.fails.filter((t) => now - t < LOGIN_WINDOW_MS);
  if (rl.fails.length >= LOGIN_MAX_FAILS) return json({ error: "too_many_attempts" }, 429);

  const b = await req.json().catch(() => ({}));
  const pw = String(b.password || "");
  let who = null;
  const owner = Netlify.env.get("OWNER_PASSWORD");
  if (owner && pw && timingSafeEqual(pw, owner)) {
    who = { pid: "owner", ov: (await hmacHex(secret, "owner:" + owner)).slice(0, 12), name: Netlify.env.get("OWNER_NAME") || "Owner", role: "editor", shared: false };
  } else if (pw) {
    const list = (await store.get("passwords", { type: "json" })) || [];
    const lookup = await hmacHex(secret, "pw:" + pw);
    const p = list.find((x) => x.lookup === lookup);
    if (p && timingSafeEqual(await pbkdf2(pw, p.salt), p.hash)) who = { pid: p.id, name: p.name, role: p.role, shared: !!p.shared };
  }
  if (!who) {
    rl.fails.push(now);
    await store.setJSON(rlKey, rl);
    await new Promise((r) => setTimeout(r, 600));
    return json({ error: "wrong_password" }, 401);
  }
  if (rl.fails.length) await store.delete(rlKey);
  const sess = { ...who, exp: now + SESSION_DAYS * 864e5 };
  const token = await sign(secret, sess);
  return json({ ok: true, session: publicSession(sess) }, 200, {
    "Set-Cookie": `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`,
  });
}

async function readSession(req, store, secret) {
  const raw = (req.headers.get("cookie") || "").split(/;\s*/).find((c) => c.startsWith(COOKIE + "="));
  if (!raw) return null;
  const sess = await verify(secret, raw.slice(COOKIE.length + 1));
  if (!sess || sess.exp < Date.now()) return null;
  if (sess.pid === "owner") {
    // changing OWNER_PASSWORD logs the owner out everywhere
    const owner = Netlify.env.get("OWNER_PASSWORD");
    return owner && sess.ov === (await hmacHex(secret, "owner:" + owner)).slice(0, 12) ? sess : null;
  }
  // a deleted password logs that person out everywhere
  const list = (await store.get("passwords", { type: "json" })) || [];
  const p = list.find((x) => x.id === sess.pid);
  if (!p) return null;
  return { ...sess, name: p.name, role: p.role, shared: !!p.shared };
}

/* ---------- checklists ---------- */
async function submitChecklist(req, store, session) {
  const b = await req.json().catch(() => null);
  if (!b || !b.checklistId) return json({ error: "bad_request" }, 400);
  const content = (await store.get("content", { type: "json" })) || emptyContent();
  const cl = (content.checklists || []).find((c) => c.id === b.checklistId);
  if (!cl) return json({ error: "unknown_checklist" }, 404);
  const name = String(session.shared ? b.name || "" : session.name).trim().slice(0, 60);
  if (!name) return json({ error: "name_required" }, 400);
  const checked = new Set((Array.isArray(b.checked) ? b.checked : []).map(Number));
  const tasks = (cl.items || []).map((it, i) => ({ i, it })).filter((x) => !x.it.h);
  const sub = {
    id: randomHex(6),
    at: new Date().toISOString(),
    checklistId: cl.id,
    checklist: cl.title && cl.title.en,
    venue: String(b.venue || "").slice(0, 40),
    name,
    signedInAs: session.name,
    notes: String(b.notes || "").slice(0, 2000),
    done: tasks.filter((x) => checked.has(x.i)).length,
    total: tasks.length,
    missed: tasks.filter((x) => !checked.has(x.i)).map((x) => x.it.en),
  };
  await store.setJSON(`sub/${sub.at}-${sub.id}`, sub);
  const emailed = await emailManagers(content, sub);
  return json({ ok: true, emailed });
}

async function emailManagers(content, sub) {
  const key = Netlify.env.get("RESEND_API_KEY");
  const from = Netlify.env.get("EMAIL_FROM");
  const to = ((content.settings && content.settings.managerEmails) || []).filter((e) => /.+@.+\..+/.test(e));
  if (!key || !from || !to.length) return false;
  const venue = (content.venues || []).find((v) => v.id === sub.venue);
  const lines = [
    `${sub.checklist} — ${venue ? venue.name : sub.venue || "no venue"}`,
    `Signed off by: ${sub.name}${sub.name !== sub.signedInAs ? ` (logged in as ${sub.signedInAs})` : ""}`,
    `Completed: ${sub.done} of ${sub.total}`,
    sub.missed.length ? `Not done:\n- ${sub.missed.join("\n- ")}` : "All tasks done.",
    sub.notes ? `Notes:\n${sub.notes}` : "No notes.",
    `Time: ${new Date(sub.at).toLocaleString("en-US", { timeZone: "America/Chicago" })}`,
  ];
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from, to, subject: `${sub.done === sub.total ? "✓" : "⚠"} ${sub.checklist} · ${venue ? venue.name : ""} · ${sub.name}`, text: lines.join("\n\n") }),
    });
    return r.ok;
  } catch {
    return false;
  }
}

/* ---------- one-time seed (protected by SEED_TOKEN env var) ---------- */
async function seed(req, store) {
  const token = Netlify.env.get("SEED_TOKEN");
  if (!token || !timingSafeEqual(req.headers.get("x-seed-token") || "", token)) return json({ error: "forbidden" }, 403);
  const b = await req.json().catch(() => null);
  if (!b || !b.content) return json({ error: "bad_request" }, 400);
  const existing = await store.get("content", { type: "json" });
  // merge: add or replace only the sections sent, keep everything else (recipes, passwords, edits) as it is
  if (b.merge && existing) {
    const content = { ...emptyContent(), ...existing, versions: { ...(existing.versions || {}) } };
    for (const s of Object.keys(b.content)) {
      if (!SECTIONS.includes(s) || !validSection(s, b.content[s])) return json({ error: "invalid_data", section: s }, 400);
      content[s] = b.content[s];
      content.versions[s] = new Date().toISOString();
    }
    await store.setJSON("content", content);
    return json({ ok: true, merged: Object.keys(b.content), counts: { recipes: content.recipes.length, checklists: content.checklists.length, reference: (content.reference || []).length } });
  }
  if (existing && !b.overwrite) return json({ error: "already_seeded" }, 409);
  const content = { ...emptyContent(), ...b.content, versions: {} };
  for (const s of SECTIONS) content.versions[s] = new Date().toISOString();
  await store.setJSON("content", content);
  return json({ ok: true, counts: { recipes: content.recipes.length, checklists: content.checklists.length } });
}

/* ---------- helpers ---------- */
function storeContext(context) {
  // production, deploy-preview and branch-deploy each get their own data, so testing never touches live data
  const c = (context && context.deploy && context.deploy.context) || Netlify.env.get("CONTEXT") || "production";
  return String(c).replace(/[^a-z-]/g, "") || "production";
}
function emptyContent() {
  return { recipes: [], checklists: [], reference: [], venues: [], roles: [], settings: { managerEmails: [] }, versions: {} };
}
function validSection(section, data) {
  if (section === "settings") return data && typeof data === "object" && !Array.isArray(data);
  return Array.isArray(data) && JSON.stringify(data).length < 4_000_000;
}
function publicSession(s) {
  return { name: s.name, role: s.role, shared: !!s.shared, owner: s.pid === "owner" };
}
function publicPw(p) {
  return { id: p.id, name: p.name, role: p.role, shared: !!p.shared, createdAt: p.createdAt, createdBy: p.createdBy };
}
function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers } });
}
function clearCookie() {
  return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}
function randomHex(n) {
  return [...crypto.getRandomValues(new Uint8Array(n))].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function b64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromB64url(s) {
  return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
}
async function hmacBytes(secret, msg) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(msg)));
}
async function hmacHex(secret, msg) {
  return [...(await hmacBytes(secret, msg))].map((x) => x.toString(16).padStart(2, "0")).join("");
}
async function sign(secret, obj) {
  const body = b64url(enc.encode(JSON.stringify(obj)));
  return body + "." + b64url(await hmacBytes(secret, body));
}
async function verify(secret, token) {
  const [body, sig] = String(token).split(".");
  if (!body || !sig) return null;
  if (!timingSafeEqual(b64url(await hmacBytes(secret, body)), sig)) return null;
  try {
    return JSON.parse(new TextDecoder().decode(fromB64url(body)));
  } catch {
    return null;
  }
}
async function pbkdf2(pw, saltHex) {
  const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const salt = Uint8Array.from(saltHex.match(/../g).map((h) => parseInt(h, 16)));
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 100000 }, key, 256);
  return [...new Uint8Array(bits)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function timingSafeEqual(a, b) {
  a = String(a);
  b = String(b);
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}
