// TrendTrooper — server-side session helpers for Cloudflare Pages Functions.
// Runs in the Workers runtime: Web Crypto + fetch only, no dependencies.
//
// Session cookie format:  base64url(JSON payload) "." base64url(HMAC-SHA256(payload, SESSION_SECRET))
// Payload fields:
//   v    format version (1)
//   k    kind: "stripe" | "token" | "dev"
//   cus  Stripe customer id (stripe kind)
//   sub  Stripe subscription id (stripe kind)
//   tok  bot-issued access token (token kind) — only ever stored in the HttpOnly cookie
//   dv   fingerprint of DEV_ACCESS_TOKEN (dev kind) — rotating the env var revokes dev sessions
//   plan plan label for display ("pro", "auto", "dev")
//   iat  issued-at (unix seconds)
//   chk  last time the subscription was confirmed active (unix seconds)
//   exp  hard expiry (unix seconds)

export const COOKIE_NAME = 'tt_session';
export const SESSION_TTL = 30 * 24 * 3600;        // hard cookie lifetime: 30 days
export const RECHECK_INTERVAL = 6 * 3600;         // re-confirm subscription with Stripe / bot every 6h
export const RECHECK_GRACE = 24 * 3600;           // tolerate upstream outages this long past a due re-check
export const ACTIVE_SUB_STATUSES = new Set(['active', 'trialing']);

const enc = new TextEncoder();
const dec = new TextDecoder();

export const now = () => Math.floor(Date.now() / 1000);

// ---------- base64url ----------
export function b64urlEncode(bytes) {
  let bin = '';
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(str) {
  if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str)) throw new Error('bad b64url');
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---------- crypto ----------
async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Constant-time string comparison (compares SHA-256 digests so length is not leaked).
export async function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const [ha, hb] = await Promise.all([sha256Hex(a), sha256Hex(b)]);
  let diff = 0;
  for (let i = 0; i < ha.length; i++) diff |= ha.charCodeAt(i) ^ hb.charCodeAt(i);
  return diff === 0 && a.length === b.length;
}

export function hasSessionSecret(env) {
  return typeof env?.SESSION_SECRET === 'string' && env.SESSION_SECRET.length >= 32;
}

export async function signSession(payload, secret) {
  const body = b64urlEncode(enc.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(body));
  return `${body}.${b64urlEncode(sig)}`;
}

// Returns the payload if the signature is valid and the session is unexpired, else null.
export async function verifySession(value, secret, at = now()) {
  if (!value || typeof value !== 'string' || value.length > 4096) return null;
  const parts = value.split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  let ok = false;
  try {
    ok = await crypto.subtle.verify('HMAC', await hmacKey(secret), b64urlDecode(sig), enc.encode(body));
  } catch {
    return null;
  }
  if (!ok) return null;
  let payload;
  try {
    payload = JSON.parse(dec.decode(b64urlDecode(body)));
  } catch {
    return null;
  }
  if (!payload || payload.v !== 1 || typeof payload.exp !== 'number' || payload.exp <= at) return null;
  if (!['stripe', 'token', 'dev'].includes(payload.k)) return null;
  return payload;
}

// ---------- cookies ----------
export function getCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
  }
  return null;
}

export function sessionCookie(value, maxAge) {
  return `${COOKIE_NAME}=${value}; Path=/; Max-Age=${Math.max(0, Math.floor(maxAge))}; HttpOnly; Secure; SameSite=Lax`;
}

export function clearCookie() {
  return `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

export async function issueSession(env, fields) {
  const t = now();
  const payload = { v: 1, iat: t, chk: t, exp: t + SESSION_TTL, ...fields };
  const value = await signSession(payload, env.SESSION_SECRET);
  return { payload, cookie: sessionCookie(value, payload.exp - t) };
}

export async function reissueSession(env, payload, changes) {
  const t = now();
  const next = { ...payload, ...changes };
  const value = await signSession(next, env.SESSION_SECRET);
  return { payload: next, cookie: sessionCookie(value, next.exp - t) };
}

// ---------- upstream checks ----------
function stripeBase(env) {
  // STRIPE_API_BASE exists only so the flow can be smoke-tested against a local mock.
  return (env.STRIPE_API_BASE || 'https://api.stripe.com').replace(/\/+$/, '');
}

// Refuse live-mode keys unless explicitly allowed (the site is meant to run in Stripe TEST mode).
export function stripeKeyProblem(env) {
  const key = env.STRIPE_SECRET_KEY;
  if (!key) return 'STRIPE_SECRET_KEY is not set';
  if (!/^(sk|rk)_(test|live)_/.test(key)) return 'STRIPE_SECRET_KEY does not look like a Stripe secret/restricted key';
  if (/^(sk|rk)_live_/.test(key) && env.STRIPE_ALLOW_LIVE !== 'true') return 'live Stripe key refused (set STRIPE_ALLOW_LIVE=true to allow)';
  return null;
}

export async function stripeGet(env, path) {
  const res = await fetch(`${stripeBase(env)}/v1/${path}`, {
    headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`, 'Stripe-Version': '2024-06-20' },
  });
  let data = null;
  try { data = await res.json(); } catch { /* ignore */ }
  return { ok: res.ok, status: res.status, data };
}

// Result: { state: 'active' | 'inactive' | 'error', plan? }
//  'inactive' = upstream says access should end; 'error' = could not determine (network, 5xx, misconfig).
export async function checkStripeSubscription(env, subId) {
  if (stripeKeyProblem(env)) return { state: 'error' };
  if (!subId || !/^sub_[A-Za-z0-9]+$/.test(subId)) return { state: 'inactive' };
  try {
    const r = await stripeGet(env, `subscriptions/${encodeURIComponent(subId)}`);
    if (r.status === 404) return { state: 'inactive' };
    if (!r.ok || !r.data) return { state: 'error' };
    return { state: ACTIVE_SUB_STATUSES.has(r.data.status) ? 'active' : 'inactive' };
  } catch {
    return { state: 'error' };
  }
}

function botVerifyUrl(env) {
  return env.BOT_VERIFY_URL || 'https://bot.trendtrooper.com/verify-token';
}

// Verifies a bot-issued subscriber token server-side (same endpoint manage.astro used to call from the browser).
export async function checkBotToken(env, token) {
  if (!token || typeof token !== 'string' || token.length > 512) return { state: 'inactive' };
  try {
    const res = await fetch(`${botVerifyUrl(env)}?token=${encodeURIComponent(token)}`, { headers: { Accept: 'application/json' } });
    if (res.status >= 500) return { state: 'error' };
    const d = await res.json().catch(() => null);
    if (!d) return { state: 'error' };
    return d.valid === true
      ? { state: 'active', plan: typeof d.plan === 'string' ? d.plan.slice(0, 32) : 'pro' }
      : { state: 'inactive' };
  } catch {
    return { state: 'error' };
  }
}

export async function devFingerprint(env) {
  const t = env.DEV_ACCESS_TOKEN;
  if (typeof t !== 'string' || t.length < 24) return null; // dev access disabled unless a long token is configured
  return (await sha256Hex(`tt-dev:${t}`)).slice(0, 32);
}

// ---------- responses ----------
export function json(data, status = 200, extraHeaders = {}) {
  const headers = new Headers({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  for (const [k, v] of Object.entries(extraHeaders)) headers.append(k, v);
  return new Response(JSON.stringify(data), { status, headers });
}

// Accept only same-site relative paths for post-login redirects.
export function safeNext(next) {
  if (typeof next !== 'string' || !next.startsWith('/') || next.startsWith('//') || next.includes('\\')) return '/dashboard';
  return next.slice(0, 200);
}
