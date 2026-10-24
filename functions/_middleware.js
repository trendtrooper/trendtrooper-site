// TrendTrooper — server-side paywall for Cloudflare Pages.
// Cloudflare Pages compiles the repo-root `functions/` directory alongside the static Astro output (./dist);
// public/_routes.json (copied into dist) decides which requests invoke Functions — the rest is served as plain static.
// Runs before static assets are served. Paid routes require a valid signed `tt_session` cookie
// (issued by /api/auth/*), otherwise the visitor is redirected to /subscribe.
import {
  COOKIE_NAME, RECHECK_INTERVAL, RECHECK_GRACE,
  getCookie, verifySession, reissueSession, clearCookie, hasSessionSecret,
  checkStripeSubscription, checkBotToken, devFingerprint, now,
} from './_lib/session.js';

// Paid page prefixes. Keep in sync with public/_routes.json (which decides which requests reach this code).
export const PROTECTED_PREFIXES = ['/dashboard', '/strategy', '/analysis', '/academy', '/screener', '/chart', '/manage'];

// "/Dashboard/index.html" -> "/dashboard", "/academy.html" -> "/academy"
export function normalizePath(pathname) {
  let p;
  try { p = decodeURIComponent(pathname); } catch { p = pathname; }
  p = p.toLowerCase().replace(/\/{2,}/g, '/');
  p = p.replace(/\/index\.html?$/, '').replace(/\.html?$/, '').replace(/\/+$/, '');
  return p || '/';
}

export function isProtected(pathname) {
  const p = normalizePath(pathname);
  return PROTECTED_PREFIXES.some((pre) => p === pre || p.startsWith(pre + '/'));
}

function toSubscribe(url, reason, extraHeaders = {}) {
  const dest = new URL('/subscribe', url);
  dest.searchParams.set('next', url.pathname);
  if (reason) dest.searchParams.set('reason', reason);
  const headers = new Headers({ Location: dest.toString(), 'Cache-Control': 'no-store' });
  for (const [k, v] of Object.entries(extraHeaders)) headers.append(k, v);
  return new Response(null, { status: 302, headers });
}

function privateResponse(res, setCookie) {
  const out = new Response(res.body, res);
  out.headers.set('Cache-Control', 'private, no-store');
  out.headers.set('Vary', 'Cookie');
  if (setCookie) out.headers.append('Set-Cookie', setCookie);
  return out;
}

// Decide whether a verified session is still entitled. Returns { allow, setCookie?, reason? }.
export async function evaluateSession(env, payload, at = now()) {
  if (payload.k === 'dev') {
    const fp = await devFingerprint(env);
    return fp && payload.dv === fp ? { allow: true } : { allow: false, reason: 'expired' };
  }

  const age = at - (payload.chk || 0);
  if (age < RECHECK_INTERVAL) return { allow: true };

  const result = payload.k === 'stripe'
    ? await checkStripeSubscription(env, payload.sub)
    : await checkBotToken(env, payload.tok);

  if (result.state === 'active') {
    const { cookie } = await reissueSession(env, payload, { chk: at, ...(result.plan ? { plan: result.plan } : {}) });
    return { allow: true, setCookie: cookie };
  }
  if (result.state === 'error' && age < RECHECK_INTERVAL + RECHECK_GRACE) {
    return { allow: true }; // upstream hiccup: keep access briefly, retry on next request
  }
  return { allow: false, reason: result.state === 'inactive' ? 'inactive' : 'recheck' };
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  if (!isProtected(url.pathname)) return next();

  if (!hasSessionSecret(env)) {
    console.error('[paywall] SESSION_SECRET missing or shorter than 32 chars — paid pages are locked');
    return toSubscribe(url, 'config');
  }

  const payload = await verifySession(getCookie(request, COOKIE_NAME), env.SESSION_SECRET);
  if (!payload) return toSubscribe(url, null, getCookie(request, COOKIE_NAME) ? { 'Set-Cookie': clearCookie() } : {});

  const decision = await evaluateSession(env, payload);
  if (!decision.allow) return toSubscribe(url, decision.reason, { 'Set-Cookie': clearCookie() });

  return privateResponse(await next(), decision.setCookie);
}
