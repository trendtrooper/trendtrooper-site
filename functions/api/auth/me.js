// GET /api/auth/me — who is signed in (used by the account bar and /manage). Never cached.
import { json, getCookie, verifySession, hasSessionSecret, COOKIE_NAME } from '../../_lib/session.js';

export async function onRequestGet({ request, env }) {
  if (!hasSessionSecret(env)) return json({ authenticated: false });
  const p = await verifySession(getCookie(request, COOKIE_NAME), env.SESSION_SECRET);
  if (!p) return json({ authenticated: false });
  return json({
    authenticated: true,
    kind: p.k,
    plan: p.plan || null,
    expires: p.exp,
    // The bot-issued token is the subscriber's own credential (they can re-use it on another device).
    token: p.k === 'token' ? p.tok : null,
  });
}
