// Shared guards for /api/auth/* endpoints.
import { json, hasSessionSecret } from './session.js';

// Reject cross-site POSTs (login CSRF / forced logout). Same-origin fetches send a matching Origin.
export function badOrigin(request) {
  const origin = request.headers.get('Origin');
  if (!origin) return null; // non-browser clients / some same-origin navigations omit it
  try {
    if (new URL(origin).host === new URL(request.url).host) return null;
  } catch { /* fall through */ }
  return json({ ok: false, error: 'Cross-origin request refused' }, 403);
}

export function missingSecret(env) {
  if (hasSessionSecret(env)) return null;
  console.error('[auth] SESSION_SECRET missing or shorter than 32 chars');
  return json({ ok: false, error: 'Server is not configured for sign-in yet.' }, 503);
}

export async function readJson(request) {
  try {
    const text = await request.text();
    if (text.length > 4096) return {};
    return JSON.parse(text) || {};
  } catch {
    return {};
  }
}
