// POST /api/auth/logout — clears the HttpOnly session cookie.
import { json, clearCookie } from '../../_lib/session.js';
import { badOrigin } from '../../_lib/auth-common.js';

export async function onRequestPost({ request }) {
  const refused = badOrigin(request);
  if (refused) return refused;
  return json({ ok: true }, 200, { 'Set-Cookie': clearCookie() });
}
