// POST /api/auth/token  { token }
// Redeems an access token entered on /subscribe:
//  - DEV_ACCESS_TOKEN (env var, compared server-side in constant time) -> developer session
//  - otherwise the token is verified with the bot (BOT_VERIFY_URL) -> subscriber session
import { json, issueSession, safeEqual, devFingerprint, checkBotToken } from '../../_lib/session.js';
import { badOrigin, missingSecret, readJson } from '../../_lib/auth-common.js';

export async function onRequestPost({ request, env }) {
  const refused = badOrigin(request) || missingSecret(env);
  if (refused) return refused;

  const { token } = await readJson(request);
  if (typeof token !== 'string' || token.trim().length < 8 || token.length > 512) {
    return json({ ok: false, error: 'Invalid token.' }, 400);
  }
  const t = token.trim();

  const fp = await devFingerprint(env);
  if (fp && (await safeEqual(t, env.DEV_ACCESS_TOKEN))) {
    const { cookie } = await issueSession(env, { k: 'dev', dv: fp, plan: 'dev' });
    return json({ ok: true, plan: 'dev' }, 200, { 'Set-Cookie': cookie });
  }

  const result = await checkBotToken(env, t);
  if (result.state === 'active') {
    const { cookie } = await issueSession(env, { k: 'token', tok: t, plan: result.plan || 'pro' });
    return json({ ok: true, plan: result.plan || 'pro' }, 200, { 'Set-Cookie': cookie });
  }
  if (result.state === 'error') return json({ ok: false, error: 'Could not verify token right now. Please retry.' }, 502);
  return json({ ok: false, error: 'Invalid token.' }, 401);
}
