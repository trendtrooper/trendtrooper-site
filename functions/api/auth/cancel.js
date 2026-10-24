// POST /api/auth/cancel — cancels the signed-in subscription at period end.
//  - bot-token sessions: forwarded to the bot's /cancel-subscription with the token held in the cookie
//  - Stripe sessions: Stripe API, cancel_at_period_end=true on the subscription in the cookie
import { json, getCookie, verifySession, stripeKeyProblem, COOKIE_NAME } from '../../_lib/session.js';
import { badOrigin, missingSecret } from '../../_lib/auth-common.js';

export async function onRequestPost({ request, env }) {
  const refused = badOrigin(request) || missingSecret(env);
  if (refused) return refused;

  const p = await verifySession(getCookie(request, COOKIE_NAME), env.SESSION_SECRET);
  if (!p) return json({ ok: false, error: 'Not signed in.' }, 401);

  try {
    if (p.k === 'token') {
      const url = env.BOT_CANCEL_URL || 'https://bot.trendtrooper.com/cancel-subscription';
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: p.tok }),
      });
      const d = await res.json().catch(() => ({}));
      return json({ ok: d.status === 'cancelled', status: d.status || 'error' }, d.status === 'cancelled' ? 200 : 502);
    }

    if (p.k === 'stripe') {
      if (stripeKeyProblem(env)) return json({ ok: false, error: 'Payments are not configured on the server.' }, 503);
      const base = (env.STRIPE_API_BASE || 'https://api.stripe.com').replace(/\/+$/, '');
      const res = await fetch(`${base}/v1/subscriptions/${encodeURIComponent(p.sub)}`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded',
          'Stripe-Version': '2024-06-20',
        },
        body: 'cancel_at_period_end=true',
      });
      return res.ok ? json({ ok: true, status: 'cancelled' }) : json({ ok: false, status: 'error' }, 502);
    }
  } catch {
    return json({ ok: false, status: 'error' }, 502);
  }

  return json({ ok: false, error: 'Developer sessions have no subscription.' }, 400);
}
