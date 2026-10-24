// POST /api/auth/checkout-complete  { session_id }
// Called by /success after Stripe Checkout. Verifies the Checkout Session with the Stripe API
// (server-side, STRIPE_SECRET_KEY) and, if paid + subscription active, sets the signed session cookie.
import { json, issueSession, stripeGet, stripeKeyProblem, ACTIVE_SUB_STATUSES, now } from '../../_lib/session.js';
import { badOrigin, missingSecret, readJson } from '../../_lib/auth-common.js';

// A Checkout Session id can only be redeemed this long after it was created (default 48h).
const DEFAULT_MAX_AGE_HOURS = 48;

export async function onRequestPost({ request, env }) {
  const refused = badOrigin(request) || missingSecret(env);
  if (refused) return refused;

  const keyProblem = stripeKeyProblem(env);
  if (keyProblem) {
    console.error('[auth] checkout-complete:', keyProblem);
    return json({ ok: false, error: 'Payments are not configured on the server.' }, 503);
  }

  const { session_id: sessionId } = await readJson(request);
  if (typeof sessionId !== 'string' || !/^cs_(test|live)_[A-Za-z0-9]{10,250}$/.test(sessionId)) {
    return json({ ok: false, error: 'Invalid checkout session.' }, 400);
  }

  let r;
  try {
    r = await stripeGet(env, `checkout/sessions/${encodeURIComponent(sessionId)}?expand[]=subscription`);
  } catch {
    return json({ ok: false, error: 'Could not reach Stripe. Please retry.' }, 502);
  }
  if (r.status === 404) return json({ ok: false, error: 'Checkout session not found.' }, 404);
  if (!r.ok || !r.data) return json({ ok: false, error: 'Could not verify checkout. Please retry.' }, 502);

  const s = r.data;
  const maxAgeH = Number(env.CHECKOUT_MAX_AGE_HOURS) > 0 ? Number(env.CHECKOUT_MAX_AGE_HOURS) : DEFAULT_MAX_AGE_HOURS;
  const sub = s.subscription && typeof s.subscription === 'object' ? s.subscription : null;
  const paid = s.status === 'complete' && (s.payment_status === 'paid' || s.payment_status === 'no_payment_required');

  if (s.mode !== 'subscription' || !paid || !sub) return json({ ok: false, error: 'Checkout is not complete.' }, 402);
  if (!ACTIVE_SUB_STATUSES.has(sub.status)) return json({ ok: false, error: 'Subscription is not active.' }, 402);
  if (typeof s.created === 'number' && now() - s.created > maxAgeH * 3600) {
    return json({ ok: false, error: 'This checkout link has expired. Use your access token to sign in.' }, 410);
  }

  const customer = typeof s.customer === 'string' ? s.customer : s.customer?.id;
  const plan = String(s.metadata?.plan || sub.metadata?.plan || 'pro').slice(0, 32);
  const { cookie } = await issueSession(env, { k: 'stripe', cus: customer || null, sub: sub.id, plan });
  return json({ ok: true, plan }, 200, { 'Set-Cookie': cookie });
}
