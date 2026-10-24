// Run: npm test   (node --test, no dependencies)
import test from 'node:test';
import assert from 'node:assert/strict';
import { signSession, verifySession, safeEqual, safeNext, stripeKeyProblem, RECHECK_INTERVAL, RECHECK_GRACE, now } from '../functions/_lib/session.js';
import { isProtected, evaluateSession, onRequest } from '../functions/_middleware.js';

const SECRET = 'x'.repeat(40);
const base = () => ({ v: 1, k: 'stripe', sub: 'sub_ok', iat: now(), chk: now(), exp: now() + 3600 });

test('sign/verify roundtrip', async () => {
  const c = await signSession(base(), SECRET);
  assert.equal((await verifySession(c, SECRET)).sub, 'sub_ok');
});

test('rejects tampered payload, wrong secret, expired, garbage', async () => {
  const c = await signSession(base(), SECRET);
  const [body, sig] = c.split('.');
  const forged = Buffer.from(JSON.stringify({ ...base(), sub: 'sub_other' })).toString('base64url');
  assert.equal(await verifySession(`${forged}.${sig}`, SECRET), null);
  assert.equal(await verifySession(c, 'y'.repeat(40)), null);
  assert.equal(await verifySession(await signSession({ ...base(), exp: now() - 1 }, SECRET), SECRET), null);
  assert.equal(await verifySession(await signSession({ ...base(), k: 'admin' }, SECRET), SECRET), null);
  for (const g of [null, '', 'abc', 'a.b.c', `${body}.`, `${body}.!!!`]) assert.equal(await verifySession(g, SECRET), null);
});

test('protected path matching', () => {
  for (const p of ['/dashboard', '/dashboard/', '/Dashboard/index.html', '/academy.html', '/ACADEMY.HTML', '/%64ashboard', '//chart', '/manage/x'])
    assert.ok(isProtected(p), p);
  for (const p of ['/', '/subscribe', '/success/', '/pine-scripts', '/pine-scripts/VWAP_Compass.pine', '/tools', '/dashboardx', '/api/auth/me'])
    assert.ok(!isProtected(p), p);
});

test('safeEqual / safeNext / live-key refusal', async () => {
  assert.ok(await safeEqual('abc', 'abc'));
  assert.ok(!(await safeEqual('abc', 'abd')));
  assert.equal(safeNext('//evil.com'), '/dashboard');
  assert.equal(safeNext('https://evil.com'), '/dashboard');
  assert.equal(safeNext('/chart'), '/chart');
  assert.equal(stripeKeyProblem({ STRIPE_SECRET_KEY: 'sk_test_1' }), null);
  assert.match(stripeKeyProblem({ STRIPE_SECRET_KEY: 'sk_live_1' }), /live/);
  assert.match(stripeKeyProblem({}), /not set/);
});

function mockFetch(status, body) {
  const calls = [];
  globalThis.fetch = async (url) => { calls.push(String(url)); if (status === 'throw') throw new Error('down'); return new Response(JSON.stringify(body), { status }); };
  return calls;
}
const env = { SESSION_SECRET: SECRET, STRIPE_SECRET_KEY: 'sk_test_x', STRIPE_API_BASE: 'http://mock' };

test('fresh session: no upstream call', async () => {
  const calls = mockFetch(200, {});
  assert.deepEqual(await evaluateSession(env, base()), { allow: true });
  assert.equal(calls.length, 0);
});

test('stale session re-checks Stripe: active -> refreshed cookie', async () => {
  const calls = mockFetch(200, { status: 'active' });
  const r = await evaluateSession(env, { ...base(), chk: now() - RECHECK_INTERVAL - 5 });
  assert.ok(r.allow && /tt_session=.*HttpOnly; Secure; SameSite=Lax/.test(r.setCookie));
  assert.equal(calls[0], 'http://mock/v1/subscriptions/sub_ok');
});

test('stale session: canceled subscription -> denied', async () => {
  mockFetch(200, { status: 'canceled' });
  assert.equal((await evaluateSession(env, { ...base(), chk: now() - RECHECK_INTERVAL - 5 })).allow, false);
});

test('stale session: Stripe outage -> grace, then denied', async () => {
  mockFetch('throw');
  assert.equal((await evaluateSession(env, { ...base(), chk: now() - RECHECK_INTERVAL - 5 })).allow, true);
  assert.equal((await evaluateSession(env, { ...base(), chk: now() - RECHECK_INTERVAL - RECHECK_GRACE - 5 })).allow, false);
});

test('dev session revoked when DEV_ACCESS_TOKEN rotates or is removed', async () => {
  const { devFingerprint } = await import('../functions/_lib/session.js');
  const e1 = { ...env, DEV_ACCESS_TOKEN: 'a'.repeat(30) };
  const p = { ...base(), k: 'dev', dv: await devFingerprint(e1) };
  assert.equal((await evaluateSession(e1, p)).allow, true);
  assert.equal((await evaluateSession({ ...env, DEV_ACCESS_TOKEN: 'b'.repeat(30) }, p)).allow, false);
  assert.equal((await evaluateSession(env, p)).allow, false);
});

test('middleware: missing SESSION_SECRET locks paid pages, public pages pass', async () => {
  const next = async () => new Response('page');
  const r = await onRequest({ request: new Request('https://t.com/dashboard'), env: {}, next });
  assert.equal(r.status, 302);
  assert.match(r.headers.get('Location'), /\/subscribe\?next=%2Fdashboard&reason=config/);
  assert.equal(await (await onRequest({ request: new Request('https://t.com/tools'), env: {}, next })).text(), 'page');
});
