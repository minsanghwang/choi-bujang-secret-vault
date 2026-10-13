import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ACCESS_COOKIE, REFRESH_COOKIE, handleAuth, isSameSite, sessionAuthorization } from '../src/auth-service.mjs';
import { handleCollection } from '../src/notes-service.mjs';

const SECRET = 'fake-test-key-not-real-0123456789';
const A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const PASSWORD = 'correct horse battery staple';

async function call(action, { method = 'POST', headers = {}, body } = {}, clients) {
  const out = { headers: new Map() };
  const response = {
    setHeader: (key, value) => out.headers.set(key.toLowerCase(), value),
    status: (code) => { out.status = code; return { json: (data) => { out.body = data; } }; },
  };
  await handleAuth({ method, headers, body, query: { action } }, response, { clients });
  return out;
}
// 공식 SDK 모양을 흉내 낸 가짜 클라이언트
function clients({ login, user, refresh, signOut = async () => ({}) } = {}) {
  const calls = [];
  const auth = {
    signInWithPassword: async (c) => { calls.push(['login', c]); return login(c); },
    getUser: async (t) => { calls.push(['getUser', t]); return user(t); },
    refreshSession: async (r) => { calls.push(['refresh', r]); return refresh(r); },
    admin: { signOut: async (t, scope) => { calls.push(['signOut', t, scope]); return signOut(t); } },
  };
  return { calls, authClient: () => ({ auth }), adminClient: () => ({ auth }) };
}
const session = { access_token: 'h.p.s', refresh_token: 'refresh-token-1', expires_in: 3600 };
const text = value => JSON.stringify(value) ?? '';

test('로그인 성공: 토큰은 httpOnly 쿠키에만 담고 응답 본문에는 이메일만 있다', async () => {
  const c = clients({ login: async () => ({ data: { session, user: { email: 'a@example.com' } }, error: null }) });
  const res = await call('login', { body: { email: ' a@example.com ', password: PASSWORD } }, c);
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { email: 'a@example.com' });
  assert.deepEqual(c.calls[0], ['login', { email: 'a@example.com', password: PASSWORD }]);
  const cookies = res.headers.get('set-cookie');
  assert.equal(cookies.length, 2);
  for (const value of cookies) {
    assert.match(value, /; Path=\/; HttpOnly; Secure; SameSite=Strict$/u);
    assert.match(value, /^__Host-/u);
  }
  assert.ok(cookies[0].startsWith(`${ACCESS_COOKIE}=h.p.s;`) && cookies[1].startsWith(`${REFRESH_COOKIE}=refresh-token-1;`));
  assert.ok(!text(res.body).includes('h.p.s') && !text(res.body).includes(PASSWORD));
});

test('로그인 실패: 이유 코드만 알리고 쿠키·비밀번호는 내보내지 않는다', async () => {
  const bad = clients({ login: async () => ({ data: {}, error: { code: 'invalid_credentials', status: 400, message: `no ${PASSWORD}` } }) });
  const res = await call('login', { body: { email: 'a@example.com', password: 'x' } }, bad);
  assert.equal(res.status, 401);
  assert.deepEqual(res.body, { error: 'LOGIN_FAILED', reason: 'invalid_credentials' });
  assert.equal(res.headers.has('set-cookie'), false);
  const limited = clients({ login: async () => ({ data: {}, error: { code: 'over_request_rate_limit', status: 429 } }) });
  assert.equal((await call('login', { body: { email: 'a@example.com', password: 'x' } }, limited)).status, 429);
  for (const body of [undefined, {}, { email: 'a@example.com' }, { email: '', password: 'x' }, { email: 'a@example.com', password: 1 }, [1]]) {
    assert.equal((await call('login', { body }, bad)).status, 400);
  }
});

test('세션 확인: 유효하면 이메일, 만료면 한 번 갱신하고, 쿠키가 없으면 401 JSON', async () => {
  const cookie = `${ACCESS_COOKIE}=old.tok.en; ${REFRESH_COOKIE}=refresh-token-1`;
  const ok = clients({ user: async () => ({ data: { user: { email: 'a@example.com' } }, error: null }) });
  const first = await call('session', { method: 'GET', headers: { cookie } }, ok);
  assert.deepEqual(first.body, { email: 'a@example.com' });
  assert.deepEqual(ok.calls, [['getUser', 'old.tok.en']]);

  const expired = clients({ user: async () => ({ data: {}, error: { status: 401 } }),
    refresh: async () => ({ data: { session, user: { email: 'a@example.com' } }, error: null }) });
  const second = await call('session', { method: 'GET', headers: { cookie } }, expired);
  assert.deepEqual(second.body, { email: 'a@example.com' });
  assert.deepEqual(expired.calls[1], ['refresh', { refresh_token: 'refresh-token-1' }]);
  assert.equal(second.headers.get('set-cookie').length, 2);

  const dead = clients({ user: async () => ({ data: {}, error: { status: 401 } }), refresh: async () => ({ data: {}, error: { status: 400 } }) });
  const third = await call('session', { method: 'GET', headers: { cookie } }, dead);
  assert.equal(third.status, 401);
  assert.deepEqual(third.body, { error: 'LOGIN_REQUIRED' });
  assert.ok(third.headers.get('set-cookie').every(value => /Max-Age=0;/u.test(value)));
  const none = await call('session', { method: 'GET' }, dead);
  assert.deepEqual([none.status, none.body], [401, { error: 'LOGIN_REQUIRED' }]);
  assert.equal(none.headers.has('set-cookie'), false);
});

test('로그아웃: 서버 세션을 거두고 쿠키를 지운다. 오류가 나도 쿠키는 지운다', async () => {
  const c = clients({});
  const res = await call('logout', { headers: { cookie: `${ACCESS_COOKIE}=h.p.s` } }, c);
  assert.deepEqual([res.status, res.body], [200, { ok: true }]);
  assert.deepEqual(c.calls[0], ['signOut', 'h.p.s', 'local']);
  assert.ok(res.headers.get('set-cookie').every(value => /Max-Age=0;/u.test(value)));
  const broken = clients({ signOut: async () => { throw new Error('boom'); } });
  const again = await call('logout', { headers: { cookie: `${ACCESS_COOKIE}=h.p.s` } }, broken);
  assert.equal(again.status, 200);
  assert.ok(again.headers.get('set-cookie').every(value => /Max-Age=0;/u.test(value)));
});

test('다른 사이트에서 온 로그인·로그아웃 요청과 잘못된 경로·방식은 거부한다', async () => {
  const c = clients({});
  assert.equal((await call('login', { headers: { 'sec-fetch-site': 'cross-site' }, body: { email: 'a@b.co', password: 'x' } }, c)).status, 403);
  assert.equal((await call('logout', { headers: { origin: 'https://evil.example', host: 'app.example' } }, c)).status, 403);
  assert.equal((await call('nope', {}, c)).status, 404);
  assert.equal((await call('login', { method: 'GET' }, c)).status, 405);
  assert.equal(isSameSite({ headers: { origin: 'https://app.example', host: 'app.example' } }), true);
  assert.equal(isSameSite({ headers: {} }), true);
});

test('설정이 없으면 500 JSON이고 아무 쿠키도 만들지 않는다', async () => {
  const saved = process.env.SUPABASE_URL;
  delete process.env.SUPABASE_URL;
  try {
    const out = await call('session', { method: 'GET' }, undefined);
    assert.deepEqual([out.status, out.body], [500, { error: 'AUTH_NOT_CONFIGURED' }]);
  } finally {
    if (saved !== undefined) process.env.SUPABASE_URL = saved;
  }
});

test('메모 API: Authorization 헤더가 있으면 그것만 쓰고, 없으면 쿠키를 쓰며, 쿠키로 온 다른 사이트 쓰기는 거부한다', async () => {
  process.env.SUPABASE_URL = 'https://abc.supabase.co';
  process.env.SUPABASE_SECRET_KEY = SECRET;
  try {
    const seen = [];
    const verify = async (authorization) => { seen.push(authorization); return authorization === 'Bearer h.p.s' ? { kind: 'student', userId: A } : null; };
    const fetch = async () => new Response(JSON.stringify([]), { status: 200 });
    const run = async (request) => {
      const out = { headers: new Map() };
      await handleCollection({ query: {}, ...request }, {
        setHeader: (key, value) => out.headers.set(key.toLowerCase(), value),
        status: (code) => { out.status = code; return { json: (data) => { out.body = data; } }; },
      }, { verify, fetch, deviceApproved: async () => true });   // 이 시험은 쿠키 로그인 처리만 봅니다(기기 확인은 device-gate 시험에서 따로 봅니다).
      return out;
    };
    const cookie = `${ACCESS_COOKIE}=h.p.s`;
    assert.equal((await run({ method: 'GET', headers: { cookie } })).status, 200);
    assert.equal(seen.at(-1), 'Bearer h.p.s');
    const both = await run({ method: 'GET', headers: { cookie, authorization: 'Bearer bad.tok.en' } });
    assert.equal(both.status, 401);
    assert.equal(seen.at(-1), 'Bearer bad.tok.en');   // 헤더가 있으면 쿠키는 보지 않음
    assert.equal((await run({ method: 'GET', headers: {} })).status, 401);
    const cross = await run({ method: 'POST', headers: { cookie, 'sec-fetch-site': 'cross-site' }, body: { title: 't', body: 'b' } });
    assert.deepEqual([cross.status, cross.body], [403, { error: 'CROSS_SITE_BLOCKED' }]);
    assert.deepEqual(sessionAuthorization({ headers: { cookie: 'a=b' } }), { value: undefined, fromCookie: false });
  } finally {
    delete process.env.SUPABASE_URL; delete process.env.SUPABASE_SECRET_KEY;
  }
});
