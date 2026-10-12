import assert from 'node:assert/strict';
import { test } from 'node:test';
import config from '../aleph.config.json' with { type: 'json' };
import { handleCollection, handleItem } from '../src/notes-service.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';

const SECRET = 'fake-test-key-not-real-0123456789';
const A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const NOTE = '11111111-1111-4111-8111-111111111111';

async function call(handler, { method = 'GET', headers = {}, body, query } = {}, deps) {
  const out = { headers: new Map() };
  const response = {
    setHeader: (key, value) => out.headers.set(key.toLowerCase(), value),
    status: (code) => { out.status = code; return { json: (data) => { out.body = data; }, end: () => { out.ended = true; } }; },
  };
  await handler({ method, headers, body, query }, response, deps);
  return out;
}
async function withEnv(fn) {
  const saved = { url: process.env.SUPABASE_URL, key: process.env.SUPABASE_SECRET_KEY };
  process.env.SUPABASE_URL = 'https://abc.supabase.co';
  process.env.SUPABASE_SECRET_KEY = SECRET;
  try { return await fn(); } finally {
    for (const [name, value] of [['SUPABASE_URL', saved.url], ['SUPABASE_SECRET_KEY', saved.key]]) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  }
}
const login = { authorization: 'Bearer a.b.c' };
const verifyA = async (authorization) => (authorization === login.authorization ? { kind: 'student', userId: A } : null);
// 서버 저장소 흉내: 호출 기록과 정해 둔 응답
function store(responses) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url: new URL(url), method: init.method, headers: init.headers, body: init.body ? JSON.parse(init.body) : undefined });
    const next = responses.shift() ?? { status: 200, body: [] };
    return new Response(JSON.stringify(next.body), { status: next.status ?? 200 });
  };
  return { calls, fetch };
}

test('로그인 없이는 401과 JSON 오류 문구만 오고, 저장소는 한 번도 부르지 않는다', async () => {
  await withEnv(async () => {
    const s = store([]);
    for (const [handler, req] of [[handleCollection, {}], [handleItem, { query: { id: NOTE } }],
      [handleCollection, { method: 'POST', body: { title: 't', body: 'b' } }],
      [handleItem, { method: 'DELETE', query: { id: NOTE } }]]) {
      for (const headers of [{}, { authorization: 'Bearer x.y.z' }, { authorization: 'Basic abc' }]) {
        const res = await call(handler, { ...req, headers }, { verify: verifyA, fetch: s.fetch });
        assert.equal(res.status, 401);
        assert.deepEqual(res.body, { error: 'LOGIN_REQUIRED' });
        assert.equal(res.headers.get('cache-control'), 'no-store');
      }
    }
    assert.equal(s.calls.length, 0);
  });
});

test('서버 전용 키나 주소가 없으면 500 JSON이고 자료는 나가지 않는다', async () => {
  const saved = { url: process.env.SUPABASE_URL, key: process.env.SUPABASE_SECRET_KEY };
  delete process.env.SUPABASE_URL; delete process.env.SUPABASE_SECRET_KEY;
  try {
    const res = await call(handleCollection, { headers: login }, {});
    assert.equal(res.status, 500);
    assert.deepEqual(res.body, { error: 'NOTES_NOT_CONFIGURED' });
  } finally {
    if (saved.url !== undefined) process.env.SUPABASE_URL = saved.url;
    if (saved.key !== undefined) process.env.SUPABASE_SECRET_KEY = saved.key;
  }
});

test('POST는 서버가 확인한 사용자 ID를 owner_id로 저장하고 본문의 userId·role은 무시한다', async () => {
  await withEnv(async () => {
    const s = store([{ status: 201, body: [{ id: NOTE, title: 't', content: 'b' }] }]);
    const res = await call(handleCollection, { method: 'POST', headers: login,
      body: { title: ' 제목 ', body: '내용', userId: 'evil', owner_id: 'evil', role: 'admin' } },
    { verify: verifyA, fetch: s.fetch });
    assert.equal(res.status, 201);
    assert.deepEqual(res.body, { id: NOTE });
    assert.deepEqual(s.calls[0].body, { owner_id: A, title: '제목', content: '내용' });
    assert.equal(s.calls[0].method, 'POST');
    assert.equal(s.calls[0].headers.apikey, SECRET);
    assert.ok(!JSON.stringify(res).includes(SECRET));
  });
});

test('POST에 id를 주면 그 UUID로 저장하고, 형식이 틀리면 400이다', async () => {
  await withEnv(async () => {
    const s = store([{ status: 201, body: [{ id: NOTE }] }]);
    const ok = await call(handleCollection, { method: 'POST', headers: login, body: { id: NOTE, title: 't', body: 'b' } },
      { verify: verifyA, fetch: s.fetch });
    assert.deepEqual(ok.body, { id: NOTE });
    assert.equal(s.calls[0].body.id, NOTE);
    for (const bad of [{ id: 'nope', title: 't', body: 'b' }, { title: '', body: 'b' }, { title: 't' }, { title: 't', body: 1 }]) {
      const res = await call(handleCollection, { method: 'POST', headers: login, body: bad }, { verify: verifyA, fetch: s.fetch });
      assert.equal(res.status, 400);
    }
    assert.equal(s.calls.length, 1);
  });
});

test('목록 GET은 로그인 사용자의 메모와 주인 없는 시작 메모를 {id,title,body}로 돌려준다', async () => {
  await withEnv(async () => {
    const s = store([{ body: [{ id: NOTE, title: 't', content: 'b', owner_id: 'x' }] }]);
    const res = await call(handleCollection, { headers: login }, { verify: verifyA, fetch: s.fetch });
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, [{ id: NOTE, title: 't', body: 'b' }]);
    assert.equal(s.calls[0].url.searchParams.get('or'), `(owner_id.eq.${A},owner_id.is.null)`);
  });
});

test('한 건 GET·PUT·DELETE와 지운 뒤 404', async () => {
  await withEnv(async () => {
    const item = (method, body) => ({ method, headers: login, query: { id: NOTE }, body });
    const s = store([
      { body: [{ id: NOTE, title: 't', content: 'b' }] },
      { body: [{ id: NOTE, title: 'new', content: 'text' }] },
      { body: [{ id: NOTE }] },
      { body: [] },
    ]);
    const deps = { verify: verifyA, fetch: s.fetch };
    const got = await call(handleItem, item('GET'), deps);
    assert.deepEqual(got.body, { id: NOTE, title: 't', body: 'b' });
    const put = await call(handleItem, item('PUT', { title: 'new', body: 'text' }), deps);
    assert.deepEqual(put.body, { id: NOTE, title: 'new', body: 'text' });
    assert.deepEqual(s.calls[1].body, { title: 'new', content: 'text' });
    const del = await call(handleItem, item('DELETE'), deps);
    assert.equal(del.status, 204);
    assert.equal(del.ended, true);
    const gone = await call(handleItem, item('GET'), deps);
    assert.equal(gone.status, 404);
    assert.deepEqual(gone.body, { error: 'NOT_FOUND' });
    const badId = await call(handleItem, { headers: login, query: { id: 'x' } }, deps);
    assert.equal(badId.status, 400);
  });
});

test('허용하지 않는 방식은 405 JSON이다', async () => {
  const a = await call(handleCollection, { method: 'DELETE' }, {});
  const b = await call(handleItem, { method: 'POST' }, {});
  for (const res of [a, b]) {
    assert.equal(res.status, 405);
    assert.deepEqual(res.body, { error: 'METHOD_NOT_ALLOWED' });
  }
});

test('상위 오류에서도 키와 상세 내용을 응답·로그에 남기지 않는다', async () => {
  await withEnv(async () => {
    const logged = [];
    const originalError = console.error;
    console.error = (...args) => logged.push(args.join(' '));
    try {
      const s = store([{ status: 401, body: { message: `denied ${SECRET}` } }]);
      const res = await call(handleCollection, { headers: login }, { verify: verifyA, fetch: s.fetch });
      assert.equal(res.status, 502);
      assert.deepEqual(res.body, { error: 'NOTES_UPSTREAM_ERROR' });
      const boom = async () => { throw new Error(`boom ${SECRET}`); };
      assert.equal((await call(handleCollection, { headers: login }, { verify: verifyA, fetch: boom })).status, 502);
    } finally {
      console.error = originalError;
    }
    assert.ok(!logged.join('\n').includes(SECRET));
  });
});

test('실제 verify-login 도우미 연결: 가짜 학생 토큰과 토큰 없음은 거부된다', async () => {
  const issuer = config.identityProvider.issuer;
  const supabaseClient = { auth: { getClaims: async () => ({ data: null, error: new Error('invalid') }) } };
  const verify = createLoginVerifier({ config, supabaseClient, judgeKeySet: async () => { throw new Error('no'); } });
  const part = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const forged = `Bearer ${part({ alg: 'ES256' })}.${part({ iss: issuer, aud: 'authenticated', role: 'authenticated', sub: A })}.${part('sig')}`;
  assert.equal(await verify(forged), null);
  assert.equal(await verify(undefined), null);
  const good = createLoginVerifier({ config, judgeKeySet: async () => {}, supabaseClient: { auth: { getClaims: async () => ({
    data: { claims: { iss: issuer, aud: 'authenticated', role: 'authenticated', sub: A, exp: Math.floor(Date.now() / 1000) + 600 } }, error: null }) } } });
  assert.deepEqual({ ...(await good(forged)) }, { kind: 'student', userId: A });
});
