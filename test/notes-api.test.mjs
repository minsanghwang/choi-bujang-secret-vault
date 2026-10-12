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

const B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const verifyAB = async (authorization) => ({ 'Bearer a.b.c': { kind: 'student', userId: A },
  'Bearer d.e.f': { kind: 'student', userId: B } })[authorization] ?? null;
const asA = { authorization: 'Bearer a.b.c' };
const asB = { authorization: 'Bearer d.e.f' };

// PostgREST처럼 id·owner_id의 eq 필터만 해석하는 메모리 DB 흉내
function memoryDb(rows = []) {
  const db = { rows: [...rows], calls: [] };
  db.fetch = async (url, init) => {
    const u = new URL(url);
    db.calls.push({ method: init.method, url: u, body: init.body ? JSON.parse(init.body) : undefined });
    const match = row => ['id', 'owner_id'].every(k => !u.searchParams.has(k) || row[k] === u.searchParams.get(k).replace(/^eq\./u, ''));
    const reply = (status, body) => new Response(JSON.stringify(body), { status });
    if (init.method === 'POST') {
      const row = { id: init.body && JSON.parse(init.body).id ? JSON.parse(init.body).id : crypto.randomUUID(), ...JSON.parse(init.body) };
      if (db.rows.some(r => r.id === row.id)) return reply(409, {});
      db.rows.push(row);
      return reply(201, [row]);
    }
    const hit = db.rows.filter(match);
    if (init.method === 'PATCH') hit.forEach(r => Object.assign(r, JSON.parse(init.body)));
    if (init.method === 'DELETE') db.rows = db.rows.filter(r => !hit.includes(r));
    return reply(200, hit.map(r => ({ ...r })));
  };
  return db;
}

test('목록 GET은 로그인 사용자 본인 메모만 {id,title,body}로 돌려준다', async () => {
  await withEnv(async () => {
    const db = memoryDb([
      { id: NOTE, owner_id: A, position: 1, title: 'a', content: 'x' },
      { id: '22222222-2222-4222-8222-222222222222', owner_id: B, position: 1, title: 'b', content: 'y' },
      { id: '33333333-3333-4333-8333-333333333333', owner_id: null, position: 1, title: '주인 없음', content: 'z' },
    ]);
    const deps = { verify: verifyAB, fetch: db.fetch };
    const forA = await call(handleCollection, { headers: asA }, deps);
    assert.deepEqual(forA.body, [{ id: NOTE, title: 'a', body: 'x' }]);
    assert.equal(db.calls.at(-1).url.searchParams.get('owner_id'), `eq.${A}`);
    assert.equal(db.calls.at(-1).url.searchParams.has('or'), false);
    const forB = await call(handleCollection, { headers: asB }, deps);
    assert.deepEqual(forB.body.map(n => n.title), ['b']);
  });
});

test('A/B 각자 자기 메모는 읽고 추가·수정·삭제하고, 상대 메모는 읽기·수정·삭제 모두 403이다', async () => {
  await withEnv(async () => {
    const db = memoryDb();
    const deps = { verify: verifyAB, fetch: db.fetch };
    const created = await call(handleCollection, { method: 'POST', headers: asA, body: { title: 'A의 글', body: 'A 내용', owner_id: B } }, deps);
    assert.equal(created.status, 201);
    const id = created.body.id;
    assert.equal(db.rows[0].owner_id, A);   // 본문의 owner_id가 아니라 확인된 ID로 저장
    const item = (headers, method = 'GET', body) => call(handleItem, { method, headers, query: { id }, body }, deps);

    assert.deepEqual((await item(asA)).body, { id, title: 'A의 글', body: 'A 내용' });
    for (const [method, body] of [['GET'], ['PUT', { title: '가로채기', body: 'x' }], ['DELETE']]) {
      const denied = await item(asB, method, body);
      assert.equal(denied.status, 403, method);
      assert.deepEqual(denied.body, { error: 'FORBIDDEN' });
    }
    assert.deepEqual({ ...db.rows[0] }, { ...db.rows[0], title: 'A의 글', content: 'A 내용', owner_id: A });
    assert.equal(db.calls.filter(c => ['PATCH', 'DELETE'].includes(c.method)).length, 0);   // 거부된 요청은 쓰기를 보내지 않음

    const updated = await item(asA, 'PUT', { title: '새 제목', body: '새 내용' });
    assert.deepEqual(updated.body, { id, title: '새 제목', body: '새 내용' });
    assert.equal(db.rows[0].owner_id, A);
    const patch = db.calls.find(c => c.method === 'PATCH');
    assert.equal(patch.url.searchParams.get('owner_id'), `eq.${A}`);
    assert.equal(patch.body.owner_id, A);

    const bOwn = await call(handleCollection, { method: 'POST', headers: asB, body: { title: 'B의 글', body: 'B 내용' } }, deps);
    assert.equal(bOwn.status, 201);
    assert.equal((await call(handleCollection, { headers: asA }, deps)).body.length, 1);
    assert.equal((await call(handleItem, { method: 'DELETE', headers: asB, query: { id: bOwn.body.id } }, deps)).status, 204);

    assert.equal((await item(asA, 'DELETE')).status, 204);
    const gone = await item(asA);
    assert.equal(gone.status, 404);
    assert.deepEqual(gone.body, { error: 'NOT_FOUND' });
  });
});

test('소유자를 바꾸려는 수정은 DB를 읽기 전에 403으로 거부하고, 주인 없는 행은 기본 거부한다', async () => {
  await withEnv(async () => {
    const orphan = '44444444-4444-4444-8444-444444444444';
    const db = memoryDb([{ id: NOTE, owner_id: A, position: 1, title: 't', content: 'c' },
      { id: orphan, owner_id: null, position: 1, title: 'o', content: 'c' }]);
    const deps = { verify: verifyAB, fetch: db.fetch };
    for (const ownerKey of ['owner_id', 'ownerId', 'userId']) {
      const res = await call(handleItem, { method: 'PUT', headers: asA, query: { id: NOTE }, body: { title: 'x', body: 'y', [ownerKey]: B } }, deps);
      assert.equal(res.status, 403);
      assert.deepEqual(res.body, { error: 'OWNER_CHANGE_FORBIDDEN' });
    }
    assert.equal(db.calls.length, 0);
    assert.equal(db.rows[0].owner_id, A);
    // 본인 ID를 그대로 적은 본문은 소유자를 바꾸지 않으므로 통과합니다.
    const same = await call(handleItem, { method: 'PUT', headers: asA, query: { id: NOTE }, body: { title: 'x', body: 'y', owner_id: A } }, deps);
    assert.equal(same.status, 200);
    for (const [method, body] of [['GET'], ['PUT', { title: 'x', body: 'y' }], ['DELETE']]) {
      const res = await call(handleItem, { method, headers: asA, query: { id: orphan }, body }, deps);
      assert.equal(res.status, 403, `주인 없는 행 ${method}`);
    }
    assert.equal(db.rows.length, 2);
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
