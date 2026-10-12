import assert from 'node:assert/strict';
import { test } from 'node:test';
import handler from '../api/notes.js';

const SECRET = 'fake-test-key-not-real-0123456789';

async function run(method) {
  const headers = new Map();
  const result = {};
  await handler({ method }, {
    setHeader: (key, value) => headers.set(key.toLowerCase(), value),
    status: (code) => { result.status = code; return { json: (body) => { result.body = body; } }; },
  });
  return { headers, ...result };
}
async function withEnv(env, fn) {
  const saved = { url: process.env.SUPABASE_URL, key: process.env.SUPABASE_SECRET_KEY, fetch: globalThis.fetch };
  for (const [k, v] of Object.entries(env)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  try { return await fn(); } finally {
    for (const [k, v] of [['SUPABASE_URL', saved.url], ['SUPABASE_SECRET_KEY', saved.key]]) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
    globalThis.fetch = saved.fetch;
  }
}

test('GET만 허용하고 응답을 저장하지 않는다', async () => {
  const res = await run('POST');
  assert.equal(res.status, 405);
  assert.equal(res.headers.get('allow'), 'GET');
  assert.equal(res.headers.get('cache-control'), 'no-store');
});

test('환경변수가 없으면 설정 오류만 알리고 값을 드러내지 않는다', async () => {
  await withEnv({ SUPABASE_URL: undefined, SUPABASE_SECRET_KEY: undefined }, async () => {
    const res = await run('GET');
    assert.equal(res.status, 500);
    assert.deepEqual(res.body, { error: 'NOTES_NOT_CONFIGURED' });
  });
  await withEnv({ SUPABASE_URL: 'http://insecure.example', SUPABASE_SECRET_KEY: SECRET }, async () => {
    assert.equal((await run('GET')).status, 500);
  });
});

test('서버 전용 키로 테이블을 읽고 title·content만 돌려준다', async () => {
  await withEnv({ SUPABASE_URL: 'https://abc.supabase.co', SUPABASE_SECRET_KEY: SECRET }, async () => {
    let seen;
    globalThis.fetch = async (url, init) => {
      seen = { url: String(url), headers: init.headers };
      return new Response(JSON.stringify([{ id: 'i1', owner_id: 'o1', title: 'T', content: 'C' }]), { status: 200 });
    };
    const res = await run('GET');
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, { notes: [{ title: 'T', content: 'C' }] });
    assert.match(seen.url, /^https:\/\/abc\.supabase\.co\/rest\/v1\/defense_notes\?/u);
    assert.equal(seen.headers.apikey, SECRET);
    assert.equal(seen.headers.Authorization, undefined);
    assert.ok(!JSON.stringify(res).includes(SECRET));
    assert.doesNotMatch(JSON.stringify(res), /owner_id|"id"/u);
  });
});

test('상위 서버 오류에서도 키와 상세 내용을 응답·로그에 남기지 않는다', async () => {
  await withEnv({ SUPABASE_URL: 'https://abc.supabase.co', SUPABASE_SECRET_KEY: SECRET }, async () => {
    const logged = [];
    const originalError = console.error;
    console.error = (...args) => logged.push(args.join(' '));
    try {
      globalThis.fetch = async () => new Response(`denied ${SECRET}`, { status: 401 });
      const res = await run('GET');
      assert.equal(res.status, 502);
      assert.deepEqual(res.body, { error: 'NOTES_UPSTREAM_ERROR' });
      globalThis.fetch = async () => { throw new Error(`boom ${SECRET}`); };
      assert.equal((await run('GET')).status, 502);
    } finally {
      console.error = originalError;
    }
    assert.ok(!logged.join('\n').includes(SECRET));
  });
});
