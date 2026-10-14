import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 2,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 2,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('production deploys report the public production domain, previews keep their own host', () => {
  const production = { ...env, VERCEL_ENV: 'production', VERCEL_PROJECT_PRODUCTION_URL: 'student-defense.vercel.app' };
  assert.equal(deploymentIdentity(production, config).publicAppUrl, 'https://student-defense.vercel.app');
  const preview = { ...production, VERCEL_ENV: 'preview' };
  assert.equal(deploymentIdentity(preview, config).publicAppUrl, 'https://student-defense-123.vercel.app');
  assert.throws(() => deploymentIdentity({ ...production, VERCEL_PROJECT_PRODUCTION_URL: 'evil.example.com' }, config));
});

test('step 5 identity adds the original API address and public database info', () => {
  const step5 = { ...config, step: 5, originalApiUrl: 'https://p.supabase.co/rest/v1/notes',
    database: { schema: 'aleph.defense.database.v1', url: 'https://p.supabase.co', publishableKey: 'pk-test-public', table: 'notes' },
    identityProvider: null, allowedRoutes: ['/api/notes'] };
  const identity = deploymentIdentity(env, step5);
  assert.equal(identity.step, 5);
  assert.equal(identity.originalApiUrl, step5.originalApiUrl);
  assert.deepEqual(identity.database, step5.database);
  assert.equal(deploymentIdentity(env, { ...step5, step: 4 }).originalApiUrl, undefined);
});

test('step 3 identity adds public login info and keeps /aleph.json fields', () => {
  const step3 = { ...config, step: 3,
    identityProvider: { issuer: 'https://p.supabase.co/auth/v1', audience: 'authenticated',
      jwksUrl: 'https://p.supabase.co/auth/v1/.well-known/jwks.json' },
    allowedRoutes: ['/api/notes', '/api/notes/:id'] };
  const identity = deploymentIdentity(env, step3);
  assert.equal(identity.step, 3);
  assert.deepEqual(identity.identityProvider, step3.identityProvider);
  assert.deepEqual(identity.allowedRoutes, step3.allowedRoutes);
  assert.equal(identity.repoUrl, 'https://github.com/student-a/aleph-defense');
  assert.equal(JSON.stringify(identity).includes('secret'), false);
});

test('step 5 attack check adds the direct anon request and leaves the login checks unrun', async () => {
  const originalFetch = globalThis.fetch;
  const requested = [];
  const step3 = { ...config, step: 5, identityProvider: { issuer: 'https://p.supabase.co/auth/v1', audience: 'authenticated' },
    originalApiUrl: 'https://p.supabase.co/rest/v1/notes', database: { publishableKey: 'pk-test-public' } };
  try {
    globalThis.fetch = async (url, init) => {
      const path = new URL(url).pathname;
      requested.push([path, init.headers?.Authorization ? 'with-token' : init.headers?.apikey ? 'apikey-only' : 'no-token']);
      if (path === '/') return new Response('<html>login</html>', { status: 200, headers: { 'content-type': 'text/html' } });
      if (path === '/rest/v1/notes') return Response.json({ message: 'permission denied' }, { status: 401 });
      if (path === '/data.json') return Response.json({ notes: [] });
      return Response.json({ error: 'LOGIN_REQUIRED' }, { status: 401 });
    };
    const results = await runAttackChecks(step3);
    assert.deepEqual(requested, [['/data.json', 'no-token'], ['/api/notes', 'no-token'], ['/api/notes', 'with-token'], ['/', 'no-token'], ['/rest/v1/notes', 'apikey-only']]);
    assert.match(results[0].observed, /^GET \/data\.json\(비로그인\) → HTTP 200, JSON, 메모 0건, 확인 표시 없음/u);
    assert.match(results[1].observed, /^GET \/api\/notes\(비로그인\) → HTTP 401, JSON, error=LOGIN_REQUIRED, 메모 0건/u);
    assert.match(results[2].observed, /^GET \/api\/notes\(서명 없는 토큰\) → HTTP 401/u);
    assert.equal(results[3].attackId, 'public_key_in_screen_code');
    assert.match(results[3].observed, /^GET \/\(첫 화면\) → HTTP 200, 공개 키 모양 문자열 0건/u);
    assert.equal(results[4].attackId, 'direct_original_api_anon_read');
    assert.match(results[4].observed, /^GET 원본 저장소 \/rest\/v1\(공개 키만\) → HTTP 401, JSON, 메모 0건/u);
    assert.deepEqual(results.slice(5).map(item => item.attackId),
      ['login_a_note_crud', 'b_reads_a_note', 'b_changes_a_note']);
    assert.ok(results.slice(5).every(item => /^미실행/u.test(item.observed)));
    globalThis.fetch = async () => new Response('<html>login</html>', { status: 200, headers: { 'content-type': 'text/html' } });
    const failed = await runAttackChecks(step3);
    assert.match(failed[1].observed, /^GET \/api\/notes\(비로그인\) → HTTP 200, JSON 아님, 메모 0건/u);   // 거부되지 않은 응답도 판정 없이 그대로 기록
    await assert.rejects(runAttackChecks({ ...step3, step: 4 }));
    // 직접 요청에서 메모가 보이면 그대로 기록합니다.
    globalThis.fetch = async (url) => (new URL(url).pathname === '/rest/v1/notes'
      ? Response.json([{ id: 'x' }]) : Response.json({ error: 'LOGIN_REQUIRED' }, { status: 401 }));
    const open = await runAttackChecks(step3);
    assert.match(open[4].observed, /→ HTTP 200, JSON, 메모 [1-9]\d*건/u);
    // 화면에 공개 키가 보이면 그대로 기록합니다.
    globalThis.fetch = async (url) => (new URL(url).pathname === '/'
      ? new Response('<script>const k="sb_publishable_ABCDEFGH12345678"</script>', { status: 200 })
      : Response.json({ error: 'LOGIN_REQUIRED' }, { status: 401 }));
    assert.match((await runAttackChecks(step3))[3].observed, /공개 키 모양 문자열 [1-9]\d*건/u);
    // 설정이 없으면 미실행으로 남깁니다.
    const none = await runAttackChecks({ ...step3, originalApiUrl: null });
    assert.match(none[4].observed, /^미실행/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 6 attack check keeps the step 5 requests and leaves the device attack to the judge', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url) => (new URL(url).pathname === '/'
      ? new Response('<html>login</html>', { status: 200 })
      : Response.json({ error: 'LOGIN_REQUIRED' }, { status: 401 }));
    const step6 = { ...config, step: 6, identityProvider: { issuer: 'https://p.supabase.co/auth/v1', audience: 'authenticated' },
      originalApiUrl: 'https://p.supabase.co/rest/v1/notes', database: { publishableKey: 'pk-test-public' } };
    const results = await runAttackChecks(step6);
    assert.equal(results.at(-1).attackId, 'unregistered_device_request');
    assert.match(results.at(-1).observed, /^미실행/u);
    await assert.rejects(runAttackChecks({ ...step6, step: 13 }));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 7 attack check lists the unusual access check as not run', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url) => (new URL(url).pathname === '/'
      ? new Response('<html>login</html>', { status: 200 })
      : Response.json({ error: 'LOGIN_REQUIRED' }, { status: 401 }));
    const step7 = { ...config, step: 7, identityProvider: { issuer: 'https://p.supabase.co/auth/v1', audience: 'authenticated' },
      originalApiUrl: 'https://p.supabase.co/rest/v1/notes', database: { publishableKey: 'pk-test-public' } };
    const results = await runAttackChecks(step7);
    assert.deepEqual(results.slice(-2).map(item => item.attackId), ['unregistered_device_request', 'unusual_access_step_up']);
    assert.match(results.at(-1).observed, /^미실행/u);
    await assert.rejects(runAttackChecks({ ...step7, step: 13 }));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 8 attack check lists the cross-zone request as not run', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url) => (new URL(url).pathname === '/'
      ? new Response('<html>login</html>', { status: 200 })
      : Response.json({ error: 'LOGIN_REQUIRED' }, { status: 401 }));
    const step8 = { ...config, step: 8, identityProvider: { issuer: 'https://p.supabase.co/auth/v1', audience: 'authenticated' },
      originalApiUrl: 'https://p.supabase.co/rest/v1/notes', database: { publishableKey: 'pk-test-public' } };
    const results = await runAttackChecks(step8);
    assert.equal(results.at(-1).attackId, 'cross_zone_direct_api');
    assert.match(results.at(-1).observed, /^미실행/u);
    await assert.rejects(runAttackChecks({ ...step8, step: 13 }));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 9 attack check lists the doppelganger revocation check as not run', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url) => (new URL(url).pathname === '/'
      ? new Response('<html>login</html>', { status: 200 })
      : Response.json({ error: 'LOGIN_REQUIRED' }, { status: 401 }));
    const step9 = { ...config, step: 9, identityProvider: { issuer: 'https://p.supabase.co/auth/v1', audience: 'authenticated' },
      originalApiUrl: 'https://p.supabase.co/rest/v1/notes', database: { publishableKey: 'pk-test-public' } };
    const results = await runAttackChecks(step9);
    assert.equal(results.at(-1).attackId, 'doppelganger_burst_revocation');
    assert.match(results.at(-1).observed, /^미실행/u);
    assert.equal(results.at(-2).attackId, 'cross_zone_direct_api');
    await assert.rejects(runAttackChecks({ ...step9, step: 13 }));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 10 attack check lists the restore and regression checks as not run', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url) => (new URL(url).pathname === '/'
      ? new Response('<html>login</html>', { status: 200 })
      : Response.json({ error: 'LOGIN_REQUIRED' }, { status: 401 }));
    const step10 = { ...config, step: 10, identityProvider: { issuer: 'https://p.supabase.co/auth/v1', audience: 'authenticated' },
      originalApiUrl: 'https://p.supabase.co/rest/v1/notes', database: { publishableKey: 'pk-test-public' } };
    const results = await runAttackChecks(step10);
    assert.deepEqual(results.slice(-2).map(item => item.attackId), ['restore_one_note_from_backup', 'post_restore_regression']);
    assert.ok(results.slice(-2).every(item => /^미실행/u.test(item.observed)));
    assert.equal(results.at(-3).attackId, 'doppelganger_burst_revocation');
    await assert.rejects(runAttackChecks({ ...step10, step: 13 }));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 10 identity also announces the public restore route, earlier steps do not', () => {
  const env = { VERCEL_GIT_PROVIDER: 'github', VERCEL_GIT_REPO_OWNER: 'student', VERCEL_GIT_REPO_SLUG: 'vault',
    VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40), VERCEL_URL: 'vault-abc.vercel.app' };
  const base = { ...config, step: 10, restoreRoute: 'POST /api/restore',
    identityProvider: { issuer: 'https://p.supabase.co/auth/v1', audience: 'authenticated' }, allowedRoutes: ['GET /api/notes'],
    originalApiUrl: 'https://p.supabase.co/rest/v1/notes', database: { publishableKey: 'pk-test-public' } };
  assert.equal(deploymentIdentity(env, base).restoreRoute, 'POST /api/restore');
  assert.equal(deploymentIdentity(env, { ...base, restoreRoute: undefined }).restoreRoute, null);
  assert.equal('restoreRoute' in deploymentIdentity(env, { ...base, step: 9 }), false);
});

test('step 11 attack check sends only the anonymous device and manifest requests and lists the approval gate as not run', async () => {
  const originalFetch = globalThis.fetch;
  const seen = [];
  try {
    globalThis.fetch = async (url) => {
      const path = new URL(url).pathname;
      seen.push(path);
      if (path === '/') return new Response('<html>login</html>', { status: 200 });
      if (path === '/manifest.webmanifest') return Response.json({ name: 'BYTE BACK 자료실' }, { status: 200 });
      return Response.json({ error: 'LOGIN_REQUIRED' }, { status: 401 });
    };
    const step11 = { ...config, step: 11, identityProvider: { issuer: 'https://p.supabase.co/auth/v1', audience: 'authenticated' },
      originalApiUrl: 'https://p.supabase.co/rest/v1/notes', database: { publishableKey: 'pk-test-public' } };
    const results = await runAttackChecks(step11);
    assert.deepEqual(results.slice(-3).map(item => item.attackId), ['device_status_without_login', 'manifest_public', 'device_approval_gate']);
    assert.match(results.at(-3).observed, /^GET \/api\/device\(비로그인\) → HTTP 401, JSON, error=LOGIN_REQUIRED, 메모 0건, state 값 없음/u);
    assert.match(results.at(-2).observed, /^GET \/manifest\.webmanifest → HTTP 200, JSON, name 값 있음/u);
    assert.match(results.at(-1).observed, /^미실행/u);
    assert.ok(seen.includes('/api/device') && seen.includes('/manifest.webmanifest'));
    assert.equal(results.at(-4).attackId, 'post_restore_regression');
    await assert.rejects(runAttackChecks({ ...step11, step: 13 }));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 12 bundle check sends no request and writes every attackId as not_run (judge-recorded attacks only)', async () => {
  const originalFetch = globalThis.fetch;
  const seen = [];
  try {
    globalThis.fetch = async (url) => { seen.push(String(url)); throw new Error('no network expected'); };
    const step12 = { ...config, step: 12, identityProvider: { issuer: 'https://p.supabase.co/auth/v1', audience: 'authenticated' },
      originalApiUrl: 'https://p.supabase.co/rest/v1/notes', database: { publishableKey: 'pk-test-public' } };
    const results = await runAttackChecks(step12);
    assert.deepEqual(seen, []);                                                                        // 제출 묶음은 요청을 보내지 않음
    assert.equal(results.length, 19);
    assert.ok(results.every(item => item.observed === 'not_run'));                                     // 심판이 기록한 실행이 아니므로 모두 not_run
    assert.ok(results.every(item => Object.keys(item).sort().join(',') === 'attackId,expected,observed'));
    assert.deepEqual(results.slice(-2).map(item => item.attackId), ['ops_summary_without_login', 'full_41_attack_run']);
    assert.equal(new Set(results.map(item => item.attackId)).size, results.length);
    assert.ok(results.every(item => item.expected.length <= 300));
    await assert.rejects(runAttackChecks({ ...step12, step: 13 }));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('attack check does not need Node-only globals such as Buffer and base64url matches the Buffer result', async () => {
  const { base64url } = await import('../src/attack-check.mjs');
  for (const text of ['', 'f', 'fo', 'foo', 'forged', '{"alg":"ES256","typ":"JWT"}', 'https://p.supabase.co/auth/v1?x=~']) {
    assert.equal(base64url(text), Buffer.from(text).toString('base64url'), text);
  }
  const savedBuffer = globalThis.Buffer;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url) => {
      const path = new URL(url).pathname;
      const plain = (status, type, data) => ({ status, headers: { get: name => (name.toLowerCase() === 'content-type' ? type : null) },
        json: async () => data, text: async () => (typeof data === 'string' ? data : JSON.stringify(data)) });   // Response 객체도 Buffer를 쓰므로 단순 객체로 대신함
      if (path === '/') return plain(200, 'text/html', '<html>login</html>');
      if (path === '/manifest.webmanifest') return plain(200, 'application/json', { name: 'BYTE BACK 자료실' });
      return plain(401, 'application/json', { error: 'LOGIN_REQUIRED' });
    };
    delete globalThis.Buffer;
    const results = await runAttackChecks({ ...config, step: 11, identityProvider: { issuer: 'https://p.supabase.co/auth/v1', audience: 'authenticated' },
      originalApiUrl: 'https://p.supabase.co/rest/v1/notes', database: { publishableKey: 'pk-test-public' } });
    assert.ok(results.length >= 15);
    assert.match(results.find(item => item.attackId === 'forged_token_notes_read').observed, /^GET \/api\/notes\(서명 없는 토큰\) → HTTP 401/u);
  } finally {
    globalThis.Buffer = savedBuffer;
    globalThis.fetch = originalFetch;
  }
});

test('attack check also runs where URL has no searchParams or origin (isolated judge environment)', async () => {
  const OriginalURL = globalThis.URL;
  const originalFetch = globalThis.fetch;
  const seen = [];
  class MinimalURL extends OriginalURL {            // 격리 환경의 단순한 URL: searchParams·origin이 없음
    get searchParams() { return undefined; }
    get origin() { return undefined; }
  }
  try {
    globalThis.URL = MinimalURL;
    globalThis.fetch = async (url, options = {}) => {
      seen.push([String(url), options.alephEvidence]);
      const path = new OriginalURL(String(url)).pathname;
      const plain = (status, type, data) => ({ status, headers: { get: name => (name.toLowerCase() === 'content-type' ? type : null) },
        json: async () => data, text: async () => (typeof data === 'string' ? data : JSON.stringify(data)) });
      if (path === '/') return plain(200, 'text/html', '<html>login</html>');
      if (path === '/manifest.webmanifest') return plain(200, 'application/json', { name: 'BYTE BACK 자료실' });
      return plain(401, 'application/json', { error: 'LOGIN_REQUIRED' });
    };
    const results = await runAttackChecks({ ...config, step: 11, identityProvider: { issuer: 'https://p.supabase.co/auth/v1', audience: 'authenticated' },
      originalApiUrl: 'https://p.supabase.co/rest/v1/notes', database: { publishableKey: 'pk-test-public' } });
    assert.ok(results.length >= 15);
    assert.equal(seen.length, 7);
    assert.ok(seen.every(([url, evidence]) => (url.includes('p.supabase.co') ? !url.includes('attackId') : url.endsWith(`attackId=${evidence}`))));
  } finally {
    globalThis.URL = OriginalURL;
    globalThis.fetch = originalFetch;
  }
});

test('step 11 attack check tags every request it really sends with its attackId and request id, and leaves unsent checks untagged', async () => {
  const originalFetch = globalThis.fetch;
  const sent = [];
  try {
    globalThis.fetch = async (url, options = {}) => {
      const path = new URL(url).pathname;
      sent.push({ path, search: new URL(url).search, headers: options.headers ?? {}, evidence: options.alephEvidence, host: new URL(url).host });
      const plain = (status, type, data) => ({ status, headers: { get: name => (name.toLowerCase() === 'content-type' ? type : null) },
        json: async () => data, text: async () => (typeof data === 'string' ? data : JSON.stringify(data)) });
      if (path === '/') return plain(200, 'text/html', '<html>login</html>');
      if (path === '/manifest.webmanifest') return plain(200, 'application/json', { name: 'BYTE BACK 자료실' });
      return plain(401, 'application/json', { error: 'LOGIN_REQUIRED' });
    };
    const step12 = { ...config, step: 11, identityProvider: { issuer: 'https://p.supabase.co/auth/v1', audience: 'authenticated' },
      originalApiUrl: 'https://p.supabase.co/rest/v1/notes', database: { publishableKey: 'pk-test-public' } };
    const results = await runAttackChecks(step12);
    const sentIds = [...new Set(sent.map(item => item.headers['x-attack-id']).filter(Boolean))].sort();
    assert.deepEqual(sentIds, ['anonymous_api_notes_read', 'device_status_without_login', 'direct_original_api_anon_read', 'forged_token_notes_read',
      'manifest_public', 'public_key_in_screen_code', 'anonymous_note_read'].sort());
    assert.equal(sent.filter(item => item.headers['x-attack-id']).length, sent.length);                  // 보낸 요청은 모두 태그가 있음
    assert.equal(sent.length, 7);                                                                       // 점검마다 요청 한 번, 다른 요청 없음
    // 점검마다 요청 한 번, 결과 목록과 같은 순서로 보냄
    assert.deepEqual(sent.map(item => item.headers['x-attack-id']), results.filter(item => sent.some(req => req.headers['x-attack-id'] === item.attackId)).map(item => item.attackId));
    for (const item of sent) {
      assert.equal(item.evidence, item.headers['x-attack-id']);                                        // alephEvidence = 점검 이름
      if (item.host === new URL(config.publicAppUrl).host) assert.equal(item.search, `?attackId=${item.headers['x-attack-id']}`);  // 우리 앱 주소에는 ?attackId=
      else assert.equal(item.search, '');                                                              // 원본 저장소 주소에는 붙이지 않음
    }
    for (const result of results) if (!sent.some(req => req.headers['x-attack-id'] === result.attackId)) assert.match(result.observed, /^미실행\(not_run\):/u, result.attackId);
    for (const item of sent) {                                                                           // 점검 이름 헤더는 소문자·표준 표기 모두, 요청 ID는 한 번만
      const id = item.headers['x-attack-id'];
      assert.deepEqual([item.headers['x-aleph-attack-id'], item.headers['X-Attack-Id'], item.headers['X-Aleph-Attack-Id']], [id, id, id]);
      assert.equal(Object.keys(item.headers).filter(name => name.toLowerCase() === 'x-request-id').length, 1);
    }
    for (const item of sent) assert.match(item.headers['X-Request-Id'], /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
    for (const result of results) {
      const request = sent.find(item => item.headers['x-attack-id'] === result.attackId);
      if (request) assert.ok(result.observed.endsWith(`[요청 ID ${request.headers['X-Request-Id']}]`), result.attackId);   // 결과의 요청 ID = 실제로 보낸 요청의 ID
      else assert.match(result.observed, /^미실행/u, result.attackId);                                       // 보내지 않은 점검은 미실행
      assert.ok(result.observed.length <= 300 && result.expected.length <= 300);
    }
    const again = await runAttackChecks(step12);                                                          // 두 번째 실행도 이전 요청 ID를 끌고 오지 않음
    assert.notEqual(again[1].observed, results[1].observed);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('보낸 점검의 결과에는 성공 문구(거부됨·보이지 않음·공개됨 같은 판정)를 쓰지 않고 관측값만 적는다', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url) => {
      const path = new URL(String(url)).pathname;
      const plain = (status, type, data) => ({ status, headers: { get: name => (name.toLowerCase() === 'content-type' ? type : null) },
        json: async () => data, text: async () => (typeof data === 'string' ? data : JSON.stringify(data)) });
      if (path === '/') return plain(200, 'text/html', '<html>login</html>');
      if (path === '/manifest.webmanifest') return plain(200, 'application/json', { name: 'BYTE BACK 자료실' });
      return plain(401, 'application/json', { error: 'LOGIN_REQUIRED' });
    };
    const results = await runAttackChecks({ ...config, step: 11, identityProvider: { issuer: 'https://p.supabase.co/auth/v1', audience: 'authenticated' },
      originalApiUrl: 'https://p.supabase.co/rest/v1/notes', database: { publishableKey: 'pk-test-public' } });
    const sent = results.filter(item => !item.observed.startsWith('미실행'));
    assert.equal(sent.length, 7);
    for (const item of sent) {
      assert.doesNotMatch(item.observed, /거부됨|거부되지|보이지 않음|보임|공개됨|확인하지 못함|통과|성공|안전/u, item.attackId);
      assert.match(item.observed, /^GET .+ → HTTP \d{3}/u, item.attackId);            // 보낸 요청 → 실제 응답 상태
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});
