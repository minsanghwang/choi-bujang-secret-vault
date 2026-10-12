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
      requested.push([path, init.headers.Authorization ? 'with-token' : init.headers.apikey ? 'apikey-only' : 'no-token']);
      if (path === '/rest/v1/notes') return Response.json({ message: 'permission denied' }, { status: 401 });
      if (path === '/data.json') return Response.json({ notes: [] });
      return Response.json({ error: 'LOGIN_REQUIRED' }, { status: 401 });
    };
    const results = await runAttackChecks(step3);
    assert.deepEqual(requested, [['/data.json', 'no-token'], ['/api/notes', 'no-token'], ['/api/notes', 'with-token'], ['/rest/v1/notes', 'apikey-only']]);
    assert.match(results[0].observed, /보이지 않음/u);
    assert.match(results[1].observed, /^비로그인 \/api\/notes 거부됨 \(HTTP 401, JSON, 메모 0건\)/u);
    assert.match(results[2].observed, /거부됨 \(HTTP 401/u);
    assert.equal(results[3].attackId, 'direct_original_api_anon_read');
    assert.match(results[3].observed, /^메모가 보이지 않음 \(HTTP 401, 메모 0건\)/u);
    assert.deepEqual(results.slice(4).map(item => item.attackId),
      ['login_a_note_crud', 'b_reads_a_note', 'b_changes_a_note']);
    assert.ok(results.slice(4).every(item => /^미실행/u.test(item.observed)));
    globalThis.fetch = async () => new Response('<html>login</html>', { status: 200, headers: { 'content-type': 'text/html' } });
    const failed = await runAttackChecks(step3);
    assert.match(failed[1].observed, /거부되지 않음/u);
    await assert.rejects(runAttackChecks({ ...step3, step: 4 }));
    // 직접 요청에서 메모가 보이면 그대로 기록합니다.
    globalThis.fetch = async (url) => (new URL(url).pathname === '/rest/v1/notes'
      ? Response.json([{ id: 'x' }]) : Response.json({ error: 'LOGIN_REQUIRED' }, { status: 401 }));
    const open = await runAttackChecks(step3);
    assert.match(open[3].observed, /^메모가 보임/u);
    // 설정이 없으면 미실행으로 남깁니다.
    const none = await runAttackChecks({ ...step3, originalApiUrl: null });
    assert.match(none[3].observed, /^미실행/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
