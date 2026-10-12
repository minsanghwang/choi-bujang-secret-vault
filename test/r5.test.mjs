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

test('step 3 attack check records denials and leaves the login check unrun', async () => {
  const originalFetch = globalThis.fetch;
  const requested = [];
  const step3 = { ...config, step: 3, identityProvider: { issuer: 'https://p.supabase.co/auth/v1', audience: 'authenticated' } };
  try {
    globalThis.fetch = async (url, init) => {
      const path = new URL(url).pathname;
      requested.push([path, init.headers.Authorization ? 'with-token' : 'no-token']);
      if (path === '/data.json') return Response.json({ notes: [] });
      return Response.json({ error: 'LOGIN_REQUIRED' }, { status: 401 });
    };
    const results = await runAttackChecks(step3);
    assert.deepEqual(requested, [['/data.json', 'no-token'], ['/api/notes', 'no-token'], ['/api/notes', 'with-token']]);
    assert.match(results[0].observed, /보이지 않음/u);
    assert.match(results[1].observed, /^비로그인 \/api\/notes 거부됨 \(HTTP 401, JSON, 메모 0건\)/u);
    assert.match(results[2].observed, /거부됨 \(HTTP 401/u);
    assert.match(results[3].observed, /^미실행/u);
    globalThis.fetch = async () => new Response('<html>login</html>', { status: 200, headers: { 'content-type': 'text/html' } });
    const failed = await runAttackChecks(step3);
    assert.match(failed[1].observed, /거부되지 않음/u);
    await assert.rejects(runAttackChecks({ ...step3, step: 2 }));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
