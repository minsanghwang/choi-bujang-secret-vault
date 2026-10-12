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

test('step 2 attack check records the static file and the still-public function', async () => {
  const originalFetch = globalThis.fetch;
  const requested = [];
  try {
    globalThis.fetch = async (url, init) => {
      requested.push([String(url), init.redirect]);
      const path = new URL(url).pathname;
      const body = path === '/api/notes'
        ? { notes: [{ title: 'x', content: 'y' }, { title: 'x', content: 'y' }] }
        : { notes: [] };
      return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
    };
    const results = await runAttackChecks(config);
    assert.deepEqual(requested, [
      ['https://student-defense.vercel.app/data.json', 'error'],
      ['https://student-defense.vercel.app/api/notes', 'error'],
    ]);
    assert.match(results[0].observed, /보이지 않음/u);
    assert.match(results[1].observed, /메모 2건이 보임/u);
    assert.doesNotMatch(JSON.stringify(results), /"content"|title/u);
    globalThis.fetch = async () => new Response(JSON.stringify({ sampleMarker: 'SAMPLE_NOTE_1', notes: [{ title: 'x' }] }), { status: 200 });
    const [leaked] = await runAttackChecks(config);
    assert.match(leaked.observed, /메모가 보임/u);
    await assert.rejects(runAttackChecks({ ...config, step: 1 }));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
