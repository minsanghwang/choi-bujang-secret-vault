import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { test } from 'node:test';
import { RULE_IDS } from '../src/decider.mjs';
import { applyRestore, diffPolicy, loadTestPolicy, loadVerified, planRestore, PolicyError } from '../src/policy-restore.mjs';

const run = promisify(execFile);
const REPO = new URL('..', import.meta.url).pathname;
async function sandbox() {
  const dir = await mkdtemp(join(tmpdir(), 'policy-'));
  await cp(join(REPO, 'policy'), join(dir, 'policy'), { recursive: true });
  return dir;
}
const breach = async dir => {
  const file = join(dir, 'policy', 'test-policy.json');
  const policy = JSON.parse(await readFile(file, 'utf8'));
  policy.services.notes.ruleIds = ['device_registered'];                    // 침해: 구역 규칙 삭제
  policy.services.notes.zoneRoutes['PUT /notices/:id'] = 'allow';            // 침해: 학생 공지 수정 허용
  policy.services.notes.stepUp.burstCount = 9999;
  policy.services.auth.cookieWriteSameSiteCheck = false;                     // 다른 서비스 규칙도 바뀐 상태
  policy.audit.push({ at: '2026-10-01T00:00:00.000Z', action: 'login', note: '기존 감사 기록' });
  await writeFile(file, JSON.stringify(policy, null, 2));
  return file;
};

test('저장소의 검증 사본은 해시 목록과 같고, 지금 코드의 규칙 이름과 일치하며, 현재 시험 정책과 차이가 없다', async () => {
  const verified = await loadVerified(REPO);
  assert.equal(verified.version, 'v1');
  assert.deepEqual(verified.policy.services.notes.ruleIds, [...RULE_IDS]);
  assert.deepEqual(planRestore(verified, await loadTestPolicy(REPO)).changes, []);
});

test('사본이 없거나 해시가 다르거나 형식이 틀리면 중단한다', async () => {
  const dir = await sandbox();
  try {
    await assert.rejects(loadVerified(dir, 'v9'), PolicyError);                                  // 없는 버전
    await writeFile(join(dir, 'policy', 'verified', 'policy-v1.json'), '{"schema":"aleph.policy.v1","version":"v1","services":{}}\n');
    await assert.rejects(loadVerified(dir), /해시가 목록과 다릅니다/u);                          // 사본이 바뀜
    await rm(join(dir, 'policy', 'verified', 'policy-v1.json'));
    await assert.rejects(loadVerified(dir), /파일이 없습니다/u);                                  // 사본 없음
    await rm(join(dir, 'policy', 'verified', 'MANIFEST.json'));
    await assert.rejects(loadVerified(dir), /해시 목록/u);                                         // 목록 없음
    await writeFile(join(dir, 'policy', 'test-policy.json'), '{"schema":"x"}');
    await assert.rejects(loadTestPolicy(dir), PolicyError);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('차이 보기는 바뀐 항목과 범위(복원/보존)를 보여 주고 아무 것도 쓰지 않는다', async () => {
  const dir = await sandbox();
  try {
    const file = await breach(dir);
    const before = await readFile(file, 'utf8');
    const { stdout } = await run('node', [join(REPO, 'scripts', 'policy-diff.mjs'), '--test-policy', file]);
    assert.match(stdout, /복원할 안전 정책 버전: v1/u);
    assert.match(stdout, /services\.notes\.zoneRoutes\.PUT \/notices\/:id/u);
    assert.match(stdout, /건드리지 않는 항목 1개/u);
    assert.match(stdout, /services\.auth\.cookieWriteSameSiteCheck/u);
    assert.equal(await readFile(file, 'utf8'), before);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('되돌리기는 확인값이 있을 때만 쓰고, 다른 서비스 규칙과 감사 이력을 보존한다', async () => {
  const dir = await sandbox();
  try {
    const file = await breach(dir);
    const before = JSON.parse(await readFile(file, 'utf8'));
    const script = join(REPO, 'scripts', 'policy-restore.mjs');
    const verified = await loadVerified(dir);
    // 확인 없이 / 틀린 확인값으로는 쓰지 않는다.
    assert.match((await run('node', [script, '--test-policy', file])).stdout, /아직 아무것도 쓰지 않았습니다/u);
    await assert.rejects(run('node', [script, '--test-policy', file, '--apply', '--confirm', 'deadbeef0000']), /다릅니다/u);
    assert.deepEqual(JSON.parse(await readFile(file, 'utf8')), before);
    // 맞는 확인값으로 적용.
    await run('node', [script, '--test-policy', file, '--apply', '--confirm', verified.sha256.slice(0, 12)]);
    const after = JSON.parse(await readFile(file, 'utf8'));
    assert.deepEqual(after.services.notes, verified.policy.services.notes);            // 대상 서비스는 사본과 같음
    assert.deepEqual(after.services.auth, before.services.auth);                        // 다른 서비스는 그대로(바뀐 채로 보존)
    assert.deepEqual(after.audit.slice(0, 1), before.audit);                            // 이전 감사 기록 보존
    assert.equal(after.audit.length, 2);
    assert.equal(after.audit[1].action, 'policy_restore');
    assert.ok(after.audit[1].changedPaths.includes('services.notes.ruleIds'));
    // 같은 사본을 다시 적용해도 바뀔 항목이 없어 쓰지 않는다.
    const again = await run('node', [script, '--test-policy', file, '--apply', '--confirm', verified.sha256.slice(0, 12)]);
    assert.match(again.stdout, /바뀔 항목이 없어 쓰지 않았습니다/u);
    assert.equal(JSON.parse(await readFile(file, 'utf8')).audit.length, 2);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('복원은 이전 감사 기록 뒤에 한 줄만 더하고, 차이가 없는 정책은 차이 목록이 비어 있다', async () => {
  const verified = await loadVerified(REPO);
  const current = JSON.parse(await readFile(join(REPO, 'policy', 'test-policy.json'), 'utf8'));
  current.audit = [{ at: 'x', action: 'keep' }];
  const plan = planRestore(verified, current);
  assert.equal(applyRestore(verified, current, plan).audit.length, 2);
  assert.deepEqual(diffPolicy(verified.policy, current), []);
});
