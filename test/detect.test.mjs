import assert from 'node:assert/strict';
import { test } from 'node:test';
import { detect } from '../src/detect.mjs';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const reads = (count, { sub = 'learner_fixture', step = 2, start = START, method = 'GET' } = {}) =>
  Array.from({ length: count }, (_, i) => ({ at: new Date(start + i * step * 1000).toISOString(), method, identity: { sub } }));
const REVOKE = sub => ({ action: 'propose_revocation', reasonCode: 'burst_read', subject: sub });

test('복합 의심(10분 안 120건 초과)만 회수 제안을 내고 정상은 observe', () => {
  assert.deepEqual(detect(reads(30)), { action: 'observe' });
  assert.deepEqual(detect(reads(120)), { action: 'observe' });          // 정확히 120건은 제안 대상이 아님
  assert.deepEqual(detect(reads(121)), REVOKE('learner_fixture'));
  assert.deepEqual(detect([]), { action: 'observe' });
});

test('10분 구간의 경계와 구간 밖 사건을 정확히 센다', () => {
  // 121건이 정확히 10분(600초) 간격 안에 있으면 제안, 첫 사건과 마지막 사건이 600초 이상 벌어지면 한 구간이 아니다.
  assert.deepEqual(detect(reads(121, { step: 599 / 120 })), REVOKE('learner_fixture'));
  assert.deepEqual(detect(reads(121, { step: 5 })), { action: 'observe' });            // 120건/10분 → 구간 안은 120건
  const split = [...reads(100), ...reads(100, { start: START + 3600 * 1000 })];       // 한 시간 간격의 두 묶음
  assert.deepEqual(detect(split), { action: 'observe' });
  const unsorted = reads(121).reverse();
  assert.deepEqual(detect(unsorted), REVOKE('learner_fixture'));                       // 순서가 뒤섞여도 같은 결과
});

test('사용자별로 따로 세고, 제안 대상은 한 명이다', () => {
  const mixed = [...reads(100), ...reads(100, { sub: 'other_fixture' })];
  assert.deepEqual(detect(mixed), { action: 'observe' });
  const both = [...reads(150, { sub: 'learner_b' }), ...reads(150, { sub: 'learner_a', start: START + 1000 })];
  assert.deepEqual(detect(both), REVOKE('learner_b'));                                 // 한도를 먼저 넘긴 한 명만
  const normalPlusBurst = [...reads(30, { sub: 'learner_ok' }), ...reads(130, { sub: 'learner_bad' })];
  assert.deepEqual(detect(normalPlusBurst), REVOKE('learner_bad'));                    // 정상 사용자는 건드리지 않음
});

test('GET이 아닌 사건과 형식이 맞지 않는 사건은 세지 않고, 응답에 다른 값을 싣지 않는다', () => {
  assert.deepEqual(detect(reads(200, { method: 'POST' })), { action: 'observe' });
  const junk = [null, undefined, 5, 'x', {}, { at: 'bad', method: 'GET', identity: { sub: 'learner_fixture' } },
    { at: new Date(START).toISOString(), method: 'GET', identity: { sub: '' } },
    { at: new Date(START).toISOString(), method: 'GET', identity: { sub: 'kim@example.com' } },   // 이메일 모양은 가명 ID가 아님
    { at: new Date(START).toISOString(), method: 'GET', identity: 'learner_fixture' },
    { at: new Date(START).toISOString(), method: 'GET' }];
  assert.deepEqual(detect([...junk, ...reads(120)]), { action: 'observe' });
  const rich = reads(121).map(e => ({ ...e, body: '메모 내용', token: 'secret', name: '실명', headers: { authorization: 'x' } }));
  const out = detect(rich);
  assert.deepEqual(out, REVOKE('learner_fixture'));
  assert.deepEqual(Object.keys(out).sort(), ['action', 'reasonCode', 'subject']);
  assert.ok(!JSON.stringify(out).includes('메모 내용') && !JSON.stringify(out).includes('secret'));
});

test('배열이 아니면 거부하고, 입력 사건을 바꾸지 않는다', () => {
  assert.throws(() => detect(null), /invalid_detection_events/);
  assert.throws(() => detect('x'), /invalid_detection_events/);
  const events = reads(121);
  const copy = JSON.stringify(events);
  detect(events);
  assert.equal(JSON.stringify(events), copy);
});
