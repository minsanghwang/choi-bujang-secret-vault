import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide, RULE_IDS } from '../src/decider.mjs';

const { normal, suspicious } = fixtureRequests();
const fresh = (base, patch = {}) => ({ ...base, requestId: randomUUID(), ...patch });

test('정상 사건은 allow, 복합 이상 사건은 step_up', async () => {
  const ok = await decide(normal);
  const odd = await decide(suspicious);
  assert.equal(ok.decision, 'allow');
  assert.equal(odd.decision, 'step_up');
  assert.equal(odd.reasonCode, 'step_up_required');
  assert.deepEqual(Object.keys(odd).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
  assert.ok(odd.ruleIds.every(id => RULE_IDS.includes(id)));
});

test('지역 하나만 달라도 막지 않고, 조건 하나만 맞아도 추가 확인하지 않는다', async () => {
  const regionOnly = fresh(normal, { signals: { ...normal.signals, region: 'foreign' } });
  assert.equal((await decide(regionOnly)).decision, 'allow');
  const hourOnly = fresh(normal, { signals: { ...normal.signals, hour: 3 } });
  assert.equal((await decide(hourOnly)).decision, 'allow');
  const noBurst = fresh(suspicious, { recentEvents: [] });
  assert.equal((await decide(noBurst)).decision, 'allow');
  const knownNetwork = fresh(suspicious, { signals: { ...suspicious.signals, network: 'usual' } });
  assert.equal((await decide(knownNetwork)).decision, 'allow');
});

test('출처가 없거나 불명확한 신호는 근거로 쓰지 않고 정상값으로 채우지도 않는다', async () => {
  for (const signals of [
    { ...suspicious.signals, source: 'none' },
    { ...suspicious.signals, source: 'client_header' },
    { ...suspicious.signals, hour: '3' },
    { ...suspicious.signals, network: 'weird' },
    undefined, null,
  ]) {
    const result = await decide(fresh(suspicious, { signals }));
    assert.equal(result.decision, 'allow', JSON.stringify(signals));
  }
});

test('위조한 헤더·계약 밖 값은 신뢰 정보로 승격되지 않는다', async () => {
  const forgedHeaders = fresh(suspicious, { headers: { 'x-forwarded-for': '1.2.3.4', 'x-geo': 'kr', 'x-device-registered': 'true' },
    geo: 'kr', device: { registered: true }, role: 'admin' });
  assert.equal((await decide(forgedHeaders)).decision, 'step_up');
  const unregistered = fresh(normal, { deviceRegistered: undefined, headers: { 'x-device-registered': 'true' }, device: { registered: true } });
  const denied = await decide(unregistered);
  assert.equal(denied.decision, 'deny');
  assert.equal(denied.reasonCode, 'device_not_registered');
  assert.equal((await decide(fresh(normal, { deviceRegistered: 'true' }))).decision, 'deny');
});

test('엔진이 검증한 새 로그인이 있을 때만 이상 접속을 허용한다', async () => {
  const verified = fresh(suspicious, { stepUp: { verified: true, authAgeSeconds: 60 } });
  assert.equal((await decide(verified)).decision, 'allow');
  for (const stepUp of [{ verified: true, authAgeSeconds: 901 }, { verified: true, authAgeSeconds: -1 },
    { verified: 'true', authAgeSeconds: 10 }, { verified: false, authAgeSeconds: null }, null]) {
    assert.equal((await decide(fresh(suspicious, { stepUp }))).decision, 'step_up', JSON.stringify(stepUp));
  }
});

test('미등록 기기는 이상 접속 여부와 상관없이 기존 규칙대로 거부한다', async () => {
  const result = await decide(fresh(suspicious, { deviceRegistered: false }));
  assert.equal(result.decision, 'deny');
  assert.equal(result.reasonCode, 'device_not_registered');
  assert.deepEqual(result.ruleIds, ['device_registered']);
});
