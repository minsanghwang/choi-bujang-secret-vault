import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { decide } from '../xdr/brute-force/decide.mjs';
import { readAlerts, mask } from '../xdr/brute-force/read-alerts.mjs';
import { buildDenyRules, checkAddress, RULE_ID } from '../xdr/brute-force/respond.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const root = new URL('..', import.meta.url).pathname;
const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
const patterns = JSON.parse(await readFile(new URL('../xdr/brute-force/patterns.json', import.meta.url), 'utf8'));
const decideSource = await readFile(new URL('../xdr/brute-force/decide.mjs', import.meta.url), 'utf8');

test('제작 1: 경보 건수와 뽑은 줄 수가 같고, 다섯 항목만 뽑으며 비밀값처럼 보이는 값은 가린다', () => {
  const rows = readAlerts(fixture);
  assert.equal(rows.length, fixture.alerts.length);
  assert.deepEqual(Object.keys(rows[0]).sort(), ['description', 'level', 'srcip', 'time', 'user']);
  assert.equal(mask('password=hunter2 token: abc'), 'password=[가림] token=[가림]');
  assert.equal(mask('x'.repeat(40)), '[가림]');
});

test('제작 2: 패턴마다 이름·찾는 조건·근거 한 줄이 있고 근거는 MITRE ATT&CK T1110 이다', () => {
  assert.ok(patterns.patterns.length >= 2);
  for (const item of patterns.patterns) {
    assert.ok(item.name && item.condition && item.evidence, item.name);
    assert.equal(item.evidence.split('\n').length, 1);
    assert.match(item.evidence, /MITRE ATT&CK T1110/u);
  }
});

test('제작 3: decide.mjs 에는 import·파일 읽기·네트워크가 없고, patterns.json 의 패턴 이름을 상수로 옮겨 적었다', () => {
  assert.doesNotMatch(decideSource, /^\s*import\s|import\(|require\(|readFile|writeFile|fetch\(/mu);
  for (const item of patterns.patterns) assert.ok(decideSource.includes(item.name) && decideSource.includes(item.evidence), item.name);
});

test('제작 3: 명확한 공격은 block, 애매한 시도는 alert, 정상 이벤트는 record 로 나뉘고 확신도 기준이 맞다', () => {
  for (const alert of fixture.alerts) {
    const out = decide(alert);
    assert.ok(['block', 'alert', 'record'].includes(out.action));
    assert.ok(out.confidence >= 0 && out.confidence <= 1 && typeof out.reason === 'string' && !out.reason.includes('\n'));
    assert.equal(out.action, out.confidence >= 0.85 ? 'block' : out.confidence >= 0.5 ? 'alert' : 'record');
    const t1110 = (alert.rule?.mitre ?? []).includes('T1110');
    if (!t1110) assert.equal(out.action, 'record', alert.id);                                   // 정상 이벤트는 막지도 알리지도 않음
    if (/성공했/u.test(alert.rule?.description ?? '')) assert.notEqual(out.action, 'block', alert.id);   // 실패 뒤 성공은 막지 않음
  }
  assert.equal(decide({}).action, 'record');                                                    // 형식이 비어도 답한다
  assert.equal(decide({ rule: { mitre: ['T1110'], level: 12 }, data: { count: '48' } }).action, 'block');
});

test('제작 5: xdr:run 의 counts 가 나오고 정상 이벤트를 block 한 경우가 없다', async () => {
  const result = await runXdr({ root, moduleKey: 'brute-force', writeError: () => {} });
  assert.deepEqual(result.counts, { block: 10, alert: 9, record: 9 });
  const byId = new Map(fixture.alerts.map(alert => [alert.id, alert]));
  assert.ok(result.decisions.every(item => item.action !== 'block' || (byId.get(item.alertId).rule.mitre ?? []).includes('T1110')));
});

test('제작 4: 차단 후보만 주소별 거부 규칙이 되고(만료 시각·근거 경보 번호), 다시 흘리면 명확한 공격만 막힌다', async () => {
  const decisions = fixture.alerts.map(alert => ({ alertId: alert.id, ...decide(alert) }));
  const { rules } = buildDenyRules(fixture.alerts, decisions);
  const byId = new Map(fixture.alerts.map(alert => [alert.id, alert]));
  for (const rule of rules) {
    assert.ok(rule.alertIds.length >= 1 && rule.expiresAt > new Date(Date.parse(rule.since)).toISOString());
    assert.equal(rule.ruleId, RULE_ID);
  }
  for (const item of decisions) {
    const alert = byId.get(item.alertId);
    const blocked = Boolean(checkAddress(rules, alert.data.srcip, alert.timestamp));
    assert.equal(blocked, item.action === 'block', item.alertId);                               // 명확한 공격만 막히고 애매·정상은 통과
  }
  const first = rules[0];
  assert.equal(checkAddress(rules, first.address, Date.parse(first.expiresAt) + 1), null);       // 만료 뒤에는 막지 않음
});

test('제작 4: 정상 기록이나 실패 뒤 성공이 있던 주소는 거부 규칙에 넣지 않는다', () => {
  const alerts = [
    { id: 'a', timestamp: '2026-09-27T09:00:00+09:00', rule: { level: 12, mitre: ['T1110'], description: '실패 60건' }, data: { srcip: '192.0.2.99', count: '60' } },
    { id: 'b', timestamp: '2026-09-27T09:05:00+09:00', rule: { level: 3, mitre: [], description: '로그인이 성공했습니다.' }, data: { srcip: '192.0.2.99' } },
  ];
  const decisions = alerts.map(alert => ({ alertId: alert.id, ...decide(alert) }));
  assert.equal(decisions[0].action, 'block');
  const { rules, skipped } = buildDenyRules(alerts, decisions);
  assert.equal(rules.length, 0);
  assert.equal(skipped[0].alertId, 'a');
});
