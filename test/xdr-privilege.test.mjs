import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { decide } from '../xdr/privilege/decide.mjs';
import { readAlerts, mask } from '../xdr/privilege/read-alerts.mjs';
import { buildDenyRules, checkAddress, RULE_ID } from '../xdr/privilege/respond.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const root = new URL('..', import.meta.url).pathname;
const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/privilege.json', import.meta.url), 'utf8'));
const patterns = JSON.parse(await readFile(new URL('../xdr/privilege/patterns.json', import.meta.url), 'utf8'));
const decideSource = await readFile(new URL('../xdr/privilege/decide.mjs', import.meta.url), 'utf8');

test('제작 1: 경보 건수와 뽑은 줄 수가 같고, 다섯 항목만 뽑으며 비밀값처럼 보이는 값은 가린다', () => {
  const rows = readAlerts(fixture);
  assert.equal(rows.length, fixture.alerts.length);
  assert.deepEqual(Object.keys(rows[0]).sort(), ['description', 'level', 'srcip', 'time', 'user']);
  assert.equal(mask('session=abc123&q=1'), 'session=[가림]&q=1');
});

test('제작 2: 패턴마다 이름·찾는 조건·근거 한 줄이 있고 근거는 MITRE ATT&CK T1068·T1078 이다', () => {
  assert.ok(patterns.patterns.length >= 3);
  for (const item of patterns.patterns) {
    assert.ok(item.name && item.condition && item.evidence, item.name);
    assert.equal(item.evidence.split('\n').length, 1);
    assert.match(item.evidence, /MITRE ATT&CK T1(068|078)/u);
  }
});

test('제작 3: decide.mjs 에는 import·파일 읽기·네트워크가 없고, patterns.json 의 패턴을 상수로 옮겨 적었다', () => {
  assert.doesNotMatch(decideSource, /^\s*import\s|import\(|require\(|readFile|writeFile|fetch\(/mu);
  for (const item of patterns.patterns) assert.ok(decideSource.includes(item.name) && decideSource.includes(item.evidence), item.name);
});

test('제작 3: 권한 변경과 평소와 다른 정황이 겹치면 block, 하나뿐이면 alert, 정상 이벤트는 record 이고 확신도 기준이 맞다', () => {
  for (const alert of fixture.alerts) {
    const out = decide(alert);
    assert.equal(out.action, out.confidence >= 0.85 ? 'block' : out.confidence >= 0.5 ? 'alert' : 'record');
    assert.ok(out.confidence >= 0 && out.confidence <= 1 && typeof out.reason === 'string' && !out.reason.includes('\n'));
    if (!(alert.rule?.mitre ?? []).length) assert.equal(out.action, 'record', alert.id);
  }
  assert.equal(decide({}).action, 'record');
  // 평소 주소에서 관리자 명령 한 번뿐이면 알림까지만, 과제 그룹 추가는 관리자 그룹이 아니므로 알림까지만
  assert.equal(decide({ rule: { level: 12, mitre: ['T1068'], description: '평소 주소에서 관리자 명령이 한 번 실행됐습니다.' }, data: {} }).action, 'alert');
  assert.equal(decide({ rule: { level: 12, mitre: ['T1078'], description: 'user02 가 과제 그룹에 추가됐습니다. 관리자 그룹은 아닙니다.' }, data: { group: 'project-week3' } }).action, 'alert');
  // 다른 계정의 권한을 빌려 실행하면 그 자체로 뚜렷함
  assert.equal(decide({ rule: { level: 12, mitre: ['T1068'], description: 'user07 이 다른 계정의 권한으로 관리자 명령을 실행했습니다.' }, data: {} }).action, 'block');
});

test('제작 5: xdr:run 의 counts 가 나오고 정상 이벤트를 block 한 경우가 없다', async () => {
  const result = await runXdr({ root, moduleKey: 'privilege', writeError: () => {} });
  assert.deepEqual(result.counts, { block: 9, alert: 8, record: 9 });
  const byId = new Map(fixture.alerts.map(alert => [alert.id, alert]));
  assert.ok(result.decisions.every(item => item.action !== 'block' || (byId.get(item.alertId).rule.mitre ?? []).length > 0));
});

test('제작 4: 차단 후보만 주소별 거부 규칙이 되고(만료 시각·근거 경보 번호), 다시 흘리면 명확한 공격만 막힌다', () => {
  const decisions = fixture.alerts.map(alert => ({ alertId: alert.id, ...decide(alert) }));
  const { rules } = buildDenyRules(fixture.alerts, decisions);
  const byId = new Map(fixture.alerts.map(alert => [alert.id, alert]));
  for (const rule of rules) assert.ok(rule.alertIds.length >= 1 && rule.ruleId === RULE_ID && rule.expiresAt);
  for (const item of decisions) {
    const alert = byId.get(item.alertId);
    assert.equal(Boolean(checkAddress(rules, alert.data.srcip, alert.timestamp)), item.action === 'block', item.alertId);
  }
  assert.equal(checkAddress(rules, rules[0].address, Date.parse(rules[0].expiresAt) + 1), null);   // 만료 뒤에는 막지 않음
});

test('제작 4: 정상 기록이 있던 주소는 거부 규칙에 넣지 않는다', () => {
  const alerts = [
    { id: 'a', timestamp: '2026-09-27T09:00:00+09:00', rule: { level: 12, mitre: ['T1078'], description: 'user01 이 원격 주소에서 관리자 그룹에 추가됐습니다.' }, data: { srcip: '192.0.2.99', group: 'administrators' } },
    { id: 'b', timestamp: '2026-09-27T09:05:00+09:00', rule: { level: 3, mitre: [], description: '자료 목록을 조회했습니다.' }, data: { srcip: '192.0.2.99', url: '/api/notes' } },
  ];
  const decisions = alerts.map(alert => ({ alertId: alert.id, ...decide(alert) }));
  assert.equal(decisions[0].action, 'block');
  const { rules, skipped } = buildDenyRules(alerts, decisions);
  assert.equal(rules.length, 0);
  assert.equal(skipped[0].alertId, 'a');
});
