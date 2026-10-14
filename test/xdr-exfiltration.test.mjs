import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { decide } from '../xdr/exfiltration/decide.mjs';
import { readAlerts, mask } from '../xdr/exfiltration/read-alerts.mjs';
import { buildDenyRules, checkAddress, RULE_ID } from '../xdr/exfiltration/respond.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const root = new URL('..', import.meta.url).pathname;
const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/exfiltration.json', import.meta.url), 'utf8'));
const patterns = JSON.parse(await readFile(new URL('../xdr/exfiltration/patterns.json', import.meta.url), 'utf8'));
const decideSource = await readFile(new URL('../xdr/exfiltration/decide.mjs', import.meta.url), 'utf8');

test('제작 1: 경보 건수와 뽑은 줄 수가 같고, 다섯 항목만 뽑으며 비밀값처럼 보이는 값은 가린다', () => {
  const rows = readAlerts(fixture);
  assert.equal(rows.length, fixture.alerts.length);
  assert.deepEqual(Object.keys(rows[0]).sort(), ['description', 'level', 'srcip', 'time', 'user']);
  assert.equal(mask('session=abc123&q=1'), 'session=[가림]&q=1');
});

test('제작 2: 패턴마다 이름·찾는 조건·근거 한 줄이 있고 근거는 MITRE ATT&CK T1041·T1048 이다', () => {
  assert.ok(patterns.patterns.length >= 3);
  for (const item of patterns.patterns) {
    assert.ok(item.name && item.condition && item.evidence, item.name);
    assert.equal(item.evidence.split('\n').length, 1);
    assert.match(item.evidence, /MITRE ATT&CK T1(041|048)/u);
  }
});

test('제작 3: decide.mjs 에는 import·파일 읽기·네트워크가 없고, patterns.json 의 패턴을 상수로 옮겨 적었다', () => {
  assert.doesNotMatch(decideSource, /^\s*import\s|import\(|require\(|readFile|writeFile|fetch\(/mu);
  for (const item of patterns.patterns) assert.ok(decideSource.includes(item.name) && decideSource.includes(item.evidence), item.name);
});

test('제작 3: 대용량이면서 신호가 겹치면 block, 작은 전송은 목적지가 낯설어도 alert, 정상 이벤트는 record 이고 확신도 기준이 맞다', () => {
  for (const alert of fixture.alerts) {
    const out = decide(alert);
    assert.equal(out.action, out.confidence >= 0.85 ? 'block' : out.confidence >= 0.5 ? 'alert' : 'record');
    assert.ok(out.confidence >= 0 && out.confidence <= 1 && typeof out.reason === 'string' && !out.reason.includes('\n'));
    if (!(alert.rule?.mitre ?? []).length) assert.equal(out.action, 'record', alert.id);
    if (Number(alert.data?.bytes ?? 0) < 50_000_000) assert.notEqual(out.action, 'block', alert.id);   // 작은 전송은 막지 않음
  }
  assert.equal(decide({}).action, 'record');
  const small = { rule: { level: 12, mitre: ['T1048'], description: '처음 보는 주소로 작은 파일이 2건 나갔습니다. 수업 시간 밖입니다.' }, data: { bytes: '400000', files: '2' } };
  assert.equal(decide(small).action, 'alert');
  // 평소 목적지로 큰 파일이 한 번 나간 경우는 막지 않음(낯선 목적지·반복 등 다른 신호가 없음)
  const usual = { rule: { level: 12, mitre: ['T1041'], description: '평소 목적지로 큰 파일이 한 번 나갔습니다.' }, data: { bytes: '90000000', files: '1' } };
  assert.notEqual(decide(usual).action, 'block');
});

test('제작 5: xdr:run 의 counts 가 나오고 정상 이벤트를 block 한 경우가 없다', async () => {
  const result = await runXdr({ root, moduleKey: 'exfiltration', writeError: () => {} });
  assert.deepEqual(result.counts, { block: 10, alert: 10, record: 10 });
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
    assert.equal(Boolean(checkAddress(rules, alert.data.dstip, alert.timestamp)), item.action === 'block', item.alertId);
  }
  assert.equal(checkAddress(rules, rules[0].address, Date.parse(rules[0].expiresAt) + 1), null);   // 만료 뒤에는 막지 않음
});

test('제작 4: 정상 전송이 오간 목적지는 거부 규칙에 넣지 않는다', () => {
  const alerts = [
    { id: 'a', timestamp: '2026-09-27T09:00:00+09:00', rule: { level: 12, mitre: ['T1048'], description: '10분 안에 자료 200건이 처음 보는 목적지로 나갔습니다.' }, data: { srcip: '192.0.2.99', dstip: '203.0.113.99', bytes: '240000000', files: '200' } },
    { id: 'b', timestamp: '2026-09-27T09:05:00+09:00', rule: { level: 3, mitre: [], description: '내 메모 한 건을 읽었습니다.' }, data: { srcip: '192.0.2.98', dstip: '203.0.113.99', bytes: '2400', files: '1' } },
  ];
  const decisions = alerts.map(alert => ({ alertId: alert.id, ...decide(alert) }));
  assert.equal(decisions[0].action, 'block');
  const { rules, skipped } = buildDenyRules(alerts, decisions);
  assert.equal(rules.length, 0);
  assert.equal(skipped[0].alertId, 'a');
});
