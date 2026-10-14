// 보너스 xdr-04 제작 4 · 알림과 차단
// decide.mjs 의 결과 가운데 차단 후보(block)만 내 ZTNA 판정기 앞단의 거부 규칙으로 내보내고, 알림은 xdr/alerts.log 에 한 줄씩 쌓습니다.
//  - decide.mjs 는 판단만 하고, 파일 쓰기와 판정기 연결은 이 파일만 합니다.
//  - 판정기(src/decider.mjs)의 기존 규칙은 고치지 않습니다. 판정기 요청 계약(docs/DECIDER_REQUEST.md)에는 출발 주소가 없어 decide()가 주소를 볼 수 없으므로,
//    거부 규칙은 판정기에 확인 단계를 하나 더하는 부품으로, 요청이 판정기에 닿기 전에 출발 주소로 대조하는 목록(deny-rules.json)과 대조 함수(checkAddress)로 둡니다.
//  - 규칙에는 만료 시각과 근거 경보 번호를 붙이고, 정상 이벤트(record)가 있었던 주소는 규칙에 넣지 않습니다(정상 사용자 차단 방지).
// 실행: npm run xdr:respond:persist   (먼저 npm run xdr:run -- persistence 으로 result.json 을 만듭니다)
import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const RULE_ID = 'xdr_persistence_block';
export const REASON_CODE = 'xdr_persistence';
export const BLOCK_MINUTES = 60;                     // 차단 규칙의 유효 시간(근거 경보 시각부터)
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/u;
const IPV6 = /^[0-9a-f:]{2,39}$/iu;
const validAddress = value => typeof value === 'string' && (IPV4.test(value) || (value.includes(':') && IPV6.test(value)));

export function buildDenyRules(alerts, decisions) {
  const byId = new Map(alerts.map(alert => [alert?.id, alert]));
  const safeAddresses = new Set(decisions.filter(item => item.action === 'record').map(item => byId.get(item.alertId)?.data?.srcip));
  const rules = new Map();
  const skipped = [];
  for (const decision of decisions) {
    if (decision.action !== 'block') continue;
    const alert = byId.get(decision.alertId);
    const address = alert?.data?.srcip;
    const at = Date.parse(alert?.timestamp ?? '');
    if (!validAddress(address) || !Number.isFinite(at)) { skipped.push({ alertId: decision.alertId, why: '주소나 시각을 읽을 수 없음' }); continue; }
    if (safeAddresses.has(address)) { skipped.push({ alertId: decision.alertId, why: '같은 주소에 정상 기록이 있어 막지 않음' }); continue; }
    const expiresAt = new Date(at + BLOCK_MINUTES * 60 * 1000).toISOString();
    const rule = rules.get(address) ?? { address, decision: 'deny', reasonCode: REASON_CODE, ruleId: RULE_ID, alertIds: [], since: alert.timestamp, expiresAt };
    rule.alertIds.push(decision.alertId);
    if (expiresAt > rule.expiresAt) rule.expiresAt = expiresAt;
    rules.set(address, rule);
  }
  return { rules: [...rules.values()], skipped };
}

// 판정기 앞단의 확인 단계: 출발 주소가 아직 만료되지 않은 거부 규칙에 걸리면 판정기 응답과 같은 모양의 거부를 돌려주고, 아니면 null(판정기로 넘김).
export function checkAddress(rules, address, at) {
  const when = typeof at === 'number' ? at : Date.parse(at ?? '');
  const rule = rules.find(item => item.address === address);
  if (!rule || !Number.isFinite(when)) return null;
  if (when < Date.parse(rule.since) || when >= Date.parse(rule.expiresAt)) return null;
  return { decision: 'deny', reasonCode: REASON_CODE, ruleIds: [RULE_ID], alertIds: [...rule.alertIds] };
}

// 알림 한 줄: 시각 · 행동 · 경보 번호 · 주소 · 계정 · 확신도 · 근거. 요청 주소(URL)는 주입 문자열이 들어 있을 수 있어 쓰지 않습니다.
export function alertLine(alert, decision) {
  return [alert?.timestamp ?? '', decision.action.toUpperCase(), decision.alertId, alert?.data?.srcip ?? '', alert?.data?.srcuser ?? '',
    decision.confidence.toFixed(2), decision.reason].join(' | ');
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  try {
    const fixture = JSON.parse(await readFile(join(root, 'xdr', 'fixtures', 'persistence.json'), 'utf8'));
    const result = JSON.parse(await readFile(join(root, 'xdr', 'persistence', 'result.json'), 'utf8'));
    const alerts = fixture.alerts;
    const { rules, skipped } = buildDenyRules(alerts, result.decisions);
    await writeFile(join(root, 'xdr', 'persistence', 'deny-rules.json'),
      `${JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', moduleKey: 'persistence', ruleId: RULE_ID, blockMinutes: BLOCK_MINUTES, rules, skipped }, null, 2)}\n`, 'utf8');

    const logPath = join(root, 'xdr', 'alerts.log');
    let existing = '';
    try { existing = await readFile(logPath, 'utf8'); } catch { /* 처음 실행 */ }
    const byId = new Map(alerts.map(alert => [alert.id, alert]));
    const fresh = result.decisions.filter(item => item.action !== 'record' && !existing.includes(` | ${item.alertId} | `))
      .map(item => alertLine(byId.get(item.alertId), item));
    if (fresh.length) await appendFile(logPath, `${fresh.join('\n')}\n`, 'utf8');

    const replay = result.decisions.map(item => {
      const alert = byId.get(item.alertId);
      return { alertId: item.alertId, action: item.action, blocked: Boolean(checkAddress(rules, alert?.data?.srcip, alert?.timestamp)) };
    });
    const normalBlocked = replay.filter(item => item.action === 'record' && item.blocked);
    const alertBlocked = replay.filter(item => item.action === 'alert' && item.blocked);
    const clearBlocked = replay.filter(item => item.action === 'block' && item.blocked).length;
    console.log(`거부 규칙 ${rules.length}개(근거 경보 ${rules.reduce((n, r) => n + r.alertIds.length, 0)}건) · 건너뜀 ${skipped.length}건 · 알림 새 줄 ${fresh.length}줄`);
    console.log(`다시 흘리기: 명확한 공격 막힘 ${clearBlocked}/${replay.filter(i => i.action === 'block').length} · 애매한 시도 막힘 ${alertBlocked.length} · 정상 이벤트 막힘 ${normalBlocked.length}`);
    if (normalBlocked.length || alertBlocked.length) process.exitCode = 1;
  } catch (error) {
    console.error(`알림·차단 첫 오류: ${error instanceof Error ? error.message : '실행 오류'}`);
    process.exitCode = 1;
  }
}
