// 보너스 xdr-05 제작 3 · 판단 모듈
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부릅니다.
// 그래서 import 문이 없고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 이 파일 안에서만 계산합니다.
// 아래 PATTERNS 는 xdr/privilege/patterns.json 의 내용을 옮겨 적은 상수입니다(바꾸면 두 곳을 같이 고칩니다).
// match 는 patterns.json 의 condition 을 경보 설명·그룹 이름에서 찾는 표기로 옮긴 것이고, points 는 패턴이 확신도(백분율)에 더하는 점수입니다.
// kind 'privilege' 는 권한 자체가 바뀐 신호, 'context' 는 평소와 다른 정황 신호, 'both' 는 둘을 한꺼번에 보이는 신호(다른 계정의 권한을 빌림)입니다.

const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'admin_group_added',
    technique: 'T1078',
    evidence: 'MITRE ATT&CK T1078 Valid Accounts: 공격자는 훔친 정상 계정을 관리자 그룹에 넣어 높은 권한을 얻고 오래 머문다.',
    kind: 'privilege',
    points: 20,
    match: /관리자\s*그룹(?:에|\s)\s*(?:추가|들어)|다시\s*관리자로\s*들어/u,
  }),
  Object.freeze({
    name: 'unfamiliar_admin_command',
    technique: 'T1068',
    evidence: 'MITRE ATT&CK T1068 Exploitation for Privilege Escalation: 공격자는 권한 상승 약점을 악용해 평소 하지 않던 관리자 명령을 실행한다.',
    kind: 'privilege',
    points: 15,
    match: /(?:관리자|권한)\s*명령(?:을|이)?[^.]*실행|관리자\s*권한으로\s*바뀌/u,
  }),
  Object.freeze({
    name: 'off_hours_privilege_use',
    technique: 'T1078',
    evidence: 'MITRE ATT&CK T1078 Valid Accounts: 도용한 정상 계정은 사용자가 없는 시간대에 권한을 쓰는 경우가 많다.',
    kind: 'context',
    points: 10,
    match: /수업\s*시간\s*밖|업무처럼\s*보이지\s*않는/u,
  }),
  Object.freeze({
    name: 'borrowed_privilege',
    technique: 'T1068',
    evidence: 'MITRE ATT&CK T1068 Exploitation for Privilege Escalation: 다른 계정의 권한을 빌려 쓰는 것은 권한 상승 악용의 전형적인 모습이다.',
    kind: 'both',
    points: 25,
    match: /다른\s*계정의\s*권한으로/u,
  }),
]);

// 정황 신호(패턴의 조건에 딸린 더 뚜렷한 모습)
const CONTEXT = Object.freeze([
  Object.freeze({ name: 'remote_address', points: 10, match: /원격\s*주소/u }),
  Object.freeze({ name: 'new_source_address', points: 15, match: /처음\s*(?:보는|봅니다)/u }),
  Object.freeze({ name: 'just_promoted', points: 15, match: /방금\s*관리자가\s*된|곧바로|같이\s*있습니다/u }),
  Object.freeze({ name: 'rejoined_admin', points: 15, match: /다시\s*관리자로\s*들어/u }),
]);

// 기준값(점수는 백분율 정수로 계산해 소수 오차를 피합니다)
const BLOCK_AT = 85;              // 이 값 이상이면 block
const ALERT_AT = 50;              // 이 값 이상이면 alert, 아래는 record
const BASE = 50;                  // T1068·T1078 표시 = 약한 신호(알림)
const MIN_LEVEL = 5;              // 규칙 수준이 이보다 낮고 신호도 없으면 기록만
const REPEATED = 3;               // 같은 주소에서 계정 3개 이상 연속
const REPEATED_POINTS = 10;

const actionOf = percent => (percent >= BLOCK_AT ? 'block' : percent >= ALERT_AT ? 'alert' : 'record');
const text = value => (typeof value === 'string' ? value : '');

export function decide(alert) {
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre.filter(item => typeof item === 'string') : [];
  const marked = mitre.some(item => /^T10(68|78)(\.|$)/u.test(item));
  const level = Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0;
  const rawCount = alert?.data?.count;
  const count = Number.isInteger(rawCount) && rawCount >= 0 ? rawCount
    : typeof rawCount === 'string' && /^\d{1,6}$/u.test(rawCount) ? Number(rawCount) : null;

  // T1068·T1078 로 표시되지 않은 경보는 정상 이벤트로 기록만 합니다.
  if (!marked) {
    return { action: 'record', confidence: Math.min(level, 6) / 20, reason: '패턴 해당 없음(T1068·T1078 표시 없는 정상 이벤트)' };
  }

  const description = text(alert?.rule?.description);
  const adminGroupData = text(alert?.data?.group).toLowerCase() === 'administrators';   // 관리자 그룹 자체가 바뀐 경보
  const kinds = new Set();
  const matched = [];
  let percent = BASE;
  for (const pattern of PATTERNS) {
    const hit = pattern.match.test(description) || (pattern.name === 'admin_group_added' && adminGroupData);
    if (!hit) continue;
    matched.push(pattern.name);
    percent += pattern.points;
    if (pattern.kind === 'both') { kinds.add('privilege'); kinds.add('context'); } else kinds.add(pattern.kind);
  }
  for (const signal of CONTEXT) {
    if (!signal.match.test(description)) continue;
    percent += signal.points;
    kinds.add('context');
  }
  if (count !== null && count >= REPEATED) { percent += REPEATED_POINTS; kinds.add('context'); }
  percent += level >= 12 ? 7 : level >= 10 ? 5 : 0;

  // 일상 경보(낮은 수준)이고 신호가 하나도 없으면 정상으로 기록만 합니다.
  if (level < MIN_LEVEL && !kinds.size) {
    return { action: 'record', confidence: Math.min(level, 6) / 20, reason: '평소 활동으로 보임(신호 없음, 낮은 수준)' };
  }
  // block 은 권한이 바뀐 신호와 평소와 다른 정황이 함께 있을 때만 갑니다. 하나뿐이면 알림까지만 둡니다.
  if (!(kinds.has('privilege') && kinds.has('context'))) percent = Math.min(percent, BLOCK_AT - 1);

  const value = Math.min(99, Math.max(0, percent)) / 100;
  const parts = [`근거 패턴: ${matched.length ? matched.join(' + ') : '관리자 그룹·명령 신호 없음'}`,
    count !== null ? `반복 ${count}건` : '반복 횟수 없음', `수준 ${level}`];
  return { action: actionOf(percent), confidence: value, reason: parts.join(' · ') };
}
