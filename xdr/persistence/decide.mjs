// 보너스 xdr-04 제작 3 · 판단 모듈
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부릅니다.
// 그래서 import 문이 없고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 이 파일 안에서만 계산합니다.
// 아래 PATTERNS 는 xdr/persistence/patterns.json 의 내용을 옮겨 적은 상수입니다(바꾸면 두 곳을 같이 고칩니다).
// match 는 patterns.json 의 condition 을 경보 설명·파일 경로에서 찾는 표기로 옮긴 것이고, points 는 패턴이 확신도(백분율)에 더하는 점수입니다.

const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'unsigned_new_service',
    technique: 'T1543',
    evidence: 'MITRE ATT&CK T1543 Create or Modify System Process: 공격자는 서명 없는 서비스를 새로 등록하거나 바꿔서 PC를 다시 켜도 프로그램이 살아남게 한다.',
    points: 15,
    match: /서명\s*없는|서명이\s*없|새\s*서비스|서비스\s*등록이\s*연속/u,
  }),
  Object.freeze({
    name: 'unfamiliar_scheduled_task',
    technique: 'T1053',
    evidence: 'MITRE ATT&CK T1053 Scheduled Task/Job: 공격자는 낯선 예약 작업으로 프로그램을 정해진 때마다 다시 실행시켜 오래 머문다.',
    points: 15,
    match: /처음\s*보는|평소\s*목록에\s*없는|임의\s*문자열|다시\s*켜도\s*남/u,
  }),
  Object.freeze({
    name: 'startup_folder_change',
    technique: 'T1543',
    evidence: 'MITRE ATT&CK T1543 (시작 폴더는 하위 기법 T1547.001): 시작 폴더에 심은 프로그램은 로그인할 때마다 자동으로 다시 실행된다.',
    points: 20,
    path: /\\start\s*menu\\programs\\startup\\/iu,
    match: /평소\s*목록에\s*없는|추가됐/u,
  }),
  Object.freeze({
    name: 'temp_folder_target',
    technique: 'T1543',
    evidence: 'MITRE ATT&CK T1543 · T1053: 지속성 항목이 정식 설치 위치가 아닌 임시 폴더의 파일을 가리키면 공격자가 내려놓은 프로그램일 가능성이 크다.',
    points: 15,
    path: /\\temp\\|\/tmp\//iu,
  }),
]);

// 기준값(점수는 백분율 정수로 계산해 소수 오차를 피합니다)
const BLOCK_AT = 85;              // 이 값 이상이면 block
const ALERT_AT = 50;              // 이 값 이상이면 alert, 아래는 record
const BASE = 50;                  // T1543·T1053 표시 = 약한 신호(알림)
const MIN_LEVEL = 5;              // 규칙 수준이 이보다 낮은 일상 경보는 신호가 없으면 기록만
const BOTH_MECHANISMS = 15;       // 서비스(T1543)와 예약 작업(T1053)이 함께 표시됨
const REPEATED = 3;               // 같은 주소에서 연속 3건 이상
const REPEATED_POINTS = 10;
const REMOTE_POINTS = 10;         // 원격 주소에서 등록
const NEEDED_KINDS = 2;           // block 은 서로 다른 신호 종류가 2개 이상일 때만

const actionOf = percent => (percent >= BLOCK_AT ? 'block' : percent >= ALERT_AT ? 'alert' : 'record');
const text = value => (typeof value === 'string' ? value : '');

export function decide(alert) {
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre.filter(item => typeof item === 'string') : [];
  const has = prefix => mitre.some(item => item === prefix || item.startsWith(`${prefix}.`));
  const level = Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0;
  const rawCount = alert?.data?.count;
  const count = Number.isInteger(rawCount) && rawCount >= 0 ? rawCount
    : typeof rawCount === 'string' && /^\d{1,6}$/u.test(rawCount) ? Number(rawCount) : null;

  // T1543·T1053 으로 표시되지 않은 경보는 정상 이벤트로 기록만 합니다.
  if (!has('T1543') && !has('T1053')) {
    return { action: 'record', confidence: Math.min(level, 6) / 20, reason: '패턴 해당 없음(T1543·T1053 표시 없는 정상 이벤트)' };
  }

  // "서비스 등록은 없습니다" 같은 부정 문장은 신호에서 뺍니다.
  const description = text(alert?.rule?.description).replace(/[^.]*(?:등록|실행)(?:은|이)?\s*(?:된\s*)?(?:기록은\s*)?없습니다\.?/gu, ' ');
  const path = text(alert?.data?.path);
  const kinds = new Set();
  const matched = [];
  let percent = BASE;
  for (const pattern of PATTERNS) {
    const byText = pattern.match ? pattern.match.test(description) : false;
    const byPath = pattern.path ? pattern.path.test(path) : false;
    // 시작 폴더 패턴은 경로와 설명이 모두 맞아야 하고, 임시 폴더 패턴은 경로만으로 판단합니다.
    const hit = pattern.name === 'startup_folder_change' ? byText && byPath : pattern.name === 'temp_folder_target' ? byPath : byText;
    if (!hit) continue;
    matched.push(pattern.name);
    percent += pattern.points;
    kinds.add(pattern.name === 'temp_folder_target' || pattern.name === 'startup_folder_change' ? 'path' : 'identity');
  }
  if (has('T1543') && has('T1053')) { percent += BOTH_MECHANISMS; kinds.add('both'); }
  if (count !== null && count >= REPEATED) { percent += REPEATED_POINTS; kinds.add('repeat'); }
  if (/원격\s*주소/u.test(description)) { percent += REMOTE_POINTS; kinds.add('remote'); }
  percent += level >= 12 ? 7 : level >= 10 ? 5 : 0;

  // 일상 경보(낮은 수준)이고 신호가 하나도 없으면 정상으로 기록만 합니다(서명된 기존 서비스, 평소 시각의 예약 등).
  if (level < MIN_LEVEL && !kinds.size) {
    return { action: 'record', confidence: Math.min(level, 6) / 20, reason: '평소 항목으로 보임(신호 없음, 낮은 수준)' };
  }
  // 신호 종류가 하나뿐이면(경로만 수상하거나 이름만 낯설면) 알림까지만 둡니다.
  if (kinds.size < NEEDED_KINDS) percent = Math.min(percent, BLOCK_AT - 1);

  const value = Math.min(99, Math.max(0, percent)) / 100;
  const parts = [`근거 패턴: ${matched.length ? matched.join(' + ') : '서명·경로·목록 신호 없음'}`,
    count !== null ? `반복 ${count}건` : '반복 횟수 없음', `수준 ${level}`];
  return { action: actionOf(percent), confidence: value, reason: parts.join(' · ') };
}
