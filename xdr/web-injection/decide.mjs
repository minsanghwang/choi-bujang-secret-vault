// 보너스 xdr-02 제작 3 · 판단 모듈
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부릅니다.
// 그래서 import 문이 없고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 이 파일 안에서만 계산합니다.
// 아래 PATTERNS 는 xdr/web-injection/patterns.json 의 내용을 옮겨 적은 상수입니다(바꾸면 두 곳을 같이 고칩니다).
// match 는 patterns.json 의 condition 을 요청 주소·설명에서 찾는 표기로 옮긴 것입니다.

const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'sql_injection',
    technique: 'T1190',
    evidence: 'MITRE ATT&CK T1190 Exploit Public-Facing Application: 외부에 공개된 웹 앱의 약점을 노리며, SQL 주입이 대표적인 예다.',
    match: /sql|select|union|\bor\b\s*['"]?\d|데이터베이스\s*조회/iu,
  }),
  Object.freeze({
    name: 'script_injection',
    technique: 'T1190',
    evidence: 'MITRE ATT&CK T1190 Exploit Public-Facing Application: 공개된 웹 앱의 입력 검증 약점을 노려 요청에 실행 코드를 넣는다.',
    match: /<\s*script|script|스크립트/iu,
  }),
  Object.freeze({
    name: 'path_traversal',
    technique: 'T1190',
    evidence: 'MITRE ATT&CK T1190 Exploit Public-Facing Application: 공개된 웹 앱의 경로 처리 약점을 노려 허용되지 않은 파일에 접근한다.',
    match: /\.\.\/|\.\.%2f|up-repeat|거슬러|경로\s*이탈/iu,
  }),
  Object.freeze({
    name: 'command_separator',
    technique: 'T1190',
    evidence: 'MITRE ATT&CK T1190 Exploit Public-Facing Application: 공개된 웹 앱의 입력을 통해 서버 쪽 명령 실행을 노린다.',
    match: /cmd|명령\s*구분자|;|\|\||&&/u,
  }),
]);

// 기준값(patterns.json 의 condition 을 숫자로 옮긴 것)
const BLOCK_AT = 0.85;            // 이 값 이상이면 block
const ALERT_AT = 0.5;             // 이 값 이상이면 alert, 아래는 record
const MANY = 10;                  // 같은 주소에서 10번 이상 반복: 아주 뚜렷
const REPEATED = 5;               // 5번 이상 반복: 뚜렷(이보다 적으면 막지 않음)

const round = value => Math.round(Math.min(0.99, Math.max(0, value)) * 100) / 100;
const actionOf = confidence => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');

export function decide(alert) {
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre.filter(item => typeof item === 'string') : [];
  const level = Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0;
  // Wazuh 경보는 data 값을 문자열로 담습니다("12"). 숫자만으로 된 값만 정수로 읽고, 그 밖에는 반복 횟수 없음으로 둡니다.
  const rawCount = alert?.data?.count;
  const count = Number.isInteger(rawCount) && rawCount >= 0 ? rawCount
    : typeof rawCount === 'string' && /^\d{1,6}$/u.test(rawCount) ? Number(rawCount) : null;
  const url = typeof alert?.data?.url === 'string' ? alert.data.url : '';
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';

  // T1190(외부 공개 앱 악용)으로 표시되지 않은 경보는 네 패턴 어디에도 해당하지 않습니다 → 정상 이벤트로 기록만.
  if (!mitre.some(item => item === 'T1190' || item.startsWith('T1190.'))) {
    return { action: 'record', confidence: round(Math.min(level, 6) / 20), reason: '패턴 해당 없음(T1190 표시 없는 정상 이벤트)' };
  }

  const text = `${url} ${description}`;
  const matched = PATTERNS.filter(pattern => pattern.match.test(text)).map(pattern => pattern.name);
  let confidence = 0.5;                                     // T1190 경보 = 약한 신호(알림)
  if (count !== null) confidence += count >= MANY ? 0.3 : count >= REPEATED ? 0.25 : count >= 2 ? 0.1 : 0;
  confidence += level >= 12 ? 0.15 : level >= 10 ? 0.1 : level >= 8 ? 0.05 : 0;
  // 막는 것은 "주입 표기가 있고 같은 주소에서 반복된" 명확한 경우뿐입니다. 표기가 없거나 반복이 적으면 알림까지만 둡니다.
  if (!matched.length || count === null || count < REPEATED) confidence = Math.min(confidence, BLOCK_AT - 0.01);

  const value = round(confidence);
  const parts = [`근거 패턴: ${matched.length ? matched.join(' + ') : '주입 표기 확인 안 됨'}`, count !== null ? `반복 ${count}번` : '반복 횟수 없음', `수준 ${level}`];
  return { action: actionOf(value), confidence: value, reason: parts.join(' · ') };
}
