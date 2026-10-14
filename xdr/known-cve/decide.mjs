// 보너스 xdr-03 제작 3 · 판단 모듈
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부릅니다.
// 그래서 import 문이 없고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 이 파일 안에서만 계산합니다.
// 아래 PATTERNS 는 xdr/known-cve/patterns.json 의 내용을 옮겨 적은 상수입니다(바꾸면 두 곳을 같이 고칩니다).
// match 는 patterns.json 의 condition 을 요청 머리글·주소·설명에서 찾는 표기로 옮긴 것입니다.

const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'jndi_lookup',
    technique: 'T1190',
    evidence: 'CVE-2021-44228 · MITRE ATT&CK T1190: 로그에 기록되는 문자열 속 ${jndi:…://…} 조회 구문이 서버가 외부 코드를 내려받아 실행하게 만드는 Log4Shell 악용 형태다.',
    complete: true,
    match: /\$\{\s*jndi\s*:\s*(?:ldaps?|rmi|dns|iiop|nis|corba|http|https)\s*:\/\//iu,
  }),
  Object.freeze({
    name: 'jndi_obfuscated',
    technique: 'T1190',
    evidence: 'CVE-2021-44228 · MITRE ATT&CK T1190: 탐지를 피하려고 jndi 글자를 쪼개거나 부호화해도 같은 Log4Shell 악용 형태다.',
    complete: true,
    match: /\$\{(?:\$\{[^}]*\}|[^}$])*ndi\s*:\s*(?:\$\{[^}]*\}|[a-z])+\s*:\/\//iu,
  }),
  Object.freeze({
    name: 'known_scanner_trace',
    technique: 'T1190',
    evidence: 'MITRE ATT&CK T1190: 공개 앱을 악용하기 전에 취약점 점검 도구(CVE-2021-44228 점검용 포함)가 요청에 남기는 흔적은 악용 시도의 앞 신호다.',
    complete: false,
    match: /점검\s*흔적|nuclei|zgrab|log4j-?scan|log4shell-?scan/iu,
  }),
]);

// 기준값(점수는 백분율 정수로 계산해 소수 오차를 피합니다)
const BLOCK_AT = 85;              // 이 값 이상이면 block
const ALERT_AT = 50;              // 이 값 이상이면 alert, 아래는 record
const BASE = 50;                  // T1190 표시 = 약한 신호
const COMPLETE_SYNTAX = 35;       // 완전한 원격 조회 구문이 있으면 곧바로 block 선(50+35=85)
const BOTH_PLACES = 5;            // 머리글과 주소 양쪽에 있음
const REPEATED = 5;               // 같은 주소에서 5번 이상 반복
const SCANNER = 5;                // 점검 도구 흔적이 함께 있음

const actionOf = percent => (percent >= BLOCK_AT ? 'block' : percent >= ALERT_AT ? 'alert' : 'record');
const decoded = text => { try { return `${text} ${decodeURIComponent(text)}`; } catch { return text; } };
const text = value => (typeof value === 'string' ? value : '');

export function decide(alert) {
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre.filter(item => typeof item === 'string') : [];
  const level = Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0;
  // Wazuh 경보는 data 값을 문자열로 담습니다("6"). 숫자만으로 된 값만 정수로 읽습니다.
  const rawCount = alert?.data?.count;
  const count = Number.isInteger(rawCount) && rawCount >= 0 ? rawCount
    : typeof rawCount === 'string' && /^\d{1,6}$/u.test(rawCount) ? Number(rawCount) : null;

  // T1190(외부 공개 앱 악용)으로 표시되지 않은 경보는 정상 이벤트로 기록만 합니다.
  if (!mitre.some(item => item === 'T1190' || item.startsWith('T1190.'))) {
    return { action: 'record', confidence: Math.min(level, 6) / 20, reason: '패턴 해당 없음(T1190 표시 없는 정상 이벤트)' };
  }

  const header = decoded(`${text(alert?.data?.useragent)} ${text(alert?.data?.referer)} ${text(alert?.data?.header)}`);
  const url = decoded(text(alert?.data?.url));
  const description = text(alert?.rule?.description);
  const hit = pattern => pattern.match.test(`${header} ${url} ${description}`);
  const matched = PATTERNS.filter(hit);
  const completeNames = matched.filter(pattern => pattern.complete).map(pattern => pattern.name);

  let percent = BASE;
  if (completeNames.length) {
    percent += COMPLETE_SYNTAX;
    if (PATTERNS.some(pattern => pattern.complete && pattern.match.test(header)) && PATTERNS.some(pattern => pattern.complete && pattern.match.test(url))) percent += BOTH_PLACES;
    if (count !== null && count >= REPEATED) percent += 5;
    if (matched.some(pattern => pattern.name === 'known_scanner_trace')) percent += SCANNER;
    percent += level >= 12 ? 5 : 0;
  } else {
    // 완전한 구문이 없으면(단어·조각·이름만 있으면) 알림까지만 둡니다.
    if (matched.length) percent += 5;
    if (count !== null && count >= 2) percent += 5;
    percent += level >= 8 ? 5 : 0;
    percent = Math.min(percent, BLOCK_AT - 1);
  }

  const value = Math.min(99, Math.max(0, percent)) / 100;
  const parts = [`근거 패턴: ${matched.length ? matched.map(pattern => pattern.name).join(' + ') : '완전한 원격 조회 구문 없음'}`,
    count !== null ? `반복 ${count}번` : '반복 횟수 없음', `수준 ${level}`];
  return { action: actionOf(percent), confidence: value, reason: parts.join(' · ') };
}
