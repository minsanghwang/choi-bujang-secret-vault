// 보너스 xdr-01 제작 3 · 판단 모듈
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부릅니다.
// 그래서 import 문이 없고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 이 파일 안에서만 계산합니다.
// 아래 PATTERNS 는 xdr/brute-force/patterns.json 의 내용을 그대로 옮겨 적은 상수입니다(바꾸면 두 곳을 같이 고칩니다).

const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'same_source_failure_burst',
    technique: 'T1110.001',
    evidence: 'MITRE ATT&CK T1110.001 Password Guessing: 공격자가 계정 비밀번호를 반복해서 추측하며, 짧은 시간의 연속 인증 실패로 드러난다.',
  }),
  Object.freeze({
    name: 'password_spraying',
    technique: 'T1110.003',
    evidence: 'MITRE ATT&CK T1110.003 Password Spraying: 계정 잠금을 피하려고 흔한 비밀번호 하나를 여러 계정에 대입한다.',
  }),
]);

// 기준값(patterns.json 의 condition 을 숫자로 옮긴 것)
const BLOCK_AT = 0.85;            // 이 값 이상이면 block
const ALERT_AT = 0.5;             // 이 값 이상이면 alert, 아래는 record
const STRONG_COUNT = 30;          // 실패 30건 이상: 아주 뚜렷
const CLEAR_COUNT = 15;           // 실패 15건 이상: 뚜렷
const SOME_COUNT = 10;            // 실패 10건 이상: 조금 뚜렷
const SPRAY = /(여러|서로\s*다른)\s*계정|계정\s*\d+\s*개|계정\s*이름을\s*바꿔|같은\s*비밀번호/u;
const SUCCEEDED = /성공했/u;      // "실패 … 뒤에 성공했습니다": 사용자의 입력 실수일 수 있음("성공은 없습니다"는 해당 없음)

const round = value => Math.round(Math.min(0.99, Math.max(0, value)) * 100) / 100;
const actionOf = confidence => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');

export function decide(alert) {
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre.filter(item => typeof item === 'string') : [];
  const level = Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0;
  // Wazuh 경보는 data 값을 문자열로 담습니다("48"). 숫자만으로 된 값만 정수로 읽고, 그 밖에는 건수 없음으로 둡니다.
  const rawCount = alert?.data?.count;
  const count = Number.isInteger(rawCount) && rawCount >= 0 ? rawCount
    : typeof rawCount === 'string' && /^\d{1,6}$/u.test(rawCount) ? Number(rawCount) : null;
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';

  // T1110(무차별 대입)으로 표시되지 않은 경보는 두 패턴 어디에도 해당하지 않습니다 → 정상 이벤트로 기록만.
  if (!mitre.some(item => item === 'T1110' || item.startsWith('T1110.'))) {
    return { action: 'record', confidence: round(Math.min(level, 6) / 20), reason: '패턴 해당 없음(T1110 표시 없는 정상 이벤트)' };
  }

  const matched = [PATTERNS[0].name];
  let confidence = 0.5;                                     // T1110 경보 = 연속 실패 패턴의 최소 신호(약함)
  if (count !== null) confidence += count >= STRONG_COUNT ? 0.3 : count >= CLEAR_COUNT ? 0.2 : count >= SOME_COUNT ? 0.1 : 0;
  confidence += level >= 12 ? 0.15 : level >= 10 ? 0.1 : level >= 8 ? 0.05 : 0;
  if (SPRAY.test(description)) { confidence += 0.25; matched.push(PATTERNS[1].name); }

  // 실패 뒤 성공한 경보는 사용자의 입력 실수일 수 있으므로 막지 않고 알림까지만 둡니다(정상 사용자 차단 방지).
  const succeeded = SUCCEEDED.test(description);
  if (succeeded) confidence = Math.min(confidence - 0.1, BLOCK_AT - 0.01);
  confidence = Math.max(confidence, ALERT_AT);              // T1110 경보는 적어도 알림으로 남깁니다.

  const value = round(confidence);
  const parts = [`근거 패턴: ${matched.join(' + ')}`, count !== null ? `실패 ${count}건` : '실패 건수 없음', `수준 ${level}`];
  if (succeeded) parts.push('실패 뒤 성공(차단 안 함)');
  return { action: actionOf(value), confidence: value, reason: parts.join(' · ') };
}
