// 보너스 xdr-06 제작 3 · 판단 모듈
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부릅니다.
// 그래서 import 문이 없고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 이 파일 안에서만 계산합니다.
// 아래 PATTERNS 는 xdr/exfiltration/patterns.json 의 내용을 옮겨 적은 상수입니다(바꾸면 두 곳을 같이 고칩니다).
// test 는 patterns.json 의 condition 을 경보의 전송량·파일 수·반복 횟수·설명으로 확인하는 표기로 옮긴 것입니다.

const LARGE_BYTES = 50_000_000;   // 이 이상이면 대용량
const HUGE_BYTES = 100_000_000;   // 이 이상이면 더 뚜렷
const MANY_FILES = 50;            // 짧은 시간에 파일 50건 이상
const REPEATED = 5;               // 같은 목적지로 5번 이상 반복

const NEW_DESTINATION = /처음\s*(?:보는|봅니다)|평소와\s*다른\s*주소|평소에\s*쓰지\s*않던/u;
const OFF_HOURS = /수업\s*시간\s*밖|업무\s*시간\s*밖/u;
const ARCHIVE = /압축\s*파일/u;

const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'large_transfer_new_destination',
    technique: 'T1048',
    evidence: 'MITRE ATT&CK T1048 Exfiltration Over Alternative Protocol: 공격자는 평소 쓰지 않는 목적지나 통로로 큰 자료를 한꺼번에 내보낸다.',
    test: f => f.bytes >= LARGE_BYTES && NEW_DESTINATION.test(f.text),
  }),
  Object.freeze({
    name: 'bulk_file_copy',
    technique: 'T1041',
    evidence: 'MITRE ATT&CK T1041 Exfiltration Over C2 Channel: 공격자는 이미 열어 둔 통로로 모아 둔 자료를 대량으로 한 번에 내보낸다.',
    test: f => f.files !== null && f.files >= MANY_FILES && f.bytes >= LARGE_BYTES,
  }),
  Object.freeze({
    name: 'off_hours_archive_transfer',
    technique: 'T1048',
    evidence: 'MITRE ATT&CK T1048 Exfiltration Over Alternative Protocol: 자료를 압축해 사용자가 없는 시간대에 빼내면 눈에 덜 띈다.',
    test: f => OFF_HOURS.test(f.text) && (ARCHIVE.test(f.text) || f.bytes >= LARGE_BYTES),
  }),
  Object.freeze({
    name: 'repeated_large_transfer',
    technique: 'T1041',
    evidence: 'MITRE ATT&CK T1041 Exfiltration Over C2 Channel: 공격자는 같은 통로로 자료를 나눠 반복해서 내보낸다.',
    test: f => f.count !== null && f.count >= REPEATED && f.bytes >= LARGE_BYTES,
  }),
]);

// 기준값(점수는 백분율 정수로 계산해 소수 오차를 피합니다)
const BLOCK_AT = 85;              // 이 값 이상이면 block
const ALERT_AT = 50;              // 이 값 이상이면 alert, 아래는 record
const BASE = 50;                  // T1041·T1048 표시 = 약한 신호(알림)
const MIN_LEVEL = 5;              // 규칙 수준이 이보다 낮고 신호도 없으면 기록만
const NEEDED_KINDS = 2;           // block 은 서로 다른 종류의 신호가 2개 이상일 때만

const actionOf = percent => (percent >= BLOCK_AT ? 'block' : percent >= ALERT_AT ? 'alert' : 'record');
const text = value => (typeof value === 'string' ? value : '');
// Wazuh 경보는 data 값을 문자열로 담습니다("240000000"). 숫자만으로 된 값만 정수로 읽습니다.
const whole = value => (Number.isInteger(value) && value >= 0 ? value : typeof value === 'string' && /^\d{1,13}$/u.test(value) ? Number(value) : null);

export function decide(alert) {
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre.filter(item => typeof item === 'string') : [];
  const marked = mitre.some(item => /^T10(41|48)(\.|$)/u.test(item));
  const level = Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0;

  // T1041·T1048 로 표시되지 않은 경보는 정상 이벤트로 기록만 합니다.
  if (!marked) {
    return { action: 'record', confidence: Math.min(level, 6) / 20, reason: '패턴 해당 없음(T1041·T1048 표시 없는 정상 이벤트)' };
  }

  const features = {
    bytes: whole(alert?.data?.bytes) ?? 0,
    files: whole(alert?.data?.files),
    count: whole(alert?.data?.count),
    text: text(alert?.rule?.description),
  };
  const kinds = new Set();
  let percent = BASE;
  if (features.bytes >= HUGE_BYTES) { percent += 25; kinds.add('volume'); }
  else if (features.bytes >= LARGE_BYTES) { percent += 20; kinds.add('volume'); }
  if (NEW_DESTINATION.test(features.text)) { percent += 15; kinds.add('destination'); }
  if (OFF_HOURS.test(features.text)) { percent += 10; kinds.add('hours'); }
  if (features.count !== null && features.count >= REPEATED) { percent += 10; kinds.add('repeat'); }
  if (features.files !== null && features.files >= MANY_FILES) { percent += 10; kinds.add('files'); }
  if (ARCHIVE.test(features.text)) percent += 5;
  percent += level >= 12 ? 7 : level >= 10 ? 5 : 0;

  const matched = PATTERNS.filter(pattern => pattern.test(features)).map(pattern => pattern.name);

  // 일상 경보(낮은 수준)이고 신호가 하나도 없으면 정상으로 기록만 합니다.
  if (level < MIN_LEVEL && !kinds.size) {
    return { action: 'record', confidence: Math.min(level, 6) / 20, reason: '평소 전송으로 보임(신호 없음, 낮은 수준)' };
  }
  // block 은 대용량이면서 서로 다른 종류의 신호가 2개 이상, 그리고 패턴에 맞을 때만 갑니다. 작은 전송은 목적지가 낯설어도 알림까지만 둡니다.
  if (!(features.bytes >= LARGE_BYTES && kinds.size >= NEEDED_KINDS && matched.length)) percent = Math.min(percent, BLOCK_AT - 1);

  const value = Math.min(99, Math.max(0, percent)) / 100;
  const megabytes = Math.round(features.bytes / 1_000_000);
  const parts = [`근거 패턴: ${matched.length ? matched.join(' + ') : '대용량·낯선 목적지 겹침 없음'}`, `전송 ${megabytes}MB`, `수준 ${level}`];
  return { action: actionOf(percent), confidence: value, reason: parts.join(' · ') };
}
