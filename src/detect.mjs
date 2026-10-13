// 9단계 탐지 함수입니다. docs/DETECT_EVENTS.md의 사건 세 값(at, method, identity.sub)만 읽습니다.
// 반 엔진이 검증한 사건만 전달해야 하며, 브라우저가 보낸 사용자 번호는 받지 않습니다.
// 메모 내용·토큰·실명 같은 다른 필드는 읽지도, 복사하지도, 출력하지도 않습니다.

const SUB_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u;   // 가명 주체 ID 모양(실명·이메일은 통과하지 못함)

// 사건 하나에서 필요한 세 값만 꺼내 새 객체로 돌려줍니다. 모양이 맞지 않으면 null이고, 정상값으로 채우지 않습니다.
function readEvent(event) {
  if (!event || typeof event !== 'object') return null;
  const { at, method, identity } = event;
  if (typeof method !== 'string' || typeof at !== 'string') return null;
  const time = Date.parse(at);
  const sub = identity && typeof identity === 'object' ? identity.sub : undefined;
  if (!Number.isFinite(time) || typeof sub !== 'string' || !SUB_PATTERN.test(sub)) return null;
  return { time, method: method.toUpperCase(), sub };
}

const WINDOW_MS = 10 * 60 * 1000;   // 10분 구간
const BURST_LIMIT = 120;            // 한 구간에서 120건을 넘을 때만 의심합니다. (정확히 120건은 의심하지 않음)

// 규칙 하나: 같은 sub의 GET이 어느 10분 구간에서든 120건을 넘으면 그 sub를 의심합니다.
// 다른 사용자의 사건은 합산하지 않고, 10분 밖의 사건은 같은 묶음으로 세지 않으며, 지역 같은 신호는 쓰지 않습니다.
function burstTime(times) {
  const sorted = [...times].sort((a, b) => a - b);
  let start = 0;
  for (let end = 0; end < sorted.length; end += 1) {
    while (sorted[end] - sorted[start] >= WINDOW_MS) start += 1;   // 구간은 [첫 사건, 첫 사건 + 10분)
    if (end - start + 1 > BURST_LIMIT) return sorted[end];          // 한도를 처음 넘긴 시각
  }
  return null;
}

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  // 이 단계는 조회(GET) 사건만 셉니다. 읽은 값 외에는 아무것도 남기지 않습니다.
  const bySub = new Map();
  for (const item of events.map(readEvent)) {
    if (!item || item.method !== 'GET') continue;
    if (!bySub.has(item.sub)) bySub.set(item.sub, []);
    bySub.get(item.sub).push(item.time);
  }
  // 여러 사용자가 동시에 걸리면 한도를 가장 먼저 넘긴 한 명(같으면 sub 순서)만 제안합니다. 대상은 항상 한 명입니다.
  let flagged = null;
  for (const [sub, times] of bySub) {
    const at = burstTime(times);
    if (at === null) continue;
    if (!flagged || at < flagged.at || (at === flagged.at && sub < flagged.sub)) flagged = { sub, at };
  }
  // 회수 제안만 돌려줍니다. 실제 회수와 걸린 시간은 운영 엔진과 심판이 확인하며, 이 함수는 권한을 바꾸지 않습니다.
  return flagged
    ? { action: 'propose_revocation', reasonCode: 'burst_read', subject: flagged.sub }
    : { action: 'observe' };
}
