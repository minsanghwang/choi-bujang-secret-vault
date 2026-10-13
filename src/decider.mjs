// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
// 이 파일은 docs/DECIDER_REQUEST.md의 요청 항목(deviceRegistered, stepUp, recentEvents, signals)만 읽습니다.
// 브라우저 헤더·위치·request.device/identity/geo/role 같은 계약 밖 값은 읽지 않습니다.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

// 7단계 가상 사건 기준. 지역 하나만으로는 어떤 결정도 바꾸지 않습니다.
const TRUSTED_SOURCES = new Set(['judge_fixture']); // 엔진이 심판의 가상 사건으로 표시한 출처만 인정
const ODD_HOURS = new Set([0, 1, 2, 3, 4, 5]);      // 평소와 다른 시각(가상 기준)
const BURST_WINDOW_SECONDS = 600;                   // 최근 10분 안의
const BURST_COUNT = 10;                             // 위험 신호 10건 이상을 "갑자기 많이 읽음"으로 봅니다.
const MAX_REAUTH_AGE_SECONDS = 900;

const isCount = value => Number.isInteger(value) && value >= 0;

// 값이 없거나 형식·출처가 맞지 않으면 null을 돌려줍니다. 정상값으로 채우지 않습니다.
function trustedSignals(request) {
  const signals = request?.signals;
  if (!signals || typeof signals !== 'object' || !TRUSTED_SOURCES.has(signals.source)) return null;
  const { network, hour } = signals;
  if (!['usual', 'unusual'].includes(network) || !Number.isInteger(hour) || hour < 0 || hour > 23) return null;
  return { network, hour };
}
function recentBurst(request) {
  const events = request?.recentEvents;
  if (!Array.isArray(events) || events.length > 12) return 0;
  return events.reduce((sum, item) => (item && item.kind === 'risk_signal' && isCount(item.ageSeconds)
    && item.ageSeconds <= BURST_WINDOW_SECONDS && isCount(item.count) ? sum + item.count : sum), 0);
}
// 엔진이 새 로그인 시각을 검증해 넘긴 경우만 인정합니다. 토큰은 보지 않습니다.
function reauthenticated(request) {
  const step = request?.stepUp;
  return Boolean(step) && step.verified === true && Number.isInteger(step.authAgeSeconds)
    && step.authAgeSeconds >= 0 && step.authAgeSeconds <= MAX_REAUTH_AGE_SECONDS;
}

export async function decide(request) {
  const answer = (decision, reasonCode, ruleId) => ({
    schema: 'aleph.decision.v1', requestId: request?.requestId, decision, reasonCode, ruleIds: [ruleId],
  });
  // 규칙 1(6단계): 등록 기기(true)만 통과합니다. false·없음·"true" 같은 값은 모두 미등록입니다.
  if (request?.deviceRegistered !== true) return answer('deny', 'device_not_registered', 'device_registered');

  // 규칙 2(7단계): 평소와 다른 시각 + 처음 보는 네트워크 + 짧은 시간의 많은 읽기가 함께일 때만 다시 확인합니다.
  // 지역(region)은 판단에 쓰지 않고, 하나라도 빠지면(또는 출처가 불명확하면) 이 규칙은 걸리지 않습니다.
  const signals = trustedSignals(request);
  const unusual = Boolean(signals) && ODD_HOURS.has(signals.hour) && signals.network === 'unusual'
    && recentBurst(request) >= BURST_COUNT;
  if (unusual && !reauthenticated(request)) return answer('step_up', 'step_up_required', 'step_up_required');

  return { ...answer('allow', 'approved', 'device_registered') };
}
