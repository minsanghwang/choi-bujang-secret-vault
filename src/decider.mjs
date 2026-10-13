// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
// 이 파일은 docs/DECIDER_REQUEST.md의 요청 항목(deviceRegistered, stepUp, recentEvents, signals)만 읽습니다.
// 브라우저 헤더·위치·request.device/identity/geo/role 같은 계약 밖 값은 읽지 않습니다.
export const RULE_IDS = Object.freeze(['device_registered', 'zone_access', 'step_up_required']);

// 7단계 가상 사건 기준. 지역 하나만으로는 어떤 결정도 바꾸지 않습니다.
const TRUSTED_SOURCES = new Set(['judge_fixture']); // 엔진이 심판의 가상 사건으로 표시한 출처만 인정
const ODD_HOURS = new Set([0, 1, 2, 3, 4, 5]);      // 평소와 다른 시각(가상 기준)
const BURST_WINDOW_SECONDS = 600;                   // 최근 10분 안의
const BURST_COUNT = 10;                             // 위험 신호 10건 이상을 "갑자기 많이 읽음"으로 봅니다.
const MAX_REAUTH_AGE_SECONDS = 900;

// 8단계 구역 표. 엔진이 확인해 넘긴 service·method·path·route가 아래 한 줄과 정확히 맞아야 합니다.
// 규칙은 자기 메모 읽기(GET)·수정(PUT)과 강사 공지 수정(PUT, 허용하지 않음) 셋뿐이고, 표에 없는 경로·메서드(목록·추가·삭제 포함)는 모두 거부합니다.
//   note   = 내 자료실 메모(소유자 확인은 자료 API가 최종으로 합니다. 판정기는 소유자 값이 없어, 경로에 사용자 ID가 있을 때만 subjectId와 대조합니다)
//   notice = 강사 공지. 요청 계약에 강사 역할 값이 없으므로 이 판정기는 공지 읽기·수정을 모두 허용하지 않습니다(표에 읽기 줄이 없음).
const ZONE_ROUTES = Object.freeze({
  'GET /notes/:id': { pattern: /^\/notes\/([^/]+)$/u, allow: true },
  'PUT /notes/:id': { pattern: /^\/notes\/([^/]+)$/u, allow: true },
  'PUT /notices/:id': { pattern: /^\/notices\/([^/]+)$/u, allow: false },
});
// 기능 이름이 자료 ID 자리에 들어오지 못하게 막습니다. (자료 ID는 쿼리가 아니라 경로 한 칸으로만 고릅니다)
const RESERVED_IDS = new Set(['export', 'import', 'search', 'all', 'list', 'new', 'bulk', 'download', 'backup', 'admin', 'share']);
// 공지·관리자 구역을 가리키는 ID는 메모 경로에서 거부합니다. (공지 ID로 메모 경로를 부르는 우회를 막음)
// 표시는 ID 맨 앞뿐 아니라 어느 위치에 있어도 읽습니다. (예: note-of-learner_other, memo-notice-1)
const NOTICE_MARKED_ID = /(notice|announce|teacher|instructor|admin)/iu;
const USER_MARKED_TOKEN = /(?:learner|student|user|subject)[_-][A-Za-z0-9_-]*/giu;
const ID_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/u;

function zoneAllowed(request) {
  if (typeof request?.subjectId !== 'string' || !request.subjectId) return false;
  if (typeof request.route !== 'string' || typeof request.method !== 'string' || !Object.hasOwn(ZONE_ROUTES, request.route)) return false;
  const entry = ZONE_ROUTES[request.route];
  // route는 표의 한 줄과 같아야 하고, 그 줄의 메서드가 요청 method와 같고, path가 그 줄의 모양과 맞아야 합니다.
  if (request.service !== 'notes' || !request.route.startsWith(`${request.method} `)) return false;
  const match = typeof request.path === 'string' ? entry.pattern.exec(request.path) : null;
  if (!match || request.queryLength !== 0) return false;
  if (match[1] !== undefined && (!ID_SEGMENT.test(match[1]) || RESERVED_IDS.has(match[1].toLowerCase()))) return false;
  if (match[1] !== undefined && NOTICE_MARKED_ID.test(match[1])) return false;
  // 사용자를 가리키는 ID(learner_…, student_…, user_…, subject_…)는 요청한 사람의 subjectId로 시작할 때만 허용합니다.
  // 다른 사용자의 ID가 붙은 경로는 같은 모양이어도 거부합니다. 사용자 표시가 없는 ID는 이 검사로 판단하지 않습니다.
  // ID 안에 사용자 표시가 하나라도 있으면 모두 요청한 사람의 subjectId로 시작해야 합니다. (다른 사람 표시가 섞이면 거부)
  const subject = request.subjectId.toLowerCase();
  if (match[1] !== undefined
      && [...match[1].matchAll(USER_MARKED_TOKEN)].some(token => !token[0].toLowerCase().startsWith(subject))) return false;
  return entry.allow;
}

// 8단계 소유 기록: 요청 계약에 자료의 주인 값이 없으므로, 허용한 메모 경로를 처음 쓴 사용자(subjectId)를 기억합니다.
// 같은 경로를 다른 사용자가 요청하면 거부합니다. 프로세스 메모리에만 있고 상한이 있으며, 최종 소유자 확인은 자료 API가 합니다.
const MAX_OWNERS = 5000;
const owners = new Map();
const ownerKey = request => (typeof request.path === 'string' ? request.path.toLowerCase() : null);
const ownerConflict = request => {
  const owner = owners.get(ownerKey(request));
  return owner !== undefined && owner !== request.subjectId.toLowerCase();
};
function rememberOwner(request) {
  const key = ownerKey(request);
  if (!key || owners.has(key)) return;
  if (owners.size >= MAX_OWNERS) owners.delete(owners.keys().next().value);
  owners.set(key, request.subjectId.toLowerCase());
}

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

  // 규칙 2(8단계): 사용자·기기·동작·정확한 경로가 구역 표의 한 줄과 맞을 때만 통과합니다. 모르는 경로는 거부합니다.
  if (!zoneAllowed(request) || ownerConflict(request)) return answer('deny', 'zone_not_allowed', 'zone_access');

  // 규칙 3(7단계): 평소와 다른 시각 + 처음 보는 네트워크 + 짧은 시간의 많은 읽기가 함께일 때만 다시 확인합니다.
  // 지역(region)은 판단에 쓰지 않고, 하나라도 빠지면(또는 출처가 불명확하면) 이 규칙은 걸리지 않습니다.
  const signals = trustedSignals(request);
  const unusual = Boolean(signals) && ODD_HOURS.has(signals.hour) && signals.network === 'unusual'
    && recentBurst(request) >= BURST_COUNT;
  if (unusual && !reauthenticated(request)) return answer('step_up', 'step_up_required', 'step_up_required');

  rememberOwner(request);   // 허용한 메모 경로의 첫 사용자를 기록합니다.
  return { ...answer('allow', 'approved', 'device_registered') };
}
